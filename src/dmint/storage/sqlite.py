"""SQLite persistence for exact pending approval request records."""

from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
from collections.abc import Container, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc8785

from ..canonicalize import redact_sensitive_data, thaw_json

from ..approvals import (
    APPROVAL_RECORD_SCHEMA_VERSION,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
    parse_approval_state,
)
from ..authority import ApprovalAssertion, ApprovalVerifier
from ..errors import (
    ApprovalConcurrentConsumeError,
    ApprovalConsumedError,
    ApprovalDeploymentInvalidError,
    ApprovalNotFoundError,
    ApprovalNotApprovedError,
    ApprovalPolicyInvalidError,
    ApprovalPrincipalMismatchError,
    ApprovalRequestMismatchError,
    ApprovalStoreError,
    CorruptApprovalRecordError,
    MalformedApprovalError,
)
from ..models import NO_RESOURCE, NoResource, ToolRequest, TrustedContext
from ..request_binding import request_binding_fingerprint
from ..versions import CANONICALIZATION_PROFILE, REQUEST_BINDING_VERSION

_ID_PATTERN = re.compile(r"^(?:req|apr)_[A-Za-z0-9_-]{43}$")
_STORED_COLUMNS = (
    "schema_version",
    "approval_id",
    "request_id",
    "request_fingerprint",
    "binding_version",
    "canonicalization_profile",
    "integration_id",
    "capability_id",
    "principal_id",
    "tool",
    "action",
    "resource_kind",
    "resource_value",
    "arguments_json",
    "trusted_context_json",
    "policy_version_id",
    "policy_digest",
    "policy_evaluated_at",
    "created_at",
    "expires_at",
    "state",
    "decision_authority_id",
    "decision_authority_subject",
    "decision_authority_kind",
    "decision_at",
    "state_reason",
    "state_at",
    "consumed_at",
    "deployment_epoch",
)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS approval_records (
    schema_version TEXT NOT NULL,
    approval_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_fingerprint TEXT NOT NULL,
    binding_version TEXT NOT NULL,
    canonicalization_profile TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('none', 'value')),
    resource_value TEXT,
    arguments_json TEXT NOT NULL,
    trusted_context_json TEXT NOT NULL,
    policy_version_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    policy_evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'PENDING', 'APPROVED', 'REJECTED', 'CANCELLED',
            'EXPIRED', 'POLICY_INVALIDATED', 'CONSUMED'
        )
    ),
    state_at TEXT NOT NULL,
    decision_authority_id TEXT,
    decision_authority_subject TEXT,
    decision_authority_kind TEXT,
    decision_at TEXT,
    state_reason TEXT,
    consumed_at TEXT,
    deployment_epoch TEXT NOT NULL,
    record_checksum TEXT NOT NULL,
    CHECK (
        (resource_kind = 'none' AND resource_value IS NULL)
        OR
        (resource_kind = 'value' AND resource_value IS NOT NULL)
    )
)
"""

_CREATE_POLICY_TABLE = """
CREATE TABLE IF NOT EXISTS store_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_CREATE_RECOVERY_TABLE = """
CREATE TABLE IF NOT EXISTS store_recovery (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    recovery_token TEXT NOT NULL,
    counter INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _canonical_json(value: Any) -> str:
    try:
        return rfc8785.dumps(value).decode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise CorruptApprovalRecordError("value is not valid JCS JSON") from exc


def _integrity_checksum(payload: Mapping[str, Any]) -> str:
    try:
        canonical = rfc8785.dumps(dict(payload))
    except (TypeError, ValueError, OverflowError) as exc:
        raise CorruptApprovalRecordError("stored integrity payload is invalid") from exc
    return hashlib.sha256(b"dmint/approval-record-integrity/v1\x00" + canonical).hexdigest()


def _load_canonical_object(raw: Any, field: str) -> dict[str, Any]:
    if type(raw) is not str:
        raise CorruptApprovalRecordError(f"stored {field} is not text")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CorruptApprovalRecordError(f"stored {field} is malformed JSON") from exc
    if type(value) is not dict:
        raise CorruptApprovalRecordError(f"stored {field} must be a JSON object")
    if _canonical_json(value) != raw:
        raise CorruptApprovalRecordError(f"stored {field} is not canonical JCS")
    return value


def _timestamp(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CorruptApprovalRecordError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _load_timestamp(value: Any, field: str) -> datetime:
    if type(value) is not str:
        raise CorruptApprovalRecordError(f"stored {field} is not text")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CorruptApprovalRecordError(f"stored {field} is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CorruptApprovalRecordError(f"stored {field} is not timezone-aware")
    normalized = parsed.astimezone(timezone.utc)
    if normalized.isoformat() != value:
        raise CorruptApprovalRecordError(f"stored {field} is not canonical UTC")
    return normalized


def _required(row: sqlite3.Row, field: str) -> Any:
    value = row[field]
    if value is None:
        raise CorruptApprovalRecordError(f"stored field is missing: {field}")
    return value


class SQLiteApprovalStore:
    """Small SQLite repository for pending exact-request approval records.

    Stage 2B persists pending records. Stage 2D adds approved-record handoff
    and an atomic APPROVED -> CONSUMED operation; neither operation executes a
    tool.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        deployment_epoch: str,
        recovery_epoch_file: str | Path | None = None,
        redact_keys: Container[str] | None = None,
        max_pending_per_principal: int = 100,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(deployment_epoch) is not str or not deployment_epoch or deployment_epoch != deployment_epoch.strip():
            raise ValueError("deployment_epoch must be a non-empty string")
        if type(max_pending_per_principal) is not int or max_pending_per_principal <= 0:
            raise ValueError("max_pending_per_principal must be a positive integer")
        self._deployment_epoch = deployment_epoch
        self._max_pending_per_principal = max_pending_per_principal
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._redact_keys = redact_keys
        db_str = str(database)
        if db_str != ":memory:" and not db_str.startswith("file:"):
            db_path = Path(db_str)
            db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not db_path.exists():
                fd = os.open(str(db_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
                os.close(fd)
            else:
                try:
                    os.chmod(str(db_path), 0o600)
                except OSError:
                    pass
            self._recovery_file = Path(recovery_epoch_file or f"{db_str}.epoch")
            if not self._recovery_file.exists():
                fd = os.open(str(self._recovery_file), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
                os.close(fd)
            else:
                try:
                    os.chmod(str(self._recovery_file), 0o600)
                except OSError:
                    pass
        else:
            self._recovery_file = None
        try:
            self._connection = sqlite3.connect(db_str)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute(_CREATE_TABLE)
            self._connection.execute(_CREATE_POLICY_TABLE)
            self._connection.execute(_CREATE_RECOVERY_TABLE)
            self._connection.commit()
            self._sync_recovery_counter(increment=False)
        except (sqlite3.Error, ApprovalStoreError) as exc:
            if isinstance(exc, ApprovalStoreError):
                raise
            raise ApprovalStoreError("could not initialize approval store") from exc

    def _sync_recovery_counter(self, *, increment: bool = False) -> None:
        if self._recovery_file is None:
            return
        try:
            row = self._connection.execute("SELECT counter FROM store_recovery WHERE id = 1").fetchone()
            db_counter = row["counter"] if row else 0

            sidecar_counter = 0
            if self._recovery_file.exists():
                content = self._recovery_file.read_text(encoding="utf-8").strip()
                if content:
                    sidecar_counter = int(content)

            if db_counter < sidecar_counter:
                raise ApprovalStoreError("database rollback detected: storage recovery counter mismatch")

            if increment or db_counter == 0:
                new_counter = max(db_counter, sidecar_counter) + (1 if increment else 0)
                if new_counter == 0:
                    new_counter = 1
                now_str = _timestamp(self._clock())
                self._connection.execute(
                    """
                    INSERT INTO store_recovery (id, recovery_token, counter, updated_at)
                    VALUES (1, 'default', ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        counter = excluded.counter,
                        updated_at = excluded.updated_at
                    """,
                    (new_counter, now_str),
                )
                self._connection.commit()
                temp_file = self._recovery_file.with_suffix(".tmp")
                temp_file.write_text(str(new_counter), encoding="utf-8")
                temp_file.replace(self._recovery_file)
        except (sqlite3.Error, ValueError) as exc:
            raise ApprovalStoreError("recovery epoch counter check failed") from exc

    def close(self) -> None:
        self._connection.close()

    def set_authoritative_policy(self, policy: Policy, provenance: PolicyProvenance) -> None:
        from ..models import AnyResource
        from ..policy import Policy, Rule
        if type(policy) is not Policy or type(provenance) is not PolicyProvenance:
            raise MalformedApprovalError("invalid policy or provenance for store")
        rules_list = []
        for r in policy.rules:
            rule_dict = {"effect": r.effect.value.lower(), "tool": r.tool, "action": r.action}
            if r.agent_id is not None:
                rule_dict["agent_id"] = r.agent_id
            if type(r.resource) is str:
                rule_dict["resource"] = r.resource
            elif type(r.resource) is AnyResource:
                rule_dict["resource"] = "*"
            if r.conditions:
                conds = []
                for c in r.conditions:
                    conds.append({"field": c.field, "operator": c.operator, "value": thaw_json(c.value)})
                rule_dict["conditions"] = conds
            rules_list.append(rule_dict)
        rules_json = _canonical_json({"rules": rules_list})
        now_str = _timestamp(self._clock())
        try:
            with self._connection:
                self._connection.execute(
                    """
                    INSERT INTO store_policy (id, version_id, policy_digest, rules_json, updated_at)
                    VALUES (1, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        version_id = excluded.version_id,
                        policy_digest = excluded.policy_digest,
                        rules_json = excluded.rules_json,
                        updated_at = excluded.updated_at
                    """,
                    (provenance.version_id, provenance.policy_digest, rules_json, now_str),
                )
        except sqlite3.Error as exc:
            raise ApprovalStoreError("could not update store policy") from exc

    def get_authoritative_policy(self) -> tuple[Policy, PolicyProvenance] | None:
        from ..policy import Policy
        try:
            row = self._connection.execute(
                "SELECT version_id, policy_digest, rules_json, updated_at FROM store_policy WHERE id = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise ApprovalStoreError("could not read store policy") from exc
        if row is None:
            return None
        try:
            rules_data = _load_canonical_object(row["rules_json"], "rules_json")
            policy = Policy.from_mapping(rules_data)
            updated_at = _load_timestamp(row["updated_at"], "updated_at")
            provenance = PolicyProvenance(row["version_id"], row["policy_digest"], updated_at)
            return policy, provenance
        except (MalformedApprovalError, CorruptApprovalRecordError, KeyError) as exc:
            raise CorruptApprovalRecordError("stored policy is corrupted") from exc

    def _rollback_safely(self) -> None:
        try:
            self._connection.rollback()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "SQLiteApprovalStore":
        return self

    def __exit__(self, exception_type: Any, exception: Any, traceback: Any) -> None:
        self.close()

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        ts = _timestamp(now or self._clock())
        try:
            with self._connection:
                cursor = self._connection.execute(
                    "DELETE FROM approval_records WHERE state = 'PENDING' AND expires_at <= ?",
                    (ts,),
                )
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise ApprovalStoreError("could not clean up expired records") from exc

    def save_pending(self, record: ApprovalRecord) -> ApprovalRecord:
        if type(record) is not ApprovalRecord or record.state is not ApprovalState.PENDING:
            raise MalformedApprovalError("Stage 2B only persists pending approvals")
        self._sync_recovery_counter(increment=False)
        self.cleanup_expired()

        # Check explicit duplicate approval_id or request_id
        existing_by_id = self._connection.execute(
            "SELECT approval_id FROM approval_records WHERE approval_id = ? OR request_id = ?",
            (record.approval_id, record.request.request_id),
        ).fetchone()
        if existing_by_id is not None:
            raise ApprovalStoreError("approval record conflicts with existing state")

        ts = _timestamp(self._clock())
        # Safe deduplication: reuse existing unexpired identical pending record
        existing_pending = self._connection.execute(
            """
            SELECT approval_id FROM approval_records
            WHERE request_fingerprint = ?
            AND principal_id = ?
            AND integration_id = ?
            AND state = 'PENDING'
            AND expires_at > ?
            """,
            (record.request_fingerprint, record.request.agent_id, record.integration_id, ts),
        ).fetchone()

        if existing_pending is not None:
            existing_record = self.get(existing_pending["approval_id"])
            if existing_record is not None:
                return existing_record

        # Check pending quota per principal
        count_row = self._connection.execute(
            """
            SELECT COUNT(*) AS count FROM approval_records
            WHERE principal_id = ? AND state = 'PENDING' AND expires_at > ?
            """,
            (record.request.agent_id, ts),
        ).fetchone()

        pending_count = count_row["count"] if count_row else 0
        if pending_count >= self._max_pending_per_principal:
            raise ApprovalStoreError("quota exceeded: maximum pending approvals reached for principal")

        self._save(record)
        return record

    def save_approved(self, record: ApprovalRecord) -> None:
        if type(record) is not ApprovalRecord or record.state is not ApprovalState.APPROVED:
            raise MalformedApprovalError("Stage 2D requires an approved approval record")
        values = self._serialize(record)
        try:
            with self._connection:
                assignments = ", ".join(f"{column} = ?" for column in (*_STORED_COLUMNS, "record_checksum"))
                cursor = self._connection.execute(
                    f"UPDATE approval_records SET {assignments} "
                    "WHERE approval_id = ? AND state = 'PENDING'",
                    values + (record.approval_id,),
                )
                if cursor.rowcount == 0:
                    self._insert_values(values)
        except sqlite3.IntegrityError as exc:
            raise ApprovalStoreError("approval record conflicts with existing state") from exc
        except sqlite3.Error as exc:
            raise ApprovalStoreError("could not persist approved approval") from exc

    def _save(self, record: ApprovalRecord) -> None:
        if type(record) is not ApprovalRecord:
            raise MalformedApprovalError("store requires an ApprovalRecord")
        values = self._serialize(record)
        try:
            with self._connection:
                self._insert_values(values)
        except sqlite3.IntegrityError as exc:
            raise ApprovalStoreError("approval record conflicts with existing state") from exc
        except sqlite3.Error as exc:
            raise ApprovalStoreError("could not persist approval record") from exc

    def _insert_values(self, values: tuple[Any, ...]) -> None:
        self._connection.execute(
            """
            INSERT INTO approval_records (
                schema_version, approval_id, request_id, request_fingerprint,
                binding_version, canonicalization_profile, integration_id,
                capability_id, principal_id, tool, action, resource_kind,
                resource_value, arguments_json, trusted_context_json,
                policy_version_id, policy_digest, policy_evaluated_at,
                created_at, expires_at, state, decision_authority_id,
                decision_authority_subject, decision_authority_kind,
                decision_at, state_reason, state_at, consumed_at,
                deployment_epoch, record_checksum
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )

    def get_pending(self, approval_id: str) -> ApprovalRecord | None:
        record = self.get(approval_id)
        if record is not None and record.state is not ApprovalState.PENDING:
            raise CorruptApprovalRecordError("stored record is not pending")
        return record

    def get_approved(self, approval_id: str) -> ApprovalRecord | None:
        record = self.get(approval_id)
        if record is not None and record.state is not ApprovalState.APPROVED:
            raise CorruptApprovalRecordError("stored record is not approved")
        return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        if type(approval_id) is not str or not _ID_PATTERN.fullmatch(approval_id) or not approval_id.startswith("apr_"):
            raise CorruptApprovalRecordError("invalid approval_id lookup")
        self._sync_recovery_counter(increment=False)
        try:
            row = self._fetch_row(approval_id)
        except sqlite3.Error as exc:
            raise ApprovalStoreError("could not load approval record") from exc
        if row is None:
            return None
        return self._deserialize(row)

    def _fetch_row(self, approval_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM approval_records WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()

    def require_pending(self, approval_id: str) -> ApprovalRecord:
        record = self.get_pending(approval_id)
        if record is None:
            raise ApprovalNotFoundError("approval record was not found")
        return record

    def invalidate_approved(
        self,
        record: ApprovalRecord,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        if type(record) is not ApprovalRecord or record.state is not ApprovalState.APPROVED:
            raise ApprovalNotApprovedError("approval is not approved")
        invalidated = record.invalidate_policy(now=now or self._clock(), reason=reason)
        serialized = self._serialize(invalidated)
        try:
            with self._connection:
                assignments = ", ".join(f"{column} = ?" for column in (*_STORED_COLUMNS, "record_checksum"))
                cursor = self._connection.execute(
                    f"UPDATE approval_records SET {assignments} "
                    "WHERE approval_id = ? AND state = 'APPROVED'",
                    serialized + (record.approval_id,),
                )
                if cursor.rowcount != 1:
                    raise ApprovalConcurrentConsumeError("approval state changed during invalidation")
            return invalidated
        except (ApprovalStoreError, MalformedApprovalError):
            self._rollback_safely()
            raise
        except sqlite3.Error as exc:
            self._rollback_safely()
            raise ApprovalStoreError("could not invalidate approval") from exc

    def consume_approved(
        self,
        *,
        approval_id: str,
        credential: ApprovalAssertion | bytes,
        expected_request: ToolRequest,
        verifier: ApprovalVerifier,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Atomically consume one approved exact request without executing it.

        Current-policy evaluation belongs to the caller and must happen before
        this operation. This method performs the final credential, request,
        expiry, deployment, and state checks inside an SQLite write lock, then
        commits APPROVED -> CONSUMED before returning.
        """

        if type(approval_id) is not str or not _ID_PATTERN.fullmatch(approval_id) or not approval_id.startswith("apr_"):
            raise CorruptApprovalRecordError("invalid approval_id lookup")
        if type(expected_request) is not ToolRequest:
            raise ApprovalRequestMismatchError("expected request is invalid")
        if not isinstance(verifier, ApprovalVerifier):
            raise ApprovalStoreError("a trusted approval verifier is required")
        now = _load_timestamp(_timestamp(now or self._clock()), "consume time")
        try:
            if type(credential) is bytes:
                credential = ApprovalAssertion.from_bytes(credential)
            if type(credential) is not ApprovalAssertion:
                raise ApprovalStoreError("approval credential is invalid")
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._fetch_row(approval_id)
            if row is None:
                raise ApprovalNotFoundError("approval record was not found")
            if row["deployment_epoch"] != self._deployment_epoch:
                raise ApprovalDeploymentInvalidError("approval deployment epoch mismatch")
            record = self._deserialize(row)
            if record.state is ApprovalState.CONSUMED:
                raise ApprovalConsumedError("approval has already been consumed")
            if record.state is ApprovalState.EXPIRED:
                raise ApprovalExpiredError("approval has expired")
            if record.state is ApprovalState.POLICY_INVALIDATED:
                raise ApprovalPolicyInvalidError("approval policy is invalid")
            if record.state is not ApprovalState.APPROVED:
                raise ApprovalNotApprovedError("approval is not approved")
            if expected_request.request_id != record.request_id:
                raise ApprovalRequestMismatchError("request_id mismatch")
            if expected_request.agent_id != record.request.agent_id:
                raise ApprovalPrincipalMismatchError("principal mismatch")
            expected_fingerprint = request_binding_fingerprint(
                expected_request,
                integration_id=record.integration_id,
                capability_id=record.capability_id,
            )
            if expected_fingerprint != record.request_fingerprint:
                raise ApprovalRequestMismatchError("request fingerprint mismatch")
            verifier.verify(credential, record, now=now)
            consumed = record.consume(now=now)
            serialized = self._serialize(consumed)
            payload = dict(zip(_STORED_COLUMNS, serialized[:-1]))
            checksum = serialized[-1]
            assignments = ", ".join(f"{column} = ?" for column in (*_STORED_COLUMNS, "record_checksum"))
            cursor = self._connection.execute(
                f"UPDATE approval_records SET {assignments} "
                "WHERE approval_id = ? "
                "AND state = 'APPROVED' "
                "AND request_id = ? "
                "AND request_fingerprint = ? "
                "AND principal_id = ? "
                "AND integration_id = ? "
                "AND deployment_epoch = ? "
                "AND expires_at > ?",
                tuple(payload[column] for column in _STORED_COLUMNS)
                + (checksum, approval_id, record.request_id, record.request_fingerprint,
                   record.request.agent_id, record.integration_id, self._deployment_epoch,
                   _timestamp(now)),
            )
            if cursor.rowcount != 1:
                raise ApprovalConcurrentConsumeError("approval consumption race was lost")
            self._connection.commit()
            self._sync_recovery_counter(increment=True)
            return consumed
        except (ApprovalStoreError, MalformedApprovalError):
            self._rollback_safely()
            raise
        except sqlite3.Error as exc:
            self._rollback_safely()
            raise ApprovalStoreError("approval consumption storage failure") from exc
        except Exception:
            self._rollback_safely()
            raise

    def _serialize(self, record: ApprovalRecord) -> tuple[Any, ...]:
        request = record.request
        raw_args = _thaw_object(request.arguments, "arguments")
        if self._redact_keys is not None:
            raw_args = redact_sensitive_data(raw_args, self._redact_keys)
        arguments = _canonical_json(raw_args)
        trusted_context = _canonical_json(_thaw_object(request.context.values, "trusted_context"))
        if type(request.resource) is NoResource:
            resource_kind = "none"
            resource_value = None
        elif type(request.resource) is str:
            resource_kind = "value"
            resource_value = request.resource
        else:
            raise CorruptApprovalRecordError("invalid request resource")
        authority = record.decision_authority
        if authority is None:
            authority_id = None
            authority_subject = None
            authority_kind = None
        else:
            authority_id = authority.authority_id
            authority_subject = authority.subject_id
            authority_kind = authority.kind.value
        payload = {
            "schema_version": record.schema_version,
            "approval_id": record.approval_id,
            "request_id": record.request_id,
            "request_fingerprint": record.request_fingerprint,
            "binding_version": record.binding_version,
            "canonicalization_profile": record.canonicalization_profile,
            "integration_id": record.integration_id,
            "capability_id": record.capability_id,
            "principal_id": request.agent_id,
            "tool": request.tool,
            "action": request.action,
            "resource_kind": resource_kind,
            "resource_value": resource_value,
            "arguments_json": arguments,
            "trusted_context_json": trusted_context,
            "policy_version_id": record.policy_provenance.version_id,
            "policy_digest": record.policy_provenance.policy_digest,
            "policy_evaluated_at": _timestamp(record.policy_provenance.evaluated_at),
            "created_at": _timestamp(record.created_at),
            "expires_at": _timestamp(record.expires_at),
            "state": record.state.value,
            "decision_authority_id": authority_id,
            "decision_authority_subject": authority_subject,
            "decision_authority_kind": authority_kind,
            "decision_at": _timestamp(record.decision_at) if record.decision_at is not None else None,
            "state_reason": record.state_reason,
            "consumed_at": _timestamp(record.consumed_at) if record.consumed_at is not None else None,
            "state_at": _timestamp(record.state_at),
            "deployment_epoch": self._deployment_epoch,
        }
        return tuple(payload[column] for column in _STORED_COLUMNS) + (
            _integrity_checksum(payload),
        )

    def _deserialize(self, row: sqlite3.Row) -> ApprovalRecord:
        try:
            payload = {column: row[column] for column in _STORED_COLUMNS}
            stored_checksum = row["record_checksum"]
            if type(stored_checksum) is not str or stored_checksum != _integrity_checksum(payload):
                raise CorruptApprovalRecordError("stored approval integrity check failed")
            schema_version = _required(row, "schema_version")
            approval_id = _required(row, "approval_id")
            request_id = _required(row, "request_id")
            fingerprint = _required(row, "request_fingerprint")
            binding_version = _required(row, "binding_version")
            profile = _required(row, "canonicalization_profile")
            integration_id = _required(row, "integration_id")
            capability_id = _required(row, "capability_id")
            principal_id = _required(row, "principal_id")
            tool = _required(row, "tool")
            action = _required(row, "action")
            resource_kind = _required(row, "resource_kind")
            resource_value = row["resource_value"]
            arguments = _load_canonical_object(_required(row, "arguments_json"), "arguments")
            context = _load_canonical_object(_required(row, "trusted_context_json"), "trusted_context")
            state = parse_approval_state(_required(row, "state"))
            deployment_epoch = _required(row, "deployment_epoch")
            if deployment_epoch != self._deployment_epoch:
                raise CorruptApprovalRecordError("approval deployment epoch mismatch")
            authority_values = (
                row["decision_authority_id"],
                row["decision_authority_subject"],
                row["decision_authority_kind"],
            )
            if all(value is None for value in authority_values):
                decision_authority = None
            elif all(type(value) is str for value in authority_values):
                try:
                    authority_kind = ApprovalAuthorityKind(authority_values[2])
                except ValueError as exc:
                    raise CorruptApprovalRecordError("invalid stored approval authority kind") from exc
                decision_authority = ApprovalAuthority._from_recorded_metadata(
                    authority_values[0],
                    authority_values[1],
                    authority_kind,
                )
            else:
                raise CorruptApprovalRecordError("incomplete stored approval authority")
            if resource_kind == "none" and resource_value is None:
                resource = NO_RESOURCE
            elif resource_kind == "value" and type(resource_value) is str:
                resource = resource_value
            else:
                raise CorruptApprovalRecordError("invalid stored resource representation")
            request = ToolRequest(
                request_id=request_id,
                agent_id=principal_id,
                tool=tool,
                action=action,
                resource=resource,
                arguments=arguments,
                context=TrustedContext(context),
            )
            policy = PolicyProvenance(
                _required(row, "policy_version_id"),
                _required(row, "policy_digest"),
                _load_timestamp(_required(row, "policy_evaluated_at"), "policy_evaluated_at"),
            )
            return ApprovalRecord._from_storage(
                schema_version=schema_version,
                approval_id=approval_id,
                request=request,
                request_fingerprint=fingerprint,
                binding_version=binding_version,
                canonicalization_profile=profile,
                integration_id=integration_id,
                capability_id=capability_id,
                policy_provenance=policy,
                created_at=_load_timestamp(_required(row, "created_at"), "created_at"),
                expires_at=_load_timestamp(_required(row, "expires_at"), "expires_at"),
                state=state,
                state_at=_load_timestamp(_required(row, "state_at"), "state_at"),
                decision_authority=decision_authority,
                decision_at=(
                    _load_timestamp(row["decision_at"], "decision_at")
                    if row["decision_at"] is not None
                    else None
                ),
                state_reason=row["state_reason"],
                consumed_at=(
                    _load_timestamp(row["consumed_at"], "consumed_at")
                    if row["consumed_at"] is not None
                    else None
                ),
            )
        except CorruptApprovalRecordError:
            raise
        except (MalformedApprovalError, TypeError, ValueError, KeyError, IndexError) as exc:
            raise CorruptApprovalRecordError("stored approval record is invalid") from exc


def _thaw_object(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CorruptApprovalRecordError(f"{field} is not an object")
    result = {key: _thaw_value(item) for key, item in value.items()}
    if type(result) is not dict:
        raise CorruptApprovalRecordError(f"{field} is not an object")
    return result


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_value(item) for item in value]
    return value
