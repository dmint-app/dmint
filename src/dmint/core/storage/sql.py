"""SQLAlchemy Core persistence for exact pending approval request records."""

from __future__ import annotations

import contextlib
import hmac
import logging
import os
from collections.abc import Callable, Collection, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:  # POSIX cross-process lock
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None  # type: ignore[assignment]

try:  # Windows cross-process lock
    import msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    msvcrt = None  # type: ignore[assignment]

from sqlalchemy import (
    CheckConstraint,
    Column,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    create_engine,
    delete,
    func,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import Connection, Engine, RowMapping
from sqlalchemy.exc import DBAPIError, IntegrityError, SQLAlchemyError

from ..canonicalize import redact_sensitive_data

if TYPE_CHECKING:
    from ..authority import LocalApprovalAuthority
    from ..policy import Policy

from .base import ApprovalStore
from ..approvals import (
    APPROVAL_RECORD_SCHEMA_VERSION,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
    parse_approval_state,
)
from ..verification import ApprovalAssertion, ApprovalVerifier
from ..errors import (
    ApprovalConcurrentConsumeError,
    ApprovalConsumedError,
    ApprovalDeploymentInvalidError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalNotApprovedError,
    ApprovalPolicyInvalidError,
    ApprovalPrincipalMismatchError,
    ApprovalRequestMismatchError,
    ApprovalStoreConfigurationError,
    ApprovalStoreError,
    CorruptApprovalRecordError,
    DeprecatedStorageFormatError,
    MalformedApprovalError,
    UnknownApprovalVersionError,
)
from ..models import NO_RESOURCE, NoResource, ToolRequest, TrustedContext

logger = logging.getLogger(__name__)
from ..request_binding import request_binding_fingerprint
from .sqlite import (
    _ID_PATTERN,
    _STORED_COLUMNS,
    _canonical_json,
    _integrity_checksum,
    _is_deprecated_v1_checksum,
    _load_canonical_object,
    _load_timestamp,
    _thaw_object,
    _timestamp,
)

if TYPE_CHECKING:
    from ..policy import Policy


def _required(row: RowMapping | Mapping[str, Any], field: str) -> Any:
    value = row.get(field)
    if value is None:
        raise CorruptApprovalRecordError(f"stored field is missing: {field}")
    return value


def _build_tables(metadata: MetaData) -> tuple[Table, Table, Table]:
    records = Table(
        "approval_records",
        metadata,
        Column("schema_version", Text, nullable=False),
        Column("approval_id", Text, primary_key=True),
        Column("request_id", Text, nullable=False, unique=True),
        Column("request_fingerprint", Text, nullable=False),
        Column("binding_version", Text, nullable=False),
        Column("canonicalization_profile", Text, nullable=False),
        Column("integration_id", Text, nullable=False),
        Column("capability_id", Text, nullable=False),
        Column("principal_id", Text, nullable=False),
        Column("tool", Text, nullable=False),
        Column("action", Text, nullable=False),
        Column("resource_kind", Text, nullable=False),
        Column("resource_value", Text, nullable=True),
        Column("arguments_json", Text, nullable=False),
        Column("trusted_context_json", Text, nullable=False),
        Column("policy_version_id", Text, nullable=False),
        Column("policy_digest", Text, nullable=False),
        Column("policy_evaluated_at", Text, nullable=False),
        Column("created_at", Text, nullable=False),
        Column("expires_at", Text, nullable=False),
        Column("state", Text, nullable=False),
        Column("state_at", Text, nullable=False),
        Column("decision_authority_id", Text, nullable=True),
        Column("decision_authority_subject", Text, nullable=True),
        Column("decision_authority_kind", Text, nullable=True),
        Column("decision_at", Text, nullable=True),
        Column("state_reason", Text, nullable=True),
        Column("consumed_at", Text, nullable=True),
        Column("deployment_epoch", Text, nullable=False),
        Column("row_version", Integer, nullable=False, default=1, server_default="1"),
        Column("record_checksum", Text, nullable=False),
        CheckConstraint("resource_kind IN ('none', 'value')", name="ck_approval_records_resource_kind"),
        CheckConstraint(
            "state IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED', 'POLICY_INVALIDATED', 'CONSUMED')",
            name="ck_approval_records_state",
        ),
        CheckConstraint(
            "(resource_kind = 'none' AND resource_value IS NULL) "
            "OR (resource_kind = 'value' AND resource_value IS NOT NULL)",
            name="ck_approval_records_resource_consistency",
        ),
    )

    Index("idx_approval_records_pending", records.c.state, records.c.expires_at)
    Index(
        "idx_approval_records_dedup",
        records.c.request_fingerprint,
        records.c.principal_id,
        records.c.integration_id,
        records.c.state,
        records.c.expires_at,
    )

    policy = Table(
        "store_policy",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("version_id", Text, nullable=False),
        Column("policy_digest", Text, nullable=False),
        Column("rules_json", Text, nullable=False),
        Column("updated_at", Text, nullable=False),
        CheckConstraint("id = 1", name="ck_store_policy_id"),
    )

    recovery = Table(
        "store_recovery",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("recovery_token", Text, nullable=False),
        Column("counter", Integer, nullable=False),
        Column("updated_at", Text, nullable=False),
        CheckConstraint("id = 1", name="ck_store_recovery_id"),
    )

    Table(
        "approval_assertions",
        metadata,
        Column("approval_id", Text, primary_key=True),
        Column("assertion_json", Text, nullable=False),
        Column("updated_at", Text, nullable=False),
    )

    return records, policy, recovery


class SQLAlchemyApprovalStore(ApprovalStore):
    """SQLAlchemy Core-backed repository for pending and approved records.

    Provides identical guarantees across SQLite and PostgreSQL backends:
    - Fail-closed deterministic security semantics
    - Concurrency protection via row-level locking (SELECT ... FOR UPDATE on Postgres)
    - Single-use atomic approval consumption
    """

    _MAX_QUERY_LIMIT: int = 1000

    def __init__(
        self,
        url_or_engine: str | Engine,
        *,
        deployment_epoch: str,
        integrity_key: bytes | Path | str | None = None,
        recovery_epoch_file: str | Path | None = None,
        redact_keys: Collection[str] | None = None,
        max_pending_per_principal: int = 100,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(deployment_epoch) is not str or not deployment_epoch or deployment_epoch != deployment_epoch.strip():
            raise ValueError("deployment_epoch must be a non-empty string")
        if type(max_pending_per_principal) is not int or max_pending_per_principal <= 0:
            raise ValueError("max_pending_per_principal must be a positive integer")

        from ..keys import load_integrity_key_source

        self._integrity_key = load_integrity_key_source(integrity_key)
        self._deployment_epoch = deployment_epoch
        self._max_pending_per_principal = max_pending_per_principal
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._redact_keys = redact_keys

        if isinstance(url_or_engine, Engine):
            self._engine = url_or_engine
            self._owns_engine = False
        else:
            raw_url = str(url_or_engine)
            if raw_url.startswith("postgres://"):
                raw_url = "postgresql://" + raw_url[len("postgres://") :]
            if raw_url.startswith("postgresql://"):
                try:
                    import psycopg  # noqa: F401
                except ImportError:
                    try:
                        import psycopg2  # noqa: F401

                        raw_url = "postgresql+psycopg2://" + raw_url[len("postgresql://") :]
                    except ImportError:
                        pass
            try:
                if raw_url.startswith("sqlite"):
                    self._engine = create_engine(raw_url, connect_args={"timeout": 30.0})
                else:
                    self._engine = create_engine(
                        raw_url,
                        pool_pre_ping=True,
                        pool_size=10,
                        max_overflow=20,
                    )
            except Exception as exc:
                from ..redaction import redact_database_url

                safe_msg = redact_database_url(str(exc))
                raise ApprovalStoreConfigurationError(f"Invalid database engine configuration: {safe_msg}") from None
            self._owns_engine = True

        # Connectivity validation ping - fail loud immediately if unreachable or auth failure
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as exc:
            if self._owns_engine:
                self._engine.dispose()
            from ..redaction import redact_database_url

            safe_msg = redact_database_url(str(exc))
            raise ApprovalStoreConfigurationError(f"Failed to connect to database: {safe_msg}") from None

        self._is_postgres = self._engine.dialect.name == "postgresql"
        self._is_sqlite = self._engine.dialect.name == "sqlite"

        # Setup sidecar file if SQLite local file path
        self._recovery_file: Path | None
        if self._is_sqlite and recovery_epoch_file is not None:
            self._recovery_file = Path(recovery_epoch_file)
        else:
            self._recovery_file = None

        # Build schema
        self._metadata = MetaData()
        self._records_table, self._policy_table, self._recovery_table = _build_tables(self._metadata)

        try:
            self._metadata.create_all(self._engine)
            self._sync_recovery_counter(increment=False)
        except (SQLAlchemyError, ApprovalStoreError) as exc:
            if isinstance(exc, ApprovalStoreError):
                raise
            raise ApprovalStoreError("could not initialize approval store schema") from exc

    @property
    def engine(self) -> Engine:
        """Underlying SQLAlchemy Engine instance."""
        return self._engine

    def _sync_recovery_counter(self, *, increment: bool = False, conn: Connection | None = None) -> None:
        try:
            if conn is not None:
                self._sync_recovery_counter_with_conn(conn, increment=increment)
            else:
                with self._engine.begin() as new_conn:
                    self._sync_recovery_counter_with_conn(new_conn, increment=increment)
        except ApprovalStoreError:
            raise
        except (SQLAlchemyError, ValueError) as exc:
            raise ApprovalStoreError("recovery epoch counter check failed") from exc

    @contextlib.contextmanager
    def _recovery_lock(self) -> Iterator[None]:
        if self._recovery_file is None:
            yield
            return
        lock_path = self._recovery_file.with_name(self._recovery_file.name + ".lock")
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            raise ApprovalStoreError("could not open recovery counter lock") from exc
        try:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                elif msvcrt is not None:  # pragma: no cover - Windows-only branch
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            except OSError as exc:
                raise ApprovalStoreError("could not acquire recovery counter lock") from exc
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no cover - Windows-only branch
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            finally:
                os.close(fd)

    def _write_recovery_sidecar(self, counter: int) -> None:
        if self._recovery_file is None:
            return
        temp_file = self._recovery_file.with_name(self._recovery_file.name + ".tmp")
        temp_file.write_text(str(counter), encoding="utf-8")
        try:
            os.chmod(str(temp_file), 0o600)
        except OSError:
            pass
        temp_file.replace(self._recovery_file)

    def _sync_recovery_counter_with_conn(self, conn: Connection, *, increment: bool = False) -> None:
        with self._recovery_lock():
            row = conn.execute(select(self._recovery_table.c.counter).where(self._recovery_table.c.id == 1)).fetchone()
            row_value = row[0] if row is not None else None
            row_missing = row_value is None
            db_counter = int(row_value) if row_value is not None else 1

            sidecar_counter = 0
            if self._recovery_file is not None and self._recovery_file.exists():
                content = self._recovery_file.read_text(encoding="utf-8").strip()
                if content:
                    sidecar_counter = int(content)

            if self._recovery_file is not None and db_counter < sidecar_counter:
                raise ApprovalStoreError("database rollback detected: storage recovery counter mismatch")

            if increment or row_missing:
                new_counter = max(db_counter, sidecar_counter) + (1 if increment else 0)
                now_str = _timestamp(self._clock())
                conn.execute(
                    text(
                        """
                        INSERT INTO store_recovery (id, recovery_token, counter, updated_at)
                        VALUES (1, 'default', :new_counter, :now_str)
                        ON CONFLICT (id) DO UPDATE SET
                            counter = :new_counter,
                            updated_at = excluded.updated_at
                        """
                    ),
                    {"new_counter": new_counter, "now_str": now_str},
                )
                self._write_recovery_sidecar(new_counter)
            elif self._recovery_file is not None and db_counter > sidecar_counter:
                self._write_recovery_sidecar(db_counter)

    def close(self) -> None:
        if self._owns_engine:
            self._engine.dispose()

    def set_authoritative_policy(self, policy: Policy, provenance: PolicyProvenance) -> None:
        from ..policy import Policy

        if type(policy) is not Policy or type(provenance) is not PolicyProvenance:
            raise MalformedApprovalError("invalid policy or provenance for store")

        rules_json = _canonical_json(policy.to_dict())
        now_str = _timestamp(self._clock())

        try:
            with self._engine.begin() as conn:
                row = conn.execute(select(self._policy_table.c.id).where(self._policy_table.c.id == 1)).fetchone()
                if row is None:
                    conn.execute(
                        insert(self._policy_table).values(
                            id=1,
                            version_id=provenance.version_id,
                            policy_digest=provenance.policy_digest,
                            rules_json=rules_json,
                            updated_at=now_str,
                        )
                    )
                else:
                    conn.execute(
                        update(self._policy_table)
                        .where(self._policy_table.c.id == 1)
                        .values(
                            version_id=provenance.version_id,
                            policy_digest=provenance.policy_digest,
                            rules_json=rules_json,
                            updated_at=now_str,
                        )
                    )
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not update store policy") from exc

    def get_authoritative_policy(self) -> tuple[Policy, PolicyProvenance] | None:
        from ..policy import Policy

        try:
            with self._engine.connect() as conn:
                row = (
                    conn.execute(
                        select(
                            self._policy_table.c.version_id,
                            self._policy_table.c.policy_digest,
                            self._policy_table.c.rules_json,
                            self._policy_table.c.updated_at,
                        ).where(self._policy_table.c.id == 1)
                    )
                    .mappings()
                    .fetchone()
                )
        except SQLAlchemyError as exc:
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

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        ts = _timestamp(now or self._clock())
        try:
            with self._engine.begin() as conn:
                result = conn.execute(
                    delete(self._records_table).where(
                        self._records_table.c.state == ApprovalState.PENDING.value,
                        self._records_table.c.expires_at <= ts,
                    )
                )
                return int(result.rowcount or 0)
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not clean up expired records") from exc

    def save_pending(self, record: ApprovalRecord) -> ApprovalRecord:
        if type(record) is not ApprovalRecord or record.state is not ApprovalState.PENDING:
            raise MalformedApprovalError("Stage 2B only persists pending approvals")

        self.cleanup_expired()
        ts = _timestamp(self._clock())

        try:
            with self._engine.begin() as conn:
                self._sync_recovery_counter_with_conn(conn, increment=False)
                # Check duplicate approval_id or request_id
                existing_by_id = conn.execute(
                    select(self._records_table.c.approval_id).where(
                        or_(
                            self._records_table.c.approval_id == record.approval_id,
                            self._records_table.c.request_id == record.request.request_id,
                        )
                    )
                ).fetchone()
                if existing_by_id is not None:
                    raise ApprovalStoreError("approval record conflicts with existing state")

                # Safe deduplication: reuse existing unexpired identical pending record
                existing_pending = conn.execute(
                    select(self._records_table.c.approval_id).where(
                        self._records_table.c.request_fingerprint == record.request_fingerprint,
                        self._records_table.c.principal_id == record.request.agent_id,
                        self._records_table.c.integration_id == record.integration_id,
                        self._records_table.c.state == ApprovalState.PENDING.value,
                        self._records_table.c.expires_at > ts,
                        self._records_table.c.deployment_epoch == self._deployment_epoch,
                    )
                ).fetchone()

                if existing_pending is not None:
                    existing_record = self._get_with_conn(conn, existing_pending[0])
                    if existing_record is not None:
                        return existing_record

                # Check pending quota per principal
                count = (
                    conn.execute(
                        select(func.count())
                        .select_from(self._records_table)
                        .where(
                            self._records_table.c.principal_id == record.request.agent_id,
                            self._records_table.c.state == ApprovalState.PENDING.value,
                            self._records_table.c.expires_at > ts,
                            self._records_table.c.deployment_epoch == self._deployment_epoch,
                        )
                    ).scalar()
                    or 0
                )

                if count >= self._max_pending_per_principal:
                    raise ApprovalStoreError("quota exceeded: maximum pending approvals reached for principal")

                values = self._serialize(record)
                payload = dict(zip((*_STORED_COLUMNS, "record_checksum"), values))
                conn.execute(insert(self._records_table).values(**payload))
                return record
        except ApprovalStoreError:
            raise
        except IntegrityError as exc:
            raise ApprovalStoreError("approval record conflicts with existing state") from exc
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not persist approval record") from exc

    def save_approved(self, record: ApprovalRecord) -> None:
        if type(record) is not ApprovalRecord or record.state is not ApprovalState.APPROVED:
            raise MalformedApprovalError("Stage 2D requires an approved approval record")

        values = self._serialize(record)
        payload = dict(zip((*_STORED_COLUMNS, "record_checksum"), values))

        try:
            with self._engine.begin() as conn:
                result = conn.execute(
                    update(self._records_table)
                    .where(
                        self._records_table.c.approval_id == record.approval_id,
                        self._records_table.c.state == ApprovalState.PENDING.value,
                    )
                    .values(**payload)
                )
                if result.rowcount == 0:
                    conn.execute(insert(self._records_table).values(**payload))
        except IntegrityError as exc:
            raise ApprovalStoreError("approval record conflicts with existing state") from exc
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not persist approved approval") from exc

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

    def get_approved_assertion_for_request(
        self,
        *,
        request_fingerprint: str,
        principal_id: str,
        integration_id: str,
    ) -> tuple[ApprovalRecord, ApprovalAssertion] | None:
        ts = _timestamp(self._clock())
        try:
            with self._engine.connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT r.approval_id, a.assertion_json
                        FROM approval_records r
                        JOIN approval_assertions a ON r.approval_id = a.approval_id
                        WHERE r.request_fingerprint = :fp
                        AND r.principal_id = :pid
                        AND r.integration_id = :iid
                        AND r.state = 'APPROVED'
                        AND r.expires_at > :ts
                        AND r.deployment_epoch = :epoch
                        ORDER BY r.decision_at DESC, r.created_at DESC
                        LIMIT 1
                        """
                    ),
                    {
                        "fp": request_fingerprint,
                        "pid": principal_id,
                        "iid": integration_id,
                        "ts": ts,
                        "epoch": self._deployment_epoch,
                    },
                ).fetchone()
        except Exception:
            return None
        if row is None:
            return None
        record = self.get(str(row[0]))
        if record is None or record.state is not ApprovalState.APPROVED:
            return None
        try:
            assertion = ApprovalAssertion.from_bytes(str(row[1]).encode("utf-8"))
        except Exception:
            return None
        return record, assertion

    def get(self, approval_id: str) -> ApprovalRecord | None:
        if type(approval_id) is not str or not _ID_PATTERN.fullmatch(approval_id) or not approval_id.startswith("apr_"):
            raise CorruptApprovalRecordError("invalid approval_id lookup")

        try:
            with self._engine.begin() as conn:
                self._sync_recovery_counter_with_conn(conn, increment=False)
                return self._get_with_conn(conn, approval_id)
        except ApprovalStoreError:
            raise
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not load approval record") from exc

    def _get_with_conn(self, conn: Connection, approval_id: str) -> ApprovalRecord | None:
        row = (
            conn.execute(select(self._records_table).where(self._records_table.c.approval_id == approval_id))
            .mappings()
            .fetchone()
        )
        if row is None:
            return None
        return self._deserialize(row)

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
        payload = dict(zip((*_STORED_COLUMNS, "record_checksum"), serialized))

        try:
            with self._engine.begin() as conn:
                result = conn.execute(
                    update(self._records_table)
                    .where(
                        self._records_table.c.approval_id == record.approval_id,
                        self._records_table.c.state == ApprovalState.APPROVED.value,
                    )
                    .values(**payload)
                )
                if result.rowcount != 1:
                    raise ApprovalConcurrentConsumeError("approval state changed during invalidation")
            return invalidated
        except (ApprovalStoreError, MalformedApprovalError):
            raise
        except SQLAlchemyError as exc:
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
        """Atomically consume one approved exact request without executing it."""
        if type(approval_id) is not str or not _ID_PATTERN.fullmatch(approval_id) or not approval_id.startswith("apr_"):
            raise CorruptApprovalRecordError("invalid approval_id lookup")
        if type(expected_request) is not ToolRequest:
            raise ApprovalRequestMismatchError("expected request is invalid")
        if not isinstance(verifier, ApprovalVerifier):
            raise ApprovalStoreError("a trusted approval verifier is required")

        now_dt = _load_timestamp(_timestamp(now or self._clock()), "consume time")

        try:
            if type(credential) is bytes:
                credential = ApprovalAssertion.from_bytes(credential)
            if type(credential) is not ApprovalAssertion:
                raise ApprovalStoreError("approval credential is invalid")

            with self._engine.begin() as conn:
                if self._is_postgres:
                    select_stmt = (
                        select(self._records_table)
                        .where(self._records_table.c.approval_id == approval_id)
                        .with_for_update()
                    )
                else:
                    select_stmt = select(self._records_table).where(self._records_table.c.approval_id == approval_id)

                row = conn.execute(select_stmt).mappings().fetchone()
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

                verifier.verify(credential, record, now=now_dt)
                consumed = record.consume(now=now_dt)
                serialized = self._serialize(consumed)
                payload = dict(zip(_STORED_COLUMNS, serialized[:-1]))
                payload["record_checksum"] = serialized[-1]

                update_stmt = (
                    update(self._records_table)
                    .where(
                        self._records_table.c.approval_id == approval_id,
                        self._records_table.c.state == ApprovalState.APPROVED.value,
                        self._records_table.c.request_id == record.request_id,
                        self._records_table.c.request_fingerprint == record.request_fingerprint,
                        self._records_table.c.principal_id == record.request.agent_id,
                        self._records_table.c.integration_id == record.integration_id,
                        self._records_table.c.deployment_epoch == self._deployment_epoch,
                        self._records_table.c.expires_at > _timestamp(now_dt),
                    )
                    .values(**payload)
                )
                result = conn.execute(update_stmt)
                if result.rowcount != 1:
                    raise ApprovalConcurrentConsumeError("approval consumption race was lost")

                self._sync_recovery_counter(increment=True, conn=conn)
                return consumed
        except (ApprovalStoreError, MalformedApprovalError):
            raise
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("approval consumption storage failure") from exc

    def list_pending(self, *, limit: int = 100) -> list[ApprovalRecord]:
        if type(limit) is not int or limit < 1:
            raise MalformedApprovalError("list_pending limit must be a positive integer")
        limit = min(limit, self._MAX_QUERY_LIMIT)
        now_str = _timestamp(self._clock())

        try:
            with self._engine.connect() as conn:
                stmt = (
                    select(self._records_table)
                    .where(
                        self._records_table.c.state == ApprovalState.PENDING.value,
                        self._records_table.c.expires_at > now_str,
                        self._records_table.c.deployment_epoch == self._deployment_epoch,
                    )
                    .order_by(self._records_table.c.created_at.desc())
                    .limit(limit)
                )
                rows = conn.execute(stmt).mappings().fetchall()
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not list pending approval records") from exc

        results: list[ApprovalRecord] = []
        skipped_unsupported_count = 0
        for row in rows:
            try:
                results.append(self._deserialize(row))
            except (UnknownApprovalVersionError, DeprecatedStorageFormatError):
                skipped_unsupported_count += 1
                continue
        if skipped_unsupported_count > 0:
            logger.warning(
                "Skipped %d pending approval records with unsupported schema version or deprecated storage format",
                skipped_unsupported_count,
            )
        return results

    def list_records(
        self,
        *,
        states: set[ApprovalState] | None = None,
        limit: int = 100,
    ) -> list[ApprovalRecord]:
        if type(limit) is not int or limit < 1:
            raise MalformedApprovalError("list_records limit must be a positive integer")
        limit = min(limit, self._MAX_QUERY_LIMIT)

        stmt = (
            select(self._records_table)
            .where(self._records_table.c.deployment_epoch == self._deployment_epoch)
            .order_by(self._records_table.c.created_at.desc())
            .limit(limit)
        )

        if states is not None:
            if not isinstance(states, set) or not states:
                raise MalformedApprovalError("states must be a non-empty set of ApprovalState")
            for s in states:
                if type(s) is not ApprovalState:
                    raise MalformedApprovalError("states must contain only ApprovalState values")
            state_values = [s.value for s in states]
            stmt = stmt.where(self._records_table.c.state.in_(state_values))

        try:
            with self._engine.connect() as conn:
                rows = conn.execute(stmt).mappings().fetchall()
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not list approval records") from exc

        records: list[ApprovalRecord] = []
        skipped_unsupported_count = 0
        for row in rows:
            try:
                records.append(self._deserialize(row))
            except (UnknownApprovalVersionError, DeprecatedStorageFormatError):
                skipped_unsupported_count += 1
                continue
        if skipped_unsupported_count > 0:
            logger.warning(
                "Skipped %d approval records with unsupported schema version or deprecated storage format",
                skipped_unsupported_count,
            )
        return records

    def approve_pending(
        self,
        approval_id: str,
        *,
        authority: LocalApprovalAuthority,
        approved_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        from ..authority import LocalApprovalAuthority

        if not isinstance(authority, LocalApprovalAuthority):
            raise MalformedApprovalError("approve_pending requires a LocalApprovalAuthority")
        if type(approved_by) is not str or not approved_by or approved_by != approved_by.strip():
            raise MalformedApprovalError("approved_by must be a non-empty string")
        if reason is not None:
            if type(reason) is not str or not reason or reason != reason.strip():
                raise MalformedApprovalError("reason must be a non-empty string if provided")
            if len(reason) > 1000:
                raise MalformedApprovalError("approval reason must not exceed 1000 characters")
        if type(approval_id) is not str or not _ID_PATTERN.fullmatch(approval_id) or not approval_id.startswith("apr_"):
            raise CorruptApprovalRecordError("invalid approval_id lookup")

        now_dt = _load_timestamp(_timestamp(now or self._clock()), "approve time")

        try:
            with self._engine.begin() as conn:
                if self._is_postgres:
                    select_stmt = (
                        select(self._records_table)
                        .where(self._records_table.c.approval_id == approval_id)
                        .with_for_update()
                    )
                else:
                    select_stmt = select(self._records_table).where(self._records_table.c.approval_id == approval_id)

                row = conn.execute(select_stmt).mappings().fetchone()
                if row is None:
                    raise ApprovalNotFoundError("approval record was not found")

                record = self._deserialize(row)
                approver = ApprovalAuthority._from_trusted_boundary(
                    authority.issuer_id,
                    approved_by,
                    ApprovalAuthorityKind.HUMAN,
                )
                approved = record.approve(approver, now=now_dt, reason=reason)
                issued_assertion = authority.issue(record, approver, now=now_dt)
                serialized = self._serialize(approved)
                payload = dict(zip((*_STORED_COLUMNS, "record_checksum"), serialized))

                result = conn.execute(
                    update(self._records_table)
                    .where(
                        self._records_table.c.approval_id == approval_id,
                        self._records_table.c.state == ApprovalState.PENDING.value,
                    )
                    .values(**payload)
                )
                if result.rowcount != 1:
                    raise ApprovalConcurrentConsumeError("approval state changed during approve operation")

                conn.execute(
                    text(
                        """
                        INSERT INTO approval_assertions (approval_id, assertion_json, updated_at)
                        VALUES (:aid, :ajson, :now_str)
                        ON CONFLICT (approval_id) DO UPDATE SET
                            assertion_json = excluded.assertion_json,
                            updated_at = excluded.updated_at
                        """
                    ),
                    {
                        "aid": approval_id,
                        "ajson": issued_assertion.to_bytes().decode("utf-8"),
                        "now_str": _timestamp(now_dt),
                    },
                )

                return approved
        except (ApprovalStoreError, MalformedApprovalError):
            raise
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not approve pending record") from exc

    def reject_pending(
        self,
        approval_id: str,
        *,
        authority: LocalApprovalAuthority,
        rejected_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        from ..authority import LocalApprovalAuthority

        if not isinstance(authority, LocalApprovalAuthority):
            raise MalformedApprovalError("reject_pending requires a LocalApprovalAuthority")
        if type(rejected_by) is not str or not rejected_by or rejected_by != rejected_by.strip():
            raise MalformedApprovalError("rejected_by must be a non-empty string")
        if reason is not None:
            if type(reason) is not str or not reason or reason != reason.strip():
                raise MalformedApprovalError("reason must be a non-empty string if provided")
            if len(reason) > 1000:
                raise MalformedApprovalError("rejection reason must not exceed 1000 characters")
        if type(approval_id) is not str or not _ID_PATTERN.fullmatch(approval_id) or not approval_id.startswith("apr_"):
            raise CorruptApprovalRecordError("invalid approval_id lookup")

        now_dt = _load_timestamp(_timestamp(now or self._clock()), "reject time")

        try:
            with self._engine.begin() as conn:
                if self._is_postgres:
                    select_stmt = (
                        select(self._records_table)
                        .where(self._records_table.c.approval_id == approval_id)
                        .with_for_update()
                    )
                else:
                    select_stmt = select(self._records_table).where(self._records_table.c.approval_id == approval_id)

                row = conn.execute(select_stmt).mappings().fetchone()
                if row is None:
                    raise ApprovalNotFoundError("approval record was not found")

                record = self._deserialize(row)
                rejecter = ApprovalAuthority._from_trusted_boundary(
                    authority.issuer_id,
                    rejected_by,
                    ApprovalAuthorityKind.HUMAN,
                )
                rejected = record.reject(rejecter, now=now_dt, reason=reason)
                serialized = self._serialize(rejected)
                payload = dict(zip((*_STORED_COLUMNS, "record_checksum"), serialized))

                result = conn.execute(
                    update(self._records_table)
                    .where(
                        self._records_table.c.approval_id == approval_id,
                        self._records_table.c.state == ApprovalState.PENDING.value,
                    )
                    .values(**payload)
                )
                if result.rowcount != 1:
                    raise ApprovalConcurrentConsumeError("approval state changed during reject operation")

                return rejected
        except (ApprovalStoreError, MalformedApprovalError):
            raise
        except SQLAlchemyError as exc:
            raise ApprovalStoreError("could not reject pending record") from exc

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
            "row_version": record.row_version,
        }
        return tuple(payload[column] for column in _STORED_COLUMNS) + (
            _integrity_checksum(payload, self._integrity_key),
        )

    def _deserialize(self, row: RowMapping | Mapping[str, Any]) -> ApprovalRecord:
        try:
            schema_version = _required(row, "schema_version")
            if schema_version != APPROVAL_RECORD_SCHEMA_VERSION:
                raise UnknownApprovalVersionError(f"unsupported approval record schema version: '{schema_version}'")

            stored_checksum = row["record_checksum"]
            if type(stored_checksum) is not str:
                raise CorruptApprovalRecordError("stored approval integrity check failed")

            if _is_deprecated_v1_checksum(row, stored_checksum):
                raise DeprecatedStorageFormatError(
                    "stored approval record uses deprecated unkeyed checksum (format v1); upgrade required"
                )

            payload = {column: row[column] for column in _STORED_COLUMNS}
            expected_mac = _integrity_checksum(payload, self._integrity_key)
            if not hmac.compare_digest(stored_checksum, expected_mac):
                raise CorruptApprovalRecordError("stored approval integrity check failed")

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
            resource_value = row.get("resource_value")
            arguments = _load_canonical_object(_required(row, "arguments_json"), "arguments")
            context = _load_canonical_object(_required(row, "trusted_context_json"), "trusted_context")
            state = parse_approval_state(_required(row, "state"))
            deployment_epoch = _required(row, "deployment_epoch")

            if deployment_epoch != self._deployment_epoch:
                raise CorruptApprovalRecordError("approval deployment epoch mismatch")

            authority_values = (
                row.get("decision_authority_id"),
                row.get("decision_authority_subject"),
                row.get("decision_authority_kind"),
            )
            if all(value is None for value in authority_values):
                decision_authority = None
            elif all(type(value) is str for value in authority_values):
                try:
                    authority_kind = ApprovalAuthorityKind(authority_values[2])  # type: ignore[arg-type]
                except ValueError as exc:
                    raise CorruptApprovalRecordError("invalid stored approval authority kind") from exc
                decision_authority = ApprovalAuthority._from_recorded_metadata(
                    authority_values[0],  # type: ignore[arg-type]
                    authority_values[1],  # type: ignore[arg-type]
                    authority_kind,
                )
            else:
                raise CorruptApprovalRecordError("incomplete stored approval authority")

            resource: str | NoResource
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
            row_version = int(row["row_version"]) if "row_version" in row and row["row_version"] is not None else 1
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
                    _load_timestamp(row["decision_at"], "decision_at") if row.get("decision_at") is not None else None
                ),
                state_reason=row.get("state_reason"),
                consumed_at=(
                    _load_timestamp(row["consumed_at"], "consumed_at") if row.get("consumed_at") is not None else None
                ),
                row_version=row_version,
            )
        except (CorruptApprovalRecordError, UnknownApprovalVersionError):
            raise
        except (MalformedApprovalError, TypeError, ValueError, KeyError, IndexError) as exc:
            raise CorruptApprovalRecordError("stored approval record is invalid") from exc
