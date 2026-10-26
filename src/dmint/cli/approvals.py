"""CLI commands for managing approvals from the terminal: pending, approve, reject."""

from __future__ import annotations

import json
from dmint.cli.ui import DmintHelpFormatter

import argparse
import getpass
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from dmint.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
)
from dmint.authority import LocalApprovalAuthority
from dmint.cli.errors import PolicyValidationError
from dmint.core.verification import DEFAULT_APPROVAL_AUDIENCE
from dmint.core.errors import ApprovalDeploymentInvalidError
from dmint.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalStoreConfigurationError,
    ApprovalStoreError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
    UnknownApprovalVersionError,
)
from dmint.models import Decision
from dmint.policy import Policy
from dmint.storage import ApprovalStore, create_approval_store


def _format_age(created_at: datetime, now: datetime | None = None) -> str:
    """Format timestamp into a clean, human-readable relative age string."""
    target_now = now or datetime.now(timezone.utc)
    delta = target_now - created_at
    total_seconds = int(delta.total_seconds())
    if total_seconds < 0:
        return "in the future"
    if total_seconds < 60:
        return f"{total_seconds}s ago"
    minutes = total_seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        rem_min = minutes % 60
        return f"{hours}h {rem_min}m ago" if rem_min else f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def _get_store(
    *,
    database_url: str | None = None,
    db_path: str | None = None,
    deployment_epoch: str | None = None,
    integrity_key_file: str | Path | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ApprovalStore:
    """Instantiate the active ApprovalStore (SQLite or Postgres)."""
    target_url = database_url or os.environ.get("DMINT_DATABASE_URL")
    target_epoch = deployment_epoch or os.environ.get("DMINT_DEPLOYMENT_EPOCH", "default")
    target_sqlite = db_path or os.environ.get("DMINT_DB_PATH")

    if not target_url and not target_sqlite:
        if Path(".dmint/approvals.sqlite3").exists():
            target_sqlite = ".dmint/approvals.sqlite3"
        elif Path("approvals.sqlite3").exists():
            target_sqlite = "approvals.sqlite3"
        elif Path("approvals.sqlite").exists():
            target_sqlite = "approvals.sqlite"
        elif Path("dmint.db").exists():
            target_sqlite = "dmint.db"
        elif Path(".dmint").is_dir():
            target_sqlite = ".dmint/approvals.sqlite3"
        else:
            target_sqlite = "approvals.sqlite3"

    integrity_key: Path | None = Path(integrity_key_file) if integrity_key_file else None
    if (
        integrity_key is None
        and not os.environ.get("DMINT_INTEGRITY_KEY")
        and not os.environ.get("DMINT_INTEGRITY_KEY_FILE")
    ):
        if target_sqlite and (Path(target_sqlite).parent / "integrity.key").exists():
            integrity_key = Path(target_sqlite).parent / "integrity.key"

    return create_approval_store(
        database_url=target_url,
        deployment_epoch=target_epoch,
        integrity_key=integrity_key,
        default_sqlite_path=target_sqlite or "approvals.sqlite3",
        clock=clock,
    )


def _get_authority(
    *,
    authority_issuer: str | None = None,
    audience: str | None = None,
    key_file: Path | str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> LocalApprovalAuthority:
    """Instantiate a local approval authority for signing assertions."""
    issuer = authority_issuer or os.environ.get("DMINT_AUTHORITY_ISSUER") or "dmint-cli"
    aud = audience or os.environ.get("DMINT_AUTHORITY_AUDIENCE", DEFAULT_APPROVAL_AUDIENCE)
    resolved_key_file = key_file
    if (
        resolved_key_file is None
        and not os.environ.get("DMINT_KEY_FILE")
        and not os.environ.get("DMINT_SIGNING_KEY_FILE")
    ):
        local_skey = Path(".dmint/signing.key")
        if local_skey.exists():
            resolved_key_file = local_skey
    return LocalApprovalAuthority(
        issuer_id=issuer,
        audience=aud,
        key_file=resolved_key_file,
        clock=clock,
    )


def _get_approver_id(approver_id: str | None = None) -> str:
    """Determine the approver subject identifier."""
    if approver_id and approver_id.strip():
        return approver_id.strip()
    env_approver = os.environ.get("DMINT_APPROVER_ID", "").strip()
    if env_approver:
        return env_approver
    try:
        user = getpass.getuser().strip()
        if user:
            return user
    except Exception:
        pass
    return "cli-human"


def _resolve_current_policy(
    store: ApprovalStore,
    policy_path: str | None = None,
) -> Policy | None:
    """Resolve the current active policy for re-verification.

    An explicit ``policy_path`` must exist and parse. A fallback ``./policy.json`` that
    exists but cannot be parsed fails closed with ``PolicyValidationError`` instead of
    silently downgrading re-verification to no verification.
    """
    if policy_path:
        p = Path(policy_path)
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        return Policy.from_json(p.read_text(encoding="utf-8"))

    store_policy_info = store.get_authoritative_policy()
    if store_policy_info is not None:
        return store_policy_info[0]

    default_p = Path("policy.json")
    if default_p.is_file():
        try:
            return Policy.from_json(default_p.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PolicyValidationError(
                f"Fallback policy file '{default_p}' exists but cannot be parsed for re-verification: {exc}"
            ) from exc

    return None


def _resolve_approval_id(store: ApprovalStore, raw_id: str) -> str:
    """Resolve either an approval_id (apr_...) or request_id (req_...) to approval_id."""
    raw_conn = getattr(store, "_connection", None)
    if raw_id.startswith("req_") and raw_conn is not None:
        try:
            row = raw_conn.execute(
                "SELECT approval_id FROM approval_records WHERE request_id = ?",
                (raw_id,),
            ).fetchone()
            if row is not None:
                return str(row["approval_id"])
        except Exception:
            pass
    return raw_id


def main_pending(args: list[str] | None = None) -> int:
    """List all approvals currently in PENDING state."""
    parser = argparse.ArgumentParser(
        prog="dmint pending",
        formatter_class=DmintHelpFormatter,
        description="List all approvals currently in PENDING state.",
        epilog="""Examples:
  dmint pending
  dmint pending --json
  dmint pending --db .dmint/approvals.sqlite3
""",
    )
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output pending records as JSON")
    parser.add_argument(
        "--db-path",
        default=None,
        help="Path to SQLite database (or set DMINT_DB_PATH)",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Database URL (SQLite or PostgreSQL, or set DMINT_DATABASE_URL)",
    )
    parser.add_argument(
        "--deployment-epoch",
        default=None,
        help="Deployment epoch (or set DMINT_DEPLOYMENT_EPOCH, default: 'default')",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of pending records to display (default: 100)",
    )
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    try:
        store = _get_store(
            database_url=parsed.database_url,
            db_path=parsed.db_path,
            deployment_epoch=parsed.deployment_epoch,
            integrity_key_file=getattr(parsed, "integrity_key_file", None),
        )
    except ApprovalStoreConfigurationError as exc:
        print(f"Error: Database configuration failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Failed to connect to approval store: {exc}", file=sys.stderr)
        return 1

    try:
        with store:
            pending_records = store.list_pending(limit=parsed.limit)

            active_epoch = parsed.deployment_epoch or os.environ.get("DMINT_DEPLOYMENT_EPOCH", "default")
            if getattr(parsed, "output_json", False):
                print(
                    json.dumps(
                        [
                            {
                                "approval_id": r.approval_id,
                                "request_id": r.request_id,
                                "capability_id": r.capability_id,
                                "resource": r.request.resource if isinstance(r.request.resource, str) else None,
                                "agent_id": r.request.agent_id,
                                "created_at": r.created_at.isoformat(),
                                "expires_at": r.expires_at.isoformat(),
                            }
                            for r in pending_records
                        ],
                        indent=2,
                    )
                )
                return 0
            if not pending_records:
                print(
                    f"No pending approvals found. (epoch: {active_epoch}) — "
                    "if your gateway uses another epoch, pass --deployment-epoch or set DMINT_DEPLOYMENT_EPOCH."
                )
                return 0

            headers = ["APPROVAL ID", "TOOL/ACTION", "RESOURCE/TARGET", "PRINCIPAL", "REQUESTED"]
            rows: list[list[str]] = []
            for record in pending_records:
                res = record.request.resource if isinstance(record.request.resource, str) else "(none)"
                rows.append(
                    [
                        record.approval_id,
                        record.capability_id,
                        res,
                        record.request.agent_id,
                        _format_age(record.created_at),
                    ]
                )

            # Calculate column widths
            col_widths = [len(h) for h in headers]
            for row in rows:
                for idx, cell in enumerate(row):
                    col_widths[idx] = max(col_widths[idx], len(cell))

            # Print table
            header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
            separator_line = "  ".join("-" * col_widths[i] for i in range(len(headers)))
            print(header_line)
            print(separator_line)
            for row in rows:
                print("  ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row)))

            return 0
    except Exception as exc:
        print(f"Error: Failed to retrieve pending approvals: {exc}", file=sys.stderr)
        return 1


def main_approve(args: list[str] | None = None) -> int:
    """Approve a pending approval request."""
    parser = argparse.ArgumentParser(
        prog="dmint approve",
        formatter_class=DmintHelpFormatter,
        description="Approve a pending tool execution request.",
        epilog="""Examples:
  dmint approve apr_... --by alice@company.com
  dmint approve req_... --by secops@company.com --reason "Verified release tag"
""",
    )
    parser.add_argument("approval_id", help="The unique approval ID (apr_...) to approve")
    parser.add_argument("--reason", default=None, help="Optional audit note/reason for approval")
    parser.add_argument("--db-path", default=None, help="Path to SQLite database (or set DMINT_DB_PATH)")
    parser.add_argument("--database-url", default=None, help="Database URL (or set DMINT_DATABASE_URL)")
    parser.add_argument("--deployment-epoch", default=None, help="Deployment epoch (default: 'default')")
    parser.add_argument("--policy", default=None, help="Path to policy file for re-verification")
    parser.add_argument(
        "--approver-id",
        "--by",
        "--approver",
        dest="approver_id",
        default=None,
        help="Approver principal ID (or set DMINT_APPROVER_ID)",
    )
    parser.add_argument("--authority-issuer", "--issuer-id", default=None, help="Authority issuer ID")
    parser.add_argument(
        "--key-file",
        "--key-path",
        dest="key_file",
        default=os.environ.get("DMINT_KEY_FILE"),
        help="Path to Ed25519 signing key file (or set DMINT_KEY_FILE)",
    )
    parser.add_argument(
        "--integrity-key-file",
        "--integrity-key-path",
        dest="integrity_key_file",
        default=None,
        help="Path to HMAC integrity key file (or set DMINT_INTEGRITY_KEY_FILE)",
    )
    parser.add_argument(
        "--audience",
        default=None,
        help=f"Target audience for the approval assertion (default: {DEFAULT_APPROVAL_AUDIENCE}, or set DMINT_AUTHORITY_AUDIENCE)",
    )
    parser.add_argument(
        "--output-assertion",
        default=None,
        help="File path to write the signed approval assertion bytes for retry",
    )
    parser.add_argument(
        "--store-assertion",
        action="store_true",
        help="Persist signed assertion in store for automatic retry (enabled by default in v2.0.4+)",
    )
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    try:
        store = _get_store(
            database_url=parsed.database_url,
            db_path=parsed.db_path,
            deployment_epoch=parsed.deployment_epoch,
            integrity_key_file=getattr(parsed, "integrity_key_file", None),
        )
    except ApprovalStoreConfigurationError as exc:
        print(f"Error: Database configuration failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Failed to connect to approval store: {exc}", file=sys.stderr)
        return 1

    try:
        with store:
            target_id = _resolve_approval_id(store, parsed.approval_id)
            record = store.get(target_id)
            if record is None:
                print(f"Error: Approval request '{parsed.approval_id}' was not found.", file=sys.stderr)
                return 1

            if record.state != ApprovalState.PENDING:
                print(
                    f"Error: Cannot approve '{parsed.approval_id}': record is in state {record.state.value} "
                    f"(expected PENDING).",
                    file=sys.stderr,
                )
                return 1

            now = datetime.now(timezone.utc)
            if record.expires_at <= now:
                print(
                    f"Error: Cannot approve '{parsed.approval_id}': request expired at "
                    f"{record.expires_at.isoformat()}.",
                    file=sys.stderr,
                )
                return 1

            # Policy re-verification
            try:
                current_policy = _resolve_current_policy(store, parsed.policy)
            except Exception as exc:
                print(f"Error: Failed to load current policy for re-verification: {exc}", file=sys.stderr)
                return 1

            if current_policy is not None:
                decision = current_policy.evaluate(record.request)
                if decision is Decision.DENY:
                    print(
                        f"Error: Cannot approve '{parsed.approval_id}': current policy denies this request "
                        f"(capability '{record.capability_id}' evaluated to DENY under updated policy).",
                        file=sys.stderr,
                    )
                    return 1

            authority = _get_authority(
                authority_issuer=parsed.authority_issuer,
                audience=parsed.audience,
                key_file=parsed.key_file,
            )
            approver_id = _get_approver_id(parsed.approver_id)

            store.approve_pending(
                target_id,
                authority=authority,
                approved_by=approver_id,
                reason=parsed.reason,
            )

            if parsed.output_assertion:
                approver = ApprovalAuthority._from_trusted_boundary(
                    authority.issuer_id,
                    approver_id,
                    ApprovalAuthorityKind.HUMAN,
                )
                assertion = authority.issue(record, approver)
                Path(parsed.output_assertion).write_bytes(assertion.to_bytes())

            try:
                from dmint.core.audit import AuditLogger

                if Path(".dmint").is_dir() or os.environ.get("DMINT_AUDIT_LOG"):
                    AuditLogger().log_event(
                        decision="APPROVED",
                        tool=record.request.tool,
                        action=record.request.action,
                        resource=record.request.resource if isinstance(record.request.resource, str) else None,
                        code="DMT_APPROVED",
                        harness=record.integration_id,
                        agent_id=record.request.agent_id,
                        event_type="approval_lifecycle",
                        approval_id=target_id,
                        details={"approved_by": approver_id, "reason": parsed.reason or ""},
                    )
            except Exception:
                pass
            print(f"✓ Approved '{parsed.approval_id}' ({record.capability_id}) successfully.")
            if parsed.reason:
                print(f"  Reason: {parsed.reason}")
            return 0
    except UnknownApprovalVersionError as exc:
        print(f"Error [{exc.code}]: Cannot approve '{parsed.approval_id}': {exc}", file=sys.stderr)
        return 1
    except ApprovalDeploymentInvalidError as exc:
        print(
            f"Error: Deployment epoch mismatch for '{parsed.approval_id}': {exc}. "
            "Pass --deployment-epoch <epoch> or set DMINT_DEPLOYMENT_EPOCH.",
            file=sys.stderr,
        )
        return 1
    except (
        ApprovalNotFoundError,
        ApprovalExpiredError,
        IllegalApprovalTransitionError,
        ApprovalConcurrentConsumeError,
        MalformedApprovalError,
        ApprovalStoreError,
    ) as exc:
        print(f"Error: Failed to approve '{parsed.approval_id}': {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Unexpected failure approving '{parsed.approval_id}': {exc}", file=sys.stderr)
        return 1


def main_reject(args: list[str] | None = None) -> int:
    """Reject a pending approval request."""
    parser = argparse.ArgumentParser(
        prog="dmint reject",
        formatter_class=DmintHelpFormatter,
        description="Reject a pending tool execution request.",
        epilog="""Examples:
  dmint reject apr_... --by secops@company.com --reason "Unauthorized production change"
""",
    )
    parser.add_argument("approval_id", help="The unique approval ID (apr_...) to reject")
    parser.add_argument("--reason", default=None, help="Optional audit note/reason for rejection")
    parser.add_argument("--db-path", default=None, help="Path to SQLite database (or set DMINT_DB_PATH)")
    parser.add_argument("--database-url", default=None, help="Database URL (or set DMINT_DATABASE_URL)")
    parser.add_argument("--deployment-epoch", default=None, help="Deployment epoch (default: 'default')")
    parser.add_argument(
        "--approver-id",
        "--by",
        "--approver",
        dest="approver_id",
        default=None,
        help="Rejecter principal ID (or set DMINT_APPROVER_ID)",
    )
    parser.add_argument("--authority-issuer", "--issuer-id", default=None, help="Authority issuer ID")
    parser.add_argument("--audience", default=None, help="Approval authority audience")
    parser.add_argument(
        "--key-file",
        "--key-path",
        dest="key_file",
        default=None,
        help="Path to Ed25519 private signing key file (or set DMINT_SIGNING_KEY_FILE)",
    )
    parser.add_argument(
        "--integrity-key-file",
        "--integrity-key-path",
        dest="integrity_key_file",
        default=None,
        help="Path to HMAC integrity key file (or set DMINT_INTEGRITY_KEY_FILE)",
    )
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    try:
        store = _get_store(
            database_url=parsed.database_url,
            db_path=parsed.db_path,
            deployment_epoch=parsed.deployment_epoch,
            integrity_key_file=getattr(parsed, "integrity_key_file", None),
        )
    except ApprovalStoreConfigurationError as exc:
        print(f"Error: Database configuration failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Failed to connect to approval store: {exc}", file=sys.stderr)
        return 1

    try:
        with store:
            target_id = _resolve_approval_id(store, parsed.approval_id)
            record = store.get(target_id)
            if record is None:
                print(f"Error: Approval request '{parsed.approval_id}' was not found.", file=sys.stderr)
                return 1

            if record.state != ApprovalState.PENDING:
                print(
                    f"Error: Cannot reject '{parsed.approval_id}': record is in state {record.state.value} "
                    f"(expected PENDING).",
                    file=sys.stderr,
                )
                return 1

            now = datetime.now(timezone.utc)
            if record.expires_at <= now:
                print(
                    f"Error: Cannot reject '{parsed.approval_id}': request expired at {record.expires_at.isoformat()}.",
                    file=sys.stderr,
                )
                return 1

            authority = _get_authority(
                authority_issuer=parsed.authority_issuer,
                audience=parsed.audience,
                key_file=parsed.key_file,
            )
            approver_id = _get_approver_id(parsed.approver_id)

            store.reject_pending(
                target_id,
                authority=authority,
                rejected_by=approver_id,
                reason=parsed.reason,
            )

            try:
                from dmint.core.audit import AuditLogger

                if Path(".dmint").is_dir() or os.environ.get("DMINT_AUDIT_LOG"):
                    AuditLogger().log_event(
                        decision="REJECTED",
                        tool=record.request.tool,
                        action=record.request.action,
                        resource=record.request.resource if isinstance(record.request.resource, str) else None,
                        code="DMT_REJECTED",
                        harness=record.integration_id,
                        agent_id=record.request.agent_id,
                        event_type="approval_lifecycle",
                        approval_id=target_id,
                        details={"rejected_by": approver_id, "reason": parsed.reason or ""},
                    )
            except Exception:
                pass
            print(f"✓ Rejected '{parsed.approval_id}' ({record.capability_id}) successfully.")
            if parsed.reason:
                print(f"  Reason: {parsed.reason}")
            return 0
    except ApprovalDeploymentInvalidError as exc:
        print(
            f"Error: Deployment epoch mismatch for '{parsed.approval_id}': {exc}. "
            "Pass --deployment-epoch <epoch> or set DMINT_DEPLOYMENT_EPOCH.",
            file=sys.stderr,
        )
        return 1
    except (
        ApprovalNotFoundError,
        ApprovalExpiredError,
        IllegalApprovalTransitionError,
        ApprovalConcurrentConsumeError,
        MalformedApprovalError,
        ApprovalStoreError,
    ) as exc:
        print(f"Error: Failed to reject '{parsed.approval_id}': {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Unexpected failure rejecting '{parsed.approval_id}': {exc}", file=sys.stderr)
        return 1
