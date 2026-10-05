"""CLI commands for managing approvals from the terminal: pending, approve, reject."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from dmint.approvals import ApprovalRecord, ApprovalState
from dmint.authority import LocalApprovalAuthority
from dmint.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalStoreConfigurationError,
    ApprovalStoreError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
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
    clock: Callable[[], datetime] | None = None,
) -> ApprovalStore:
    """Instantiate the active ApprovalStore (SQLite or Postgres)."""
    target_url = database_url or os.environ.get("DMINT_DATABASE_URL")
    target_epoch = deployment_epoch or os.environ.get("DMINT_DEPLOYMENT_EPOCH", "default")
    target_sqlite = db_path or os.environ.get("DMINT_DB_PATH")

    if not target_url and not target_sqlite:
        if Path("approvals.sqlite3").exists():
            target_sqlite = "approvals.sqlite3"
        elif Path("approvals.sqlite").exists():
            target_sqlite = "approvals.sqlite"
        elif Path("dmint.db").exists():
            target_sqlite = "dmint.db"
        else:
            target_sqlite = "approvals.sqlite3"

    return create_approval_store(
        database_url=target_url,
        deployment_epoch=target_epoch,
        default_sqlite_path=target_sqlite or "approvals.sqlite3",
        clock=clock,
    )


def _get_authority(
    *,
    authority_issuer: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> LocalApprovalAuthority:
    """Instantiate a local approval authority for signing assertions."""
    issuer = authority_issuer or os.environ.get("DMINT_AUTHORITY_ISSUER") or "dmint-cli"
    return LocalApprovalAuthority(
        issuer_id=issuer,
        audience="dmint/cli/v1",
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
    """Resolve the current active policy for re-verification."""
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
        except Exception:
            pass

    return None


def main_pending(args: list[str] | None = None) -> int:
    """List all approvals currently in PENDING state."""
    parser = argparse.ArgumentParser(
        prog="dmint pending",
        description="List all approvals currently in PENDING state.",
    )
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

            if not pending_records:
                print("No pending approvals found.")
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
        description="Approve a pending tool execution request.",
    )
    parser.add_argument("approval_id", help="The unique approval ID (apr_...) to approve")
    parser.add_argument("--reason", default=None, help="Optional audit note/reason for approval")
    parser.add_argument("--db-path", default=None, help="Path to SQLite database (or set DMINT_DB_PATH)")
    parser.add_argument("--database-url", default=None, help="Database URL (or set DMINT_DATABASE_URL)")
    parser.add_argument("--deployment-epoch", default=None, help="Deployment epoch (default: 'default')")
    parser.add_argument("--policy", default=None, help="Path to policy file for re-verification")
    parser.add_argument("--approver-id", default=None, help="Approver principal ID (or set DMINT_APPROVER_ID)")
    parser.add_argument("--authority-issuer", default=None, help="Authority issuer ID")
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    try:
        store = _get_store(
            database_url=parsed.database_url,
            db_path=parsed.db_path,
            deployment_epoch=parsed.deployment_epoch,
        )
    except ApprovalStoreConfigurationError as exc:
        print(f"Error: Database configuration failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Failed to connect to approval store: {exc}", file=sys.stderr)
        return 1

    try:
        with store:
            record = store.get(parsed.approval_id)
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

            authority = _get_authority(authority_issuer=parsed.authority_issuer)
            approver_id = _get_approver_id(parsed.approver_id)

            store.approve_pending(
                parsed.approval_id,
                authority=authority,
                approved_by=approver_id,
                reason=parsed.reason,
            )

            print(f"✓ Approved '{parsed.approval_id}' ({record.capability_id}) successfully.")
            if parsed.reason:
                print(f"  Reason: {parsed.reason}")
            return 0
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
        description="Reject a pending tool execution request.",
    )
    parser.add_argument("approval_id", help="The unique approval ID (apr_...) to reject")
    parser.add_argument("--reason", default=None, help="Optional audit note/reason for rejection")
    parser.add_argument("--db-path", default=None, help="Path to SQLite database (or set DMINT_DB_PATH)")
    parser.add_argument("--database-url", default=None, help="Database URL (or set DMINT_DATABASE_URL)")
    parser.add_argument("--deployment-epoch", default=None, help="Deployment epoch (default: 'default')")
    parser.add_argument("--approver-id", default=None, help="Rejecter principal ID (or set DMINT_APPROVER_ID)")
    parser.add_argument("--authority-issuer", default=None, help="Authority issuer ID")
    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    try:
        store = _get_store(
            database_url=parsed.database_url,
            db_path=parsed.db_path,
            deployment_epoch=parsed.deployment_epoch,
        )
    except ApprovalStoreConfigurationError as exc:
        print(f"Error: Database configuration failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: Failed to connect to approval store: {exc}", file=sys.stderr)
        return 1

    try:
        with store:
            record = store.get(parsed.approval_id)
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

            authority = _get_authority(authority_issuer=parsed.authority_issuer)
            approver_id = _get_approver_id(parsed.approver_id)

            store.reject_pending(
                parsed.approval_id,
                authority=authority,
                rejected_by=approver_id,
                reason=parsed.reason,
            )

            print(f"✓ Rejected '{parsed.approval_id}' ({record.capability_id}) successfully.")
            if parsed.reason:
                print(f"  Reason: {parsed.reason}")
            return 0
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
