"""Branch-coverage edges for the approvals CLI (SRC-18).

The Phase-6 branch report flagged `dmint.cli.approvals` below the production
branch-coverage gate. These tests cover the age formatter buckets, default
store discovery, approver-id fallbacks, policy resolution, and the CLI
error-handling branches that must fail closed with actionable messages.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from dmint.approvals import ApprovalRecord, PolicyProvenance, new_request_id
from dmint.cli import approvals as cli_approvals
from dmint.cli.approvals import (
    _format_age,
    _get_approver_id,
    _resolve_current_policy,
    main_approve,
    main_pending,
    main_reject,
)
from dmint.core.errors import ApprovalStoreConfigurationError
from dmint.core.keys import write_private_key_atomic
from dmint.core.models import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.core.policy import Decision, Policy, Rule
from dmint.storage.sqlite import SQLiteApprovalStore

_NOW = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_record(
    *,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> ApprovalRecord:
    now = created_at or datetime.now(timezone.utc)
    exp = expires_at or (now + timedelta(minutes=15))
    request = ToolRequest(
        request_id=new_request_id(),
        agent_id="branch-agent",
        tool="postgres",
        action="drop_table",
        resource="prod_users",
        arguments={"table": "prod_users"},
        context=TrustedContext({}),
    )
    return ApprovalRecord.create(
        request=request,
        integration_id="mcp.postgres",
        capability_id="postgres.drop_table",
        policy_provenance=PolicyProvenance(
            version_id="policy-v1",
            policy_digest=hashlib.sha256(b"dummy-policy").hexdigest(),
            evaluated_at=now,
        ),
        created_at=now,
        expires_at=exp,
    )


def _save_record(tmp_path, record: ApprovalRecord):
    db_path = tmp_path / "approvals.sqlite3"
    store = SQLiteApprovalStore(db_path, deployment_epoch="default")
    store.__enter__()
    try:
        store.save_pending(record)
    finally:
        store.__exit__(None, None, None)
    return db_path


def test_format_age_covers_every_relative_bucket() -> None:
    assert _format_age(_NOW + timedelta(seconds=5), _NOW) == "in the future"
    assert _format_age(_NOW - timedelta(seconds=30), _NOW) == "30s ago"
    assert _format_age(_NOW - timedelta(minutes=5), _NOW) == "5m ago"
    assert _format_age(_NOW - timedelta(hours=3, minutes=25), _NOW) == "3h 25m ago"
    assert _format_age(_NOW - timedelta(hours=2), _NOW) == "2h ago"
    assert _format_age(_NOW - timedelta(days=3, hours=1), _NOW) == "3d ago"


def test_get_store_default_sqlite_discovery(tmp_path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_create(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(cli_approvals, "create_approval_store", _fake_create)
    monkeypatch.delenv("DMINT_DATABASE_URL", raising=False)
    monkeypatch.delenv("DMINT_DB_PATH", raising=False)
    monkeypatch.chdir(tmp_path)

    cli_approvals._get_store()
    assert captured["default_sqlite_path"] == "approvals.sqlite3"

    (tmp_path / "dmint.db").write_text("", encoding="utf-8")
    cli_approvals._get_store()
    assert captured["default_sqlite_path"] == "dmint.db"

    (tmp_path / "approvals.sqlite").write_text("", encoding="utf-8")
    cli_approvals._get_store()
    assert captured["default_sqlite_path"] == "approvals.sqlite"

    (tmp_path / "approvals.sqlite3").write_text("", encoding="utf-8")
    cli_approvals._get_store()
    assert captured["default_sqlite_path"] == "approvals.sqlite3"


def test_get_approver_id_prefers_explicit_then_env_then_fallback(monkeypatch) -> None:
    assert _get_approver_id("explicit-human") == "explicit-human"

    monkeypatch.setenv("DMINT_APPROVER_ID", "env-human")
    assert _get_approver_id() == "env-human"
    monkeypatch.delenv("DMINT_APPROVER_ID")

    def _raise(*_args, **_kwargs):
        raise OSError("no user available")

    monkeypatch.setattr(cli_approvals.getpass, "getuser", _raise)
    assert _get_approver_id() == "cli-human"


def test_resolve_current_policy_missing_explicit_file_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        _resolve_current_policy(object(), policy_path=str(tmp_path / "missing.json"))  # type: ignore[arg-type]


def test_resolve_current_policy_prefers_store_authoritative_policy() -> None:
    policy = Policy((Rule(Decision.ALLOW, "postgres", "drop_table"),))

    class _Store:
        def get_authoritative_policy(self):
            return (policy, "policy-v1")

    assert _resolve_current_policy(_Store()) is policy  # type: ignore[arg-type]


def test_main_pending_reports_store_configuration_failure(monkeypatch, capsys) -> None:
    def _raise(**_kwargs):
        raise ApprovalStoreConfigurationError("bad config")

    monkeypatch.setattr(cli_approvals, "_get_store", _raise)
    assert main_pending([]) == 1
    assert "Database configuration failed" in capsys.readouterr().err


def test_main_pending_reports_connection_failure(monkeypatch, capsys) -> None:
    def _raise(**_kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(cli_approvals, "_get_store", _raise)
    assert main_pending([]) == 1
    assert "Failed to connect to approval store" in capsys.readouterr().err


def test_main_pending_reports_list_failure(monkeypatch, capsys) -> None:
    class _BrokenStore:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def list_pending(self, limit=100):
            raise RuntimeError("query exploded")

    monkeypatch.setattr(cli_approvals, "_get_store", lambda **_kw: _BrokenStore())
    assert main_pending([]) == 1
    assert "Failed to retrieve pending approvals" in capsys.readouterr().err


def test_main_approve_reports_store_configuration_failure(monkeypatch, capsys) -> None:
    def _raise(**_kwargs):
        raise ApprovalStoreConfigurationError("bad config")

    monkeypatch.setattr(cli_approvals, "_get_store", _raise)
    assert main_approve(["apr_0000000000000000000000000000000000000000"]) == 1
    assert "Database configuration failed" in capsys.readouterr().err


def test_main_approve_reports_unexpected_failure(tmp_path, monkeypatch, capsys) -> None:
    record = _make_record()
    db_path = _save_record(tmp_path, record)

    monkeypatch.setattr(cli_approvals, "_resolve_current_policy", lambda *_a, **_k: None)

    def _raise(**_kwargs):
        raise RuntimeError("authority exploded")

    monkeypatch.setattr(cli_approvals, "_get_authority", _raise)
    assert main_approve([record.approval_id, "--db-path", str(db_path)]) == 1
    assert "Unexpected failure approving" in capsys.readouterr().err


def test_main_approve_writes_signed_assertion_when_requested(tmp_path, monkeypatch) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    record = _make_record()
    db_path = _save_record(tmp_path, record)
    key_file = tmp_path / "signing.key"
    write_private_key_atomic(key_file, Ed25519PrivateKey.generate())

    monkeypatch.setattr(cli_approvals, "_resolve_current_policy", lambda *_a, **_k: None)

    out_path = tmp_path / "assertion.bin"
    rc = main_approve(
        [
            record.approval_id,
            "--db-path",
            str(db_path),
            "--key-file",
            str(key_file),
            "--output-assertion",
            str(out_path),
        ]
    )
    assert rc == 0
    assert out_path.read_bytes()


def test_main_reject_refuses_expired_record(tmp_path, capsys) -> None:
    now = datetime.now(timezone.utc)
    record = _make_record(created_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
    db_path = _save_record(tmp_path, record)

    assert main_reject([record.approval_id, "--db-path", str(db_path)]) == 1
    assert "expired" in capsys.readouterr().err


def test_main_reject_reports_unexpected_failure(tmp_path, monkeypatch, capsys) -> None:
    record = _make_record()
    db_path = _save_record(tmp_path, record)

    def _raise(**_kwargs):
        raise RuntimeError("authority exploded")

    monkeypatch.setattr(cli_approvals, "_get_authority", _raise)
    assert main_reject([record.approval_id, "--db-path", str(db_path)]) == 1
    assert "Unexpected failure rejecting" in capsys.readouterr().err
