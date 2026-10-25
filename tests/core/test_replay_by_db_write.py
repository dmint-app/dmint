"""Tests for HMAC-SHA256 row integrity and replay prevention by DB write (T1.2)."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
try:
    import rfc8785
except ImportError:
    import types as _types
    from dmint.core.canonicalize import canonicalize_bytes as _cb
    rfc8785 = _types.SimpleNamespace(dumps=_cb)  # type: ignore[assignment]

from dmint.core.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
)
from dmint.core.authority import LocalApprovalAuthority
from dmint.core.errors import (
    CorruptApprovalRecordError,
    DeprecatedStorageFormatError,
    KeyLoadError,
)
from dmint.core.keys import (
    load_integrity_key_from_file,
    load_integrity_key_source,
    write_integrity_key_atomic,
)
from dmint.core.models import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.core.storage.sql import SQLAlchemyApprovalStore
from dmint.core.storage.sqlite import (
    _OLD_V1_STORED_COLUMNS,
    _STORED_COLUMNS,
    _integrity_checksum,
    SQLiteApprovalStore,
)
from dmint.core.verification import ApprovalVerifier

TEST_KEY_BYTES = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
OTHER_KEY_BYTES = bytes.fromhex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")


def _make_request(req_id: str = "req_1111111111111111111111111111111111111111111") -> ToolRequest:
    return ToolRequest(
        request_id=req_id,
        agent_id="test-agent",
        tool="test-tool",
        action="execute",
        resource=NO_RESOURCE,
        arguments={"arg": "val"},
        context=TrustedContext({}),
    )


def _make_record(
    req: ToolRequest | None = None,
    now: datetime | None = None,
) -> ApprovalRecord:
    now = now or datetime.now(timezone.utc)
    req = req or _make_request()
    provenance = PolicyProvenance(version_id="v1", policy_digest="a" * 64, evaluated_at=now)
    return ApprovalRecord.create(
        request=req,
        integration_id="test-int",
        capability_id="test-cap",
        policy_provenance=provenance,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def test_reset_consumed_to_approved_with_plain_sha256_rejected(tmp_path: Path) -> None:
    """T1.2: Resetting CONSUMED to APPROVED with recomputed unkeyed SHA-256 must be rejected."""
    db_path = tmp_path / "test.db"
    now = datetime.now(timezone.utc)
    epoch = "test-epoch"

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_key = Ed25519PrivateKey.generate()
    authority = LocalApprovalAuthority(issuer_id="auth-1", audience="test-int", private_key=priv_key)
    verifier = ApprovalVerifier(trusted_issuers={authority.issuer_id: authority.public_key}, audience="test-int")

    store = SQLiteApprovalStore(db_path, deployment_epoch=epoch, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    record = _make_record(now=now)
    store.save_pending(record)

    approver = ApprovalAuthority._from_trusted_boundary("auth-1", "admin", ApprovalAuthorityKind.HUMAN)
    assertion = authority.issue(record, approver, now=now)
    approved = store.approve_pending(record.approval_id, authority=authority, approved_by="admin", now=now)
    consumed = store.consume_approved(
        approval_id=record.approval_id,
        credential=assertion,
        expected_request=record.request,
        verifier=verifier,
        now=now,
    )
    assert consumed.state is ApprovalState.CONSUMED
    store.close()

    # Attacker directly modifies SQLite DB: resets state to APPROVED, clears consumed_at
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM approval_records WHERE approval_id = ?", (record.approval_id,)).fetchone()
    assert row is not None

    # Compute unkeyed v1 checksum as the old vulnerable implementation did
    v1_payload = {col: row[col] for col in _OLD_V1_STORED_COLUMNS}
    v1_payload["state"] = "APPROVED"
    v1_payload["consumed_at"] = None
    canonical_v1 = rfc8785.dumps(v1_payload)
    old_checksum = hashlib.sha256(b"dmint/approval-record-integrity/v1\x00" + canonical_v1).hexdigest()

    conn.execute(
        "UPDATE approval_records SET state = 'APPROVED', consumed_at = NULL, record_checksum = ? WHERE approval_id = ?",
        (old_checksum, record.approval_id),
    )
    conn.commit()
    conn.close()

    # Reopen store and attempt to read or consume the tampered record
    store2 = SQLiteApprovalStore(db_path, deployment_epoch=epoch, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    with pytest.raises(DeprecatedStorageFormatError, match="deprecated unkeyed checksum"):
        store2.get(record.approval_id)

    # list_pending should NOT crash or return this record
    pending = store2.list_pending()
    assert len(pending) == 0
    store2.close()


def test_tampered_state_or_wrong_mac_rejected(tmp_path: Path) -> None:
    """T1.2: Any field modification without valid HMAC is rejected on read."""
    db_path = tmp_path / "test.db"
    now = datetime.now(timezone.utc)
    epoch = "test-epoch"

    store = SQLiteApprovalStore(db_path, deployment_epoch=epoch, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    record = _make_record(now=now)
    store.save_pending(record)
    store.close()

    # Tamper with the row by modifying arguments_json or fake record_checksum
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE approval_records SET record_checksum = 'bad_checksum' WHERE approval_id = ?",
        (record.approval_id,),
    )
    conn.commit()
    conn.close()

    store2 = SQLiteApprovalStore(db_path, deployment_epoch=epoch, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    with pytest.raises(CorruptApprovalRecordError, match="stored approval integrity check failed"):
        store2.get(record.approval_id)
    store2.close()


def test_row_copied_to_another_epoch_fails(tmp_path: Path) -> None:
    """T1.2: A row copied or moved to a different deployment epoch fails HMAC verification."""
    db_path = tmp_path / "test.db"
    now = datetime.now(timezone.utc)
    epoch1 = "epoch-1"
    epoch2 = "epoch-2"

    store1 = SQLiteApprovalStore(db_path, deployment_epoch=epoch1, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    record = _make_record(now=now)
    store1.save_pending(record)
    store1.close()

    # Directly change deployment_epoch in database without updating HMAC
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE approval_records SET deployment_epoch = ? WHERE approval_id = ?",
        (epoch2, record.approval_id),
    )
    conn.commit()
    conn.close()

    store2 = SQLiteApprovalStore(db_path, deployment_epoch=epoch2, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    # The HMAC bound to epoch1 will fail verification under epoch2
    with pytest.raises(CorruptApprovalRecordError, match="stored approval integrity check failed"):
        store2.get(record.approval_id)
    store2.close()


def test_missing_or_wrong_integrity_key_fails_closed(tmp_path: Path) -> None:
    """T1.2: Missing or malformed integrity key fails closed at store initialization."""
    db_path = tmp_path / "test.db"

    # 1. Missing integrity key
    with patch.dict(os.environ, {}, clear=True):
        # Patch default file so it doesn't resolve default config
        with patch("dmint.core.keys.DEFAULT_INTEGRITY_KEY_FILE", tmp_path / "nonexistent.key"):
            with pytest.raises(KeyLoadError, match="no integrity key source found"):
                SQLiteApprovalStore(db_path, deployment_epoch="ep1", integrity_key=None)

            with pytest.raises(KeyLoadError, match="no integrity key source found"):
                SQLAlchemyApprovalStore(f"sqlite:///{db_path}", deployment_epoch="ep1", integrity_key=None)

    # 2. Malformed integrity key (wrong length / non-hex)
    with pytest.raises(KeyLoadError, match="integrity key must be 32 bytes"):
        SQLiteApprovalStore(db_path, deployment_epoch="ep1", integrity_key="tooshort")


def test_store_opened_with_wrong_key_rejects_existing_records(tmp_path: Path) -> None:
    """T1.2: Store opened with a different HMAC key fails integrity check on existing rows."""
    db_path = tmp_path / "test.db"
    now = datetime.now(timezone.utc)
    epoch = "test-epoch"

    store = SQLiteApprovalStore(db_path, deployment_epoch=epoch, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    record = _make_record(now=now)
    store.save_pending(record)
    store.close()

    store_other = SQLiteApprovalStore(db_path, deployment_epoch=epoch, integrity_key=OTHER_KEY_BYTES, clock=lambda: now)
    with pytest.raises(CorruptApprovalRecordError, match="stored approval integrity check failed"):
        store_other.get(record.approval_id)
    store_other.close()


def test_sql_store_hmac_integrity(tmp_path: Path) -> None:
    """T1.2: SQLAlchemyApprovalStore also enforces HMAC integrity and detects tampering."""
    db_path = tmp_path / "test_sql.db"
    url = f"sqlite:///{db_path}"
    now = datetime.now(timezone.utc)
    epoch = "test-epoch"

    store = SQLAlchemyApprovalStore(url, deployment_epoch=epoch, integrity_key=TEST_KEY_BYTES, clock=lambda: now)
    record = _make_record(now=now)
    store.save_pending(record)

    loaded = store.get(record.approval_id)
    assert loaded is not None
    assert loaded.row_version == 1

    # Tamper with the row in DB
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE approval_records SET record_checksum = 'bad_checksum' WHERE approval_id = ?",
        (record.approval_id,),
    )
    conn.commit()
    conn.close()

    with pytest.raises(CorruptApprovalRecordError, match="stored approval integrity check failed"):
        store.get(record.approval_id)
    store.close()
