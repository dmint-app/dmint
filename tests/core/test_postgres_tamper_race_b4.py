"""B4: PostgreSQL 10-process consume race and K-21 tamper scenarios.

Validates that PostgreSQL backing store enforces:
1. 10-process concurrent consume race: exactly 1 process succeeds and 9 fail closed.
2. K-21 tamper scenarios against PostgreSQL:
   - Reset CONSUMED to APPROVED with recomputed unkeyed SHA-256 hash fails closed.
   - Tampered row or wrong HMAC fails closed with CorruptApprovalRecordError.
   - Deleted row fails closed with ApprovalNotFoundError.
   - Row copied/moved to a different deployment epoch fails HMAC verification.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    import rfc8785
except ImportError:
    import types as _types
    from dmint.core.canonicalize import canonicalize_bytes as _cb

    rfc8785 = _types.SimpleNamespace(dumps=_cb)  # type: ignore[assignment]
from sqlalchemy import text

from dmint.core.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
)
from dmint.core.authority import LocalApprovalAuthority
from dmint.core.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalConsumedError,
    ApprovalNotFoundError,
    CorruptApprovalRecordError,
    DeprecatedStorageFormatError,
)
from dmint.core.models import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.core.storage.sql import SQLAlchemyApprovalStore
from dmint.core.storage.sqlite import _OLD_V1_STORED_COLUMNS
from dmint.core.verification import ApprovalVerifier
from tests.postgres_support import require_postgres

TEST_KEY_BYTES = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")


def _consume_race_worker(
    url: str,
    epoch: str,
    key_bytes: bytes,
    approval_id: str,
    assertion,
    req_id: str,
    pub_key_bytes: bytes,
    barrier,
    out_queue,
) -> None:
    try:
        barrier.wait(timeout=10)
        store = SQLAlchemyApprovalStore(url, deployment_epoch=epoch, integrity_key=key_bytes)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        verifier = ApprovalVerifier(trusted_issuers={"auth-1": pub_key}, audience="test-int")
        req = ToolRequest(
            request_id=req_id,
            agent_id="agent-1",
            tool="db-tool",
            action="drop",
            resource=NO_RESOURCE,
            arguments={},
            context=TrustedContext({}),
        )
        now = datetime.now(timezone.utc)
        store.consume_approved(
            approval_id=approval_id,
            credential=assertion,
            expected_request=req,
            verifier=verifier,
            now=now,
        )
        store.close()
        out_queue.put("SUCCESS")
    except (ApprovalConsumedError, ApprovalConcurrentConsumeError) as exc:
        out_queue.put(getattr(exc, "code", type(exc).__name__))
    except Exception as exc:
        out_queue.put(f"ERROR: {type(exc).__name__}: {exc}")


class PostgresTamperRaceB4Tests(unittest.TestCase):
    """B4 tests: 10-process consume race and K-21 tamper attacks on PostgreSQL."""

    def setUp(self) -> None:
        self.url = require_postgres()
        self.epoch = "b4-epoch"
        self.store = SQLAlchemyApprovalStore(
            self.url,
            deployment_epoch=self.epoch,
            integrity_key=TEST_KEY_BYTES,
        )
        with self.store.engine.begin() as conn:
            conn.execute(text("DELETE FROM approval_records"))

    def tearDown(self) -> None:
        if hasattr(self, "store") and self.store:
            self.store.close()

    def _make_record(self, tag: str = "default") -> tuple[ApprovalRecord, ToolRequest]:
        now = datetime.now(timezone.utc)
        req_id = "req_" + (tag + "_" + "1" * 43)[:43]
        req = ToolRequest(
            request_id=req_id,
            agent_id="agent-1",
            tool="db-tool",
            action="drop",
            resource=NO_RESOURCE,
            arguments={},
            context=TrustedContext({}),
        )
        provenance = PolicyProvenance(version_id="v1", policy_digest="a" * 64, evaluated_at=now)
        record = ApprovalRecord.create(
            request=req,
            integration_id="test-int",
            capability_id="test-cap",
            policy_provenance=provenance,
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        )
        return record, req

    def test_ten_process_consume_race_on_postgres(self) -> None:
        """B4: 10 concurrent OS processes race to consume approved record in Postgres. Exactly 1 wins."""
        rec, req = self._make_record("race")
        self.store.save_pending(rec)

        now = datetime.now(timezone.utc)
        priv_key = Ed25519PrivateKey.generate()
        authority = LocalApprovalAuthority(issuer_id="auth-1", audience="test-int", private_key=priv_key)
        self.store.approve_pending(rec.approval_id, authority=authority, approved_by="admin", now=now)
        approver = ApprovalAuthority._from_trusted_boundary("auth-1", "admin", ApprovalAuthorityKind.HUMAN)
        assertion = authority.issue(rec, approver, now=now)
        pub_bytes = priv_key.public_key().public_bytes_raw()

        barrier = mp.Barrier(10)
        out_q: mp.Queue = mp.Queue()
        procs = [
            mp.Process(
                target=_consume_race_worker,
                args=(
                    self.url,
                    self.epoch,
                    TEST_KEY_BYTES,
                    rec.approval_id,
                    assertion,
                    req.request_id,
                    pub_bytes,
                    barrier,
                    out_q,
                ),
            )
            for _ in range(10)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=15)

        results = [out_q.get(timeout=5) for _ in range(10)]
        self.assertEqual(results.count("SUCCESS"), 1, f"Expected 1 winner, got {results}")
        failures = [r for r in results if r != "SUCCESS"]
        self.assertEqual(len(failures), 9)
        for f in failures:
            self.assertIn(f, ("DMT_APPROVAL_CONSUMED", "DMT_APPROVAL_CONCURRENT_CONSUME"))

        # Verify state in PostgreSQL is CONSUMED
        final_record = self.store.get(rec.approval_id)
        self.assertIsNotNone(final_record)
        assert final_record is not None
        self.assertEqual(final_record.state, ApprovalState.CONSUMED)

    def test_postgres_tamper_reset_consumed_to_approved_unkeyed_hash_rejected(self) -> None:
        """B4: Resetting CONSUMED to APPROVED with old unkeyed SHA-256 hash fails closed on Postgres."""
        rec, req = self._make_record("reset")
        self.store.save_pending(rec)

        now = datetime.now(timezone.utc)
        priv_key = Ed25519PrivateKey.generate()
        authority = LocalApprovalAuthority(issuer_id="auth-1", audience="test-int", private_key=priv_key)
        verifier = ApprovalVerifier(trusted_issuers={"auth-1": authority.public_key}, audience="test-int")
        self.store.approve_pending(rec.approval_id, authority=authority, approved_by="admin", now=now)
        approver = ApprovalAuthority._from_trusted_boundary("auth-1", "admin", ApprovalAuthorityKind.HUMAN)
        assertion = authority.issue(rec, approver, now=now)

        consumed = self.store.consume_approved(
            approval_id=rec.approval_id,
            credential=assertion,
            expected_request=req,
            verifier=verifier,
            now=now,
        )
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)

        # Attacker tampers directly with PostgreSQL row: resets state to APPROVED, recomputes old unkeyed v1 checksum
        with self.store.engine.begin() as conn:
            row = (
                conn.execute(
                    text("SELECT * FROM approval_records WHERE approval_id = :id"),
                    {"id": rec.approval_id},
                )
                .mappings()
                .fetchone()
            )
            self.assertIsNotNone(row)
            assert row is not None

            v1_payload = {col: row[col] for col in _OLD_V1_STORED_COLUMNS}
            v1_payload["state"] = "APPROVED"
            v1_payload["consumed_at"] = None
            canonical_v1 = rfc8785.dumps(v1_payload)
            old_checksum = hashlib.sha256(b"dmint/approval-record-integrity/v1\x00" + canonical_v1).hexdigest()

            conn.execute(
                text(
                    "UPDATE approval_records SET state = 'APPROVED', consumed_at = NULL, record_checksum = :chk WHERE approval_id = :id"
                ),
                {"chk": old_checksum, "id": rec.approval_id},
            )

        with self.assertRaises(DeprecatedStorageFormatError) as exc_info:
            self.store.get(rec.approval_id)
        self.assertIn("deprecated unkeyed checksum", str(exc_info.exception))

        # list_pending does not return or crash on the tampered row
        pending = self.store.list_pending()
        self.assertEqual(len(pending), 0)

    def test_postgres_tamper_wrong_mac_rejected(self) -> None:
        """B4: Tampered field or invalid HMAC on PostgreSQL row fails closed."""
        rec, _ = self._make_record("mac")
        self.store.save_pending(rec)

        # Attacker overwrites record_checksum with bad MAC in Postgres
        with self.store.engine.begin() as conn:
            conn.execute(
                text("UPDATE approval_records SET record_checksum = 'bad_checksum' WHERE approval_id = :id"),
                {"id": rec.approval_id},
            )

        with self.assertRaises(CorruptApprovalRecordError) as exc_info:
            self.store.get(rec.approval_id)
        self.assertIn("stored approval integrity check failed", str(exc_info.exception))

    def test_postgres_tamper_deleted_row_rejected(self) -> None:
        """B4: Deleting row from PostgreSQL results in ApprovalNotFoundError on consume."""
        rec, req = self._make_record("del")
        self.store.save_pending(rec)

        now = datetime.now(timezone.utc)
        priv_key = Ed25519PrivateKey.generate()
        authority = LocalApprovalAuthority(issuer_id="auth-1", audience="test-int", private_key=priv_key)
        verifier = ApprovalVerifier(trusted_issuers={"auth-1": authority.public_key}, audience="test-int")
        self.store.approve_pending(rec.approval_id, authority=authority, approved_by="admin", now=now)
        approver = ApprovalAuthority._from_trusted_boundary("auth-1", "admin", ApprovalAuthorityKind.HUMAN)
        assertion = authority.issue(rec, approver, now=now)

        # Attacker deletes row from Postgres
        with self.store.engine.begin() as conn:
            conn.execute(
                text("DELETE FROM approval_records WHERE approval_id = :id"),
                {"id": rec.approval_id},
            )

        self.assertIsNone(self.store.get(rec.approval_id))
        with self.assertRaises(ApprovalNotFoundError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request=req,
                verifier=verifier,
                now=now,
            )

    def test_postgres_tamper_epoch_copy_fails(self) -> None:
        """B4: Row copied or moved to a different deployment epoch fails HMAC verification on Postgres."""
        rec, _ = self._make_record("epoch")
        self.store.save_pending(rec)

        epoch2 = "b4-epoch-other"
        # Directly update deployment_epoch in database without valid HMAC for epoch2
        with self.store.engine.begin() as conn:
            conn.execute(
                text("UPDATE approval_records SET deployment_epoch = :ep WHERE approval_id = :id"),
                {"ep": epoch2, "id": rec.approval_id},
            )

        store2 = SQLAlchemyApprovalStore(
            self.url,
            deployment_epoch=epoch2,
            integrity_key=TEST_KEY_BYTES,
        )
        try:
            with self.assertRaises(CorruptApprovalRecordError) as exc_info:
                store2.get(rec.approval_id)
            self.assertIn("stored approval integrity check failed", str(exc_info.exception))
        finally:
            store2.close()
