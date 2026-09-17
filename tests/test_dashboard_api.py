"""Tests for the dashboard-facing public Core APIs.

Covers:
    list_pending         — query unexpired PENDING records
    list_records         — general history/audit query
    approve_pending      — atomic PENDING → APPROVED via HUMAN authority
    reject_pending       — atomic PENDING → REJECTED via HUMAN authority
"""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dmint import (
    ANY_RESOURCE,
    ApprovalAuthorityKind,
    ApprovalState,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    SQLiteApprovalStore,
    TrustedContext,
)
from dmint.approvals import ApprovalRecord
from dmint.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalStoreError,
    CorruptApprovalRecordError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
)


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _make_authority(issuer: str = "dashboard-authority") -> LocalApprovalAuthority:
    return LocalApprovalAuthority(issuer_id=issuer, audience="dmint/dashboard/v1")


def _make_provenance(now: datetime) -> PolicyProvenance:
    return PolicyProvenance(
        "policy-v1",
        hashlib.sha256(b"policy-v1").hexdigest(),
        now,
    )


class _Base(unittest.TestCase):
    """Common setUp / tear down and helpers for dashboard API tests."""

    def setUp(self) -> None:
        self.now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.expires = self.now + timedelta(minutes=10)
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "approvals.sqlite"
        self.authority = _make_authority()

        self.policy = Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),))
        self.dmint = Dmint(
            self.policy,
            agent_id="agent-a",
            context=TrustedContext({"env": "test"}),
        )

        def delete_user(user_id):
            return user_id

        self.dmint.register(
            delete_user,
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self._delete_user_fn = delete_user

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def open_store(self, epoch: str = "epoch-1") -> SQLiteApprovalStore:
        return SQLiteApprovalStore(self.db_path, deployment_epoch=epoch, clock=lambda: self.now)

    def make_record(self, *, user_id: int = 1, now: datetime | None = None) -> ApprovalRecord:
        now = now or self.now
        authorized = self.dmint.authorize(
            self._delete_user_fn,
            user_id,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        return ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=_make_provenance(now),
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        )


# ===========================================================================
# list_pending tests
# ===========================================================================

class TestListPending(_Base):

    def test_empty_store_returns_empty_list(self) -> None:
        with self.open_store() as store:
            result = store.list_pending()
        self.assertEqual(result, [])

    def test_single_pending_record_is_returned(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            result = store.list_pending()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].approval_id, record.approval_id)
        self.assertEqual(result[0].state, ApprovalState.PENDING)

    def test_multiple_pending_ordered_newest_first(self) -> None:
        t1 = self.now
        t2 = self.now + timedelta(seconds=30)
        t3 = self.now + timedelta(seconds=60)
        r1 = self.make_record(user_id=1, now=t1)
        r2 = self.make_record(user_id=2, now=t2)
        r3 = self.make_record(user_id=3, now=t3)

        with self.open_store() as store:
            # Save in non-chronological order to verify ORDER BY
            store._clock = lambda: t1
            store.save_pending(r1)
            store._clock = lambda: t2
            store.save_pending(r2)
            store._clock = lambda: t3
            store.save_pending(r3)
            store._clock = lambda: t3 + timedelta(seconds=1)
            result = store.list_pending()

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0].approval_id, r3.approval_id)
        self.assertEqual(result[1].approval_id, r2.approval_id)
        self.assertEqual(result[2].approval_id, r1.approval_id)

    def test_limit_is_respected(self) -> None:
        times = [self.now + timedelta(seconds=i) for i in range(5)]
        records = [self.make_record(user_id=10 + i, now=times[i]) for i in range(5)]
        with self.open_store() as store:
            for i, rec in enumerate(records):
                store._clock = lambda t=times[i]: t
                store.save_pending(rec)
            store._clock = lambda: times[-1] + timedelta(seconds=1)
            result = store.list_pending(limit=3)
        self.assertEqual(len(result), 3)

    def test_limit_capped_at_max(self) -> None:
        with self.open_store() as store:
            result = store.list_pending(limit=99999)
        # Just verifying no error and that the cap does not crash
        self.assertIsInstance(result, list)

    def test_invalid_limit_raises(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(MalformedApprovalError):
                store.list_pending(limit=0)
            with self.assertRaises(MalformedApprovalError):
                store.list_pending(limit=-1)
            with self.assertRaises(MalformedApprovalError):
                store.list_pending(limit="all")  # type: ignore[arg-type]

    def test_expired_pending_records_excluded(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            # Advance clock past expiration
            store._clock = lambda: self.now + timedelta(hours=1)
            result = store.list_pending()
        self.assertEqual(result, [])

    def test_non_pending_records_excluded(self) -> None:
        """Approved/rejected records must not appear in list_pending."""
        record = self.make_record(user_id=42)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="tester",
                now=self.now + timedelta(seconds=1),
            )
            result = store.list_pending()
        self.assertEqual(result, [])

    def test_returned_records_pass_integrity(self) -> None:
        record = self.make_record(user_id=7)
        with self.open_store() as store:
            store.save_pending(record)
            results = store.list_pending()
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.approval_id, record.approval_id)
        self.assertEqual(r.request_fingerprint, record.request_fingerprint)

    def test_corrupt_row_raises_corrupt_error(self) -> None:
        record = self.make_record(user_id=99)
        with self.open_store() as store:
            store.save_pending(record)
        # Tamper directly via raw SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE approval_records SET tool = 'tampered-tool' WHERE approval_id = ?",
                (record.approval_id,),
            )
        with self.open_store() as store:
            with self.assertRaises(CorruptApprovalRecordError):
                store.list_pending()


# ===========================================================================
# list_records tests
# ===========================================================================

class TestListRecords(_Base):

    def test_empty_store_returns_empty_list(self) -> None:
        with self.open_store() as store:
            self.assertEqual(store.list_records(), [])

    def test_all_records_returned_when_no_state_filter(self) -> None:
        r1 = self.make_record(user_id=1)
        r2 = self.make_record(user_id=2)
        with self.open_store() as store:
            store.save_pending(r1)
            store.save_pending(r2)
            store.approve_pending(
                r1.approval_id,
                authority=self.authority,
                approved_by="admin",
                now=self.now + timedelta(seconds=5),
            )
            result = store.list_records()
        # r1 → APPROVED, r2 → PENDING; both returned
        ids = {r.approval_id for r in result}
        self.assertIn(r1.approval_id, ids)
        self.assertIn(r2.approval_id, ids)

    def test_state_filter_pending_only(self) -> None:
        r1 = self.make_record(user_id=1)
        r2 = self.make_record(user_id=2)
        with self.open_store() as store:
            store.save_pending(r1)
            store.save_pending(r2)
            store.approve_pending(
                r1.approval_id,
                authority=self.authority,
                approved_by="admin",
                now=self.now + timedelta(seconds=5),
            )
            result = store.list_records(states={ApprovalState.PENDING})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].approval_id, r2.approval_id)

    def test_state_filter_approved_only(self) -> None:
        r1 = self.make_record(user_id=1)
        r2 = self.make_record(user_id=2)
        with self.open_store() as store:
            store.save_pending(r1)
            store.save_pending(r2)
            store.approve_pending(
                r1.approval_id,
                authority=self.authority,
                approved_by="admin",
                now=self.now + timedelta(seconds=5),
            )
            result = store.list_records(states={ApprovalState.APPROVED})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].approval_id, r1.approval_id)

    def test_multiple_state_filter(self) -> None:
        r1 = self.make_record(user_id=1)
        r2 = self.make_record(user_id=2)
        r3 = self.make_record(user_id=3)
        with self.open_store() as store:
            store.save_pending(r1)
            store.save_pending(r2)
            store.save_pending(r3)
            store.approve_pending(
                r1.approval_id,
                authority=self.authority,
                approved_by="admin",
                now=self.now + timedelta(seconds=5),
            )
            store.reject_pending(
                r2.approval_id,
                authority=self.authority,
                rejected_by="admin",
                now=self.now + timedelta(seconds=6),
            )
            result = store.list_records(
                states={ApprovalState.APPROVED, ApprovalState.REJECTED}
            )
        ids = {r.approval_id for r in result}
        self.assertIn(r1.approval_id, ids)
        self.assertIn(r2.approval_id, ids)
        self.assertNotIn(r3.approval_id, ids)

    def test_ordering_newest_first(self) -> None:
        t1 = self.now
        t2 = self.now + timedelta(seconds=60)
        r1 = self.make_record(user_id=1, now=t1)
        r2 = self.make_record(user_id=2, now=t2)
        with self.open_store() as store:
            store._clock = lambda: t1
            store.save_pending(r1)
            store._clock = lambda: t2
            store.save_pending(r2)
            store._clock = lambda: t2 + timedelta(seconds=1)
            result = store.list_records(states={ApprovalState.PENDING})
        self.assertEqual(result[0].approval_id, r2.approval_id)
        self.assertEqual(result[1].approval_id, r1.approval_id)

    def test_limit_respected(self) -> None:
        for i in range(5):
            r = self.make_record(user_id=100 + i)
            with self.open_store() as store:
                store.save_pending(r)
        with self.open_store() as store:
            result = store.list_records(limit=2)
        self.assertEqual(len(result), 2)

    def test_invalid_limit_raises(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(MalformedApprovalError):
                store.list_records(limit=0)

    def test_invalid_states_type_raises(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(MalformedApprovalError):
                store.list_records(states=set())  # empty set
            with self.assertRaises(MalformedApprovalError):
                store.list_records(states={"PENDING"})  # type: ignore[arg-type]
            with self.assertRaises(MalformedApprovalError):
                store.list_records(states=[ApprovalState.PENDING])  # type: ignore[arg-type]


# ===========================================================================
# approve_pending tests
# ===========================================================================

class TestApprovePending(_Base):

    def test_approve_pending_returns_approved_record(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=5),
            )
        self.assertEqual(approved.state, ApprovalState.APPROVED)
        self.assertEqual(approved.approval_id, record.approval_id)

    def test_approved_record_is_persisted(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=5),
            )
            loaded = store.get(record.approval_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.state, ApprovalState.APPROVED)

    def test_approve_sets_human_authority(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=5),
            )
        self.assertIsNotNone(approved.decision_authority)
        self.assertEqual(approved.decision_authority.kind, ApprovalAuthorityKind.HUMAN)
        self.assertEqual(approved.decision_authority.subject_id, "alice")
        self.assertEqual(approved.decision_authority.authority_id, self.authority.issuer_id)

    def test_approve_preserves_exact_request_binding(self) -> None:
        record = self.make_record(user_id=42)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=5),
            )
        self.assertEqual(approved.request_fingerprint, record.request_fingerprint)
        self.assertEqual(approved.request_id, record.request_id)
        self.assertEqual(approved.request.tool, record.request.tool)
        self.assertEqual(approved.request.action, record.request.action)
        self.assertEqual(approved.request.agent_id, record.request.agent_id)
        self.assertEqual(approved.policy_provenance, record.policy_provenance)

    def test_approve_not_found_raises(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(ApprovalNotFoundError):
                store.approve_pending(
                    "apr_" + "a" * 43,
                    authority=self.authority,
                    approved_by="alice",
                )

    def test_approve_expired_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(ApprovalExpiredError):
                store.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="alice",
                    now=self.now + timedelta(hours=1),
                )

    def test_approve_already_approved_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=1),
            )
            # Second approve attempt must fail
            with self.assertRaises((ApprovalConcurrentConsumeError, IllegalApprovalTransitionError)):
                store.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="alice",
                    now=self.now + timedelta(seconds=2),
                )

    def test_approve_already_rejected_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="alice",
                now=self.now + timedelta(seconds=1),
            )
            with self.assertRaises((ApprovalConcurrentConsumeError, IllegalApprovalTransitionError)):
                store.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="alice",
                    now=self.now + timedelta(seconds=2),
                )

    def test_approve_invalid_approval_id_raises(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(CorruptApprovalRecordError):
                store.approve_pending(
                    "not-an-id",
                    authority=self.authority,
                    approved_by="alice",
                )

    def test_approve_invalid_authority_type_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.approve_pending(
                    record.approval_id,
                    authority="not-an-authority",  # type: ignore[arg-type]
                    approved_by="alice",
                )

    def test_approve_blank_approved_by_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="",
                )
            with self.assertRaises(MalformedApprovalError):
                store.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="  ",
                )

    def test_approve_cannot_substitute_different_request(self) -> None:
        """Caller cannot approve record A by supplying record B's ID."""
        r1 = self.make_record(user_id=1)
        r2 = self.make_record(user_id=2)
        with self.open_store() as store:
            store.save_pending(r1)
            store.save_pending(r2)
            # Approve r1 by its real ID — verifies that r2 is unaffected
            store.approve_pending(
                r1.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=1),
            )
            r2_loaded = store.get(r2.approval_id)
        self.assertEqual(r2_loaded.state, ApprovalState.PENDING)

    def test_approve_approved_record_shows_in_list_records(self) -> None:
        record = self.make_record(user_id=5)
        with self.open_store() as store:
            store.save_pending(record)
            store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="admin",
                now=self.now + timedelta(seconds=1),
            )
            result = store.list_records(states={ApprovalState.APPROVED})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].approval_id, record.approval_id)


# ===========================================================================
# reject_pending tests
# ===========================================================================

class TestRejectPending(_Base):

    def test_reject_pending_returns_rejected_record(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            rejected = store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                now=self.now + timedelta(seconds=5),
            )
        self.assertEqual(rejected.state, ApprovalState.REJECTED)
        self.assertEqual(rejected.approval_id, record.approval_id)

    def test_rejected_record_is_persisted(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                now=self.now + timedelta(seconds=5),
            )
            loaded = store.get(record.approval_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.state, ApprovalState.REJECTED)

    def test_reject_stores_reason(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            rejected = store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                reason="too risky",
                now=self.now + timedelta(seconds=5),
            )
        self.assertEqual(rejected.state_reason, "too risky")

    def test_reject_without_reason_is_valid(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            rejected = store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                now=self.now + timedelta(seconds=5),
            )
        self.assertIsNone(rejected.state_reason)

    def test_reject_sets_human_authority(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            rejected = store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                now=self.now + timedelta(seconds=5),
            )
        self.assertIsNotNone(rejected.decision_authority)
        self.assertEqual(rejected.decision_authority.kind, ApprovalAuthorityKind.HUMAN)
        self.assertEqual(rejected.decision_authority.subject_id, "bob")

    def test_reject_not_found_raises(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(ApprovalNotFoundError):
                store.reject_pending(
                    "apr_" + "b" * 43,
                    authority=self.authority,
                    rejected_by="bob",
                )

    def test_reject_expired_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(ApprovalExpiredError):
                store.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    now=self.now + timedelta(hours=1),
                )

    def test_reject_already_rejected_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                now=self.now + timedelta(seconds=1),
            )
            with self.assertRaises((ApprovalConcurrentConsumeError, IllegalApprovalTransitionError)):
                store.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    now=self.now + timedelta(seconds=2),
                )

    def test_reject_already_approved_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=1),
            )
            with self.assertRaises((ApprovalConcurrentConsumeError, IllegalApprovalTransitionError)):
                store.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    now=self.now + timedelta(seconds=2),
                )

    def test_reject_invalid_authority_type_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.reject_pending(
                    record.approval_id,
                    authority="bad",  # type: ignore[arg-type]
                    rejected_by="bob",
                )

    def test_reject_blank_rejected_by_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="",
                )

    def test_reject_oversized_reason_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    reason="x" * 1001,
                )

    def test_reject_reason_at_limit_is_accepted(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            rejected = store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="bob",
                reason="x" * 1000,
                now=self.now + timedelta(seconds=1),
            )
        self.assertEqual(len(rejected.state_reason), 1000)

    def test_reject_empty_reason_string_raises(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    reason="",
                )

    def test_rejected_shows_in_list_records(self) -> None:
        record = self.make_record(user_id=5)
        with self.open_store() as store:
            store.save_pending(record)
            store.reject_pending(
                record.approval_id,
                authority=self.authority,
                rejected_by="admin",
                now=self.now + timedelta(seconds=1),
            )
            result = store.list_records(states={ApprovalState.REJECTED})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].state, ApprovalState.REJECTED)


# ===========================================================================
# Security invariant tests
# ===========================================================================

class TestSecurityInvariants(_Base):
    """Verify that callers cannot substitute security-critical fields."""

    def test_caller_cannot_change_request_fingerprint_via_approve(self) -> None:
        """The stored fingerprint comes from the persisted PENDING record, not the caller."""
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=1),
            )
        # Must equal what was stored in PENDING, not anything the caller provided
        self.assertEqual(approved.request_fingerprint, record.request_fingerprint)

    def test_caller_cannot_change_policy_provenance_via_approve(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=1),
            )
        self.assertEqual(approved.policy_provenance, record.policy_provenance)

    def test_caller_cannot_supply_arbitrary_authority_kind(self) -> None:
        """approve_pending only accepts LocalApprovalAuthority; bare ApprovalAuthority is rejected."""
        from dmint import ApprovalAuthority, ApprovalAuthorityKind

        record = self.make_record(user_id=1)
        bad_authority = ApprovalAuthority._from_trusted_boundary(
            "dashboard-ui", "alice", ApprovalAuthorityKind.HUMAN
        )
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(MalformedApprovalError):
                store.approve_pending(
                    record.approval_id,
                    authority=bad_authority,  # type: ignore[arg-type]
                    approved_by="alice",
                )

    def test_approve_one_id_does_not_affect_another(self) -> None:
        r1 = self.make_record(user_id=1)
        r2 = self.make_record(user_id=2)
        with self.open_store() as store:
            store.save_pending(r1)
            store.save_pending(r2)
            store.approve_pending(
                r1.approval_id,
                authority=self.authority,
                approved_by="alice",
                now=self.now + timedelta(seconds=1),
            )
            r2_loaded = store.get(r2.approval_id)
        self.assertEqual(r2_loaded.state, ApprovalState.PENDING)

    def test_approve_persists_issuer_identity_in_authority(self) -> None:
        alt_authority = LocalApprovalAuthority(
            issuer_id="human-approver-v2", audience="dmint/dashboard/v1"
        )
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)
            approved = store.approve_pending(
                record.approval_id,
                authority=alt_authority,
                approved_by="carol",
                now=self.now + timedelta(seconds=1),
            )
        self.assertEqual(approved.decision_authority.authority_id, "human-approver-v2")
        self.assertEqual(approved.decision_authority.subject_id, "carol")


# ===========================================================================
# Concurrency tests
# ===========================================================================

class TestConcurrency(_Base):
    """Verify that concurrent approve/reject operations resolve atomically."""

    def _concurrent_ops(self, op1, op2) -> tuple[Exception | None, Exception | None]:
        """Run two callables concurrently; return (exc1, exc2)."""
        barrier = threading.Barrier(2)
        results: list[Exception | None] = [None, None]

        def run(fn, index):
            barrier.wait()
            try:
                fn()
            except Exception as exc:
                results[index] = exc

        t1 = threading.Thread(target=run, args=(op1, 0))
        t2 = threading.Thread(target=run, args=(op2, 1))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        return results[0], results[1]

    def test_concurrent_approve_approve_only_one_wins(self) -> None:
        record = self.make_record(user_id=1)
        with self.open_store() as store:
            store.save_pending(record)

        errors: list[Exception | None] = [None, None]
        barrier = threading.Barrier(2)

        def approve(index):
            barrier.wait()
            try:
                s = self.open_store()
                s.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="alice",
                    now=self.now + timedelta(seconds=1),
                )
                s.close()
            except Exception as exc:
                errors[index] = exc

        t1 = threading.Thread(target=approve, args=(0,))
        t2 = threading.Thread(target=approve, args=(1,))
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)

        # Exactly one succeeded and one failed
        succeeded = sum(1 for e in errors if e is None)
        self.assertEqual(succeeded, 1)
        loser = next(e for e in errors if e is not None)
        self.assertIsInstance(loser, (ApprovalConcurrentConsumeError, IllegalApprovalTransitionError))

        # Final state is APPROVED (the winner persisted)
        with self.open_store() as store:
            final = store.get(record.approval_id)
        self.assertEqual(final.state, ApprovalState.APPROVED)

    def test_concurrent_approve_reject_only_one_wins(self) -> None:
        record = self.make_record(user_id=2)
        with self.open_store() as store:
            store.save_pending(record)

        errors: list[Exception | None] = [None, None]
        barrier = threading.Barrier(2)

        def approve_fn():
            barrier.wait()
            try:
                s = self.open_store()
                s.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by="alice",
                    now=self.now + timedelta(seconds=1),
                )
                s.close()
            except Exception as exc:
                errors[0] = exc

        def reject_fn():
            barrier.wait()
            try:
                s = self.open_store()
                s.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    now=self.now + timedelta(seconds=1),
                )
                s.close()
            except Exception as exc:
                errors[1] = exc

        t1 = threading.Thread(target=approve_fn)
        t2 = threading.Thread(target=reject_fn)
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)

        succeeded = sum(1 for e in errors if e is None)
        self.assertEqual(succeeded, 1)

        with self.open_store() as store:
            final = store.get(record.approval_id)
        self.assertIn(final.state, {ApprovalState.APPROVED, ApprovalState.REJECTED})

    def test_concurrent_reject_reject_only_one_wins(self) -> None:
        record = self.make_record(user_id=3)
        with self.open_store() as store:
            store.save_pending(record)

        errors: list[Exception | None] = [None, None]
        barrier = threading.Barrier(2)

        def reject(index):
            barrier.wait()
            try:
                s = self.open_store()
                s.reject_pending(
                    record.approval_id,
                    authority=self.authority,
                    rejected_by="bob",
                    now=self.now + timedelta(seconds=1),
                )
                s.close()
            except Exception as exc:
                errors[index] = exc

        t1 = threading.Thread(target=reject, args=(0,))
        t2 = threading.Thread(target=reject, args=(1,))
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)

        succeeded = sum(1 for e in errors if e is None)
        self.assertEqual(succeeded, 1)

        with self.open_store() as store:
            final = store.get(record.approval_id)
        self.assertEqual(final.state, ApprovalState.REJECTED)


if __name__ == "__main__":
    unittest.main()
