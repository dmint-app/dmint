"""Regression tests: one shared SQLiteApprovalStore must be thread-safe.

The store opens a single sqlite connection with ``check_same_thread=False``
and relies on ``BEGIN IMMEDIATE`` transactions for atomicity, so a shared
instance must serialize its own operations across threads.  Interleaved
transactions on one connection previously raised raw ``sqlite3`` errors and
left records PENDING; these tests pin the corrected behavior:

* concurrent approvals of distinct records all succeed;
* decision races resolve to exactly one winner and the loser receives a
  typed Core approval error (never a raw ``sqlite3`` error);
* storage failures surface as ``ApprovalStoreError``.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint import (
    ANY_RESOURCE,
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
    ApprovalStoreError,
    IllegalApprovalTransitionError,
)

NOW = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)


def delete_user(user_id: int) -> int:
    return user_id


def _dmint() -> Dmint:
    dmint = Dmint(
        Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),)),
        agent_id="race-agent",
        context=TrustedContext({"environment": "test"}),
    )
    dmint.register(delete_user, "database.delete", resource=lambda arguments: f"users/{arguments['user_id']}")
    return dmint


def _record(dmint: Dmint, user_id: int) -> ApprovalRecord:
    authorized = dmint.authorize(
        delete_user,
        user_id,
        capability="database.delete",
        resource=lambda arguments: f"users/{arguments['user_id']}",
    )
    return ApprovalRecord.create(
        request=authorized.request,
        integration_id="race-runtime",
        capability_id="database.delete",
        policy_provenance=PolicyProvenance("policy-v1", hashlib.sha256(b"policy-v1").hexdigest(), NOW),
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


def _open_store(tmp_path: Path, name: str = "races.sqlite3") -> SQLiteApprovalStore:
    return SQLiteApprovalStore(tmp_path / name, deployment_epoch="race-epoch", clock=lambda: NOW)


def _authority() -> LocalApprovalAuthority:
    return LocalApprovalAuthority(
        issuer_id="race-authority",
        audience="dmint/dashboard/v1",
        private_key=Ed25519PrivateKey.generate(),
        clock=lambda: NOW,
    )


def _race(*operations: Callable[[], None]) -> list[Exception | None]:
    """Run operations on threads released together; return per-op exceptions."""
    barrier = threading.Barrier(len(operations))
    outcomes: list[Exception | None] = [None] * len(operations)

    def runner(index: int, operation: Callable[[], None]) -> None:
        barrier.wait(timeout=10)
        try:
            operation()
        except Exception as exc:  # noqa: BLE001 - the exception is the test subject
            outcomes[index] = exc

    threads = [threading.Thread(target=runner, args=(index, operation)) for index, operation in enumerate(operations)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    return outcomes


def test_shared_store_concurrent_approvals_of_distinct_records_all_succeed(tmp_path: Path) -> None:
    store = _open_store(tmp_path)
    try:
        authority = _authority()
        dmint = _dmint()
        records = [_record(dmint, user_id) for user_id in (1, 2, 3, 4)]
        for record in records:
            store.save_pending(record)

        outcomes = _race(
            *(
                lambda bound=record: store.approve_pending(bound.approval_id, authority=authority, approved_by="human")
                for record in records
            )
        )

        assert outcomes == [None] * len(records), outcomes
        for record in records:
            loaded = store.get(record.approval_id)
            assert loaded is not None and loaded.state is ApprovalState.APPROVED
    finally:
        store.close()


def test_shared_store_double_approve_race_has_exactly_one_typed_winner(tmp_path: Path) -> None:
    store = _open_store(tmp_path)
    try:
        authority = _authority()
        record = _record(_dmint(), user_id=5)
        store.save_pending(record)

        outcomes = _race(
            lambda: store.approve_pending(record.approval_id, authority=authority, approved_by="first"),
            lambda: store.approve_pending(record.approval_id, authority=authority, approved_by="second"),
        )

        winners = [outcome for outcome in outcomes if outcome is None]
        losers = [outcome for outcome in outcomes if outcome is not None]
        assert len(winners) == 1
        assert len(losers) == 1
        assert isinstance(losers[0], (ApprovalConcurrentConsumeError, IllegalApprovalTransitionError))
        loaded = store.get(record.approval_id)
        assert loaded is not None and loaded.state is ApprovalState.APPROVED
    finally:
        store.close()


def test_shared_store_approve_reject_race_has_exactly_one_typed_winner(tmp_path: Path) -> None:
    store = _open_store(tmp_path)
    try:
        authority = _authority()
        record = _record(_dmint(), user_id=6)
        store.save_pending(record)

        outcomes = _race(
            lambda: store.approve_pending(record.approval_id, authority=authority, approved_by="approver"),
            lambda: store.reject_pending(
                record.approval_id, authority=authority, rejected_by="rejecter", reason="race"
            ),
        )

        winners = [outcome for outcome in outcomes if outcome is None]
        losers = [outcome for outcome in outcomes if outcome is not None]
        assert len(winners) == 1
        assert len(losers) == 1
        assert isinstance(losers[0], (ApprovalConcurrentConsumeError, IllegalApprovalTransitionError))
        loaded = store.get(record.approval_id)
        assert loaded is not None and loaded.state in (ApprovalState.APPROVED, ApprovalState.REJECTED)
    finally:
        store.close()


@pytest.mark.parametrize("operation", ["approve", "reject"])
def test_storage_failures_surface_as_typed_store_errors(tmp_path: Path, operation: str) -> None:
    store = _open_store(tmp_path, name=f"{operation}.sqlite3")
    try:
        authority = _authority()
        record = _record(_dmint(), user_id=7)
        store.save_pending(record)
        store._connection.execute("DROP TABLE approval_records")
        store._connection.commit()

        with pytest.raises(ApprovalStoreError):
            if operation == "approve":
                store.approve_pending(record.approval_id, authority=authority, approved_by="human")
            else:
                store.reject_pending(record.approval_id, authority=authority, rejected_by="human")
    finally:
        store.close()
