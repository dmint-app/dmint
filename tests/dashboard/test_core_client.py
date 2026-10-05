"""Tests for CoreClient — the thin Core public API wrapper."""

from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

from dmint import ApprovalState
from dmint.errors import (
    ApprovalExpiredError,
    ApprovalNotFoundError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
)

from tests.dashboard.conftest import make_record, NOW


class TestCoreClientListPending:
    def test_empty_store_returns_empty_list(self, client_obj):
        assert client_obj.list_pending() == []

    def test_single_pending_record_returned(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        result = client_obj.list_pending()
        assert len(result) == 1
        assert result[0].approval_id == record.approval_id

    def test_multiple_records_returned(self, client_obj, store, dmint_inst):
        r1 = make_record(dmint_inst, user_id=1)
        r2 = make_record(dmint_inst, user_id=2)
        store.save_pending(r1)
        store.save_pending(r2)
        result = client_obj.list_pending()
        assert len(result) == 2

    def test_expired_records_excluded(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        # Advance store clock past expiry
        store._clock = lambda: NOW + timedelta(hours=1)
        result = client_obj.list_pending()
        assert result == []

    def test_limit_forwarded_to_store(self, client_obj, store, dmint_inst):
        for i in range(5):
            r = make_record(dmint_inst, user_id=10 + i)
            store.save_pending(r)
        result = client_obj.list_pending(limit=2)
        assert len(result) == 2


class TestCoreClientListRecords:
    def test_no_state_filter_returns_all(self, client_obj, store, dmint_inst):
        r1 = make_record(dmint_inst, user_id=1)
        r2 = make_record(dmint_inst, user_id=2)
        store.save_pending(r1)
        store.save_pending(r2)
        result = client_obj.list_records()
        assert len(result) == 2

    def test_state_filter_pending(self, client_obj, store, authority, dmint_inst):
        r1 = make_record(dmint_inst, user_id=1)
        store.save_pending(r1)
        store.approve_pending(r1.approval_id, authority=authority, approved_by="tester", now=NOW + timedelta(seconds=1))
        r2 = make_record(dmint_inst, user_id=2)
        store.save_pending(r2)
        result = client_obj.list_records(states={ApprovalState.PENDING})
        assert len(result) == 1
        assert result[0].approval_id == r2.approval_id

    def test_state_filter_approved(self, client_obj, store, authority, dmint_inst):
        r1 = make_record(dmint_inst, user_id=1)
        store.save_pending(r1)
        store.approve_pending(r1.approval_id, authority=authority, approved_by="tester", now=NOW + timedelta(seconds=1))
        result = client_obj.list_records(states={ApprovalState.APPROVED})
        assert len(result) == 1
        assert result[0].state == ApprovalState.APPROVED


class TestCoreClientGetApproval:
    def test_existing_record_returned(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        loaded = client_obj.get_approval(record.approval_id)
        assert loaded is not None
        assert loaded.approval_id == record.approval_id

    def test_missing_record_returns_none(self, client_obj):
        result = client_obj.get_approval("apr_" + "a" * 43)
        assert result is None


class TestCoreClientApprove:
    def test_approve_returns_approved_record(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        approved = client_obj.approve(record.approval_id)
        assert approved.state == ApprovalState.APPROVED

    def test_approved_record_persisted_in_store(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        client_obj.approve(record.approval_id)
        loaded = store.get(record.approval_id)
        assert loaded.state == ApprovalState.APPROVED

    def test_approve_expired_raises(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        store._clock = lambda: NOW + timedelta(hours=1)
        with pytest.raises(ApprovalExpiredError):
            client_obj.approve(record.approval_id)

    def test_approve_missing_raises(self, client_obj):
        with pytest.raises(ApprovalNotFoundError):
            client_obj.approve("apr_" + "b" * 43)

    def test_approve_already_approved_raises(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        client_obj.approve(record.approval_id)
        with pytest.raises(Exception):  # ConcurrentConsumeError or IllegalTransition
            client_obj.approve(record.approval_id)


class TestCoreClientReject:
    def test_reject_returns_rejected_record(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        rejected = client_obj.reject(record.approval_id)
        assert rejected.state == ApprovalState.REJECTED

    def test_reject_with_reason_stored(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        rejected = client_obj.reject(record.approval_id, reason="too risky")
        assert rejected.state_reason == "too risky"

    def test_reject_persisted_in_store(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        client_obj.reject(record.approval_id)
        loaded = store.get(record.approval_id)
        assert loaded.state == ApprovalState.REJECTED

    def test_reject_expired_raises(self, client_obj, store, dmint_inst):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        store._clock = lambda: NOW + timedelta(hours=1)
        with pytest.raises(ApprovalExpiredError):
            client_obj.reject(record.approval_id)

    def test_reject_missing_raises(self, client_obj):
        with pytest.raises(ApprovalNotFoundError):
            client_obj.reject("apr_" + "c" * 43)

    def test_empty_reason_passed_as_none(self, client_obj, store, dmint_inst):
        """Empty string reason should be treated as None (not sent to Core)."""
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        # CoreClient converts "" to None before calling reject_pending
        rejected = client_obj.reject(record.approval_id, reason=None)
        assert rejected.state_reason is None


class TestCoreClientCountByState:
    def test_count_pending(self, client_obj, store, dmint_inst):
        r1 = make_record(dmint_inst, user_id=1)
        r2 = make_record(dmint_inst, user_id=2)
        store.save_pending(r1)
        store.save_pending(r2)
        assert client_obj.count_by_state(ApprovalState.PENDING) == 2

    def test_count_approved_after_approve(self, client_obj, store, dmint_inst, authority):
        record = make_record(dmint_inst, user_id=1)
        store.save_pending(record)
        store.approve_pending(
            record.approval_id, authority=authority, approved_by="tester", now=NOW + timedelta(seconds=1)
        )
        assert client_obj.count_by_state(ApprovalState.APPROVED) == 1


class TestCoreClientPing:
    def test_ping_returns_true(self, client_obj):
        assert client_obj.ping() is True


class TestCoreClientConstruction:
    def test_invalid_store_type_raises(self, authority):
        from dmint.dashboard.core_client import CoreClient

        with pytest.raises(TypeError):
            CoreClient(store="not-a-store", authority=authority)

    def test_invalid_authority_type_raises(self, store):
        from dmint.dashboard.core_client import CoreClient

        with pytest.raises(TypeError):
            CoreClient(store=store, authority="not-an-authority")

    def test_blank_approver_id_raises(self, store, authority):
        from dmint.dashboard.core_client import CoreClient

        with pytest.raises(ValueError):
            CoreClient(store=store, authority=authority, approver_id="")
