"""Real end-to-end integration tests: Core + Dashboard working together.

These tests use the actual Core SQLite store, the actual LocalApprovalAuthority,
and the actual dashboard routes.  No mocks.
"""

from __future__ import annotations

import hashlib
import tempfile
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

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

from dmint.dashboard.app import create_app
from dmint.dashboard.core_client import CoreClient, ThreadSafeApprovalStore

from tests.dashboard.conftest import make_record, make_dmint, NOW


# ---------------------------------------------------------------------------
# Full pipeline: create pending → dashboard reads → approve
# ---------------------------------------------------------------------------


class TestIntegrationApproveFlow:
    def test_full_approve_flow_via_dashboard(self, tmp_path):
        """
        1. Create pending Core approval
        2. Dashboard reads it via list_pending
        3. Dashboard approves via POST /approvals/{id}/approve
        4. Core SQLite state becomes APPROVED
        """
        db = tmp_path / "integration.sqlite"
        store = ThreadSafeApprovalStore(db, deployment_epoch="integration-test", clock=lambda: NOW)
        authority = LocalApprovalAuthority(
            issuer_id="integration-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW
        )
        client = CoreClient(store=store, authority=authority, approver_id="integration-human")
        app = create_app(client)
        http = TestClient(app, raise_server_exceptions=False)

        # Step 1: Create pending approval using Core
        dmint = make_dmint()
        record = make_record(dmint, user_id=101)
        store.save_pending(record)

        # Step 2: Dashboard reads it
        pending = client.list_pending()
        assert len(pending) == 1
        assert pending[0].approval_id == record.approval_id
        assert pending[0].state == ApprovalState.PENDING

        # Step 3: Dashboard approves via HTTP
        resp = http.post(f"/approvals/{record.approval_id}/approve")
        assert resp.status_code in (200, 303)  # redirect or follow

        # Step 4: Core SQLite state is now APPROVED
        final = store.get(record.approval_id)
        assert final is not None
        assert final.state == ApprovalState.APPROVED
        assert final.decision_authority is not None
        assert final.decision_authority.subject_id == "integration-human"

        store.close()

    def test_full_reject_flow_via_dashboard(self, tmp_path):
        """
        1. Create pending Core approval
        2. Dashboard reads it
        3. Dashboard rejects via POST /approvals/{id}/reject
        4. Core SQLite state becomes REJECTED
        """
        db = tmp_path / "reject_integration.sqlite"
        store = ThreadSafeApprovalStore(db, deployment_epoch="reject-epoch", clock=lambda: NOW)
        authority = LocalApprovalAuthority(
            issuer_id="reject-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW
        )
        client = CoreClient(store=store, authority=authority, approver_id="reject-human")
        app = create_app(client)
        http = TestClient(app, raise_server_exceptions=False)

        dmint = make_dmint()
        record = make_record(dmint, user_id=202)
        store.save_pending(record)

        # Dashboard reads it
        pending = client.list_pending()
        assert len(pending) == 1

        # Dashboard rejects via HTTP
        resp = http.post(
            f"/approvals/{record.approval_id}/reject",
            data={"reason": "scope too broad for production"},
        )
        assert resp.status_code in (200, 303)

        # Core SQLite state is REJECTED
        final = store.get(record.approval_id)
        assert final is not None
        assert final.state == ApprovalState.REJECTED
        assert final.state_reason == "scope too broad for production"
        assert final.decision_authority.subject_id == "reject-human"

        store.close()


class TestIntegrationAuditFlow:
    def test_audit_shows_approved_and_rejected(self, tmp_path):
        db = tmp_path / "audit.sqlite"
        store = ThreadSafeApprovalStore(db, deployment_epoch="audit-epoch", clock=lambda: NOW)
        authority = LocalApprovalAuthority(
            issuer_id="audit-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW
        )
        client = CoreClient(store=store, authority=authority)
        app = create_app(client)
        http = TestClient(app, raise_server_exceptions=False)

        dmint = make_dmint()

        # Create and approve one
        r1 = make_record(dmint, user_id=1)
        store.save_pending(r1)
        http.post(f"/approvals/{r1.approval_id}/approve")

        # Create and reject another
        r2 = make_record(dmint, user_id=2)
        store.save_pending(r2)
        http.post(f"/approvals/{r2.approval_id}/reject", data={"reason": "denied"})

        # Audit page should show both
        resp = http.get("/audit")
        assert resp.status_code == 200
        assert b"APPROVED" in resp.content
        assert b"REJECTED" in resp.content
        assert b"denied" in resp.content

        store.close()


class TestIntegrationConcurrency:
    def test_concurrent_approve_only_one_wins(self, tmp_path):
        """Two HTTP requests to approve the same approval — Core must be authoritative."""
        db = tmp_path / "concurrent.sqlite"
        store = ThreadSafeApprovalStore(db, deployment_epoch="concurrent-epoch", clock=lambda: NOW)
        authority = LocalApprovalAuthority(
            issuer_id="concurrent-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW
        )
        client = CoreClient(store=store, authority=authority)
        app = create_app(client)

        dmint = make_dmint()
        record = make_record(dmint, user_id=1)
        store.save_pending(record)

        results: list[int] = []
        barrier = threading.Barrier(2)

        def send_approve():
            c = TestClient(
                create_app(
                    CoreClient(
                        store=ThreadSafeApprovalStore(db, deployment_epoch="concurrent-epoch", clock=lambda: NOW),
                        authority=LocalApprovalAuthority(
                            issuer_id="concurrent-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW
                        ),
                    )
                ),
                raise_server_exceptions=False,
            )
            barrier.wait()
            r = c.post(f"/approvals/{record.approval_id}/approve", follow_redirects=True)
            results.append(r.status_code)

        t1 = threading.Thread(target=send_approve)
        t2 = threading.Thread(target=send_approve)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # Final state must be APPROVED (exactly once)
        final = store.get(record.approval_id)
        assert final.state == ApprovalState.APPROVED
        # Both HTTP responses should be 200 (one success flash, one conflict flash)
        assert all(s == 200 for s in results)

        store.close()

    def test_concurrent_approve_and_reject(self, tmp_path):
        """Approve and reject racing — Core picks one winner."""
        db = tmp_path / "race.sqlite"
        store = ThreadSafeApprovalStore(db, deployment_epoch="race-epoch", clock=lambda: NOW)

        dmint = make_dmint()
        record = make_record(dmint, user_id=2)
        store.save_pending(record)

        results: list[ApprovalState] = []

        def do_approve():
            s = ThreadSafeApprovalStore(db, deployment_epoch="race-epoch", clock=lambda: NOW)
            auth = LocalApprovalAuthority(issuer_id="race-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW)
            c = CoreClient(store=s, authority=auth)
            try:
                c.approve(record.approval_id)
                results.append(ApprovalState.APPROVED)
            except Exception:
                results.append(ApprovalState.REJECTED)
            finally:
                s.close()

        def do_reject():
            s = ThreadSafeApprovalStore(db, deployment_epoch="race-epoch", clock=lambda: NOW)
            auth = LocalApprovalAuthority(issuer_id="race-dashboard", audience="dmint/dashboard/v1", clock=lambda: NOW)
            c = CoreClient(store=s, authority=auth)
            try:
                c.reject(record.approval_id)
                results.append(ApprovalState.REJECTED)
            except Exception:
                results.append(ApprovalState.APPROVED)
            finally:
                s.close()

        t1 = threading.Thread(target=do_approve)
        t2 = threading.Thread(target=do_reject)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        final = store.get(record.approval_id)
        assert final.state in {ApprovalState.APPROVED, ApprovalState.REJECTED}

        store.close()
