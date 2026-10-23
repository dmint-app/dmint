"""HTTP route tests for dmint-dashboard.

Uses Starlette TestClient against a real FastAPI app backed by a real
SQLiteApprovalStore.  No mocks — all Core behavior is live.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

from dmint import ApprovalState
from dmint.dashboard.routes import _redirect_to_approval
from dmint.errors import ApprovalExpiredError, ApprovalStoreError

from tests.dashboard.conftest import make_record, NOW


class TestHealth:
    def test_returns_200(self, test_client):
        resp = test_client.get("/health")
        assert resp.status_code == 200

    def test_returns_json_ok(self, test_client):
        resp = test_client.get("/health")
        body = resp.json()
        assert body["status"] == "ok"


class TestRedirectTargetSafety:
    @pytest.mark.parametrize(
        "approval_id",
        [
            "https://evil.example",
            "//evil.example",
            r"\\evil.example",
            r"/\evil.example",
            "..%2f..%2fevil.example",
            "apr_x?next=//evil.example",
        ],
    )
    def test_approval_redirect_stays_local(self, approval_id: str) -> None:
        response = _redirect_to_approval(approval_id, msg="test", msg_type="danger")
        location = response.headers["location"]
        parsed = urlsplit(location)

        assert response.status_code == 303
        assert parsed.scheme == ""
        assert parsed.netloc == ""
        assert parsed.path.startswith("/approvals/")
        assert parse_qs(parsed.query) == {"msg": ["test"], "msg_type": ["danger"]}


class TestApiDashboard:
    def test_returns_200(self, test_client):
        resp = test_client.get("/api/dashboard")
        assert resp.status_code == 200

    def test_valid_json_structure_empty(self, test_client):
        resp = test_client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "pending_count" in data
        assert "approved_count" in data
        assert "rejected_count" in data
        assert "pending" in data
        assert data["pending_count"] == 0
        assert data["approved_count"] == 0
        assert data["rejected_count"] == 0
        assert data["pending"] == []

    def test_store_error_details_not_exposed(self, test_client, client_obj, monkeypatch, caplog) -> None:
        secret = "/tmp/private-approval-store.sqlite: database is locked"

        def fail_list_pending(*args: object, **kwargs: object) -> None:
            raise ApprovalStoreError(secret)

        monkeypatch.setattr(client_obj, "list_pending", fail_list_pending)

        with caplog.at_level(logging.ERROR, logger="dmint_dashboard"):
            resp = test_client.get("/api/dashboard")

        assert resp.status_code == 200
        body = resp.json()
        assert body["error"] == "Approval store unavailable."
        assert body["pending_count"] == 0
        assert body["approved_count"] == 0
        assert body["rejected_count"] == 0
        assert body["pending"] == []
        assert secret not in resp.text
        assert secret in caplog.text

    def test_pending_data_returned_from_core(self, test_client, pending_record):
        resp = test_client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pending_count"] == 1
        assert len(data["pending"]) == 1
        item = data["pending"][0]
        assert item["approval_id"] == pending_record.approval_id
        assert item["agent_id"] == pending_record.request.agent_id
        assert item["tool"] == pending_record.request.tool
        assert item["action"] == pending_record.request.action
        assert item["resource"] == "users/42"
        assert item["state"] == "PENDING"
        assert "created_at" in item
        assert "expires_at" in item

    def test_counts_accurate_after_decisions(self, test_client, store, client_obj, pending_record, dmint_inst):
        # Initial: 1 pending
        resp = test_client.get("/api/dashboard")
        data = resp.json()
        assert data["pending_count"] == 1
        assert data["approved_count"] == 0

        # Approve pending_record
        client_obj.approve(pending_record.approval_id)
        resp2 = test_client.get("/api/dashboard")
        data2 = resp2.json()
        assert data2["pending_count"] == 0
        assert data2["approved_count"] == 1
        assert data2["rejected_count"] == 0
        assert data2["pending"] == []

        # Add another record and reject it
        rec2 = make_record(dmint_inst, user_id=99)
        store.save_pending(rec2)
        client_obj.reject(rec2.approval_id, reason="denied")
        resp3 = test_client.get("/api/dashboard")
        data3 = resp3.json()
        assert data3["pending_count"] == 0
        assert data3["approved_count"] == 1
        assert data3["rejected_count"] == 1

    def test_expired_records_excluded_from_api_pending(self, test_client, store, dmint_inst):
        rec = make_record(dmint_inst, user_id=77)
        store.save_pending(rec)
        # Advance clock by 1 hour past expiration
        store._clock = lambda: NOW + timedelta(hours=1)
        resp = test_client.get("/api/dashboard")
        data = resp.json()
        assert data["pending_count"] == 0
        assert data["pending"] == []


class TestIndex:
    def test_returns_200(self, test_client):
        resp = test_client.get("/")
        assert resp.status_code == 200

    def test_store_error_details_not_exposed(self, test_client, client_obj, monkeypatch, caplog) -> None:
        secret = "/tmp/private-approval-store.sqlite: database is locked"

        def fail_list_pending(*args: object, **kwargs: object) -> None:
            raise ApprovalStoreError(secret)

        monkeypatch.setattr(client_obj, "list_pending", fail_list_pending)

        with caplog.at_level(logging.ERROR, logger="dmint_dashboard"):
            resp = test_client.get("/")

        assert resp.status_code == 200
        assert b"Approval Store Error" in resp.content
        assert secret.encode() not in resp.content
        assert secret in caplog.text

    def test_shows_no_pending_message_when_empty(self, test_client):
        resp = test_client.get("/")
        assert resp.status_code == 200
        assert b"Queue is clear" in resp.content

    def test_shows_pending_records(self, test_client, pending_record):
        resp = test_client.get("/")
        assert resp.status_code == 200
        # Agent ID and tool should appear in the table
        assert pending_record.request.agent_id.encode() in resp.content

    def test_shows_pending_count(self, test_client, pending_record):
        resp = test_client.get("/")
        assert resp.status_code == 200
        # Should render a stat card with count
        assert b"Pending" in resp.content

    def test_review_link_present(self, test_client, pending_record):
        resp = test_client.get("/")
        assert pending_record.approval_id[:20].encode() in resp.content or b"Review" in resp.content


class TestApprovalDetail:
    def test_returns_200_for_existing_record(self, test_client, pending_record):
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert resp.status_code == 200

    def test_shows_agent_id(self, test_client, pending_record):
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert pending_record.request.agent_id.encode() in resp.content

    def test_shows_tool_and_action(self, test_client, pending_record):
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert pending_record.request.tool.encode() in resp.content
        assert pending_record.request.action.encode() in resp.content

    def test_shows_approval_id(self, test_client, pending_record):
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert pending_record.approval_id.encode() in resp.content

    def test_shows_approve_and_reject_buttons_for_pending(self, test_client, pending_record):
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert b"Approve" in resp.content
        assert b"Reject" in resp.content

    def test_not_found_returns_error_page(self, test_client):
        resp = test_client.get("/approvals/apr_" + "z" * 43)
        assert resp.status_code == 200  # error page renders with 200
        assert b"not found" in resp.content.lower()

    def test_invalid_id_returns_error_page(self, test_client):
        resp = test_client.get("/approvals/invalid-id")
        assert b"not found" in resp.content.lower() or b"error" in resp.content.lower()

    def test_approved_record_shows_no_approve_buttons(self, test_client, store, client_obj, pending_record):
        client_obj.approve(pending_record.approval_id)
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert resp.status_code == 200
        assert b"APPROVED" in resp.content

    def test_rejected_record_shows_state(self, test_client, client_obj, pending_record):
        client_obj.reject(pending_record.approval_id, reason="not allowed")
        resp = test_client.get(f"/approvals/{pending_record.approval_id}")
        assert b"REJECTED" in resp.content
        assert b"not allowed" in resp.content

    def test_nested_dict_and_list_arguments_rendered_cleanly(self, test_client, store):
        from dmint.approvals import ApprovalRecord, new_request_id
        from dmint.models import NO_RESOURCE, ToolRequest, TrustedContext
        from tests.dashboard.conftest import make_provenance

        req = ToolRequest(
            request_id=new_request_id(),
            tool="nested_tool",
            action="execute",
            agent_id="test-agent",
            resource=NO_RESOURCE,
            arguments={
                "config": {
                    "debug": True,
                    "endpoints": ["https://api.internal/v1", "https://api.internal/v2"],
                },
                "items": [{"id": 1, "name": "item1"}],
            },
            context=TrustedContext({}),
        )
        record = ApprovalRecord.create(
            request=req,
            integration_id="test-runtime",
            capability_id="test.execute",
            policy_provenance=make_provenance(NOW),
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )
        store.save_pending(record)

        resp = test_client.get(f"/approvals/{record.approval_id}")
        assert resp.status_code == 200
        assert b"(could not render)" not in resp.content
        assert b"endpoints" in resp.content
        assert b"https://api.internal/v1" in resp.content
        assert b"item1" in resp.content

    def test_xss_payloads_in_keys_and_values_rendered_escaped(self, test_client, store):
        from dmint.approvals import ApprovalRecord, new_request_id
        from dmint.models import NO_RESOURCE, ToolRequest, TrustedContext
        from tests.dashboard.conftest import make_provenance

        xss_args = {
            "<script>alert('xss_key')</script>": "<script>alert('xss_val')</script>",
            "<img src=x onerror=alert('img_key')>": "<img src=x onerror=alert('img_val')>",
        }
        req = ToolRequest(
            request_id=new_request_id(),
            tool="xss_tool",
            action="execute",
            agent_id="test-agent",
            resource=NO_RESOURCE,
            arguments=xss_args,
            context=TrustedContext({}),
        )
        record = ApprovalRecord.create(
            request=req,
            integration_id="test-runtime",
            capability_id="test.execute",
            policy_provenance=make_provenance(NOW),
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )
        store.save_pending(record)

        resp = test_client.get(f"/approvals/{record.approval_id}")
        assert resp.status_code == 200
        assert b"(could not render)" not in resp.content
        # Ensure executable raw script/img tags are NOT present in HTML
        assert b"<script>alert('xss_key')</script>" not in resp.content
        assert b"<script>alert('xss_val')</script>" not in resp.content
        assert b"<img src=x onerror=alert('img_key')>" not in resp.content
        assert b"<img src=x onerror=alert('img_val')>" not in resp.content
        # Ensure HTML-escaped entities are present in HTML
        assert "&lt;script&gt;" in resp.text
        assert "&lt;img" in resp.text


class TestApprove:
    def test_approve_redirects_on_success(self, test_client, pending_record):
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            follow_redirects=False,
        )
        # Should be a redirect (303)
        assert resp.status_code == 303

    def test_approve_redirect_is_local(self, test_client, pending_record):
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            follow_redirects=False,
        )
        parsed = urlsplit(resp.headers["location"])

        assert parsed.scheme == ""
        assert parsed.netloc == ""
        assert parsed.path == f"/approvals/{pending_record.approval_id}"

    def test_approve_sets_core_state_to_approved(self, test_client, store, pending_record):
        test_client.post(f"/approvals/{pending_record.approval_id}/approve")
        loaded = store.get(pending_record.approval_id)
        assert loaded.state == ApprovalState.APPROVED

    def test_approve_success_flash_message(self, test_client, pending_record):
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            follow_redirects=True,
        )
        assert b"approved" in resp.content.lower() or b"success" in resp.content.lower()

    def test_approve_nonexistent_shows_error(self, test_client):
        resp = test_client.post(
            "/approvals/apr_" + "x" * 43 + "/approve",
            follow_redirects=True,
        )
        assert b"not found" in resp.content.lower()

    def test_double_approve_shows_conflict_message(self, test_client, pending_record):
        test_client.post(f"/approvals/{pending_record.approval_id}/approve")
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            follow_redirects=True,
        )
        # Should show some kind of error/warning
        assert (
            b"pending" in resp.content.lower()
            or b"concurrent" in resp.content.lower()
            or b"already" in resp.content.lower()
        )

    def test_approve_already_rejected_shows_error(self, test_client, client_obj, pending_record):
        client_obj.reject(pending_record.approval_id)
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_approve_with_clock_skew_shows_guided_error_not_500(self, test_client, store):
        """Backward clock skew at assertion issuance yields a guided redirect, never HTTP 500 (SRC-12)."""
        from dmint.approvals import ApprovalRecord, new_request_id
        from dmint.models import NO_RESOURCE, ToolRequest, TrustedContext
        from tests.dashboard.conftest import make_provenance

        # The policy-evaluation host clock is one hour ahead of this host's clock
        # (multi-host skew), so assertion issuance sees policy_evaluated_at > issued_at.
        req = ToolRequest(
            request_id=new_request_id(),
            tool="skew_tool",
            action="execute",
            agent_id="test-agent",
            resource=NO_RESOURCE,
            arguments={},
            context=TrustedContext({}),
        )
        record = ApprovalRecord.create(
            request=req,
            integration_id="test-runtime",
            capability_id="test.execute",
            policy_provenance=make_provenance(NOW + timedelta(hours=1)),
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )
        store.save_pending(record)

        resp = test_client.post(
            f"/approvals/{record.approval_id}/approve",
            follow_redirects=False,
        )

        # Clean redirect with an actionable message — not HTTP 500.
        assert resp.status_code == 303
        assert "clock" in resp.headers["location"].lower()

        # Fail closed: the record must remain PENDING (no state transition).
        assert store.get(record.approval_id).state == ApprovalState.PENDING

        # The follow-up page must render the guidance.
        followed = test_client.get(resp.headers["location"])
        assert followed.status_code == 200
        assert b"clock" in followed.content.lower()


class TestReject:
    def test_reject_redirects_on_success(self, test_client, pending_record):
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_reject_redirect_is_local(self, test_client, pending_record):
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": ""},
            follow_redirects=False,
        )
        parsed = urlsplit(resp.headers["location"])

        assert parsed.scheme == ""
        assert parsed.netloc == ""
        assert parsed.path == f"/approvals/{pending_record.approval_id}"

    def test_reject_sets_core_state_to_rejected(self, test_client, store, pending_record):
        test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": ""},
        )
        loaded = store.get(pending_record.approval_id)
        assert loaded.state == ApprovalState.REJECTED

    def test_reject_with_reason_stored_in_core(self, test_client, store, pending_record):
        test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": "scope too broad"},
        )
        loaded = store.get(pending_record.approval_id)
        assert loaded.state_reason == "scope too broad"

    def test_reject_success_flash_message(self, test_client, pending_record):
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": ""},
            follow_redirects=True,
        )
        assert b"rejected" in resp.content.lower()

    def test_reject_nonexistent_shows_error(self, test_client):
        resp = test_client.post(
            "/approvals/apr_" + "y" * 43 + "/reject",
            data={"reason": ""},
            follow_redirects=True,
        )
        assert b"not found" in resp.content.lower()

    def test_double_reject_shows_conflict_message(self, test_client, pending_record):
        test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": ""},
        )
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": "again"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_reject_already_approved_shows_error(self, test_client, client_obj, pending_record):
        client_obj.approve(pending_record.approval_id)
        resp = test_client.post(
            f"/approvals/{pending_record.approval_id}/reject",
            data={"reason": ""},
            follow_redirects=True,
        )
        assert resp.status_code == 200


class TestAudit:
    def test_returns_200(self, test_client):
        resp = test_client.get("/audit")
        assert resp.status_code == 200

    def test_shows_approved_records(self, test_client, client_obj, pending_record):
        client_obj.approve(pending_record.approval_id)
        resp = test_client.get("/audit")
        assert b"APPROVED" in resp.content

    def test_shows_rejected_records(self, test_client, client_obj, pending_record):
        client_obj.reject(pending_record.approval_id)
        resp = test_client.get("/audit")
        assert b"REJECTED" in resp.content

    def test_state_filter_query_param(self, test_client, client_obj, pending_record):
        client_obj.approve(pending_record.approval_id)
        resp = test_client.get("/audit?state=APPROVED")
        assert resp.status_code == 200
        assert b"APPROVED" in resp.content

    def test_invalid_state_filter_shows_all(self, test_client):
        resp = test_client.get("/audit?state=INVALID_STATE")
        assert resp.status_code == 200

    def test_empty_store_shows_no_records(self, test_client):
        resp = test_client.get("/audit")
        assert resp.status_code == 200
        assert b"No records found" in resp.content


class TestExpiredApproval:
    def test_approve_expired_shows_expired_message(self, test_client, store, dmint_inst, authority):
        from tests.dashboard.conftest import make_record, NOW

        record = make_record(dmint_inst, user_id=99)
        store.save_pending(record)
        # Make store think it's expired
        store._clock = lambda: NOW + timedelta(hours=1)
        resp = test_client.post(
            f"/approvals/{record.approval_id}/approve",
            follow_redirects=True,
        )
        assert b"expired" in resp.content.lower()
