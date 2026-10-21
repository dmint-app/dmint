"""Dashboard assertion handoff and approver-identity attribution regressions."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from dmint import ApprovalState, ApprovalVerifier, LocalApprovalAuthority
from dmint.core.verification import ApprovalAssertion
from dmint.dashboard.app import create_app
from dmint.dashboard.core_client import CoreClient, ThreadSafeApprovalStore
from dmint.errors import IllegalApprovalTransitionError

from tests.dashboard.conftest import NOW, make_dmint, make_record


def _client(tmp_path):
    store = ThreadSafeApprovalStore(
        tmp_path / "handoff.sqlite",
        deployment_epoch="handoff-epoch",
        clock=lambda: NOW,
    )
    authority = LocalApprovalAuthority(
        issuer_id="handoff-dashboard",
        audience="dmint/dashboard/v1",
        private_key=Ed25519PrivateKey.generate(),
        clock=lambda: NOW,
    )
    return store, authority, CoreClient(store=store, authority=authority, approver_id="handoff-human")


def test_approve_with_assertion_returns_verifiable_exact_request_credential(tmp_path) -> None:
    store, authority, client = _client(tmp_path)
    try:
        record = make_record(make_dmint(), user_id=77)
        store.save_pending(record)

        approved, assertion = client.approve_with_assertion(record.approval_id, approved_by="alice")

        assert approved.state is ApprovalState.APPROVED
        verifier = ApprovalVerifier(
            trusted_issuers={"handoff-dashboard": authority.public_key},
            audience="dmint/dashboard/v1",
            clock=lambda: NOW,
        )
        verified = verifier.verify(assertion, approved, now=NOW)
        assert verified.assertion.approval_id == record.approval_id
        assert verified.assertion.request_fingerprint == record.request_fingerprint
        assert verified.assertion.approver_subject_id == "alice"
        assert verified.assertion.approver_kind == "HUMAN"

        # A later download must preserve the recorded approver, not the
        # downloader/default dashboard identity.
        reissued = client.issue_assertion(record.approval_id)
        assert reissued.approver_subject_id == "alice"
        verifier.verify(reissued, approved, now=NOW)
    finally:
        store.close()


def test_issue_assertion_rejects_non_approved_records(tmp_path) -> None:
    store, _authority, client = _client(tmp_path)
    try:
        record = make_record(make_dmint(), user_id=78)
        store.save_pending(record)
        with pytest.raises(IllegalApprovalTransitionError):
            client.issue_assertion(record.approval_id)
    finally:
        store.close()


def test_dashboard_downloads_assertion_for_approved_record(tmp_path) -> None:
    store, authority, client = _client(tmp_path)
    try:
        app = create_app(
            client,
            auth_token="handoff-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        http = TestClient(app, raise_server_exceptions=False)
        http.headers["Origin"] = "http://testserver"
        http.post("/login", data={"token": "handoff-token", "identity": "alice"})
        session_id = http.cookies.get("dmint_session")
        assert session_id is not None
        http.headers["X-CSRF-Token"] = app.state.sessions[session_id]["csrf_token"]

        record = make_record(make_dmint(), user_id=79)
        store.save_pending(record)
        assert http.get(f"/approvals/{record.approval_id}/assertion").status_code == 409
        assert http.post(f"/approvals/{record.approval_id}/approve").status_code in (200, 303)

        response = http.get(f"/approvals/{record.approval_id}/assertion")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        assert "attachment" in response.headers["content-disposition"]
        assertion = ApprovalAssertion.from_bytes(response.content)
        approved = store.get(record.approval_id)
        assert approved is not None
        verifier = ApprovalVerifier(
            trusted_issuers={"handoff-dashboard": authority.public_key},
            audience="dmint/dashboard/v1",
            clock=lambda: NOW,
        )
        verifier.verify(assertion, approved, now=NOW)
    finally:
        store.close()


def test_trusted_proxy_header_overrides_self_asserted_login_identity(tmp_path) -> None:
    store, _authority, client = _client(tmp_path)
    try:
        app = create_app(
            client,
            auth_token="identity-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
            trusted_proxy=True,
            trusted_identity_header="X-Auth-User",
        )
        http = TestClient(app, raise_server_exceptions=False)
        http.headers["Origin"] = "http://testserver"
        http.headers["X-Auth-User"] = "alice@example.com"
        response = http.post(
            "/login",
            data={"token": "identity-token", "identity": "spoofed-form-value"},
        )
        assert response.status_code in (200, 303)
        session_id = http.cookies.get("dmint_session")
        assert session_id is not None
        session = app.state.sessions[session_id]
        assert session["identity"] == "alice@example.com"
        assert session["identity_source"] == "trusted_proxy"
        http.headers["X-CSRF-Token"] = session["csrf_token"]

        record = make_record(make_dmint(), user_id=80)
        store.save_pending(record)
        assert http.post(f"/approvals/{record.approval_id}/approve").status_code in (200, 303)
        approved = store.get(record.approval_id)
        assert approved is not None
        assert approved.decision_authority is not None
        assert approved.decision_authority.subject_id == "alice@example.com"
    finally:
        store.close()


def test_existing_session_missing_proxy_header_cannot_approve(tmp_path) -> None:
    store, _authority, client = _client(tmp_path)
    try:
        app = create_app(
            client,
            auth_token="revoked-header-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
            trusted_proxy=True,
            trusted_identity_header="X-Auth-User",
        )
        http = TestClient(app, raise_server_exceptions=False)
        http.headers["Origin"] = "http://testserver"
        http.headers["X-Auth-User"] = "alice@example.com"
        assert http.post("/login", data={"token": "revoked-header-token"}).status_code in (200, 303)
        session_id = http.cookies.get("dmint_session")
        assert session_id is not None
        csrf = app.state.sessions[session_id]["csrf_token"]
        http.headers["X-CSRF-Token"] = csrf

        record = make_record(make_dmint(), user_id=81)
        store.save_pending(record)
        del http.headers["X-Auth-User"]
        response = http.post(f"/approvals/{record.approval_id}/approve")
        assert response.status_code == 401
        assert response.json()["error"] == "trusted_identity_missing"
        assert store.get(record.approval_id).state is ApprovalState.PENDING
    finally:
        store.close()


def test_trusted_proxy_missing_header_fails_login_closed(tmp_path) -> None:
    store, _authority, client = _client(tmp_path)
    try:
        app = create_app(
            client,
            auth_token="missing-header-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
            trusted_proxy=True,
            trusted_identity_header="X-Auth-User",
        )
        http = TestClient(app, raise_server_exceptions=False)
        http.headers["Origin"] = "http://testserver"
        response = http.post(
            "/login",
            data={"token": "missing-header-token", "identity": "form-supplied-user"},
        )
        assert response.status_code == 401
        assert "Trusted identity header" in response.text
        assert http.cookies.get("dmint_session") is None
        assert app.state.sessions == {}
    finally:
        store.close()


def test_identity_header_requires_trusted_proxy_mode(tmp_path) -> None:
    store, _authority, client = _client(tmp_path)
    try:
        with pytest.raises(ValueError, match="trusted_proxy"):
            create_app(
                client,
                auth_token="misconfigured-token",
                allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
                trusted_identity_header="X-Auth-User",
            )
    finally:
        store.close()


def test_self_asserted_identity_is_labelled_in_session(tmp_path) -> None:
    store, _authority, client = _client(tmp_path)
    try:
        app = create_app(
            client,
            auth_token="label-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        http = TestClient(app, raise_server_exceptions=False)
        http.headers["Origin"] = "http://testserver"
        http.post("/login", data={"token": "label-token", "identity": "alice"})
        session_id = http.cookies.get("dmint_session")
        assert session_id is not None
        assert app.state.sessions[session_id]["identity_source"] == "self-asserted"
    finally:
        store.close()
