"""Security and authentication tests for Dmint Dashboard (Phase 2 hardening).

Verifies:
- Unauthenticated requests are rejected or redirected to login
- CSRF validation is strictly enforced on all state-changing POST requests
- Host header validation blocks DNS rebinding attacks
- Origin and Referer validation blocks cross-origin state changes
- `approved_by` is bound to the authenticated session identity
- Cookies are HttpOnly and SameSite=Strict
- CLI rejects binding to 0.0.0.0 without explicit permission flag
"""

from __future__ import annotations

import re
import pytest
from starlette.testclient import TestClient

from dmint import ApprovalState
from dmint.dashboard.app import create_app
from dmint.dashboard.core_client import CoreClient


class TestDashboardAuthenticationAndSecurity:
    """Rigorous security test suite for Dashboard authentication, CSRF, and DNS rebinding."""

    def test_unauthenticated_approve_rejected(self, client_obj, pending_record) -> None:
        """Unauthenticated POST to approve must be rejected immediately."""
        app = create_app(client_obj, auth_token="super-secret-token")
        client = TestClient(app, raise_server_exceptions=False)

        # Attempt to approve without any session cookie or credentials
        resp = client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            data={"csrf_token": "any"},
            follow_redirects=False,
        )
        # Must be rejected (redirected to login or 401)
        assert resp.status_code in (303, 401)
        if resp.status_code == 303:
            assert "/login" in resp.headers.get("location", "")

        # Verify the pending record in the approval store remains untouched (PENDING)
        current = client_obj.get_approval(pending_record.approval_id)
        assert current is not None
        assert current.state == ApprovalState.PENDING

    def test_unauthenticated_page_redirects_to_login(self, client_obj) -> None:
        """Unauthenticated browser navigation must redirect to /login."""
        app = create_app(client_obj, auth_token="super-secret-token")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/login")

    def test_unauthenticated_api_returns_401(self, client_obj) -> None:
        """Unauthenticated API requests must return HTTP 401 JSON error."""
        app = create_app(client_obj, auth_token="super-secret-token")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/dashboard", follow_redirects=False)
        assert resp.status_code == 401
        assert resp.json().get("error") == "unauthorized"

    def test_missing_csrf_rejected(self, client_obj, pending_record) -> None:
        """Authenticated POST without a CSRF token must be rejected with HTTP 403."""
        app = create_app(client_obj, auth_token="super-secret-token")
        client = TestClient(app, raise_server_exceptions=False)

        # 1. Log in successfully
        login_resp = client.post(
            "/login",
            data={"token": "super-secret-token", "identity": "alice"},
            follow_redirects=False,
        )
        assert login_resp.status_code == 303

        # 2. Attempt approve without CSRF token
        approve_resp = client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            data={},  # No CSRF token
            follow_redirects=False,
        )
        assert approve_resp.status_code == 403
        assert "csrf" in approve_resp.text.lower()

        # Approval store record must remain PENDING
        current = client_obj.get_approval(pending_record.approval_id)
        assert current is not None
        assert current.state == ApprovalState.PENDING

    def test_wrong_origin_rejected(self, client_obj, pending_record) -> None:
        """State-changing POST with an untrusted Origin header must be rejected with HTTP 403."""
        app = create_app(client_obj, auth_token="super-secret-token")
        client = TestClient(app, raise_server_exceptions=False)

        # Log in
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})

        # Get CSRF token from app session
        session_id = client.cookies.get("dmint_session")
        assert session_id is not None
        csrf_token = app.state.sessions[session_id]["csrf_token"]

        # Attempt approve with malicious origin
        resp = client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            data={"csrf_token": csrf_token},
            headers={"Origin": "https://malicious-attacker.com"},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert "origin" in resp.text.lower()

        # Record remains PENDING
        current = client_obj.get_approval(pending_record.approval_id)
        assert current is not None
        assert current.state == ApprovalState.PENDING

    def test_wrong_host_rejected(self, client_obj) -> None:
        """Requests with an untrusted Host header must be rejected with HTTP 400 (DNS rebinding defense)."""
        app = create_app(client_obj, auth_token="super-secret-token")
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/login", headers={"Host": "attacker-dns-rebind.com"})
        assert resp.status_code == 400
        assert "Host header" in resp.text

    def test_valid_flow_works(self, client_obj, pending_record) -> None:
        """Complete valid flow: unauthenticated redirect -> login -> CSRF retrieval -> approved with session identity."""
        app = create_app(client_obj, auth_token="my-valid-passphrase")
        client = TestClient(app, raise_server_exceptions=False)

        # 1. Unauthenticated root redirects to /login
        r1 = client.get("/", follow_redirects=False)
        assert r1.status_code == 303
        assert "/login" in r1.headers["location"]

        # 2. Login with valid token and custom approver identity
        r2 = client.post(
            "/login",
            data={"token": "my-valid-passphrase", "identity": "secops-auditor"},
            follow_redirects=False,
        )
        assert r2.status_code == 303
        assert "dmint_session" in client.cookies

        # Verify cookie attributes
        set_cookie_header = r2.headers.get("set-cookie", "").lower()
        assert "httponly" in set_cookie_header
        assert "samesite=strict" in set_cookie_header

        # 3. Access approval detail page and extract CSRF token from the rendered HTML form
        detail_resp = client.get(f"/approvals/{pending_record.approval_id}")
        assert detail_resp.status_code == 200
        html = detail_resp.text

        match = re.search(r'<input\s+type="hidden"\s+name="csrf_token"\s+value="([^"]+)"', html)
        assert match is not None, "CSRF token input field not found in approval HTML"
        csrf_token = match.group(1)

        # 4. Perform POST approve with valid session, valid CSRF token, and valid host
        approve_resp = client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert approve_resp.status_code == 303

        # 5. Verify Core storage transition and exact approved_by identity
        updated = client_obj.get_approval(pending_record.approval_id)
        assert updated is not None
        assert updated.state == ApprovalState.APPROVED
        assert updated.decision_authority is not None
        assert updated.decision_authority.subject_id == "secops-auditor"

    def test_bind_0000_refused_without_flag(self) -> None:
        """CLI main must refuse to bind to 0.0.0.0 unless --allow-public-bind is passed."""
        from dmint.dashboard.__main__ import main

        with pytest.raises(SystemExit) as exc:
            main(["--host", "0.0.0.0", "--db-path", "/dev/null"])
        assert exc.value.code != 0

    def test_bind_0000_allowed_with_flag(self, monkeypatch, tmp_path) -> None:
        """CLI main accepts 0.0.0.0 when --allow-public-bind flag is provided."""
        import uvicorn
        from dmint.dashboard.__main__ import main

        run_called = False

        def fake_run(app, host, port, **kwargs):
            nonlocal run_called
            run_called = True
            assert host == "0.0.0.0"

        monkeypatch.setattr(uvicorn, "run", fake_run)
        db_file = tmp_path / "test.sqlite"

        main(["--host", "0.0.0.0", "--allow-public-bind", "--db-path", str(db_file)])
        assert run_called is True
