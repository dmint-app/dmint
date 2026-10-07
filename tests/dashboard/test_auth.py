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
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

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
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/login")

    def test_unauthenticated_api_returns_401(self, client_obj) -> None:
        """Unauthenticated API requests must return HTTP 401 JSON error."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/dashboard", follow_redirects=False)
        assert resp.status_code == 401
        assert resp.json().get("error") == "unauthorized"

    def test_missing_csrf_rejected(self, client_obj, pending_record) -> None:
        """Authenticated POST without a CSRF token must be rejected with HTTP 403."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

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
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)

        # Log in
        client.headers["Origin"] = "http://testserver"
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
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/login", headers={"Host": "attacker-dns-rebind.com"})
        assert resp.status_code == 400
        assert "Host header" in resp.text

    def test_valid_flow_works(self, client_obj, pending_record) -> None:
        """Complete valid flow: unauthenticated redirect -> login -> CSRF retrieval -> approved with session identity."""
        app = create_app(
            client_obj,
            auth_token="my-valid-passphrase",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

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
            main(["--host", "0.0.0.0", "--db-path", "/dev/null", "--approver-id", "test-approver"])
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
        key_file = tmp_path / "signing.key"
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from dmint.core.keys import write_private_key_atomic

        write_private_key_atomic(key_file, Ed25519PrivateKey.generate())

        main(
            [
                "--host",
                "0.0.0.0",
                "--allow-public-bind",
                "--db-path",
                str(db_file),
                "--approver-id",
                "test-approver",
                "--key-file",
                str(key_file),
            ]
        )
        assert run_called is True

    def test_bind_non_loopback_ip_refused_without_flag(self) -> None:
        """CLI main must refuse any non-loopback IP (e.g. 192.168.1.5) without --allow-public-bind."""
        from dmint.dashboard.__main__ import main

        with pytest.raises(SystemExit) as exc:
            main(["--host", "192.168.1.5", "--db-path", "/dev/null", "--approver-id", "test-approver"])
        assert exc.value.code != 0

    def test_approver_id_required_in_cli(self) -> None:
        """CLI main must refuse to start without --approver-id or DMINT_APPROVER_ID."""
        from dmint.dashboard.__main__ import main

        with pytest.raises(SystemExit) as exc:
            main(["--host", "127.0.0.1", "--db-path", "/dev/null"])
        assert exc.value.code != 0

    def test_post_missing_origin_and_referer_rejected(self, client_obj, pending_record) -> None:
        """State-changing POST with BOTH Origin and Referer missing must be rejected (403)."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        # Login with Origin set
        client.headers["Origin"] = "http://testserver"
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})
        session_id = client.cookies.get("dmint_session")
        assert session_id is not None
        csrf_token = app.state.sessions[session_id]["csrf_token"]

        # Now remove Origin and Referer
        del client.headers["Origin"]
        if "Referer" in client.headers:
            del client.headers["Referer"]

        resp = client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert resp.json().get("error") == "missing_origin_referer"

    def test_token_file_permissions(self, tmp_path) -> None:
        """Token file requires 0600 (or 0400) permissions on POSIX systems; looser permissions rejected."""
        import os
        from dmint.dashboard.auth import InsecureTokenFileError, load_token_from_file

        token_file = tmp_path / "secret.token"
        token_file.write_text("my-file-token\n", encoding="utf-8")

        # 0600: must succeed
        token_file.chmod(0o600)
        assert load_token_from_file(token_file) == "my-file-token"

        if os.name == "posix":
            # 0644 (world readable): must raise InsecureTokenFileError
            token_file.chmod(0o644)
            with pytest.raises(InsecureTokenFileError):
                load_token_from_file(token_file)

            # 0777 (world read/write/exec): must raise InsecureTokenFileError
            token_file.chmod(0o777)
            with pytest.raises(InsecureTokenFileError):
                load_token_from_file(token_file)

    def test_login_rate_limiting(self, client_obj) -> None:
        """Login rate limiting triggers HTTP 429 after 5 failed login attempts."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

        for _ in range(5):
            r = client.post("/login", data={"token": "wrong-token"})
            assert r.status_code == 401

        # 6th attempt should be rate limited (429)
        r6 = client.post("/login", data={"token": "wrong-token"})
        assert r6.status_code == 429
        assert "Too many failed login attempts" in r6.text

    def test_session_regeneration_and_expiry(self, client_obj) -> None:
        """Session ID is regenerated on login, and expired sessions are rejected."""
        import time

        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

        # Login 1
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})
        s1 = client.cookies.get("dmint_session")
        assert s1 is not None

        # Login 2: session ID must be regenerated
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})
        s2 = client.cookies.get("dmint_session")
        assert s2 is not None
        assert s1 != s2
        assert s1 not in app.state.sessions

        # Expire session artificially
        app.state.sessions[s2]["expires_at"] = time.time() - 10
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]

    def test_security_headers_present(self, client_obj) -> None:
        """All HTTP responses must carry X-Frame-Options, CSP, and Cache-Control headers."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/login")
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'none'"
        assert resp.headers["Cache-Control"] == "no-store"

    def test_csrf_on_logout(self, client_obj) -> None:
        """POST /logout without valid CSRF token is rejected with 403."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

        # Login
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})
        session_id = client.cookies.get("dmint_session")
        assert session_id in app.state.sessions

        # Logout with missing CSRF
        resp = client.post("/logout", data={}, follow_redirects=False)
        assert resp.status_code == 403

        # Logout with valid CSRF
        valid_csrf = app.state.sessions[session_id]["csrf_token"]
        resp_valid = client.post("/logout", data={"csrf_token": valid_csrf}, follow_redirects=False)
        assert resp_valid.status_code == 303
        assert session_id not in app.state.sessions

    def test_cross_port_origin_rejected(self, client_obj, pending_record) -> None:
        """Origin on port 3000 must be rejected when dashboard is on port 8080 (full origin matching)."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Host"] = "localhost:8080"
        client.headers["Origin"] = "http://localhost:8080"

        # Log in
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})
        session_id = client.cookies.get("dmint_session")
        assert session_id is not None
        csrf_token = app.state.sessions[session_id]["csrf_token"]

        # POST with origin http://localhost:3000 (different port)
        client.headers["Origin"] = "http://localhost:3000"
        resp = client.post(
            f"/approvals/{pending_record.approval_id}/approve",
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert resp.json().get("error") == "invalid_origin"

    def test_bearer_auth_host_validation_enforced(self, client_obj) -> None:
        """Host validation must be enforced on Bearer-authenticated requests too."""
        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]"},
        )
        client = TestClient(app, raise_server_exceptions=False)

        # Valid Bearer token but malicious Host header
        resp = client.get(
            "/api/dashboard",
            headers={
                "Authorization": "Bearer super-secret-token",
                "Host": "attacker-dns-rebind.com",
            },
        )
        assert resp.status_code == 400
        assert "Host header" in resp.text

    def test_trusted_proxy_setting_behavior(self, client_obj) -> None:
        """X-Forwarded-Proto is ignored by default unless trusted_proxy is explicitly enabled."""
        # 1. Default (trusted_proxy=False) -> cookie secure is False over http even with x-forwarded-proto: https
        app_default = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
            trusted_proxy=False,
        )
        c1 = TestClient(app_default, raise_server_exceptions=False)
        c1.headers["Origin"] = "http://testserver"
        c1.headers["X-Forwarded-Proto"] = "https"
        r1 = c1.post("/login", data={"token": "super-secret-token"}, follow_redirects=False)
        cookie1 = r1.headers.get("set-cookie", "")
        assert "secure" not in cookie1.lower()

        # 2. With trusted_proxy=True -> cookie secure is True when x-forwarded-proto: https
        app_trusted = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
            trusted_proxy=True,
        )
        c2 = TestClient(app_trusted, raise_server_exceptions=False)
        c2.headers["Origin"] = "https://testserver"
        c2.headers["X-Forwarded-Proto"] = "https"
        r2 = c2.post("/login", data={"token": "super-secret-token"}, follow_redirects=False)
        cookie2 = r2.headers.get("set-cookie", "")
        assert "secure" in cookie2.lower()

    def test_idle_session_timeout(self, client_obj) -> None:
        """Sessions inactive for more than 30 minutes must be expired."""
        import time

        app = create_app(
            client_obj,
            auth_token="super-secret-token",
            allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = "http://testserver"

        # Login
        client.post("/login", data={"token": "super-secret-token", "identity": "alice"})
        s_id = client.cookies.get("dmint_session")
        assert s_id in app.state.sessions

        # Advance last_active past 30 minutes (e.g. 31 minutes ago)
        app.state.sessions[s_id]["last_active"] = time.time() - (31 * 60)

        # Attempt to access dashboard
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]
        assert s_id not in app.state.sessions
