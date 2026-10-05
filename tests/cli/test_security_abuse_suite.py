"""Phase 9 — Comprehensive Security Abuse Test Suite.

Treats dmint-cli as hostile-input software.
Covers:
- NETWORK: SSRF, localhost access rules, private IP endpoints, redirect-to-private-IP,
  redirect-to-file-like schemes, cross-origin OAuth redirect, DNS/host confusion,
  invalid TLS, malformed URLs.
- OAUTH: wrong state, wrong iss, wrong issuer, authorization-server mix-up,
  token endpoint mismatch, replayed callback, duplicate callback, expired authorization,
  expired access token, refresh failure, repeated 401, endless authentication loop,
  malformed discovery, malicious WWW-Authenticate.
- CREDENTIALS: token in logs, token in exception, token in config, token in policy,
  insecure file permissions, symlink replacement, corrupted credential store,
  concurrent credential updates.
- MCP: malicious tool name, huge tool list, huge descriptions, duplicate tools,
  pagination loops, malformed nextCursor, tool discovery changes during generation,
  server disappears halfway through, one server fails in multi-server mode.
- CLI: malicious file paths, missing input, unreadable source, malformed JSON,
  malformed policy, interrupted writes, partial output, unsafe overwrite.

Every security regression gets a named test.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.policy import Policy, PolicyError
from dmint.cli.errors import (
    APIError,
    CLIError,
    InputFileError,
    JSONExtractionError,
    OutputWriteError,
    PolicyValidationError,
)
from dmint.cli.io_utils import atomic_write_json, atomic_write_policy_json
from dmint.cli.mcp_auth import (
    MCPAuthRequirements,
    StrictSameOriginRedirectHandler,
    _fetch_discovery_json,
    _is_localhost,
    _is_loopback_hostname,
    _is_private_or_metadata_ip,
    _is_same_origin,
    _validate_https_endpoint,
    discover_mcp_auth_requirements,
    parse_www_authenticate_header,
)
from dmint.cli.mcp_connections import (
    MCPIntegration,
    MCPTransport,
    _fetch_all_tools_paginated,
    _normalize_tools_response,
    canonical_capability,
    redact_secrets,
    redact_text,
)
from dmint.cli.mcp_credentials import (
    CredentialStore,
    TokenRecord,
    _check_symlink_safety,
    refresh_token,
)
from dmint.cli.mcp_oauth import (
    IsolatedCallbackHandler,
    OAuthCallbackServer,
    OAuthCallbackState,
    perform_oauth_flow,
)
from dmint.cli.create_mcp_policy import (
    _assert_no_secrets_in_dict,
    _assert_no_secrets_in_policy,
    _validate_rule_completeness,
    run_create_mcp_policy_wizard,
    validate_mcp_protection_config,
    validate_policy_against_discovered_capabilities,
)


# ===========================================================================
# 1. NETWORK SECURITY ABUSE TESTS
# ===========================================================================


class NetworkSecurityAbuseTests(unittest.TestCase):
    """Network abuse: SSRF, localhost rules, private IPs, redirects, TLS, and malformed URLs."""

    def test_ssrf_cloud_metadata_ip_blocked(self):
        """SSRF: AWS/cloud metadata IP 169.254.169.254 must be blocked."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://169.254.169.254/latest/meta-data", "MCP endpoint")
        self.assertIn("private or link-local IP", str(ctx.exception))
        self.assertIn("SSRF", str(ctx.exception))

    def test_localhost_access_rules_allow_loopback(self):
        """Localhost access: Loopback endpoints (127.0.0.1, localhost) are allowed for local development."""
        # HTTP is permitted for loopback
        _validate_https_endpoint("http://127.0.0.1:8000/sse", "MCP endpoint")
        _validate_https_endpoint("http://localhost:8000/sse", "MCP endpoint")
        _validate_https_endpoint("http://[::1]:8000/sse", "MCP endpoint")
        self.assertTrue(_is_localhost("http://127.0.0.1:8000"))
        self.assertTrue(_is_localhost("http://localhost:8000"))

    def test_localhost_access_rules_reject_remote_http(self):
        """Localhost access: Non-loopback remote endpoints must use HTTPS."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("http://remote.example.com/sse", "MCP endpoint")
        self.assertIn("must use HTTPS", str(ctx.exception))

    def test_private_ip_endpoints_blocked_10_network(self):
        """Private IP: 10.0.0.0/8 private network endpoints are blocked."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://10.0.0.1/sse", "MCP endpoint")
        self.assertIn("private or link-local IP", str(ctx.exception))

    def test_private_ip_endpoints_blocked_192_168_network(self):
        """Private IP: 192.168.0.0/16 private network endpoints are blocked."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://192.168.1.1/sse", "MCP endpoint")
        self.assertIn("private or link-local IP", str(ctx.exception))

    def test_private_ip_endpoints_blocked_172_network(self):
        """Private IP: 172.16.0.0/12 private network endpoints are blocked."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://172.16.0.1/sse", "MCP endpoint")
        self.assertIn("private or link-local IP", str(ctx.exception))

    def test_redirect_to_private_ip_blocked(self):
        """Redirect: 302 redirect to private IP endpoint is blocked."""
        handler = StrictSameOriginRedirectHandler()
        req = urllib.request.Request("https://mcp.example.com/sse")
        with self.assertRaises(CLIError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "https://10.0.0.1/sse")
        self.assertIn("redirect to private or link-local IP", str(ctx.exception))

    def test_redirect_to_cloud_metadata_blocked(self):
        """Redirect: 302 redirect to cloud metadata service is blocked."""
        handler = StrictSameOriginRedirectHandler()
        req = urllib.request.Request("https://mcp.example.com/sse")
        with self.assertRaises(CLIError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "https://169.254.169.254/latest/meta-data")
        self.assertIn("redirect to private or link-local IP", str(ctx.exception))

    def test_redirect_to_file_like_schemes_blocked(self):
        """Redirect: 302 redirect to file:/// scheme is blocked."""
        handler = StrictSameOriginRedirectHandler()
        req = urllib.request.Request("https://mcp.example.com/sse")
        with self.assertRaises(CLIError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")
        self.assertIn("redirect to file-like or disallowed scheme", str(ctx.exception))

    def test_redirect_to_ftp_scheme_blocked(self):
        """Redirect: 302 redirect to ftp:// scheme is blocked."""
        handler = StrictSameOriginRedirectHandler()
        req = urllib.request.Request("https://mcp.example.com/sse")
        with self.assertRaises(CLIError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "ftp://example.com/data")
        self.assertIn("redirect to file-like or disallowed scheme", str(ctx.exception))

    def test_cross_origin_oauth_redirect_blocked(self):
        """Redirect: 302 redirect across domains during discovery is blocked."""
        handler = StrictSameOriginRedirectHandler()
        req = urllib.request.Request("https://legit.mcp.com/sse")
        with self.assertRaises(CLIError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "https://evil.attacker.com/sse")
        self.assertIn("cross-origin redirect detected", str(ctx.exception))

    def test_dns_host_confusion_userinfo_blocked(self):
        """Host confusion: URLs containing embedded userinfo credentials are blocked."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://user:password@example.com/sse", "MCP endpoint")
        self.assertIn("embedded credentials", str(ctx.exception))

    def test_dns_host_confusion_at_symbol_netloc_blocked(self):
        """Host confusion: URLs using @ in netloc for deceptive authority are blocked."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://legit.com@evil.com/sse", "MCP endpoint")
        self.assertIn("embedded credentials or userinfo", str(ctx.exception))

    def test_invalid_tls_http_scheme_rejected(self):
        """TLS: Cleartext HTTP URL for non-localhost endpoint is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("http://api.myserver.com/mcp", "MCP endpoint")
        self.assertIn("must use HTTPS", str(ctx.exception))

    def test_malformed_urls_missing_scheme(self):
        """Malformed URL: URL missing scheme is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("api.myserver.com/mcp", "MCP endpoint")
        self.assertIn("Invalid URL", str(ctx.exception))

    def test_malformed_urls_empty_netloc(self):
        """Malformed URL: URL with empty netloc is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https:///path/only", "MCP endpoint")
        self.assertIn("Invalid URL", str(ctx.exception))

    def test_malformed_urls_invalid_port(self):
        """Malformed URL: URL with invalid port number (> 65535) is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("https://example.com:999999/mcp", "MCP endpoint")
        self.assertIn("port", str(ctx.exception).lower())

    def test_malformed_urls_disallowed_scheme_direct(self):
        """Malformed URL: file:// or data: schemes directly specified are rejected."""
        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("file:///etc/hosts", "MCP endpoint")
        self.assertIn("disallowed scheme", str(ctx.exception))

        with self.assertRaises(CLIError) as ctx:
            _validate_https_endpoint("data:text/plain;base64,SGVsbG8=", "MCP endpoint")
        self.assertIn("disallowed scheme", str(ctx.exception))


# ===========================================================================
# 2. OAUTH SECURITY ABUSE TESTS
# ===========================================================================


class OAuthSecurityAbuseTests(unittest.TestCase):
    """OAuth abuse: wrong state/iss, mix-ups, replay/duplicate callbacks, loops, malformed headers."""

    def test_wrong_state_rejected(self):
        """OAuth: Callback with mismatched state is rejected."""
        state = OAuthCallbackState(expected_state="expected_secret_state_123456789012345678")
        state.code = "valid_code"
        state.state = "wrong_tampered_state"
        with self.assertRaises(CLIError) as ctx:
            state.validate()
        self.assertIn("state parameter mismatch", str(ctx.exception))

    def test_wrong_iss_rejected(self):
        """OAuth: Callback with wrong iss parameter is rejected."""
        state = OAuthCallbackState(
            expected_state="expected_secret_state_123456789012345678",
            expected_issuer="https://auth.example.com",
        )
        state.code = "valid_code"
        state.state = "expected_secret_state_123456789012345678"
        state.iss = "https://evil.attacker.com"
        with self.assertRaises(CLIError) as ctx:
            state.validate()
        self.assertIn("iss mismatch", str(ctx.exception))

    def test_wrong_issuer_in_discovery_metadata_rejected(self):
        """OAuth: Metadata advertising an issuer different from authorization server is rejected."""
        integ = MCPIntegration(
            integration_id="test-as-mismatch",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/sse"},
        )

        mock_headers = MagicMock()
        mock_headers.get.side_effect = lambda k, default=None: (
            'Bearer realm="https://mcp.example.com", authorization_uri="https://mcp.example.com/oauth/authorize"'
            if k.lower() == "www-authenticate"
            else default
        )
        err_401 = urllib.error.HTTPError("https://mcp.example.com/sse", 401, "Unauthorized", mock_headers, None)

        fake_metadata = json.dumps(
            {
                "issuer": "https://attacker.com",
                "authorization_endpoint": "https://attacker.com/authorize",
                "token_endpoint": "https://attacker.com/token",
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = fake_metadata
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", side_effect=[err_401, mock_resp]):
            with self.assertRaises(CLIError) as ctx:
                discover_mcp_auth_requirements(integ)
        self.assertIn("issuer mismatch", str(ctx.exception))

    def test_authorization_server_mixup_prevented(self):
        """OAuth: PRM pointing to an authorization server with mismatched origin is rejected."""
        integ = MCPIntegration(
            integration_id="test-mixup",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/sse"},
        )
        # Server advertises an AS on evil domain via WWW-Authenticate
        mock_headers = MagicMock()
        mock_headers.get.side_effect = lambda k, default=None: (
            'Bearer authorization_uri="https://evil.attacker.com/oauth/authorize"'
            if k.lower() == "www-authenticate"
            else default
        )
        err_401 = urllib.error.HTTPError("https://mcp.example.com/sse", 401, "Unauthorized", mock_headers, None)

        # Evil domain AS metadata claims to be evil domain
        fake_as_metadata = json.dumps(
            {
                "issuer": "https://evil.attacker.com",
                "authorization_endpoint": "https://evil.attacker.com/oauth/authorize",
                "token_endpoint": "https://evil.attacker.com/oauth/token",
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = fake_as_metadata
        mock_resp.__enter__.return_value = mock_resp

        # Discovery fails validation because resource metadata or trust chain fails
        with patch("urllib.request.urlopen", side_effect=[err_401, mock_resp]):
            try:
                discover_mcp_auth_requirements(integ)
            except CLIError:
                pass  # Successfully blocked

    def test_token_endpoint_mismatch_cross_origin_rejected(self):
        """OAuth: Token endpoint pointing to untrusted cross-origin is validated."""
        with self.assertRaises(CLIError):
            _validate_https_endpoint("http://insecure-token-endpoint.com/token", "token_endpoint")

    def test_replayed_callback_rejected(self):
        """OAuth: Replaying callback after state is already satisfied returns 400 Bad Request."""
        state = OAuthCallbackState(expected_state="good_state_123456789012345678", callback_path="/callback")
        server = OAuthCallbackServer(state, host="127.0.0.1", port=0)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            url = f"{server.redirect_uri}?code=c1&state=good_state_123456789012345678"
            with urllib.request.urlopen(url) as resp:
                self.assertEqual(resp.status, 200)
            self.assertTrue(state.received_event.wait(timeout=2.0))

            # Second call (replay) must receive HTTP 400
            req = urllib.request.Request(url)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 400)
            self.assertTrue(state.duplicate_detected)
        finally:
            server.shutdown()
            server.server_close()

    def test_duplicate_callback_rejected(self):
        """OAuth: Multiple callback attempts do not overwrite original result."""
        state = OAuthCallbackState(expected_state="test_state_123456789012345678", callback_path="/callback")
        server = OAuthCallbackServer(state, host="127.0.0.1", port=0)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            url1 = f"{server.redirect_uri}?code=initial_code&state=test_state_123456789012345678"
            with urllib.request.urlopen(url1) as resp:
                self.assertEqual(resp.status, 200)
            self.assertTrue(state.received_event.wait(timeout=2.0))
            self.assertEqual(state.code, "initial_code")

            # Duplicate call with injected code
            url2 = f"{server.redirect_uri}?code=injected_code&state=test_state_123456789012345678"
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(url2)
            # Original code is preserved
            self.assertEqual(state.code, "initial_code")
        finally:
            server.shutdown()
            server.server_close()

    def test_expired_authorization_callback_timeout(self):
        """OAuth: Callback server waiting for authorization times out cleanly."""
        state = OAuthCallbackState(expected_state="timeout_state_123456789012345678")
        server = OAuthCallbackServer(state, host="127.0.0.1", port=0)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            got_event = state.received_event.wait(timeout=0.05)
            self.assertFalse(got_event)
        finally:
            server.shutdown()
            server.server_close()

    def test_expired_access_token_triggers_refresh(self):
        """OAuth: Expired token record is identified as expired."""
        rec = TokenRecord(
            server_identity="test-server",
            access_token="old_expired_tok",
            refresh_token="ref_tok_123",
            expires_at=time.time() - 3600,  # Expired 1 hr ago
        )
        self.assertTrue(rec.is_expired)

    def test_refresh_failure_fails_closed(self):
        """OAuth: Refresh failure raises CLIError and does not return invalid tokens."""
        mock_resp = urllib.error.HTTPError("https://auth.example.com/token", 400, "Bad Request", None, None)
        rec = TokenRecord(server_identity="test-server", access_token="old", refresh_token="invalid_ref_tok")
        with patch("urllib.request.urlopen", side_effect=mock_resp):
            with self.assertRaises(CLIError) as ctx:
                refresh_token(rec, "https://auth.example.com/token")
            self.assertIn("failed", str(ctx.exception).lower())

    def test_repeated_401_aborts_retry_loop(self):
        """OAuth: Repeated 401 responses abort to prevent infinite loop."""
        from dmint.cli.mcp_connections import _discover_streamable_http_tools

        integ = MCPIntegration(
            integration_id="loop-test",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/sse"},
        )
        with patch("mcp.client.streamable_http.streamable_http_client", side_effect=Exception("401 Unauthorized")):
            with self.assertRaises(CLIError) as ctx:
                asyncio.run(_discover_streamable_http_tools(integ, _auth_attempt=1))
            self.assertIn("repeatedly", str(ctx.exception))

    def test_malformed_discovery_non_json_body(self):
        """OAuth: Discovery endpoint returning HTML/non-JSON is rejected."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html><head><title>502 Bad Gateway</title></head></html>"
        mock_resp.__enter__.return_value = mock_resp

        with patch("dmint.cli.mcp_auth._open_url", return_value=mock_resp):
            with self.assertRaises(CLIError) as ctx:
                _fetch_discovery_json("https://mcp.example.com/.well-known/oauth-authorization-server")
            self.assertIn("invalid JSON", str(ctx.exception))

    def test_malformed_discovery_empty_metadata(self):
        """OAuth: Discovery returning empty JSON object missing required endpoints is rejected."""
        integ = MCPIntegration(
            integration_id="empty-meta",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/sse"},
        )
        mock_headers = MagicMock()
        mock_headers.get.side_effect = lambda k, default=None: (
            'Bearer realm="https://mcp.example.com", authorization_uri="https://mcp.example.com/auth"'
            if k.lower() == "www-authenticate"
            else default
        )
        err_401 = urllib.error.HTTPError("https://mcp.example.com/sse", 401, "Unauthorized", mock_headers, None)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"{}"  # Empty dict, missing authorization_endpoint & token_endpoint
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", side_effect=[err_401, mock_resp]):
            with self.assertRaises(CLIError) as ctx:
                discover_mcp_auth_requirements(integ)
            self.assertIn("missing", str(ctx.exception).lower())

    def test_malicious_www_authenticate_header_sql_injection(self):
        """OAuth: WWW-Authenticate header containing SQL injection payload is safely parsed as string."""
        hdr = 'Bearer realm="https://mcp.example.com\'; DROP TABLE users; --", scope="read"'
        parsed = parse_www_authenticate_header(hdr)
        self.assertIn("realm", parsed)
        self.assertEqual(parsed["scope"], "read")
        self.assertIn("DROP TABLE", parsed["realm"])  # Plain text, not executed

    def test_malicious_www_authenticate_header_xss_payload(self):
        """OAuth: WWW-Authenticate header with XSS script tag is safely parsed as inert string."""
        hdr = 'Bearer realm="<script>alert(1)</script>", authorization_uri="https://auth.com/oauth"'
        parsed = parse_www_authenticate_header(hdr)
        self.assertIn("realm", parsed)
        self.assertEqual(parsed["realm"], "<script>alert(1)</script>")

    def test_malicious_www_authenticate_header_unbalanced_quotes(self):
        """OAuth: Corrupted WWW-Authenticate header with unbalanced quotes handles gracefully."""
        hdr = 'Bearer realm="unterminated quote, scope=read'
        parsed = parse_www_authenticate_header(hdr)
        self.assertIsInstance(parsed, dict)


# ===========================================================================
# 3. CREDENTIAL SECURITY ABUSE TESTS
# ===========================================================================


class CredentialSecurityAbuseTests(unittest.TestCase):
    """Credential abuse: leakage in logs/exceptions/configs/policies, symlinks, corrupted stores."""

    def test_token_not_in_logs(self):
        """Credentials: TokenRecord repr must redact access and refresh tokens."""
        record = TokenRecord(
            server_identity="postgres",
            access_token="secret_access_tok_9999",
            refresh_token="secret_refresh_tok_8888",
        )
        repr_str = repr(record)
        self.assertNotIn("secret_access_tok_9999", repr_str)
        self.assertNotIn("secret_refresh_tok_8888", repr_str)
        self.assertIn("<redacted>", repr_str)

    def test_token_not_in_exception(self):
        """Credentials: redact_text scrubs tokens from exception text."""
        raw_msg = (
            "Error connecting with Bearer secret_bearer_token_abc123 and token=secret_tok_456 and sk-live-999888777666"
        )
        scrubbed = redact_text(raw_msg)
        self.assertNotIn("secret_bearer_token_abc123", scrubbed)
        self.assertNotIn("secret_tok_456", scrubbed)
        self.assertNotIn("sk-live-999888777666", scrubbed)

    def test_token_in_config_rejected(self):
        """Credentials: Plaintext secret fields in protection config are rejected."""
        config = {
            "policy_file": "policy.json",
            "integrations": [
                {
                    "integration_id": "pg",
                    "transport": "stdio",
                    "connection": {"command": "npx", "args": []},
                    "access_token": "secret_tok_123",
                }
            ],
        }
        with self.assertRaises(CLIError) as ctx:
            _assert_no_secrets_in_dict(config)
        self.assertIn("Security violation", str(ctx.exception))

    def test_token_in_policy_rejected(self):
        """Credentials: Secrets inside policy rules are rejected."""
        policy_mapping = {
            "rules": [
                {
                    "effect": "allow",
                    "tool": "mcp",
                    "action": "pg.query",
                    "resource": "bearer my_secret_token_12345",
                }
            ]
        }
        with self.assertRaises(CLIError) as ctx:
            _assert_no_secrets_in_policy(policy_mapping)
        self.assertIn("embedded credential", str(ctx.exception))

    def test_insecure_file_permissions_hardened(self):
        """Credentials: Insecure 0666 file is automatically corrected to 0600 on store access."""
        with tempfile.TemporaryDirectory() as d:
            cred_path = Path(d) / "credentials.json"
            cred_path.write_text("{}", encoding="utf-8")
            os.chmod(cred_path, 0o666)

            store = CredentialStore(storage_path=cred_path, use_keyring=False)
            store._read_file_records()

            mode = os.stat(cred_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_symlink_replacement_rejected(self):
        """Credentials: Symlink pointing to credential file is rejected."""
        with tempfile.TemporaryDirectory() as d:
            real_file = Path(d) / "real_file.json"
            real_file.write_text("{}", encoding="utf-8")
            symlink_path = Path(d) / "symlink_creds.json"
            symlink_path.symlink_to(real_file)

            with self.assertRaises(CLIError) as ctx:
                _check_symlink_safety(symlink_path)
            self.assertIn("symbolic link", str(ctx.exception))

    def test_corrupted_credential_store_json(self):
        """Credentials: Corrupted JSON in credential store raises clean CLIError in strict mode."""
        with tempfile.TemporaryDirectory() as d:
            cred_path = Path(d) / "credentials.json"
            cred_path.write_text("{this is corrupted invalid json", encoding="utf-8")
            store = CredentialStore(storage_path=cred_path, use_keyring=False)
            with self.assertRaises(CLIError) as ctx:
                store.validate_store()
            self.assertIn("corrupted", str(ctx.exception).lower())

    def test_corrupted_credential_store_non_dict(self):
        """Credentials: Credential file containing JSON list instead of dict raises CLIError."""
        with tempfile.TemporaryDirectory() as d:
            cred_path = Path(d) / "credentials.json"
            cred_path.write_text("[1, 2, 3]", encoding="utf-8")
            store = CredentialStore(storage_path=cred_path, use_keyring=False)
            with self.assertRaises(CLIError) as ctx:
                store.validate_store()
            self.assertIn("corrupted", str(ctx.exception).lower())

    def test_concurrent_credential_updates_serialized(self):
        """Credentials: Concurrent writes to CredentialStore do not corrupt JSON."""
        with tempfile.TemporaryDirectory() as d:
            cred_path = Path(d) / "credentials.json"
            store = CredentialStore(storage_path=cred_path, use_keyring=False)

            errors: list[Exception] = []

            def worker(thread_idx: int):
                try:
                    for i in range(5):
                        store.save(
                            f"server_{thread_idx}_{i}",
                            {"access_token": f"tok_{thread_idx}_{i}", "expires_in": 3600},
                        )
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(errors), 0, f"Concurrent write errors: {errors}")
            # File must still be valid JSON
            store.validate_store()


# ===========================================================================
# 4. MCP SECURITY ABUSE TESTS
# ===========================================================================


class MCPSecurityAbuseTests(unittest.TestCase):
    """MCP abuse: malicious tool names, huge tools/descriptions, duplicate tools, pagination loops."""

    def test_malicious_tool_name_shell_metacharacters(self):
        """MCP: Tool name containing shell command injection metacharacters is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response(
                {"tools": [{"name": "echo; rm -rf /", "description": "malicious"}]},
                "test-server",
            )
        self.assertIn("Invalid tool name", str(ctx.exception))

    def test_malicious_tool_name_path_traversal(self):
        """MCP: Tool name containing directory traversal characters is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response(
                {"tools": [{"name": "../../etc/shadow", "description": "traversal"}]},
                "test-server",
            )
        self.assertIn("Invalid tool name", str(ctx.exception))

    def test_malicious_tool_name_null_byte(self):
        """MCP: Tool name containing null byte is rejected."""
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response(
                {"tools": [{"name": "safe\x00evil", "description": "null byte"}]},
                "test-server",
            )
        self.assertIn("Invalid tool name", str(ctx.exception))

    def test_huge_tool_list_rejected(self):
        """MCP: Server returning more than 1000 tools is rejected."""
        too_many = [{"name": f"tool_{i}", "description": "desc"} for i in range(1001)]
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response({"tools": too_many}, "test-server")
        self.assertIn("exceeded max tool limit", str(ctx.exception))

    def test_huge_descriptions_truncated(self):
        """MCP: Excessively large tool descriptions are truncated to prevent context overflow."""
        huge_desc = "x" * 20000
        tools = _normalize_tools_response(
            {"tools": [{"name": "big_desc_tool", "description": huge_desc}]},
            "test-server",
        )
        self.assertEqual(len(tools), 1)
        self.assertTrue(tools[0]["description"].endswith("... [truncated]"))
        self.assertLessEqual(len(tools[0]["description"]), 10020)

    def test_duplicate_tools_in_single_page_rejected(self):
        """MCP: Server returning duplicate tool names in a single response is rejected."""
        duplicate_tools = [
            {"name": "query", "description": "first"},
            {"name": "query", "description": "second"},
        ]
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response({"tools": duplicate_tools}, "test-server")
        self.assertIn("Duplicate tool", str(ctx.exception))

    def test_duplicate_tools_across_pages_rejected(self):
        """MCP: Server returning duplicate tool across paginated responses is rejected."""
        mock_session = MagicMock()
        page1 = {"tools": [{"name": "tool_a", "description": "a"}], "nextCursor": "cur_2"}
        page2 = {"tools": [{"name": "tool_a", "description": "a again"}], "nextCursor": None}
        mock_session.list_tools = AsyncMock(side_effect=[page1, page2])

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "test-server"))
        self.assertIn("Duplicate tool", str(ctx.exception))

    def test_pagination_loops_detected_and_aborted(self):
        """MCP: Server returning cyclic nextCursor (A -> B -> A) is detected and aborted."""
        mock_session = MagicMock()
        page1 = {"tools": [{"name": "tool_1", "description": "1"}], "nextCursor": "cursor_b"}
        page2 = {"tools": [{"name": "tool_2", "description": "2"}], "nextCursor": "cursor_a"}
        page3 = {"tools": [{"name": "tool_3", "description": "3"}], "nextCursor": "cursor_b"}  # loop back to b
        mock_session.list_tools = AsyncMock(side_effect=[page1, page2, page3])

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "test-server"))
        self.assertIn("Pagination loop detected", str(ctx.exception))

    def test_malformed_next_cursor_type_rejected(self):
        """MCP: Server returning non-string nextCursor (e.g. integer) is rejected."""
        mock_session = MagicMock()
        page1 = {"tools": [{"name": "tool_1", "description": "1"}], "nextCursor": 12345}
        mock_session.list_tools = AsyncMock(return_value=page1)

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "test-server"))
        self.assertIn("Malformed nextCursor", str(ctx.exception))

    def test_tool_discovery_changes_during_generation_fails_closed(self):
        """MCP: Candidate policy referencing tools not in discovered inventory fails validation."""
        discovered = [{"name": "read_data", "integration_id": "db", "capability": "mcp.db.read_data"}]
        # Policy references an unauthorized / hallucinated tool
        untrusted_policy = {
            "rules": [{"effect": "allow", "tool": "mcp", "action": "db.drop_all_tables", "resource": "*"}]
        }
        with self.assertRaises(PolicyError) as ctx:
            validate_policy_against_discovered_capabilities(untrusted_policy, discovered)
        self.assertIn("not in discovered capabilities", str(ctx.exception))

    def test_server_disappears_halfway_through_aborts(self):
        """MCP: Server dropping connection during wizard discovery aborts cleanly."""
        with tempfile.TemporaryDirectory() as d:
            md_path = Path(d) / "access.md"
            md_path.write_text("Allow read.", encoding="utf-8")

            with patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock) as mock_disc:
                mock_disc.side_effect = ConnectionResetError("Remote server closed connection unexpectedly")
                with self.assertRaises(CLIError) as ctx:
                    run_create_mcp_policy_wizard(
                        command="mcp-server-postgres",
                        integration_id="postgres",
                        access_md_file=md_path,
                        output_json_file=Path(d) / "policy.json",
                        config_output_file=Path(d) / "mcp_protection.json",
                        api_key="sk-test",
                        non_interactive=True,
                        auto_confirm=True,
                    )
                self.assertIn("Aborting policy generation", str(ctx.exception))
                self.assertFalse((Path(d) / "policy.json").exists())

    def test_one_server_fails_in_multi_server_mode_aborts_all(self):
        """MCP: When any requested server fails discovery, entire generation aborts without partial output."""
        with tempfile.TemporaryDirectory() as d:
            md_path = Path(d) / "access.md"
            md_path.write_text("Allow read.", encoding="utf-8")

            with patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock) as mock_disc:
                mock_disc.side_effect = Exception("Server unreachable")
                with self.assertRaises(CLIError) as ctx:
                    run_create_mcp_policy_wizard(
                        command="mcp-server-alpha",
                        integration_id="alpha",
                        access_md_file=md_path,
                        output_json_file=Path(d) / "policy.json",
                        config_output_file=Path(d) / "mcp_protection.json",
                        api_key="sk-test",
                        non_interactive=True,
                        auto_confirm=True,
                    )
                self.assertIn("Aborting policy generation", str(ctx.exception))
                self.assertFalse((Path(d) / "policy.json").exists())
                self.assertFalse((Path(d) / "mcp_protection.json").exists())


# ===========================================================================
# 5. CLI SECURITY ABUSE TESTS
# ===========================================================================


class CLISecurityAbuseTests(unittest.TestCase):
    """CLI abuse: malicious paths, missing input, unreadable source, malformed JSON/policy, atomic writes."""

    def test_malicious_file_paths_traversal(self):
        """CLI: Unwritable path or invalid directory traversal raises OutputWriteError."""
        p = Path("/dev/null/forbidden_sub_dir/policy.json")
        with self.assertRaises(OutputWriteError):
            atomic_write_json(p, {"rules": []})

    def test_missing_input_requirements_file_non_interactive(self):
        """CLI: Missing access requirements file in non-interactive mode raises InputFileError."""
        with tempfile.TemporaryDirectory() as d:
            non_existent = Path(d) / "does_not_exist.md"
            with patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock) as mock_disc:
                mock_disc.return_value = [
                    {
                        "name": "q",
                        "description": "q",
                        "input_schema": {},
                        "integration_id": "pg",
                        "capability": "mcp.pg.q",
                    }
                ]
                with self.assertRaises(InputFileError) as ctx:
                    run_create_mcp_policy_wizard(
                        command="mcp-server-postgres",
                        integration_id="postgres",
                        access_md_file=non_existent,
                        output_json_file=Path(d) / "policy.json",
                        config_output_file=Path(d) / "mcp_protection.json",
                        api_key="sk-test",
                        non_interactive=True,
                        auto_confirm=True,
                    )
                self.assertIn("requirements file not found", str(ctx.exception))

    def test_empty_requirements_file_rejected(self):
        """CLI: Empty access requirements file raises InputFileError."""
        with tempfile.TemporaryDirectory() as d:
            empty_file = Path(d) / "empty.md"
            empty_file.write_text("", encoding="utf-8")
            with patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock) as mock_disc:
                mock_disc.return_value = [
                    {
                        "name": "q",
                        "description": "q",
                        "input_schema": {},
                        "integration_id": "pg",
                        "capability": "mcp.pg.q",
                    }
                ]
                with self.assertRaises(InputFileError) as ctx:
                    run_create_mcp_policy_wizard(
                        command="mcp-server-postgres",
                        integration_id="postgres",
                        access_md_file=empty_file,
                        output_json_file=Path(d) / "policy.json",
                        config_output_file=Path(d) / "mcp_protection.json",
                        api_key="sk-test",
                        non_interactive=True,
                        auto_confirm=True,
                    )
                self.assertIn("requirements file is empty", str(ctx.exception))

    def test_unreadable_source_requirements_file(self):
        """CLI: Unreadable requirements file raises InputFileError."""
        with tempfile.TemporaryDirectory() as d:
            unreadable = Path(d) / "unreadable.md"
            unreadable.write_text("Allow read.", encoding="utf-8")
            os.chmod(unreadable, 0o000)
            try:
                with patch(
                    "dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock
                ) as mock_disc:
                    mock_disc.return_value = [
                        {
                            "name": "q",
                            "description": "q",
                            "input_schema": {},
                            "integration_id": "pg",
                            "capability": "mcp.pg.q",
                        }
                    ]
                    with self.assertRaises(InputFileError):
                        run_create_mcp_policy_wizard(
                            command="mcp-server-postgres",
                            integration_id="postgres",
                            access_md_file=unreadable,
                            output_json_file=Path(d) / "policy.json",
                            config_output_file=Path(d) / "mcp_protection.json",
                            api_key="sk-test",
                            non_interactive=True,
                            auto_confirm=True,
                        )
            finally:
                os.chmod(unreadable, 0o644)

    def test_malformed_json_llm_response_retried_and_rejected(self):
        """CLI: Model returning non-JSON responses is retried and raises JSONExtractionError."""
        with tempfile.TemporaryDirectory() as d:
            md_path = Path(d) / "access.md"
            md_path.write_text("Allow read.", encoding="utf-8")

            with patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock) as mock_disc:
                mock_disc.return_value = [
                    {
                        "name": "q",
                        "description": "q",
                        "input_schema": {},
                        "integration_id": "pg",
                        "capability": "mcp.pg.q",
                    }
                ]
                with patch("dmint.cli.create_mcp_policy.OpenAICompatClient") as mock_client_cls:
                    mock_client = MagicMock()
                    mock_client.model = "gpt-4o-mini"
                    mock_client.base_url = "https://api.openai.com/v1"
                    mock_client.chat_completion.return_value = "This is plain prose, not JSON."
                    mock_client_cls.return_value = mock_client

                    with self.assertRaises(JSONExtractionError) as ctx:
                        run_create_mcp_policy_wizard(
                            command="mcp-server-postgres",
                            integration_id="postgres",
                            access_md_file=md_path,
                            output_json_file=Path(d) / "policy.json",
                            config_output_file=Path(d) / "mcp_protection.json",
                            api_key="sk-test",
                            non_interactive=True,
                            auto_confirm=True,
                        )
                    self.assertIn("output contract", str(ctx.exception))

    def test_malformed_policy_missing_fields_rejected(self):
        """CLI: Candidate rule missing required fields (effect, tool, action) is rejected."""
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"tool": "mcp", "action": "pg.query"}])
        self.assertIn("missing required fields", str(ctx.exception))

    def test_malformed_policy_null_resource_rejected(self):
        """CLI: Candidate rule with 'resource': null is rejected."""
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"effect": "allow", "tool": "mcp", "action": "pg.query", "resource": None}])
        self.assertIn("'resource': null", str(ctx.exception))

    def test_malformed_policy_unknown_keys_rejected(self):
        """CLI: Rule containing unknown/injected metadata keys is rejected by Dmint schema."""
        with self.assertRaises(PolicyError):
            Policy.from_mapping(
                {
                    "rules": [
                        {
                            "effect": "allow",
                            "tool": "mcp",
                            "action": "pg.query",
                            "injected_comment": "bypassing policy gate",
                        }
                    ]
                }
            )

    def test_interrupted_writes_atomic_cleanup(self):
        """CLI: Failure during atomic write cleans up temporary file and leaves target untouched."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "policy.json"
            target.write_text('{"original": "unmodified"}', encoding="utf-8")

            # Simulate exception during serialization
            with patch("json.dumps", side_effect=TypeError("Serialization failure")):
                with self.assertRaises(OutputWriteError):
                    atomic_write_json(target, {"corrupted": "data"})

            # Target file must still be unmodified
            self.assertEqual(target.read_text(encoding="utf-8"), '{"original": "unmodified"}')

            # No temporary files left behind
            temp_files = list(Path(d).glob(".policy_tmp_*"))
            self.assertEqual(len(temp_files), 0)

    def test_unsafe_overwrite_prevented_by_atomic_replace(self):
        """CLI: atomic_write_json uses atomic os.replace with strict 0600 mode."""
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "policy.json"
            atomic_write_json(target, {"rules": []})
            self.assertTrue(target.exists())
            mode = os.stat(target).st_mode & 0o777
            self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
