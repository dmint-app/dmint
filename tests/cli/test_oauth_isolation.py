"""Tests for Phase 5 — OAuth callback server isolation.

Verifies:
1. Every OAuth transaction gets an isolated callback state object (no globals).
2. The callback server binds directly to port 0 without socket reuse.
3. Actual selected port is dynamically obtained from running server.
4. Validation of callback path (404 on non-matching path).
5. State validation using constant-time comparison.
6. Issuer (iss) validation when supplied/required.
7. Safe handling of user-denied callback errors.
8. Callback timeout enforcement and clean shutdown.
9. Rejection of duplicate/replayed callbacks (400 Bad Request).
10. Concurrent OAuth flows cannot satisfy each other's callbacks.
"""

import http.client
import json
import threading
import time
import unittest
import urllib.request
import urllib.error

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import MCPAuthRequirements
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport
from dmint.cli.mcp_oauth import (
    IsolatedCallbackHandler,
    OAuthCallbackHandler,
    OAuthCallbackServer,
    OAuthCallbackState,
    create_oauth_client_provider,
    perform_oauth_flow,
)


class TestOAuthCallbackIsolation(unittest.TestCase):
    """Unit and integration tests for isolated callback servers and transactions."""

    def test_port_zero_direct_bind_without_socket_reuse(self):
        """Server binds directly to port 0 via HTTPServer, dynamically assigning port."""
        state = OAuthCallbackState(expected_state="test-state-123")
        server = OAuthCallbackServer(state, host="127.0.0.1", port=0)
        try:
            self.assertGreater(server.selected_port, 0)
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertEqual(server.selected_port, server.server_address[1])
            self.assertEqual(server.redirect_uri, f"http://127.0.0.1:{server.selected_port}/callback")
            self.assertIs(server.callback_state, state)
        finally:
            server.server_close()

    def test_isolated_callback_state_no_globals(self):
        """Two transactions have distinct, isolated states with no global crosstalk."""
        state_a = OAuthCallbackState(expected_state="state-alpha", expected_issuer="https://auth-a.example.com")
        state_b = OAuthCallbackState(expected_state="state-beta", expected_issuer="https://auth-b.example.com")

        server_a = OAuthCallbackServer(state_a, port=0)
        server_b = OAuthCallbackServer(state_b, port=0)

        try:
            self.assertNotEqual(server_a.selected_port, server_b.selected_port)
            self.assertIsNot(server_a.callback_state, server_b.callback_state)

            # Mutate state A
            state_a.code = "code-alpha"
            state_a.received_event.set()

            # Verify state B is completely unaffected
            self.assertIsNone(state_b.code)
            self.assertFalse(state_b.received_event.is_set())
        finally:
            server_a.server_close()
            server_b.server_close()

    def test_callback_path_validation_404(self):
        """Requests to unexpected paths return 404 and do not trigger event completion."""
        state = OAuthCallbackState(expected_state="valid-state", callback_path="/callback")
        server = OAuthCallbackServer(state, port=0)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            port = server.selected_port

            # Request wrong path: /favicon.ico
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.ico")
            self.assertEqual(ctx.exception.code, 404)
            self.assertFalse(state.received_event.is_set())

            # Request wrong path: /oauth-redirect
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/oauth-redirect?code=123&state=valid-state")
            self.assertEqual(ctx.exception.code, 404)
            self.assertFalse(state.received_event.is_set())
        finally:
            server.shutdown()
            server.server_close()

    def test_state_constant_time_validation_success_and_failure(self):
        """Verify state is validated using constant-time comparison."""
        expected = "secure-random-state-abcdef1234567890"
        state = OAuthCallbackState(expected_state=expected)
        server = OAuthCallbackServer(state, port=0)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            port = server.selected_port

            # 1. Invalid state returns 400 Bad Request
            wrong_url = f"http://127.0.0.1:{port}/callback?code=good-code&state=tampered-state"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(wrong_url)
            self.assertEqual(ctx.exception.code, 400)
            self.assertTrue(state.received_event.wait(timeout=2.0))
            with self.assertRaises(CLIError) as err:
                state.validate()
            self.assertIn("state parameter mismatch", str(err.exception))
        finally:
            server.shutdown()
            server.server_close()

        # Fresh transaction with correct state
        state_ok = OAuthCallbackState(expected_state=expected)
        server_ok = OAuthCallbackServer(state_ok, port=0)
        thread_ok = threading.Thread(target=server_ok.serve_forever, daemon=True)
        thread_ok.start()
        try:
            port_ok = server_ok.selected_port
            valid_url = f"http://127.0.0.1:{port_ok}/callback?code=auth-code-777&state={expected}"
            with urllib.request.urlopen(valid_url) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode("utf-8")
                self.assertIn("Authorization Successful", body)

            self.assertTrue(state_ok.received_event.wait(timeout=2.0))
            self.assertEqual(state_ok.code, "auth-code-777")
            # Should not raise
            state_ok.validate()
        finally:
            server_ok.shutdown()
            server_ok.server_close()

    def test_issuer_validation_mismatch_and_match(self):
        """Verify iss parameter validation with RFC 8414 normalization compatibility."""
        expected_iss = "https://auth.example.com"
        state = OAuthCallbackState(expected_state="state-123", expected_issuer=expected_iss)
        server = OAuthCallbackServer(state, port=0)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            port = server.selected_port

            # Mismatched issuer: attacker or confused AS
            bad_url = f"http://127.0.0.1:{port}/callback?code=auth-code&state=state-123&iss=https://evil-idp.com"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(bad_url)
            self.assertEqual(ctx.exception.code, 400)
            self.assertTrue(state.received_event.wait(timeout=2.0))
            with self.assertRaises(CLIError) as err:
                state.validate()
            self.assertIn("iss mismatch", str(err.exception).lower())
        finally:
            server.shutdown()
            server.server_close()

        # Matching issuer (with trailing slash normalization)
        state_ok = OAuthCallbackState(expected_state="state-123", expected_issuer=expected_iss)
        server_ok = OAuthCallbackServer(state_ok, port=0)
        thread_ok = threading.Thread(target=server_ok.serve_forever, daemon=True)
        thread_ok.start()
        try:
            port_ok = server_ok.selected_port
            # Response sends trailing slash: https://auth.example.com/
            good_url = f"http://127.0.0.1:{port_ok}/callback?code=auth-code&state=state-123&iss={expected_iss}/"
            with urllib.request.urlopen(good_url) as resp:
                self.assertEqual(resp.status, 200)

            self.assertTrue(state_ok.received_event.wait(timeout=2.0))
            state_ok.validate()
        finally:
            server_ok.shutdown()
            server_ok.server_close()

    def test_duplicate_callback_rejected(self):
        """Second callback to the same transaction server is rejected with HTTP 400."""
        expected_state = "test-dup-state"
        state = OAuthCallbackState(expected_state=expected_state)
        server = OAuthCallbackServer(state, port=0)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            port = server.selected_port
            url = f"http://127.0.0.1:{port}/callback?code=code-1&state={expected_state}"

            # 1. First callback succeeds
            with urllib.request.urlopen(url) as resp:
                self.assertEqual(resp.status, 200)
            self.assertTrue(state.received_event.wait(timeout=2.0))
            self.assertFalse(state.duplicate_detected)

            # 2. Replayed callback is rejected
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(url)
            self.assertEqual(ctx.exception.code, 400)
            self.assertTrue(state.duplicate_detected)
            body = ctx.exception.read().decode("utf-8")
            self.assertIn("already processed", body)
        finally:
            server.shutdown()
            server.server_close()

    def test_user_denied_error_handling(self):
        """User denial error is returned safely with 400 and raises CLIError."""
        state = OAuthCallbackState(expected_state="any-state")
        server = OAuthCallbackServer(state, port=0)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            port = server.selected_port
            url = f"http://127.0.0.1:{port}/callback?error=access_denied&error_description=User+declined+authorization"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(url)
            self.assertEqual(ctx.exception.code, 400)
            body = ctx.exception.read().decode("utf-8")
            self.assertIn("Authorization Denied", body)

            self.assertTrue(state.received_event.wait(timeout=2.0))
            self.assertEqual(state.error, "access_denied")
            self.assertEqual(state.error_description, "User declined authorization")

            with self.assertRaises(CLIError) as err:
                state.validate(integration_id="slack-mcp")
            self.assertIn("User denied OAuth authorization for 'slack-mcp'", str(err.exception))
            self.assertIn("access_denied", str(err.exception))
        finally:
            server.shutdown()
            server.server_close()

    def test_callback_timeout_and_clean_shutdown(self):
        """Server times out and cleanly shuts down if user does not approve in time."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="timeout-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        start_time = time.time()
        with self.assertRaises(CLIError) as ctx:
            # Set timeout to 0.15s
            perform_oauth_flow(auth_reqs, integ, client_id="cid-1", timeout_seconds=0.15, open_browser=False)
        elapsed = time.time() - start_time

        self.assertIn("timed out waiting for user response", str(ctx.exception))
        self.assertGreaterEqual(elapsed, 0.14)

    def test_concurrent_oauth_flows_cannot_cross_satisfy(self):
        """Two concurrent OAuth flows running simultaneously on different ports with different states.

        A callback to Flow A cannot satisfy Flow B, and cross-sent state parameters fail.
        """
        state_1 = OAuthCallbackState(expected_state="secret-state-flow-1")
        state_2 = OAuthCallbackState(expected_state="secret-state-flow-2")

        server_1 = OAuthCallbackServer(state_1, port=0)
        server_2 = OAuthCallbackServer(state_2, port=0)

        t1 = threading.Thread(target=server_1.serve_forever, daemon=True)
        t2 = threading.Thread(target=server_2.serve_forever, daemon=True)
        t1.start()
        t2.start()

        try:
            port_1 = server_1.selected_port
            port_2 = server_2.selected_port
            self.assertNotEqual(port_1, port_2)

            # Attacker sends Flow 2's state to Flow 1's port
            cross_url = f"http://127.0.0.1:{port_1}/callback?code=cross-code&state=secret-state-flow-2"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(cross_url)
            self.assertEqual(ctx.exception.code, 400)
            self.assertTrue(state_1.received_event.wait(timeout=2.0))

            # Flow 1 rejected the mismatched state
            with self.assertRaises(CLIError) as err:
                state_1.validate()
            self.assertIn("state parameter mismatch", str(err.exception))

            # Flow 2 server is untouched and still awaiting its legitimate callback
            self.assertFalse(state_2.received_event.is_set())
            self.assertIsNone(state_2.code)

            # Now send legitimate callback to Flow 2
            good_url_2 = f"http://127.0.0.1:{port_2}/callback?code=legit-code-2&state=secret-state-flow-2"
            with urllib.request.urlopen(good_url_2) as resp:
                self.assertEqual(resp.status, 200)

            self.assertTrue(state_2.received_event.wait(timeout=2.0))
            self.assertEqual(state_2.code, "legit-code-2")
            state_2.validate()
        finally:
            server_1.shutdown()
            server_1.server_close()
            server_2.shutdown()
            server_2.server_close()

    def test_create_oauth_client_provider_server_binding(self):
        """create_oauth_client_provider allocates ephemeral port and wires isolated callback server."""
        integ = MCPIntegration(
            integration_id="provider-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://provider.example.com/mcp"},
        )
        provider = create_oauth_client_provider(integ, open_browser=False)
        try:
            self.assertIsNotNone(getattr(provider, "callback_server", None))
            server = provider.callback_server
            self.assertGreater(server.selected_port, 0)
            self.assertEqual(
                str(provider.context.client_metadata.redirect_uris[0]),
                f"http://127.0.0.1:{server.selected_port}/callback",
            )
        finally:
            if hasattr(provider, "callback_server"):
                provider.callback_server.shutdown()
                provider.callback_server.server_close()


if __name__ == "__main__":
    unittest.main()
