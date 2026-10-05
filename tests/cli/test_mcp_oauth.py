"""Unit and security tests for interactive OAuth 2.0 PKCE flow (src/dmint_cli/mcp_oauth.py)."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import MCPAuthRequirements
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport
from dmint.cli.mcp_oauth import (
    OAuthCallbackHandler,
    PKCEParameters,
    perform_oauth_flow,
    register_dynamic_client,
)


class MCPOAuthTests(unittest.TestCase):
    def test_pkce_generation(self):
        pkce = PKCEParameters.generate()
        self.assertEqual(len(pkce.code_verifier), 86)
        self.assertEqual(pkce.code_challenge_method, "S256")
        self.assertTrue(len(pkce.code_challenge) > 20)

    @patch("urllib.request.urlopen")
    def test_dynamic_client_registration_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"client_id": "dynamic-client-99"}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        client_id = register_dynamic_client("https://auth.example.com/register", "http://127.0.0.1:8000/callback")
        self.assertEqual(client_id, "dynamic-client-99")

    def test_missing_client_id_and_no_registration_endpoint_raises_cli_error(self):
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
            registration_endpoint=None,  # No registration endpoint
        )
        integ = MCPIntegration(
            integration_id="remote-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )
        with self.assertRaises(CLIError) as ctx:
            perform_oauth_flow(auth_reqs, integ, client_id=None, open_browser=False)

        self.assertIn("no pre-registered client_id was provided", str(ctx.exception))

    @patch("webbrowser.open", return_value=False)
    @patch("urllib.request.urlopen")
    def test_browser_launch_fallback_prints_url(self, mock_urlopen, mock_browser):
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
            registration_endpoint="https://auth.example.com/register",
        )
        integ = MCPIntegration(
            integration_id="remote-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(CLIError):
                perform_oauth_flow(auth_reqs, integ, client_id="test-client", timeout_seconds=0.1, open_browser=True)

        self.assertIn("Could not open browser automatically", buf.getvalue())
        self.assertIn("https://auth.example.com/oauth/authorize", buf.getvalue())

    @patch("webbrowser.open")
    def test_no_credential_leakage_in_exceptions(self, mock_browser):
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="remote-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        OAuthCallbackHandler.callback_code = "valid-code"
        OAuthCallbackHandler.callback_state = "mock-state"
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state"):
                with patch("urllib.request.urlopen", side_effect=Exception("Error Bearer secret_access_token_9999")):
                    with self.assertRaises(CLIError) as ctx:
                        perform_oauth_flow(
                            auth_reqs, integ, client_id="client", timeout_seconds=1.0, open_browser=False
                        )

        self.assertNotIn("secret_access_token_9999", str(ctx.exception))
        self.assertIn("<redacted>", str(ctx.exception))

    @patch("webbrowser.open")
    @patch("urllib.request.urlopen")
    def test_successful_oauth_flow(self, mock_urlopen, mock_browser):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "access_token": "access_token_val",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        ).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="remote-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        OAuthCallbackHandler.callback_code = "valid-code"
        OAuthCallbackHandler.callback_state = "mock-state"
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state"):
                tokens = perform_oauth_flow(auth_reqs, integ, client_id="client-123", open_browser=False)

        self.assertEqual(tokens["access_token"], "access_token_val")

    def test_state_mismatch_raises_cli_error(self):
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="remote-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        OAuthCallbackHandler.callback_code = "valid-code"
        OAuthCallbackHandler.callback_state = "wrong-state"
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="expected-state"):
                with self.assertRaises(CLIError) as ctx:
                    perform_oauth_flow(auth_reqs, integ, client_id="client-123", open_browser=False)

        self.assertIn("state parameter mismatch", str(ctx.exception))

    def test_user_denied_raises_cli_error(self):
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="remote-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        OAuthCallbackHandler.callback_error = "access_denied"
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with self.assertRaises(CLIError) as ctx:
                perform_oauth_flow(auth_reqs, integ, client_id="client-123", open_browser=False)

        self.assertIn("User denied OAuth authorization", str(ctx.exception))
