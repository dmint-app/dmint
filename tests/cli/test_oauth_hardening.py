"""Integration tests for MCP OAuth Architecture Hardening (Phase 2).

Tests prove:
1. Successful OAuth flow end-to-end with dynamic registration, PKCE S256, and state.
2. Wrong state parameter is rejected (constant-time verification).
3. Wrong iss (issuer) parameter is rejected.
4. Wrong authorization server / issuer mismatch is rejected.
5. Expired token in storage triggers re-authentication or refresh.
6. Denied user consent in authorization flow is rejected.
7. Token endpoint failure is surfaced without swallowing the error.
8. Authorization endpoint failure or missing endpoint is surfaced.
9. Malformed metadata is detected and rejected.
10. Server returning 401 repeatedly is terminated.
11. No infinite retry occurs when authentication fails repeatedly.
"""

from __future__ import annotations

import asyncio
from io import BytesIO
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import MCPAuthRequirements, discover_mcp_auth_requirements
from dmint.cli.mcp_connections import (
    MCPIntegration,
    MCPTransport,
    discover_mcp_tools_generic,
)
from dmint.cli.mcp_credentials import CredentialStore, TokenRecord
from dmint.cli.mcp_oauth import (
    DmintTokenStorage,
    OAuthCallbackHandler,
    PKCEParameters,
    create_oauth_client_provider,
    perform_oauth_flow,
)


class MCPOAuthHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Bind ephemeral port on loopback
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.valid_token = "valid-mcp-access-token-xyz"
        cls.refresh_token = "valid-mcp-refresh-token-123"

        # Routes for mock OAuth authorization server & MCP server
        async def metadata_route(request):
            return JSONResponse(
                {
                    "issuer": cls.base_url,
                    "authorization_endpoint": f"{cls.base_url}/oauth/authorize",
                    "token_endpoint": f"{cls.base_url}/oauth/token",
                    "registration_endpoint": f"{cls.base_url}/oauth/register",
                    "scopes_supported": ["tools:read"],
                    "code_challenge_methods_supported": ["S256"],
                }
            )

        async def register_route(request):
            data = await request.json()
            return JSONResponse(
                {
                    "client_id": "auto-client-id-12345",
                    "client_name": "Dmint CLI",
                    "redirect_uris": data.get("redirect_uris", []),
                    "token_endpoint_auth_method": "none",
                }
            )

        async def token_route(request):
            form = await request.form()
            grant_type = form.get("grant_type")
            if grant_type == "authorization_code":
                code = form.get("code")
                if code == "valid-auth-code":
                    return JSONResponse(
                        {
                            "access_token": cls.valid_token,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "refresh_token": cls.refresh_token,
                        }
                    )
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            elif grant_type == "refresh_token":
                rf_token = form.get("refresh_token")
                if rf_token == cls.refresh_token:
                    return JSONResponse(
                        {
                            "access_token": "refreshed-mcp-access-token-999",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "refresh_token": cls.refresh_token,
                        }
                    )
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        async def mcp_route(request):
            auth_hdr = request.headers.get("authorization", "")
            if auth_hdr == f"Bearer {cls.valid_token}" or auth_hdr == "Bearer refreshed-mcp-access-token-999":
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "tools": [
                                {
                                    "name": "query_db",
                                    "description": "Query database",
                                    "input_schema": {"type": "object"},
                                }
                            ]
                        },
                    }
                )
            return Response(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer realm="{cls.base_url}"'},
            )

        app = Starlette(
            routes=[
                Route("/.well-known/oauth-authorization-server", metadata_route),
                Route("/oauth/register", register_route, methods=["POST"]),
                Route("/oauth/token", token_route, methods=["POST"]),
                Route("/mcp", mcp_route, methods=["GET", "POST"]),
            ]
        )

        config = uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="warning")
        cls.uv_server = uvicorn.Server(config)
        cls.server_thread = threading.Thread(target=cls.uv_server.run, daemon=True)
        cls.server_thread.start()

        for _ in range(50):
            time.sleep(0.05)
            if cls.uv_server.started:
                break

    @classmethod
    def tearDownClass(cls):
        cls.uv_server.should_exit = True
        cls.server_thread.join(timeout=3.0)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.cred_store = CredentialStore(storage_path=self.base_path / "creds.json", use_keyring=False)
        self._reset_callback_state()

    def tearDown(self):
        self._reset_callback_state()
        self.temp_dir.cleanup()

    def _reset_callback_state(self):
        OAuthCallbackHandler.callback_error = None
        OAuthCallbackHandler.callback_code = None
        OAuthCallbackHandler.callback_state = None
        OAuthCallbackHandler.callback_iss = None
        OAuthCallbackHandler.received_event.clear()

    def test_successful_oauth_flow(self):
        """Successful OAuth flow with PKCE S256, state, and token persistence."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            issuer=self.base_url,
            authorization_endpoint=f"{self.base_url}/oauth/authorize",
            token_endpoint=f"{self.base_url}/oauth/token",
            registration_endpoint=f"{self.base_url}/oauth/register",
        )
        integ = MCPIntegration(
            integration_id="oauth-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
        )

        OAuthCallbackHandler.callback_code = "valid-auth-code"
        OAuthCallbackHandler.callback_state = "mock-state-123"
        OAuthCallbackHandler.callback_iss = self.base_url
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state-123"):
                tokens = perform_oauth_flow(
                    auth_reqs,
                    integ,
                    open_browser=False,
                    credential_store=self.cred_store,
                )

        self.assertEqual(tokens["access_token"], self.valid_token)
        self.assertEqual(tokens["token_type"], "Bearer")

        # Verify token was persisted to CredentialStore
        record = self.cred_store.load(f"{self.base_url}/mcp::oauth-mcp")
        self.assertIsNotNone(record)
        self.assertEqual(record.access_token, self.valid_token)

    def test_wrong_state_is_rejected(self):
        """Tampered or mismatched state parameter is rejected with constant-time verification."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            issuer=self.base_url,
            authorization_endpoint=f"{self.base_url}/oauth/authorize",
            token_endpoint=f"{self.base_url}/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="tamper-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
            authentication={"client_id": "test-client"},
        )

        OAuthCallbackHandler.callback_code = "valid-auth-code"
        OAuthCallbackHandler.callback_state = "tampered-attacker-state"
        OAuthCallbackHandler.callback_iss = self.base_url
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="expected-state-value"):
                with self.assertRaises(CLIError) as ctx:
                    perform_oauth_flow(auth_reqs, integ, open_browser=False)

        self.assertIn("state parameter mismatch", str(ctx.exception).lower())

    def test_wrong_iss_is_rejected(self):
        """Mismatched RFC 9207 iss parameter from authorization callback is rejected."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            issuer=self.base_url,
            authorization_endpoint=f"{self.base_url}/oauth/authorize",
            token_endpoint=f"{self.base_url}/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="iss-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
            authentication={"client_id": "test-client"},
        )

        OAuthCallbackHandler.callback_code = "valid-auth-code"
        OAuthCallbackHandler.callback_state = "mock-state"
        OAuthCallbackHandler.callback_iss = "http://rogue-authorization-server.com"
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state"):
                with self.assertRaises(CLIError) as ctx:
                    perform_oauth_flow(auth_reqs, integ, open_browser=False)

        self.assertIn("iss mismatch", str(ctx.exception).lower())

    def test_wrong_authorization_server_rejected(self):
        """Authorization server metadata issuer on an unexpected host is rejected."""
        integ = MCPIntegration(
            integration_id="bad-as-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
        )

        err_headers = {"WWW-Authenticate": f'Bearer realm="{self.base_url}"'}
        mock_err = urllib.error.HTTPError(
            url=f"{self.base_url}/mcp",
            code=401,
            msg="Unauthorized",
            hdrs=err_headers,
            fp=BytesIO(b""),
        )

        mock_meta = MagicMock()
        mock_meta.status = 200
        mock_meta.read.return_value = json.dumps(
            {
                "issuer": "http://evil-attacker-host.com",
                "authorization_endpoint": "http://evil-attacker-host.com/authorize",
                "token_endpoint": "http://evil-attacker-host.com/token",
            }
        ).encode("utf-8")
        mock_meta.__enter__.return_value = mock_meta

        with patch("urllib.request.urlopen", side_effect=[mock_err, mock_meta]):
            with self.assertRaises(CLIError) as ctx:
                discover_mcp_auth_requirements(integ)

        self.assertIn("issuer mismatch", str(ctx.exception).lower())

    def test_expired_token_in_storage(self):
        """Expired stored token is recognized as expired and not returned by storage."""
        server_id = f"{self.base_url}/mcp::expired-test"
        expired_record = TokenRecord(
            server_identity=server_id,
            access_token="expired-token-old",
            refresh_token=self.refresh_token,
            expires_at=time.time() - 100.0,
        )
        self.cred_store.save(server_id, expired_record.to_dict())

        storage = DmintTokenStorage(self.cred_store, server_id)
        token_obj = asyncio.run(storage.get_tokens())
        self.assertIsNone(token_obj)

    def test_denied_consent_raises_cli_error(self):
        """User declining authorization in browser callback raises explicit CLIError."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            issuer=self.base_url,
            authorization_endpoint=f"{self.base_url}/oauth/authorize",
            token_endpoint=f"{self.base_url}/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="denied-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
            authentication={"client_id": "test-client"},
        )

        OAuthCallbackHandler.callback_error = "access_denied"
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with self.assertRaises(CLIError) as ctx:
                perform_oauth_flow(auth_reqs, integ, open_browser=False)

        self.assertIn("User denied OAuth authorization", str(ctx.exception))

    def test_token_endpoint_failure_surfaced(self):
        """Token endpoint returning error is surfaced without swallowing."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            issuer=self.base_url,
            authorization_endpoint=f"{self.base_url}/oauth/authorize",
            token_endpoint=f"{self.base_url}/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="token-err-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
            authentication={"client_id": "test-client"},
        )

        # Send invalid code that triggers 400 invalid_grant from mock token endpoint
        OAuthCallbackHandler.callback_code = "invalid-code-triggers-error"
        OAuthCallbackHandler.callback_state = "mock-state"
        OAuthCallbackHandler.callback_iss = self.base_url
        OAuthCallbackHandler.received_event.set()

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state"):
                with self.assertRaises(CLIError) as ctx:
                    perform_oauth_flow(auth_reqs, integ, open_browser=False)

        self.assertIn("OAuth token exchange failed", str(ctx.exception))

    def test_authorization_endpoint_missing_raises_error(self):
        """Missing authorization endpoint in requirements fails cleanly."""
        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint=None,  # Missing
            token_endpoint=f"{self.base_url}/oauth/token",
        )
        integ = MCPIntegration(
            integration_id="missing-ep-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
        )

        with self.assertRaises(CLIError) as ctx:
            perform_oauth_flow(auth_reqs, integ, open_browser=False)

        self.assertIn("Missing authorization or token endpoints", str(ctx.exception))

    def test_malformed_metadata_rejected(self):
        """Malformed authorization metadata missing required endpoints is rejected."""
        integ = MCPIntegration(
            integration_id="malformed-meta-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
        )

        err_headers = {"WWW-Authenticate": f'Bearer realm="{self.base_url}"'}
        mock_err = urllib.error.HTTPError(
            url=f"{self.base_url}/mcp",
            code=401,
            msg="Unauthorized",
            hdrs=err_headers,
            fp=BytesIO(b""),
        )

        # Missing token_endpoint in metadata
        mock_bad_meta = MagicMock()
        mock_bad_meta.status = 200
        mock_bad_meta.read.return_value = json.dumps(
            {
                "issuer": self.base_url,
                "authorization_endpoint": f"{self.base_url}/oauth/authorize",
                # token_endpoint missing!
            }
        ).encode("utf-8")
        mock_bad_meta.__enter__.return_value = mock_bad_meta

        with patch("urllib.request.urlopen", side_effect=[mock_err, mock_bad_meta]):
            with self.assertRaises(CLIError) as ctx:
                discover_mcp_auth_requirements(integ)

        self.assertIn("Malformed authorization server metadata", str(ctx.exception))

    def test_server_returning_401_repeatedly_aborts(self):
        """Server returning 401 repeatedly is terminated after bounded attempts."""
        integ = MCPIntegration(
            integration_id="repeat-401-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
        )

        with patch("dmint.cli.mcp_oauth.perform_oauth_flow", return_value={"access_token": "bad-token"}):
            with self.assertRaises(CLIError) as ctx:
                asyncio.run(discover_mcp_tools_generic(integ))

        err_msg = str(ctx.exception)
        self.assertIn("401 Unauthorized", err_msg)

    def test_no_infinite_retry(self):
        """Repeated 401 authentication failures cleanly abort with bounded retry."""
        integ = MCPIntegration(
            integration_id="no-infinite-loop",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp"},
        )

        OAuthCallbackHandler.callback_code = "valid-auth-code"
        OAuthCallbackHandler.callback_state = "mock-state-loop"
        OAuthCallbackHandler.callback_iss = self.base_url
        OAuthCallbackHandler.received_event.set()

        # Mock the server transport to reject with 401 even after receiving token
        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state-loop"):
                with patch(
                    "mcp.client.streamable_http.streamable_http_client", side_effect=Exception("HTTP 401 Unauthorized")
                ):
                    with self.assertRaises(CLIError) as ctx:
                        asyncio.run(discover_mcp_tools_generic(integ))

        err_msg = str(ctx.exception)
        self.assertIn("repeatedly", err_msg)
        self.assertIn("Aborting to prevent infinite retry loop", err_msg)


if __name__ == "__main__":
    unittest.main()
