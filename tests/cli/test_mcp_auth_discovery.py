"""Local integration fixtures and unit tests for MCP Authorization Discovery (Phase 4).

Fixtures implemented:
A. Valid protected-resource metadata (RFC 9728 / PRM -> OASM flow).
B. Multiple authorization servers in PRM (selects primary).
C. Wrong issuer (issuer confusion attack rejection).
D. Wrong resource (RFC 8707 resource mismatch rejection).
E. Wrong token endpoint (OAuth endpoint mix-up rejection).
F. Cross-origin redirect (cross-origin redirect forbidden during discovery).
G. Malformed WWW-Authenticate header (robust parameter parsing and safe fallback).
H. Malformed JSON metadata (unparseable JSON or schema violation).
I. 403 without OAuth challenge (distinct from 401 semantics).
J. Repeated 401 (bounded abort without infinite retry loops).
K. Missing metadata (all discovery URLs 404).
L. Unsupported auth configuration (non-Bearer scheme, missing token_endpoint).
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

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
import uvicorn

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import (
    MCPAuthRequirements,
    StrictSameOriginRedirectHandler,
    _is_same_origin,
    discover_mcp_auth_requirements,
    parse_www_authenticate_header,
)
from dmint.cli.mcp_connections import (
    MCPIntegration,
    MCPTransport,
    discover_mcp_tools_generic,
)


class MCPAuthDiscoveryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Bind ephemeral port on loopback
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.base_url = f"http://127.0.0.1:{cls.port}"

        # ---------------------------------------------------------------------
        # Route definitions for integration test scenarios
        # ---------------------------------------------------------------------

        # A. Valid PRM
        async def mcp_valid_prm(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/valid"'
                },
            )

        async def prm_valid(request):
            return JSONResponse(
                {
                    "resource": f"{cls.base_url}/mcp/valid-prm",
                    "authorization_servers": [f"{cls.base_url}/oauth"],
                    "scopes_supported": ["tools:read", "tools:write"],
                }
            )

        async def as_metadata_valid(request):
            return JSONResponse(
                {
                    "issuer": f"{cls.base_url}/oauth",
                    "authorization_endpoint": f"{cls.base_url}/oauth/authorize",
                    "token_endpoint": f"{cls.base_url}/oauth/token",
                    "registration_endpoint": f"{cls.base_url}/oauth/register",
                    "scopes_supported": ["tools:read", "tools:write"],
                    "code_challenge_methods_supported": ["S256"],
                }
            )

        # B. Multiple authorization servers
        async def mcp_multi_as(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/multi"'
                },
            )

        async def prm_multi(request):
            return JSONResponse(
                {
                    "resource": f"{cls.base_url}/mcp/multi-as",
                    "authorization_servers": [
                        f"{cls.base_url}/oauth-primary",
                        f"{cls.base_url}/oauth-secondary",
                    ],
                    "scopes_supported": ["read"],
                }
            )

        async def as_primary(request):
            return JSONResponse(
                {
                    "issuer": f"{cls.base_url}/oauth-primary",
                    "authorization_endpoint": f"{cls.base_url}/oauth-primary/authorize",
                    "token_endpoint": f"{cls.base_url}/oauth-primary/token",
                    "scopes_supported": ["read"],
                    "code_challenge_methods_supported": ["S256"],
                }
            )

        # C. Wrong issuer
        async def mcp_wrong_issuer(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/wrong-iss"'
                },
            )

        async def prm_wrong_iss(request):
            return JSONResponse(
                {
                    "resource": f"{cls.base_url}/mcp/wrong-issuer",
                    "authorization_servers": [f"{cls.base_url}/oauth-wrong-iss"],
                }
            )

        async def as_wrong_iss(request):
            return JSONResponse(
                {
                    "issuer": "http://127.0.0.1:9999/rogue-different-issuer",  # Mismatch!
                    "authorization_endpoint": f"{cls.base_url}/oauth-wrong-iss/authorize",
                    "token_endpoint": f"{cls.base_url}/oauth-wrong-iss/token",
                }
            )

        # D. Wrong resource
        async def mcp_wrong_resource(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/wrong-res"'
                },
            )

        async def prm_wrong_res(request):
            return JSONResponse(
                {
                    "resource": "http://127.0.0.1:9999/different-unrelated-resource",  # Mismatch!
                    "authorization_servers": [f"{cls.base_url}/oauth"],
                }
            )

        # E. Wrong token endpoint (mix-up)
        async def mcp_wrong_token(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/wrong-token"'
                },
            )

        async def prm_wrong_token(request):
            return JSONResponse(
                {
                    "resource": f"{cls.base_url}/mcp/wrong-token",
                    "authorization_servers": [f"{cls.base_url}/oauth-wrong-token"],
                }
            )

        async def as_wrong_token(request):
            return JSONResponse(
                {
                    "issuer": f"{cls.base_url}/oauth-wrong-token",
                    "authorization_endpoint": f"{cls.base_url}/oauth-wrong-token/authorize",
                    "token_endpoint": "https://attacker-token-harvest.com/token",  # Endpoint mix-up!
                }
            )

        # F. Cross-origin redirect
        async def mcp_cross_origin(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/prm-redirect"'},
            )

        async def prm_redirect(request):
            # Redirect to cross-origin URL
            return RedirectResponse("http://127.0.0.2:80/evil-cross-origin-target", status_code=302)

        # G. Malformed WWW-Authenticate header
        async def mcp_malformed_www_auth(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": '???invalid garbage=syntax, ==""'},
            )

        # H. Malformed JSON metadata
        async def mcp_malformed_json(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/corrupt"'
                },
            )

        async def prm_corrupt(request):
            return PlainTextResponse("<html><body>Not valid JSON</body></html>", status_code=200)

        # I. 403 without OAuth challenge
        async def mcp_plain_403(request):
            return Response("Forbidden", status_code=403)

        async def mcp_step_up_403(request):
            return Response(
                "Forbidden",
                status_code=403,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/stepup", error="insufficient_scope", scope="admin:write"'
                },
            )

        async def prm_stepup(request):
            return JSONResponse(
                {
                    "resource": f"{cls.base_url}/mcp/step-up-403",
                    "authorization_servers": [f"{cls.base_url}/oauth"],
                    "scopes_supported": ["tools:read", "tools:write", "admin:write"],
                }
            )

        # K. Missing metadata (404)
        async def mcp_missing_meta(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/nonexistent-meta"'},
            )

        # L. Unsupported auth configuration
        async def mcp_basic_auth(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="restricted-access"'},
            )

        async def mcp_missing_token_ep(request):
            return Response(
                "Unauthorized",
                status_code=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{cls.base_url}/.well-known/oauth-protected-resource/no-token-ep"'
                },
            )

        async def prm_no_token_ep(request):
            return JSONResponse(
                {
                    "resource": f"{cls.base_url}/mcp/missing-token-ep",
                    "authorization_servers": [f"{cls.base_url}/oauth-no-token"],
                }
            )

        async def as_no_token_ep(request):
            return JSONResponse(
                {
                    "issuer": f"{cls.base_url}/oauth-no-token",
                    "authorization_endpoint": f"{cls.base_url}/oauth-no-token/authorize",
                    # token_endpoint is omitted!
                }
            )

        routes = [
            # A
            Route("/mcp/valid-prm", mcp_valid_prm),
            Route("/.well-known/oauth-protected-resource/valid", prm_valid),
            Route("/oauth/.well-known/oauth-authorization-server", as_metadata_valid),
            Route("/.well-known/oauth-authorization-server/oauth", as_metadata_valid),
            # B
            Route("/mcp/multi-as", mcp_multi_as),
            Route("/.well-known/oauth-protected-resource/multi", prm_multi),
            Route("/oauth-primary/.well-known/oauth-authorization-server", as_primary),
            Route("/.well-known/oauth-authorization-server/oauth-primary", as_primary),
            # C
            Route("/mcp/wrong-issuer", mcp_wrong_issuer),
            Route("/.well-known/oauth-protected-resource/wrong-iss", prm_wrong_iss),
            Route("/oauth-wrong-iss/.well-known/oauth-authorization-server", as_wrong_iss),
            Route("/.well-known/oauth-authorization-server/oauth-wrong-iss", as_wrong_iss),
            # D
            Route("/mcp/wrong-resource", mcp_wrong_resource),
            Route("/.well-known/oauth-protected-resource/wrong-res", prm_wrong_res),
            # E
            Route("/mcp/wrong-token", mcp_wrong_token),
            Route("/.well-known/oauth-protected-resource/wrong-token", prm_wrong_token),
            Route("/oauth-wrong-token/.well-known/oauth-authorization-server", as_wrong_token),
            Route("/.well-known/oauth-authorization-server/oauth-wrong-token", as_wrong_token),
            # F
            Route("/mcp/cross-origin", mcp_cross_origin),
            Route("/prm-redirect", prm_redirect),
            # G
            Route("/mcp/malformed-www-auth", mcp_malformed_www_auth),
            # H
            Route("/mcp/malformed-json", mcp_malformed_json),
            Route("/.well-known/oauth-protected-resource/corrupt", prm_corrupt),
            # I
            Route("/mcp/plain-403", mcp_plain_403),
            Route("/mcp/step-up-403", mcp_step_up_403),
            Route("/.well-known/oauth-protected-resource/stepup", prm_stepup),
            # K
            Route("/mcp/missing-meta", mcp_missing_meta),
            # L
            Route("/mcp/basic-auth", mcp_basic_auth),
            Route("/mcp/missing-token-ep", mcp_missing_token_ep),
            Route("/.well-known/oauth-protected-resource/no-token-ep", prm_no_token_ep),
            Route("/oauth-no-token/.well-known/oauth-authorization-server", as_no_token_ep),
            Route("/.well-known/oauth-authorization-server/oauth-no-token", as_no_token_ep),
        ]

        app = Starlette(routes=routes)
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

    # -------------------------------------------------------------------------
    # Fixture A: Valid Protected-Resource Metadata
    # -------------------------------------------------------------------------
    def test_fixture_a_valid_protected_resource_metadata(self):
        """MCP server returning valid PRM and OASM resolves full trust chain."""
        integ = MCPIntegration(
            integration_id="valid-prm-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/valid-prm"},
        )
        reqs = discover_mcp_auth_requirements(integ)

        self.assertTrue(reqs.required)
        self.assertEqual(reqs.issuer, f"{self.base_url}/oauth")
        self.assertEqual(reqs.authorization_endpoint, f"{self.base_url}/oauth/authorize")
        self.assertEqual(reqs.token_endpoint, f"{self.base_url}/oauth/token")
        self.assertEqual(reqs.registration_endpoint, f"{self.base_url}/oauth/register")
        self.assertEqual(reqs.scopes, ["tools:read", "tools:write"])
        self.assertTrue(reqs.pkce_supported)

    # -------------------------------------------------------------------------
    # Fixture B: Multiple Authorization Servers
    # -------------------------------------------------------------------------
    def test_fixture_b_multiple_authorization_servers_selects_primary(self):
        """PRM advertising multiple authorization servers selects the primary (first)."""
        integ = MCPIntegration(
            integration_id="multi-as-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/multi-as"},
        )
        reqs = discover_mcp_auth_requirements(integ)

        self.assertTrue(reqs.required)
        self.assertEqual(reqs.issuer, f"{self.base_url}/oauth-primary")
        self.assertEqual(reqs.authorization_endpoint, f"{self.base_url}/oauth-primary/authorize")
        self.assertEqual(reqs.token_endpoint, f"{self.base_url}/oauth-primary/token")

    # -------------------------------------------------------------------------
    # Fixture C: Wrong Issuer
    # -------------------------------------------------------------------------
    def test_fixture_c_wrong_issuer_rejected(self):
        """Authorization server returning mismatched issuer is rejected (anti-issuer confusion)."""
        integ = MCPIntegration(
            integration_id="wrong-iss-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/wrong-issuer"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("issuer mismatch", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture D: Wrong Resource
    # -------------------------------------------------------------------------
    def test_fixture_d_wrong_resource_rejected(self):
        """PRM advertising a resource that doesn't match the MCP server is rejected per RFC 8707."""
        integ = MCPIntegration(
            integration_id="wrong-res-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/wrong-resource"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("wrong resource", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture E: Wrong Token Endpoint (Mix-up)
    # -------------------------------------------------------------------------
    def test_fixture_e_wrong_token_endpoint_mixup_rejected(self):
        """Token endpoint belonging to a foreign untrusted host is rejected (endpoint mix-up)."""
        integ = MCPIntegration(
            integration_id="wrong-token-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/wrong-token"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("endpoint mix-up", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture F: Cross-Origin Redirect
    # -------------------------------------------------------------------------
    def test_fixture_f_cross_origin_redirect_forbidden(self):
        """Cross-origin redirect during metadata discovery is rejected."""
        integ = MCPIntegration(
            integration_id="cross-origin-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/cross-origin"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("cross-origin redirect", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture G: Malformed WWW-Authenticate Header
    # -------------------------------------------------------------------------
    def test_fixture_g_malformed_www_authenticate_handled_cleanly(self):
        """Malformed WWW-Authenticate header does not crash and fails deterministically."""
        integ = MCPIntegration(
            integration_id="malformed-www-auth-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/malformed-www-auth"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("no valid oauth 2.0 / mcp authorization server metadata", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture H: Malformed JSON Metadata
    # -------------------------------------------------------------------------
    def test_fixture_h_malformed_json_metadata_rejected(self):
        """Discovery endpoint returning non-JSON or malformed payload is rejected."""
        integ = MCPIntegration(
            integration_id="malformed-json-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/malformed-json"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("malformed metadata", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture I: 403 Without OAuth Challenge
    # -------------------------------------------------------------------------
    def test_fixture_i_403_without_oauth_challenge_raises_distinct_error(self):
        """HTTP 403 without OAuth challenge is kept distinct from 401 and rejected immediately."""
        integ = MCPIntegration(
            integration_id="plain-403-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/plain-403"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        err_msg = str(ctx.exception)
        self.assertIn("Access forbidden (HTTP 403)", err_msg)
        self.assertIn("without an OAuth authorization challenge", err_msg)

    def test_fixture_i_403_with_step_up_scope_challenge_proceeds_to_discovery(self):
        """HTTP 403 with insufficient_scope error is treated as scope step-up challenge."""
        integ = MCPIntegration(
            integration_id="step-up-403-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/step-up-403"},
        )
        reqs = discover_mcp_auth_requirements(integ)
        self.assertTrue(reqs.required)
        self.assertIn("admin:write", reqs.scopes)

    # -------------------------------------------------------------------------
    # Fixture J: Repeated 401 Bounded Abort
    # -------------------------------------------------------------------------
    def test_fixture_j_repeated_401_aborts_bounded(self):
        """Repeated 401 failures terminate cleanly without infinite retry loops."""
        integ = MCPIntegration(
            integration_id="repeat-401-fixture",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/valid-prm"},
        )
        with patch("mcp.client.streamable_http.streamable_http_client", side_effect=Exception("HTTP 401 Unauthorized")):
            with self.assertRaises(CLIError) as ctx:
                asyncio.run(discover_mcp_tools_generic(integ))
        err_msg = str(ctx.exception)
        self.assertIn("401 Unauthorized", err_msg)

    # -------------------------------------------------------------------------
    # Fixture K: Missing Metadata (404)
    # -------------------------------------------------------------------------
    def test_fixture_k_missing_metadata_raises_actionable_error(self):
        """When discovery URLs return 404, fails with actionable error."""
        integ = MCPIntegration(
            integration_id="missing-meta-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/missing-meta"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("no valid oauth 2.0 / mcp authorization server metadata", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Fixture L: Unsupported Auth Configuration
    # -------------------------------------------------------------------------
    def test_fixture_l1_non_bearer_scheme_rejected(self):
        """WWW-Authenticate specifying non-Bearer scheme is rejected as unsupported."""
        integ = MCPIntegration(
            integration_id="basic-auth-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/basic-auth"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("unsupported authorization scheme", str(ctx.exception).lower())

    def test_fixture_l2_missing_token_endpoint_rejected(self):
        """Authorization server metadata missing token_endpoint is rejected."""
        integ = MCPIntegration(
            integration_id="no-token-ep-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": f"{self.base_url}/mcp/missing-token-ep"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("token_endpoint", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Security Rule Tests: Requirements 11 & 13
    # -------------------------------------------------------------------------
    def test_origin_equality_does_not_infer_trust_from_netloc_alone(self):
        """Origin trust check verifies scheme, host, and port, never netloc alone."""
        # Different scheme
        self.assertFalse(_is_same_origin("http://example.com/a", "https://example.com/b"))
        # Different port
        self.assertFalse(_is_same_origin("https://example.com:8080/a", "https://example.com:8443/b"))
        # Same origin with default port
        self.assertTrue(_is_same_origin("https://example.com:443/a", "https://example.com/b"))
        self.assertTrue(_is_same_origin("http://example.com:80/a", "http://example.com/b"))
        # Case insensitive host
        self.assertTrue(_is_same_origin("https://Example.COM/a", "https://example.com/b"))

    def test_strict_redirect_handler_detects_cross_origin(self):
        """StrictSameOriginRedirectHandler rejects any cross-origin redirection."""
        handler = StrictSameOriginRedirectHandler()
        req = urllib.request.Request("https://safe.example.com/start", method="GET")

        # Same origin is allowed
        res = handler.redirect_request(req, None, 302, "Found", {}, "https://safe.example.com/next")
        self.assertIsNotNone(res)

        # Cross origin is blocked
        with self.assertRaises(CLIError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "https://attacker.example.com/next")
        self.assertIn("cross-origin redirect", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
