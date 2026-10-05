"""Unit tests for agent transport authentication and identity binding."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
import httpx2

from dmint.mcp.auth import (
    AgentAuthenticator,
    AgentAuthMiddleware,
    CURRENT_AGENT_ID,
)
from dmint.mcp.errors import MCPConfigurationError


class TestAgentAuthenticator(unittest.TestCase):
    """Tests for AgentAuthenticator credentials and verification."""

    def test_single_token_initialization(self):
        auth = AgentAuthenticator(single_token="secret_token_123", default_agent_id="test-agent")
        self.assertTrue(auth.has_tokens)
        self.assertEqual(auth.configured_agents, ["test-agent"])
        self.assertEqual(auth.authenticate("secret_token_123"), "test-agent")
        self.assertIsNone(auth.authenticate("wrong_token"))
        self.assertIsNone(auth.authenticate(""))
        self.assertIsNone(auth.authenticate(None))

    def test_token_mapping_initialization(self):
        auth = AgentAuthenticator(
            token_mapping={
                "tok_alpha": "agent_alpha",
                "tok_beta": "agent_beta",
            }
        )
        self.assertTrue(auth.has_tokens)
        self.assertEqual(auth.configured_agents, ["agent_alpha", "agent_beta"])
        self.assertEqual(auth.authenticate("tok_alpha"), "agent_alpha")
        self.assertEqual(auth.authenticate("tok_beta"), "agent_beta")
        self.assertIsNone(auth.authenticate("tok_gamma"))

    def test_from_spec_single_token(self):
        auth = AgentAuthenticator.from_spec("token_xyz", default_agent_id="worker")
        self.assertEqual(auth.authenticate("token_xyz"), "worker")

    def test_from_spec_mapping(self):
        auth = AgentAuthenticator.from_spec("token1=agent1,token2=agent2")
        self.assertEqual(auth.authenticate("token1"), "agent1")
        self.assertEqual(auth.authenticate("token2"), "agent2")
        self.assertIsNone(auth.authenticate("token3"))

    def test_from_spec_invalid(self):
        with self.assertRaises(MCPConfigurationError):
            AgentAuthenticator.from_spec("")
        with self.assertRaises(MCPConfigurationError):
            AgentAuthenticator.from_spec("   ")
        with self.assertRaises(MCPConfigurationError):
            AgentAuthenticator.from_spec("invalid=pair,malformed")

    def test_authenticate_header(self):
        auth = AgentAuthenticator(single_token="my_secret_token", default_agent_id="agent-1")
        # Valid header with Bearer
        self.assertEqual(auth.authenticate_header("Bearer my_secret_token"), "agent-1")
        # Case insensitive scheme
        self.assertEqual(auth.authenticate_header("bearer my_secret_token"), "agent-1")
        self.assertEqual(auth.authenticate_header("BEARER my_secret_token"), "agent-1")
        # Invalid scheme
        self.assertIsNone(auth.authenticate_header("Basic my_secret_token"))
        # Missing token
        self.assertIsNone(auth.authenticate_header("Bearer"))
        # Too many parts
        self.assertIsNone(auth.authenticate_header("Bearer extra token parts"))
        # Wrong token
        self.assertIsNone(auth.authenticate_header("Bearer bad_token"))
        # None or empty
        self.assertIsNone(auth.authenticate_header(None))
        self.assertIsNone(auth.authenticate_header(""))

    def test_invalid_agent_id_rejected(self):
        with self.assertRaises(MCPConfigurationError):
            AgentAuthenticator(single_token="tok", default_agent_id="  leading space")
        with self.assertRaises(MCPConfigurationError):
            AgentAuthenticator(single_token="tok", default_agent_id="")
        with self.assertRaises(MCPConfigurationError):
            AgentAuthenticator(token_mapping={"tok": ""})


class TestAgentAuthMiddleware(unittest.IsolatedAsyncioTestCase):
    """Tests for AgentAuthMiddleware ASGI request processing."""

    async def asyncSetUp(self):
        self.authenticator = AgentAuthenticator(
            token_mapping={
                "token_alice": "agent_alice",
                "token_bob": "agent_bob",
            },
            default_agent_id="default_agent",
        )

        async def endpoint(request: Request):
            return JSONResponse(
                {
                    "agent_id": request.state.agent_id,
                    "contextvar_agent": CURRENT_AGENT_ID.get(),
                }
            )

        async def crash_endpoint(request: Request):
            raise RuntimeError("Database connection string: postgresql://admin:secret@db.local/mcp")

        routes = [
            Route("/test", endpoint, methods=["GET", "POST"]),
            Route("/crash", crash_endpoint, methods=["GET"]),
        ]
        self.app = Starlette(routes=routes)
        self.app.add_middleware(
            AgentAuthMiddleware,
            authenticator=self.authenticator,
            default_agent_id="default_agent",
            max_request_body_size=1024,  # 1 KB for test
        )

    async def test_missing_auth_header_returns_401(self):
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/test")
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.headers.get("www-authenticate"), 'Bearer error="invalid_token"')
            data = resp.json()
            self.assertEqual(data["error"], "unauthorized")

    async def test_invalid_bearer_token_returns_401(self):
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/test", headers={"Authorization": "Bearer bad_token_12345"})
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.headers.get("www-authenticate"), 'Bearer error="invalid_token"')
            data = resp.json()
            self.assertEqual(data["error"], "unauthorized")
            # Ensure token is never echoed in error response
            self.assertNotIn("bad_token_12345", resp.text)

    async def test_valid_token_binds_identity_correctly(self):
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Alice
            resp_alice = await client.get("/test", headers={"Authorization": "Bearer token_alice"})
            self.assertEqual(resp_alice.status_code, 200)
            data_alice = resp_alice.json()
            self.assertEqual(data_alice["agent_id"], "agent_alice")
            self.assertEqual(data_alice["contextvar_agent"], "agent_alice")

            # Bob
            resp_bob = await client.get("/test", headers={"Authorization": "Bearer token_bob"})
            self.assertEqual(resp_bob.status_code, 200)
            data_bob = resp_bob.json()
            self.assertEqual(data_bob["agent_id"], "agent_bob")
            self.assertEqual(data_bob["contextvar_agent"], "agent_bob")

    async def test_oversize_body_rejected_with_413(self):
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            oversize_payload = "X" * 2048  # Exceeds 1024 limit
            resp = await client.post(
                "/test",
                content=oversize_payload,
                headers={
                    "Authorization": "Bearer token_alice",
                    "Content-Type": "text/plain",
                },
            )
            self.assertEqual(resp.status_code, 413)
            data = resp.json()
            self.assertEqual(data["error"], "payload_too_large")

    async def test_unhandled_server_crash_sanitized_to_500(self):
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get(
                "/crash",
                headers={"Authorization": "Bearer token_alice"},
            )
            self.assertEqual(resp.status_code, 500)
            data = resp.json()
            self.assertEqual(data["error"], "internal_error")
            # Critical: No credentials, connection strings, or stack traces leaked
            self.assertNotIn("postgresql://", resp.text)
            self.assertNotIn("secret@db.local", resp.text)
            self.assertNotIn("Traceback", resp.text)


if __name__ == "__main__":
    unittest.main()
