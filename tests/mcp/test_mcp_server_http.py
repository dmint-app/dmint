"""Unit and integration tests for agent-facing HTTP transport security, binding, and error boundaries."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from starlette.applications import Starlette
import httpx2

from datetime import datetime, timezone
from dmint.approvals import PolicyProvenance
from dmint.policy import Policy, policy_digest
from dmint.mcp.auth import AgentAuthenticator
from dmint.mcp.config import (
    DisclosureMode,
    DiscoveryMode,
    MCPIntegrationConfig,
    MCPToolBinding,
    MCPTransportType,
)
from dmint.mcp.config_loader import MCPGatewayConfig
from dmint.mcp.errors import MCPConfigurationError
from dmint.mcp.gateway import MCPGateway


class TestMCPServerHTTP(unittest.TestCase):
    """Tests for agent-facing HTTP server setup, binding security, and CORS."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temp_dir.name) / "approvals.db"

        self.integration_cfg = MCPIntegrationConfig(
            integration_id="local-echo",
            transport_type=MCPTransportType.STDIO,
            command="python3",
            args=["-m", "echo"],
            tool_bindings={
                "echo": MCPToolBinding(
                    tool_name="echo",
                    capability="echo.run",
                    discovery=DiscoveryMode.EXPOSED,
                ),
            },
        )
        self.policy = Policy()
        self.provenance = PolicyProvenance(
            "v1",
            policy_digest(self.policy),
            datetime.now(timezone.utc),
        )
        self.gateway_config = MCPGatewayConfig(
            server_name="test-dmint-gateway",
            agent_id="test-agent",
            policy=self.policy,
            policy_provenance=self.provenance,
            integrations=[self.integration_cfg],
            approval_store_path=self.store_path,
            disclosure_mode=DisclosureMode.DOG,
        )
        self.gateway = MCPGateway(self.gateway_config)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_public_bind_without_auth_rejected(self):
        """Attempting to bind public host (0.0.0.0 or routable IP) without auth fails closed."""
        with self.assertRaises(MCPConfigurationError) as ctx:
            self.gateway.create_http_app(host="0.0.0.0", auth_token=None)
        self.assertIn("Cannot bind public host '0.0.0.0'", str(ctx.exception))

        with self.assertRaises(MCPConfigurationError) as ctx:
            self.gateway.create_http_app(host="192.168.1.50", auth_token=None)
        self.assertIn("Cannot bind public host '192.168.1.50'", str(ctx.exception))

    def test_public_bind_with_auth_allowed(self):
        """Binding public host with authenticated tokens succeeds."""
        app = self.gateway.create_http_app(host="0.0.0.0", auth_token="super_secret_token_123")
        self.assertIsInstance(app, Starlette)

    def test_loopback_bind_without_auth_allowed(self):
        """Loopback bindings (127.0.0.1, 127.0.0.2, localhost, ::1) are permitted for local development."""
        app1 = self.gateway.create_http_app(host="127.0.0.1")
        self.assertIsInstance(app1, Starlette)

        app2 = self.gateway.create_http_app(host="127.0.0.2")
        self.assertIsInstance(app2, Starlette)

        app3 = self.gateway.create_http_app(host="localhost")
        self.assertIsInstance(app3, Starlette)

        app4 = self.gateway.create_http_app(host="::1")
        self.assertIsInstance(app4, Starlette)

    def test_hostname_prefix_not_treated_as_loopback(self):
        """Hostnames starting with 127. such as 127.example.com must not be treated as loopback."""
        with self.assertRaises(MCPConfigurationError) as ctx:
            self.gateway.create_http_app(host="127.example.com", auth_token=None)
        self.assertIn("Cannot bind public host '127.example.com'", str(ctx.exception))

        with self.assertRaises(MCPConfigurationError) as ctx:
            self.gateway.create_http_app(host="8.8.8.8", auth_token=None)
        self.assertIn("Cannot bind public host '8.8.8.8'", str(ctx.exception))

        with self.assertRaises(MCPConfigurationError) as ctx:
            self.gateway.create_http_app(host="invalid!!host", auth_token=None)
        self.assertIn("Cannot bind public host 'invalid!!host'", str(ctx.exception))

    def test_wildcard_cors_with_auth_forbidden(self):
        """Wildcard CORS ('*') with authentication is strictly forbidden."""
        with self.assertRaises(MCPConfigurationError) as ctx:
            self.gateway.create_http_app(
                host="127.0.0.1",
                auth_token="secret_key",
                allowed_origins=["*"],
            )
        self.assertIn("Permissive wildcard CORS", str(ctx.exception))

    def test_explicit_cors_origins_allowed(self):
        """Explicit allowed origins list is accepted."""
        app = self.gateway.create_http_app(
            host="127.0.0.1",
            auth_token="secret_key",
            allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        )
        self.assertIsInstance(app, Starlette)


class TestMCPServerHTTPLimitsAndErrors(unittest.IsolatedAsyncioTestCase):
    """Tests for payload size limits and error boundary sanitization."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temp_dir.name) / "approvals.db"

        self.integration_cfg = MCPIntegrationConfig(
            integration_id="local-echo",
            transport_type=MCPTransportType.STDIO,
            command="python3",
            args=["-m", "echo"],
            tool_bindings={
                "echo": MCPToolBinding(
                    tool_name="echo",
                    capability="echo.run",
                    discovery=DiscoveryMode.EXPOSED,
                ),
            },
        )
        self.policy = Policy()
        self.provenance = PolicyProvenance(
            "v1",
            policy_digest(self.policy),
            datetime.now(timezone.utc),
        )
        self.gateway_config = MCPGatewayConfig(
            server_name="test-dmint-gateway",
            agent_id="test-agent",
            policy=self.policy,
            policy_provenance=self.provenance,
            integrations=[self.integration_cfg],
            approval_store_path=self.store_path,
            disclosure_mode=DisclosureMode.DOG,
        )
        self.gateway = MCPGateway(self.gateway_config)
        self.auth_token = "secret_gateway_token_999"
        self.app = self.gateway.create_http_app(
            host="127.0.0.1",
            auth_token=self.auth_token,
            max_request_body_size=512,  # 512 bytes limit for testing
        )

    async def asyncTearDown(self):
        await self.gateway.disconnect()
        self.temp_dir.cleanup()

    async def test_request_size_limit_rejection(self):
        """Requests with body exceeding max_request_body_size receive 413 Payload Too Large."""
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            oversize_body = "A" * 1024
            resp = await client.post(
                "/mcp",
                content=oversize_body,
                headers={
                    "Authorization": f"Bearer {self.auth_token}",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(resp.status_code, 413)
            data = resp.json()
            self.assertEqual(data["error"], "payload_too_large")

    async def test_auth_error_sanitization_no_token_leak(self):
        """Failed auth responses never leak configured secrets or internal tokens."""
        transport = httpx2.ASGITransport(app=self.app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            resp = await client.post(
                "/mcp",
                content='{"method": "tools/list"}',
                headers={
                    "Authorization": "Bearer totally_wrong_token",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(resp.status_code, 401)
            # Ensure none of our secrets or client tokens are leaked
            self.assertNotIn(self.auth_token, resp.text)
            self.assertNotIn("totally_wrong_token", resp.text)
            self.assertNotIn("Traceback", resp.text)
            self.assertNotIn("approvals.db", resp.text)


if __name__ == "__main__":
    unittest.main()
