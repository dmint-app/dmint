"""Unit and integration tests for DownstreamMCPClient Streamable HTTP transport."""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import unittest

from mcp.server.mcpserver import MCPServer
import mcp.types as types
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import uvicorn

from dmint.mcp.client import DownstreamMCPClient
from dmint.mcp.config import MCPIntegrationConfig, MCPTransportType
from dmint.mcp.errors import MCPConnectionError, MCPTimeoutError


class TestStreamableHTTPClient(unittest.IsolatedAsyncioTestCase):
    """Tests for DownstreamMCPClient using Streamable HTTP transport."""

    @classmethod
    def setUpClass(cls):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.mcp_server = MCPServer("test-http-server")

        @cls.mcp_server.tool()
        def echo(message: str) -> str:
            """Echo message back."""
            return f"echo: {message}"

        @cls.mcp_server.tool()
        def slow_tool(delay: float) -> str:
            """Tool that sleeps to trigger timeouts."""
            time.sleep(delay)
            return "done"

        cls.base_app = cls.mcp_server.streamable_http_app()
        cls.captured_headers: list[dict[str, str]] = []
        cls.secret_token = "secret-token-xyz-123456"

        class AuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                auth = request.headers.get("authorization", "")
                custom = request.headers.get("x-custom-header", "")
                TestStreamableHTTPClient.captured_headers.append(
                    {
                        "path": request.url.path,
                        "authorization": auth,
                        "x-custom-header": custom,
                    }
                )
                if request.url.path.startswith("/mcp"):
                    # Check if endpoint requires auth
                    if request.headers.get("x-require-auth") == "true":
                        if not auth:
                            return Response("Unauthorized", status_code=401)
                        if auth != f"Bearer {TestStreamableHTTPClient.secret_token}":
                            return Response("Forbidden", status_code=403)
                return await call_next(request)

        cls.base_app.add_middleware(AuthMiddleware)

        cls.server_config = uvicorn.Config(
            cls.base_app,
            host="127.0.0.1",
            port=cls.port,
            log_level="error",
        )
        cls.uv_server = uvicorn.Server(cls.server_config)
        cls.server_thread = threading.Thread(target=cls.uv_server.run, daemon=True)
        cls.server_thread.start()

        for _ in range(50):
            time.sleep(0.05)
            if cls.uv_server.started:
                break

        cls.mcp_url = f"http://127.0.0.1:{cls.port}/mcp"

    @classmethod
    def tearDownClass(cls):
        cls.uv_server.should_exit = True
        cls.server_thread.join(timeout=3.0)

    def setUp(self):
        self.captured_headers.clear()

    async def test_successful_connect_list_and_call(self):
        """Client connects via streamable HTTP, discovers tools and executes tool calls."""
        config = MCPIntegrationConfig(
            integration_id="remote-srv",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=self.mcp_url,
            connect_timeout=10.0,
            call_timeout=10.0,
            list_timeout=10.0,
        )

        client = DownstreamMCPClient(config)
        self.assertFalse(client.is_connected)

        await client.connect()
        self.assertTrue(client.is_connected)

        try:
            tools = await client.list_tools()
            tool_names = [t.name for t in tools]
            self.assertIn("echo", tool_names)
            self.assertIn("slow_tool", tool_names)

            result = await client.call_tool("echo", {"message": "hello"})
            self.assertFalse(result.isError if hasattr(result, "isError") else False)
            text = result.content[0].text
            self.assertIn("echo: hello", text)
        finally:
            await client.disconnect()

        self.assertFalse(client.is_connected)

    async def test_headers_propagation(self):
        """Configured headers (Authorization and custom) reach the downstream server."""
        config = MCPIntegrationConfig(
            integration_id="remote-srv",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=self.mcp_url,
            headers={
                "Authorization": f"Bearer {self.secret_token}",
                "X-Custom-Header": "dmint-test-header-val",
            },
        )

        client = DownstreamMCPClient(config)
        await client.connect()
        try:
            await client.list_tools()
            # Verify captured headers contain our custom header and authorization
            auth_headers = [h["authorization"] for h in self.captured_headers if h["authorization"]]
            custom_headers = [h["x-custom-header"] for h in self.captured_headers if h["x-custom-header"]]
            self.assertTrue(any(f"Bearer {self.secret_token}" in h for h in auth_headers))
            self.assertIn("dmint-test-header-val", custom_headers)
        finally:
            await client.disconnect()

    async def test_secret_redaction_on_auth_failure(self):
        """When 401/403 or connection errors occur, configured secrets are redacted from errors."""
        config = MCPIntegrationConfig(
            integration_id="remote-srv",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=self.mcp_url,
            headers={
                "Authorization": f"Bearer wrong-secret-value-9999",
                "X-Require-Auth": "true",
            },
            connect_timeout=3.0,
        )

        client = DownstreamMCPClient(config)
        with self.assertRaises(MCPConnectionError) as ctx:
            await client.connect()

        err_msg = str(ctx.exception)
        self.assertNotIn("wrong-secret-value-9999", err_msg)
        self.assertTrue("403" in err_msg or "401" in err_msg or "forbidden" in err_msg.lower())

    async def test_connection_refused_error_mapping(self):
        """Connection to non-listening port raises MCPConnectionError."""
        # Find unused port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            unused_port = s.getsockname()[1]

        config = MCPIntegrationConfig(
            integration_id="dead-srv",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=f"http://127.0.0.1:{unused_port}/mcp",
            connect_timeout=2.0,
        )

        client = DownstreamMCPClient(config)
        with self.assertRaises(MCPConnectionError) as ctx:
            await client.connect()
        self.assertIn("could not connect", str(ctx.exception).lower())

    async def test_call_timeout_expiration(self):
        """Slow tool execution exceeds call_timeout and raises MCPTimeoutError."""
        config = MCPIntegrationConfig(
            integration_id="remote-srv",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=self.mcp_url,
            call_timeout=0.5,
        )

        client = DownstreamMCPClient(config)
        await client.connect()
        try:
            with self.assertRaises(MCPTimeoutError) as ctx:
                await client.call_tool("slow_tool", {"delay": 2.0})
            self.assertIn("timed out after 0.5s", str(ctx.exception))
        finally:
            await client.disconnect()


if __name__ == "__main__":
    unittest.main()
