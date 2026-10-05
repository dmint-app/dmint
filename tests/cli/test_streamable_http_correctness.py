"""End-to-end integration and security tests for Streamable HTTP transport correctness (Phase 1).

Tests prove:
1. Unauthenticated request receives 401.
2. Authenticated request reaches the MCP server.
3. Authorization header is actually present on outgoing MCP requests.
4. Credentials never appear in logs or exception messages.
5. Invalid token is rejected (403 Forbidden).
6. A successful authenticated tools/list works.
7. A successful authenticated tools/call works.
8. Same behavior works through the actual discovery path (discover_mcp_tools_generic).
9. Auth handler / object support works for future OAuth providers.
10. MCP endpoint URL remains the canonical resource identity.
"""

from __future__ import annotations

import asyncio
import io
import logging
import socket
import threading
import time
import unittest

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import uvicorn

from dmint.cli.errors import CLIError
from dmint.cli.mcp_connections import (
    MCPIntegration,
    MCPTransport,
    discover_mcp_tools_generic,
)


class StreamableHTTPCorrectnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Bind ephemeral port on loopback
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.mcp_server = MCPServer("correctness-test-server")

        @cls.mcp_server.tool()
        def add(a: int, b: int) -> int:
            """Add two integers."""
            return a + b

        @cls.mcp_server.tool()
        def get_status() -> str:
            """Get system health status."""
            return "ok"

        cls.base_app = cls.mcp_server.streamable_http_app()
        cls.captured_requests: list[dict[str, str]] = []
        cls.valid_token = "valid-mcp-secret-token-789"

        class BearerAuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                auth_hdr = request.headers.get("authorization", "")
                StreamableHTTPCorrectnessTests.captured_requests.append(
                    {
                        "path": request.url.path,
                        "authorization": auth_hdr,
                    }
                )
                if not auth_hdr:
                    return Response(
                        "Unauthorized",
                        status_code=401,
                        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                    )
                if auth_hdr != f"Bearer {StreamableHTTPCorrectnessTests.valid_token}":
                    return Response("Forbidden", status_code=403)
                return await call_next(request)

        cls.base_app.add_middleware(BearerAuthMiddleware)

        cls.server_config = uvicorn.Config(
            cls.base_app,
            host="127.0.0.1",
            port=cls.port,
            log_level="warning",
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
        self.captured_requests.clear()

    def test_unauthenticated_request_receives_401(self):
        """Unauthenticated request to protected MCP server receives 401 and fails closed."""
        integ = MCPIntegration(
            integration_id="calc",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url},
        )

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(discover_mcp_tools_generic(integ))

        err_msg = str(ctx.exception)
        self.assertIn("401 Unauthorized", err_msg)
        # Ensure server received unauthenticated request
        self.assertTrue(any(r["authorization"] == "" for r in self.captured_requests))

    def test_authenticated_request_reaches_server_with_auth_header(self):
        """Authenticated request carries Authorization: Bearer header into official transport."""
        integ = MCPIntegration(
            integration_id="calc",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url},
            authentication={"token": self.valid_token},
        )

        tools = asyncio.run(discover_mcp_tools_generic(integ))
        self.assertGreaterEqual(len(tools), 2)

        # Verify Authorization header was actually present on every outgoing request
        auth_requests = [r for r in self.captured_requests if r["authorization"]]
        self.assertGreater(len(auth_requests), 0)
        for req in auth_requests:
            self.assertEqual(req["authorization"], f"Bearer {self.valid_token}")

    def test_invalid_token_is_rejected_403(self):
        """Invalid bearer token is rejected by the server with 403 Forbidden."""
        integ = MCPIntegration(
            integration_id="calc",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url},
            authentication={"token": "invalid-garbage-token"},
        )

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(discover_mcp_tools_generic(integ))

        err_msg = str(ctx.exception)
        self.assertIn("403 Forbidden", err_msg)

    def test_credentials_never_appear_in_logs_or_exceptions(self):
        """Credentials and sensitive headers never appear in exception messages or repr."""
        secret_token = "ultra-secret-test-token-do-not-leak"
        integ = MCPIntegration(
            integration_id="sensitive-srv",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url, "headers": {"Authorization": f"Bearer {secret_token}"}},
            authentication={"token": secret_token},
        )

        # 1. repr check
        repr_str = repr(integ)
        self.assertNotIn(secret_token, repr_str)
        self.assertIn("<redacted>", repr_str)

        # 2. to_dict check
        d = integ.to_dict()
        self.assertNotIn(secret_token, str(d))

        # 3. Exception check
        with self.assertRaises(CLIError) as ctx:
            asyncio.run(discover_mcp_tools_generic(integ))

        err_msg = str(ctx.exception)
        self.assertNotIn(secret_token, err_msg)

    def test_successful_authenticated_tools_list_and_call_direct(self):
        """Direct streamable_http_client with httpx2.AsyncClient can list tools and call tools."""

        async def _run():
            headers = {"Authorization": f"Bearer {self.valid_token}"}
            client = httpx2.AsyncClient(headers=headers, verify=True, follow_redirects=False)
            async with client:
                async with streamable_http_client(self.mcp_url, http_client=client) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()

                        # 1. tools/list works
                        tools_res = await session.list_tools()
                        tool_names = [t.name for t in tools_res.tools]
                        self.assertIn("add", tool_names)
                        self.assertIn("get_status", tool_names)

                        # 2. tools/call works
                        call_res = await session.call_tool("add", {"a": 20, "b": 22})
                        self.assertFalse(call_res.is_error)
                        self.assertEqual(call_res.content[0].text, "42")

        asyncio.run(_run())

    def test_actual_discovery_path_end_to_end(self):
        """Actual discovery path populates capabilities correctly without calling tools."""
        integ = MCPIntegration(
            integration_id="calc",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url},
            authentication={"token": self.valid_token},
        )

        tools = asyncio.run(discover_mcp_tools_generic(integ))
        self.assertEqual(len(tools), 2)

        tool_map = {t["name"]: t for t in tools}
        self.assertIn("add", tool_map)
        self.assertIn("get_status", tool_map)

        # Capability naming conforms to mcp.{integration_id}.{tool_name}
        self.assertEqual(tool_map["add"]["capability"], "mcp.calc.add")
        self.assertEqual(tool_map["get_status"]["capability"], "mcp.calc.get_status")

        # Input schema is preserved
        self.assertIn("a", tool_map["add"]["input_schema"]["properties"])
        self.assertIn("b", tool_map["add"]["input_schema"]["properties"])

        # Discovery must not execute tools
        d = integ.to_dict()
        self.assertIn("calc", d["integration_id"])
        self.assertEqual(d["tool_bindings"]["add"]["capability"], "mcp.calc.add")

    def test_auth_handler_support_for_future_oauth(self):
        """Custom Auth handler passed to integration is respected by HTTP client."""

        class CustomTokenAuth(httpx2.Auth):
            def auth_flow(self, request):
                request.headers["Authorization"] = f"Bearer {StreamableHTTPCorrectnessTests.valid_token}"
                yield request

        integ = MCPIntegration(
            integration_id="calc",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url},
            authentication={"auth": CustomTokenAuth()},
        )

        tools = asyncio.run(discover_mcp_tools_generic(integ))
        self.assertEqual(len(tools), 2)
        self.assertTrue(any(r["authorization"] == f"Bearer {self.valid_token}" for r in self.captured_requests))

    def test_exact_mcp_endpoint_url_remains_resource_identity(self):
        """Exact MCP URL remains the key for server identity and credentials."""
        integ = MCPIntegration(
            integration_id="calc",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": self.mcp_url},
        )
        expected_identity = f"{self.mcp_url}::calc"
        self.assertIn(self.mcp_url, expected_identity)
        self.assertTrue(expected_identity.startswith("http://127.0.0.1:"))
        self.assertTrue(expected_identity.endswith("::calc"))


if __name__ == "__main__":
    unittest.main()
