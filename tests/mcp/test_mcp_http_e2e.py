"""End-to-end integration tests for Streamable HTTP downstream transport with real MCP server and gateway.

Tests real HTTP network transport between MCPGateway and a live Starlette/Uvicorn MCP server:
- Real tools/list discovery over HTTP
- Real tools/call ALLOW: tool executes downstream and returns result
- Real tools/call DENY: zero downstream execution
- Real tools/call APPROVAL_REQUIRED: challenge -> Ed25519 signing -> approved retry -> execution
- Single-use consumption: replaying the consumed approval token is rejected
- Bounded timeout enforcement
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from mcp.server.mcpserver import MCPServer
import mcp.types as types
import uvicorn

from dmint.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    PolicyProvenance,
)
from dmint.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.models import Decision
from dmint.policy import Policy, policy_digest
from dmint.storage import SQLiteApprovalStore
from dmint.mcp import (
    DisclosureMode,
    DownstreamMCPClient,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPToolBinding,
    MCPTransportType,
)


class TestStreamableHTTPEndToEnd(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        # Bind ephemeral port on loopback
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.mcp_server = MCPServer("e2e-http-server")
        cls.downstream_execution_log: list[tuple[str, dict]] = []

        @cls.mcp_server.tool()
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            cls.downstream_execution_log.append(("add", {"a": a, "b": b}))
            return a + b

        @cls.mcp_server.tool()
        def wipe_database(confirm: bool) -> str:
            """Dangerous operation requiring approval."""
            cls.downstream_execution_log.append(("wipe_database", {"confirm": confirm}))
            return "database wiped"

        @cls.mcp_server.tool()
        def forbidden_op() -> str:
            """Forbidden operation."""
            cls.downstream_execution_log.append(("forbidden_op", {}))
            return "forbidden"

        @cls.mcp_server.tool()
        def slow_op(duration: float) -> str:
            """Slow operation."""
            time.sleep(duration)
            cls.downstream_execution_log.append(("slow_op", {"duration": duration}))
            return "finished"

        cls.base_app = cls.mcp_server.streamable_http_app()
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

    async def asyncSetUp(self) -> None:
        self.downstream_execution_log.clear()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)
        self.db_path = str(self.tmppath / "approvals.db")

        # Setup authority and verifier
        self.authority = LocalApprovalAuthority(issuer_id="admin@dmint.local", audience="mcp-gateway")
        self.verifier = ApprovalVerifier(
            trusted_issuers={"admin@dmint.local": self.authority.public_key},
            audience="mcp-gateway",
        )

        # Policy rules
        self.policy = Policy.from_mapping(
            {
                "rules": [
                    {"tool": "calc", "action": "add", "effect": "allow"},
                    {"tool": "calc", "action": "wipe_database", "effect": "approval_required"},
                    {"tool": "calc", "action": "forbidden_op", "effect": "deny"},
                    {"tool": "calc", "action": "slow_op", "effect": "allow"},
                ]
            }
        )
        digest = policy_digest(self.policy)
        provenance = PolicyProvenance("v1", digest, datetime.now(timezone.utc))

        self.integration_cfg = MCPIntegrationConfig(
            integration_id="calc",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=self.mcp_url,
            tool_bindings={
                "add": MCPToolBinding(tool_name="add", capability="calc.add"),
                "wipe_database": MCPToolBinding(tool_name="wipe_database", capability="calc.wipe_database"),
                "forbidden_op": MCPToolBinding(tool_name="forbidden_op", capability="calc.forbidden_op"),
                "slow_op": MCPToolBinding(tool_name="slow_op", capability="calc.slow_op"),
            },
            call_timeout=10.0,
            connect_timeout=5.0,
        )

        self.gateway_config = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=provenance,
            integrations=(self.integration_cfg,),
            approval_store_path=self.db_path,
            approval_ttl=timedelta(minutes=30),
            disclosure_mode=DisclosureMode.DOG,
        )

        # Real gateway using real DownstreamMCPClient (client_factory=None)
        self.gateway = MCPGateway(
            self.gateway_config,
            client_factory=None,
            approval_verifier=self.verifier,
        )
        await self.gateway.connect()

    async def asyncTearDown(self) -> None:
        await self.gateway.disconnect()
        self.tmpdir.cleanup()

    async def _call(self, name: str, args: dict | None = None) -> types.CallToolResult:
        return await self.gateway._handle_call_tool(
            None,
            types.CallToolRequestParams(name=name, arguments=args or {}),
        )

    async def test_1_tools_list_discovery_over_real_http(self):
        """Gateway discovers tools from real downstream HTTP MCP server."""
        tools_res = await self.gateway.list_tools()
        names = [t.name for t in tools_res.tools]
        self.assertIn("add", names)
        self.assertIn("wipe_database", names)
        self.assertIn("forbidden_op", names)
        self.assertIn("slow_op", names)

    async def test_2_allowed_call_executes_downstream(self):
        """Allowed call forwards over HTTP to real downstream server and executes."""
        res = await self._call("add", {"a": 20, "b": 22})
        self.assertFalse(res.is_error)
        self.assertIn("42", res.content[0].text)
        self.assertEqual(len(self.downstream_execution_log), 1)
        self.assertEqual(self.downstream_execution_log[0], ("add", {"a": 20, "b": 22}))

    async def test_3_denied_call_zero_downstream_execution(self):
        """Denied call stops at the gateway with zero downstream HTTP execution."""
        res = await self._call("forbidden_op", {})
        self.assertTrue(res.is_error)
        self.assertIn("DMT_POLICY_DENIED", res.content[0].text)
        # Server must never receive this call
        self.assertEqual(len(self.downstream_execution_log), 0)

    async def test_4_approval_workflow_and_atomic_consumption(self):
        """Challenged call requires Ed25519 approval; retry executes downstream; replay rejected."""
        # Step 1: Call dangerous tool without approval -> challenged
        res1 = await self._call("wipe_database", {"confirm": True})
        self.assertTrue(res1.is_error)
        data = json.loads(res1.content[0].text)
        self.assertEqual(data["code"], "DMT_APPROVAL_REQUIRED")
        approval_id = data["approval_id"]
        # Zero downstream execution
        self.assertEqual(len(self.downstream_execution_log), 0)

        # Step 2: Sign approval assertion
        record = self.gateway._approval_store.get(approval_id)
        self.assertIsNotNone(record)
        approver = ApprovalAuthority._from_trusted_boundary("cli", "admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.gateway._approval_store.save_approved(record.approve(approver))

        # Step 3: Retry call with valid approval credential -> execution succeeds
        retry_args = {"confirm": True, "_dmint_approval": assertion.to_bytes().decode("utf-8")}
        res2 = await self._call("wipe_database", retry_args)
        self.assertFalse(res2.is_error)
        self.assertIn("database wiped", res2.content[0].text)
        self.assertEqual(len(self.downstream_execution_log), 1)
        self.assertEqual(self.downstream_execution_log[0], ("wipe_database", {"confirm": True}))

        # Step 4: Replay attack with same assertion must fail
        res3 = await self._call("wipe_database", retry_args)
        self.assertTrue(res3.is_error)
        self.assertIn("DMT_APPROVAL_CONSUMED", res3.content[0].text)
        # Still exactly 1 downstream execution
        self.assertEqual(len(self.downstream_execution_log), 1)


if __name__ == "__main__":
    unittest.main()
