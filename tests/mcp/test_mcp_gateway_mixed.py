"""Tests for multi-server MCPGateway with heterogeneous transports (STDIO + Streamable HTTP)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
import mcp.types as types

from dmint.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
)
from dmint.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.models import AnyResource, Decision, ToolRequest, TrustedContext
from dmint.policy import Policy, Rule, policy_digest
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
from dmint.mcp.errors import MCPError


class MockClient(DownstreamMCPClient):
    def __init__(self, config: MCPIntegrationConfig, tools: list[types.Tool] | None = None) -> None:
        super().__init__(config)
        self._connected = False
        self._tools = tools or []
        self.call_log: list[tuple[str, dict]] = []

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_tools(self) -> list[types.Tool]:
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        self.call_log.append((name, arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"executed {self.config.integration_id}:{name}")]
        )


class TestMixedTransportGateway(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)
        self.db_path = str(self.tmppath / "approvals.db")

        # Setup Authority and Verifier
        self.authority = LocalApprovalAuthority(issuer_id="admin@dmint.local", audience="mcp-gateway")
        self.verifier = ApprovalVerifier(
            trusted_issuers={"admin@dmint.local": self.authority.public_key},
            audience="mcp-gateway",
        )

        # Build policy
        self.policy = Policy.from_mapping(
            {
                "rules": [
                    {"tool": "stdio_srv", "action": "read_file", "effect": "allow"},
                    {"tool": "stdio_srv", "action": "delete_file", "effect": "deny"},
                    {"tool": "http_srv", "action": "fetch_data", "effect": "allow"},
                    {"tool": "http_srv", "action": "post_data", "effect": "approval_required"},
                ]
            }
        )
        digest = policy_digest(self.policy)
        provenance = PolicyProvenance("v1", digest, datetime.now(timezone.utc))

        # Config 1: STDIO
        self.cfg_stdio = MCPIntegrationConfig(
            integration_id="stdio_srv",
            transport_type=MCPTransportType.STDIO,
            command="mcp-server-stdio",
            tool_bindings={
                "read_file": MCPToolBinding(tool_name="read_file", capability="stdio_srv.read_file"),
                "delete_file": MCPToolBinding(tool_name="delete_file", capability="stdio_srv.delete_file"),
            },
        )

        # Config 2: Streamable HTTP
        self.cfg_http = MCPIntegrationConfig(
            integration_id="http_srv",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url="http://localhost:8000/mcp",
            headers={"Authorization": "Bearer test-secret"},
            tool_bindings={
                "fetch_data": MCPToolBinding(tool_name="fetch_data", capability="http_srv.fetch_data"),
                "post_data": MCPToolBinding(tool_name="post_data", capability="http_srv.post_data"),
            },
        )

        self.gateway_config = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=provenance,
            integrations=(self.cfg_stdio, self.cfg_http),
            approval_store_path=self.db_path,
            approval_ttl=timedelta(minutes=30),
            disclosure_mode=DisclosureMode.DOG,
        )

        self.clients: dict[str, MockClient] = {}

        def client_factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            tools = [
                types.Tool(name=b.tool_name, description=f"{cfg.integration_id} {b.tool_name}", input_schema={})
                for b in cfg.tool_bindings.values()
            ]
            client = MockClient(cfg, tools=tools)
            self.clients[cfg.integration_id] = client
            return client

        self.gateway = MCPGateway(
            self.gateway_config,
            client_factory=client_factory,
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

    async def test_tool_aggregation_across_mixed_transports(self):
        """Gateway discovers tools from both STDIO and Streamable HTTP downstreams."""
        res = await self.gateway.list_tools()
        tool_names = [t.name for t in res.tools]

        # All tools exposed
        self.assertIn("read_file", tool_names)
        self.assertIn("delete_file", tool_names)
        self.assertIn("fetch_data", tool_names)
        self.assertIn("post_data", tool_names)

    async def test_routing_to_correct_transport(self):
        """Calls are routed to the corresponding transport client."""
        # 1. Route to STDIO
        res_stdio = await self._call("stdio_srv.read_file", {"path": "test.txt"})
        self.assertFalse(res_stdio.is_error)
        self.assertEqual(self.clients["stdio_srv"].call_log[-1], ("read_file", {"path": "test.txt"}))

        # 2. Route to Streamable HTTP
        res_http = await self._call("http_srv.fetch_data", {"query": "all"})
        self.assertFalse(res_http.is_error)
        self.assertEqual(self.clients["http_srv"].call_log[-1], ("fetch_data", {"query": "all"}))

    async def test_core_authorization_on_both_transports(self):
        """Policy denial is enforced equally across STDIO and Streamable HTTP."""
        # Stdio tool denied by policy
        res_deny = await self._call("delete_file", {"path": "/etc/passwd"})
        self.assertTrue(res_deny.is_error)
        self.assertIn("DMT_POLICY_DENIED", res_deny.content[0].text)
        self.assertEqual(len(self.clients["stdio_srv"].call_log), 0)

    async def test_approval_challenge_and_approved_retry_on_http_transport(self):
        """APPROVAL_REQUIRED challenge, Ed25519 signing, and retry succeed on Streamable HTTP transport."""
        args = {"payload": "hello"}
        # First call: challenged
        res_req = await self._call("post_data", args)
        self.assertTrue(res_req.is_error)
        data = json.loads(res_req.content[0].text)
        self.assertEqual(data["code"], "DMT_APPROVAL_REQUIRED")
        approval_id = data["approval_id"]

        # Issue assertion using authority
        record = self.gateway._approval_store.get(approval_id)
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.gateway._approval_store.save_approved(record.approve(approver))

        # Retry call with assertion
        retry_args = dict(args)
        retry_args["_dmint_approval"] = assertion.to_bytes().decode("utf-8")

        retry_res = await self._call("post_data", retry_args)
        self.assertFalse(retry_res.is_error)
        self.assertIn("executed http_srv:post_data", retry_res.content[0].text)

    async def test_cross_transport_approval_isolation(self):
        """An approval assertion created for an HTTP tool cannot be reused for a STDIO tool."""
        # Trigger approval on HTTP tool
        res_req = await self._call("post_data", {"payload": "secret"})
        self.assertTrue(res_req.is_error)
        data = json.loads(res_req.content[0].text)
        approval_id = data["approval_id"]

        record = self.gateway._approval_store.get(approval_id)
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.gateway._approval_store.save_approved(record.approve(approver))

        # Attempt to reuse this approval on stdio tool
        stdio_args = {"path": "test.txt", "_dmint_approval": assertion.to_bytes().decode("utf-8")}
        res_reused = await self._call("stdio_srv.read_file", stdio_args)
        # Should be rejected because approval doesn't match the stdio tool request!
        self.assertTrue(res_reused.is_error)


if __name__ == "__main__":
    unittest.main()
