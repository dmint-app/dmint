"""Tests for Dmint MCP Multi-Server Gateway (gateway.py)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

import mcp.types as types

from dmint.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
)
from dmint.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.errors import (
    ApprovalError,
    ApprovalRequiredError,
    AuthorizationError,
)
from dmint.models import Decision, NO_RESOURCE, TrustedContext
from dmint.policy import Policy, policy_digest
from dmint.storage import SQLiteApprovalStore

from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    GatewayIntegration,
    MCPError,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPMappingError,
    MCPProxyError,
    MCPTimeoutError,
    MCPToolBinding,
    MCPTransportType,
)
from dmint.mcp.client import DownstreamMCPClient


class MockDownstreamClient(DownstreamMCPClient):
    """Mock downstream client simulating an MCP server."""

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


class TestMCPGateway(unittest.IsolatedAsyncioTestCase):
    """Test suite for MCPGateway multi-server routing and enforcement."""

    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)
        self.db_path = str(self.tmppath / "approvals.db")

        # Authority and verifier
        self.authority = LocalApprovalAuthority(issuer_id="test-issuer", audience="gateway_epoch")
        self.verifier = ApprovalVerifier(
            trusted_issuers={"test-issuer": self.authority.public_key}, audience="gateway_epoch"
        )

        # Setup policy with rules:
        # 1. postgres.query -> ALLOW
        # 2. postgres.drop_table -> APPROVAL_REQUIRED
        # 3. mysql.query -> ALLOW
        # 4. mysql.drop_table -> APPROVAL_REQUIRED
        # 5. mysql.mysql_unique -> ALLOW
        # default: DENY
        self.policy = Policy.from_mapping(
            {
                "rules": [
                    {"tool": "postgres", "action": "query", "effect": "allow"},
                    {"tool": "postgres", "action": "drop_table", "effect": "approval_required"},
                    {"tool": "mysql", "action": "query", "effect": "allow"},
                    {"tool": "mysql", "action": "drop_table", "effect": "approval_required"},
                    {"tool": "mysql", "action": "mysql_unique", "effect": "allow"},
                ]
            }
        )

        self.provenance = PolicyProvenance(
            "v1",
            policy_digest(self.policy),
            datetime.now(timezone.utc),
        )

        # Integration 1: Postgres
        self.pg_cfg = MCPIntegrationConfig(
            integration_id="postgres",
            command="mcp-postgres",
            tool_bindings=[
                MCPToolBinding("query", "postgres.query", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("drop_table", "postgres.drop_table", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("secret_diag", "postgres.secret_diag", discovery=DiscoveryMode.HIDDEN),
            ],
        )

        # Integration 2: MySQL
        self.mysql_cfg = MCPIntegrationConfig(
            integration_id="mysql",
            command="mcp-mysql",
            tool_bindings=[
                MCPToolBinding("query", "mysql.query", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("drop_table", "mysql.drop_table", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("mysql_unique", "mysql.mysql_unique", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("mysql_denied", "mysql.mysql_denied", discovery=DiscoveryMode.EXPOSED),
            ],
        )

        self.gateway_config = MCPGatewayConfig(
            policy=self.policy,
            policy_file=None,
            policy_provenance=self.provenance,
            integrations=(self.pg_cfg, self.mysql_cfg),
            approval_store_path=self.db_path,
            approval_ttl=timedelta(minutes=30),
            disclosure_mode=DisclosureMode.DOG,
            agent_id="test-agent",
        )

        # Map of clients
        self.clients: dict[str, MockDownstreamClient] = {}

        def mock_factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            client = MockDownstreamClient(
                cfg,
                tools=[
                    types.Tool(name=b.tool_name, description=f"{cfg.integration_id} {b.tool_name}", inputSchema={})
                    for b in cfg.tool_bindings.values()
                ],
            )
            self.clients[cfg.integration_id] = client
            return client  # type: ignore

        self.gateway = MCPGateway(
            self.gateway_config,
            client_factory=mock_factory,
            approval_verifier=self.verifier,
        )

    async def asyncTearDown(self) -> None:
        if self.gateway.is_connected:
            await self.gateway.disconnect()
        self.tmpdir.cleanup()

    async def test_lifecycle_connect_and_disconnect(self) -> None:
        """Gateway connects and disconnects all downstream clients cleanly."""
        self.assertFalse(self.gateway.is_connected)
        await self.gateway.connect()
        self.assertTrue(self.gateway.is_connected)
        self.assertTrue(self.clients["postgres"].is_connected)
        self.assertTrue(self.clients["mysql"].is_connected)

        await self.gateway.disconnect()
        self.assertFalse(self.gateway.is_connected)
        self.assertFalse(self.clients["postgres"].is_connected)
        self.assertFalse(self.clients["mysql"].is_connected)

    async def test_tool_aggregation_and_discovery(self) -> None:
        """Gateway aggregates tools from all integrations, respecting discovery mode."""
        await self.gateway.connect()
        tools = await self.gateway.list_tools()
        tool_names = [t.name for t in tools.tools]

        # Exposed tools from postgres: query, drop_table (secret_diag is hidden)
        # Exposed tools from mysql: query, drop_table, mysql_unique, mysql_denied
        # Colliding tools must be exposed with namespace prefix:
        # postgres.query, mysql.query, postgres.drop_table, mysql.drop_table
        # Unique tools should be accessible as bare name or namespaced
        self.assertIn("postgres.query", tool_names)
        self.assertIn("mysql.query", tool_names)
        self.assertIn("postgres.drop_table", tool_names)
        self.assertIn("mysql.drop_table", tool_names)
        self.assertIn("mysql_unique", tool_names)

        # Hidden tool must NOT be listed
        self.assertNotIn("secret_diag", tool_names)
        self.assertNotIn("postgres.secret_diag", tool_names)

    async def test_tool_routing_namespaced(self) -> None:
        """Explicit dot and slash namespacing route to the exact downstream server."""
        await self.gateway.connect()

        # Dot notation: postgres.query
        res1 = await self.gateway.route_call("postgres.query", {"sql": "SELECT 1"})
        self.assertFalse(res1.is_error)
        self.assertEqual(len(self.clients["postgres"].call_log), 1)
        self.assertEqual(self.clients["postgres"].call_log[0], ("query", {"sql": "SELECT 1"}))

        # Slash notation: mysql/query
        res2 = await self.gateway.route_call("mysql/query", {"sql": "SELECT 2"})
        self.assertFalse(res2.is_error)
        self.assertEqual(len(self.clients["mysql"].call_log), 1)
        self.assertEqual(self.clients["mysql"].call_log[0], ("query", {"sql": "SELECT 2"}))

    async def test_tool_routing_unambiguous_bare_name(self) -> None:
        """Unambiguous bare tool name routes directly to the single server that owns it."""
        await self.gateway.connect()

        # mysql_unique exists only in mysql integration
        res = await self.gateway.route_call("mysql_unique", {"arg": "val"})
        self.assertFalse(res.is_error)
        self.assertEqual(self.clients["mysql"].call_log[-1], ("mysql_unique", {"arg": "val"}))

    async def test_tool_routing_ambiguous_bare_name_raises(self) -> None:
        """Ambiguous bare tool name matching multiple integrations raises DMT_MCP_TOOL_AMBIGUOUS."""
        await self.gateway.connect()

        # "query" is present in both postgres and mysql
        with self.assertRaises(MCPError) as ctx:
            await self.gateway.route_call("query", {"sql": "SELECT 1"})
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_AMBIGUOUS")
        self.assertIn("postgres.query", str(ctx.exception))
        self.assertIn("mysql.query", str(ctx.exception))

    async def test_tool_routing_unknown_tool_raises(self) -> None:
        """Unknown tool name raises DMT_MCP_TOOL_NOT_FOUND."""
        await self.gateway.connect()

        with self.assertRaises(MCPError) as ctx:
            await self.gateway.route_call("postgres.nonexistent", {})
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

        with self.assertRaises(MCPError) as ctx:
            await self.gateway.route_call("unknown_service.tool", {})
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

    async def test_enforcement_default_deny(self) -> None:
        """Calls to unconfigured or denied capabilities raise AuthorizationError."""
        await self.gateway.connect()

        # mysql_denied has no allow rule in policy -> default DENY
        with self.assertRaises(AuthorizationError) as ctx:
            await self.gateway.route_call("mysql.mysql_denied", {})
        self.assertEqual(ctx.exception.code, "DMT_POLICY_DENIED")

    async def test_enforcement_approval_required(self) -> None:
        """Calls to approval_required tools raise ApprovalRequiredError with challenge details."""
        await self.gateway.connect()

        with self.assertRaises(ApprovalRequiredError) as ctx:
            await self.gateway.route_call("postgres.drop_table", {"table": "users"})
        err = ctx.exception
        self.assertTrue(err.approval_id)
        self.assertTrue(err.request_fingerprint)
        self.assertTrue(err.request_id)

    async def test_cross_integration_approval_isolation(self) -> None:
        """An approval assertion issued for server A CANNOT be used on server B."""
        await self.gateway.connect()

        # 1. Trigger approval required on postgres.drop_table
        try:
            await self.gateway.route_call("postgres.drop_table", {"table": "accounts"})
            self.fail("Expected ApprovalRequiredError")
        except ApprovalRequiredError as exc:
            approval_err = exc

        # 2. Authority signs approval assertion specifically for postgres request
        record = self.gateway.approval_store.get(approval_err.approval_id)  # type: ignore
        self.assertIsNotNone(record)
        self.assertEqual(record.integration_id, "postgres")

        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.gateway.approval_store.save_approved(record.approve(approver))  # type: ignore

        # 3. Successful retry on postgres.drop_table
        retry_res = await self.gateway.retry_call(
            tool_name="postgres.drop_table",
            arguments={"table": "accounts"},
            approval_credential=assertion.to_bytes(),
        )
        self.assertFalse(retry_res.is_error)
        self.assertEqual(self.clients["postgres"].call_log[-1], ("drop_table", {"table": "accounts"}))

        # 4. Now simulate: attacker attempts to use the same assertion on mysql.drop_table
        # mysql has an identical drop_table tool, but different integration_id!
        with self.assertRaises(ApprovalError):
            await self.gateway.retry_call(
                tool_name="mysql.drop_table",
                arguments={"table": "accounts"},
                approval_credential=assertion.to_bytes(),
            )

    async def test_protocol_handler_retry_via_arguments(self) -> None:
        """_handle_call_tool detects _dmint_approval in arguments and routes to retry_call."""
        await self.gateway.connect()

        # Step 1: Call that requires approval via protocol handler
        res1 = await self.gateway._handle_call_tool(
            None,  # type: ignore
            types.CallToolRequestParams(name="postgres.drop_table", arguments={"table": "audit"}),
        )
        self.assertTrue(res1.is_error)
        self.assertIn("DMT_APPROVAL_REQUIRED", res1.content[0].text)  # type: ignore
        data = json.loads(res1.content[0].text)  # type: ignore
        approval_id = data["approval_id"]

        # Step 2: Sign assertion
        record = self.gateway.approval_store.get(approval_id)  # type: ignore
        self.assertIsNotNone(record)
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.gateway.approval_store.save_approved(record.approve(approver))  # type: ignore

        # Step 3: Call again with _dmint_approval embedded in arguments
        res2 = await self.gateway._handle_call_tool(
            None,  # type: ignore
            types.CallToolRequestParams(
                name="postgres.drop_table",
                arguments={
                    "table": "audit",
                    "_dmint_approval": assertion.to_bytes().decode("utf-8"),
                },
            ),
        )
        self.assertFalse(res2.is_error)
        self.assertIn("executed postgres:drop_table", res2.content[0].text)  # type: ignore

    async def test_downstream_timeout_formatted_cleanly(self) -> None:
        """When downstream client raises MCPTimeoutError, gateway formats DMT_MCP_TIMEOUT."""
        await self.gateway.connect()

        # Make client raise MCPTimeoutError
        async def mock_timeout(name: str, arguments: dict | None = None) -> types.CallToolResult:
            raise MCPTimeoutError("downstream server timed out after 5.0s")

        self.clients["postgres"].call_tool = mock_timeout  # type: ignore

        res = await self.gateway._handle_call_tool(
            None,  # type: ignore
            types.CallToolRequestParams(name="postgres.query", arguments={"sql": "SLEEP(100)"}),
        )
        self.assertTrue(res.is_error)
        self.assertIn("DMT_MCP_TIMEOUT", res.content[0].text)  # type: ignore


if __name__ == "__main__":
    unittest.main()
