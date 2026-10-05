"""Concurrency, race condition, and replay attack tests for Dmint MCP Gateway."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from typing import Any
import unittest

import mcp.types as types

from dmint.approvals import ApprovalAuthority, ApprovalAuthorityKind, ApprovalRecord, ApprovalState, PolicyProvenance
from dmint.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.errors import ApprovalRequiredError
from dmint.models import AnyResource, Decision
from dmint.policy import Policy, Rule, policy_digest
from dmint.storage import SQLiteApprovalStore
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPToolBinding,
    MCPTransportType,
)
from dmint.mcp.client import DownstreamMCPClient

ISSUER = "local-sec-ops"
AUDIENCE = "dmint-gateway"


class ConcurrencyMockClient(DownstreamMCPClient):
    """Mock client tracking downstream execution counts under concurrency."""

    def __init__(self, config: MCPIntegrationConfig) -> None:
        super().__init__(config)
        self._connected = True
        self.call_count = 0
        self.call_history: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(name="read_data", inputSchema={"type": "object"}),
            types.Tool(name="delete_data", inputSchema={"type": "object"}),
        ]

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> types.CallToolResult:
        async with self._lock:
            self.call_count += 1
            self.call_history.append({"tool": tool_name, "arguments": arguments})
        # Simulate slight network jitter
        await asyncio.sleep(0.01)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"executed:{tool_name}:{self.call_count}")]
        )


class TestMCPConcurrencyAndReplay(unittest.IsolatedAsyncioTestCase):
    """Tests verifying concurrency safety and atomic replay defense."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temp_dir.name) / "approvals.db"

        self.authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE)
        self.verifier = ApprovalVerifier(trusted_issuers={ISSUER: self.authority.public_key}, audience=AUDIENCE)

        self.policy = Policy(
            rules=(
                Rule.allow("db", "read", resource=AnyResource()),
                Rule.approval_required("db", "delete", resource=AnyResource()),
            )
        )

        self.provenance = PolicyProvenance(
            "v1",
            policy_digest(self.policy),
            datetime.now(timezone.utc),
        )

        self.integ_cfg = MCPIntegrationConfig(
            integration_id="db",
            command="dummy-cmd",
            tool_bindings=[
                MCPToolBinding("read_data", "db.read", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("delete_data", "db.delete", discovery=DiscoveryMode.EXPOSED),
            ],
        )

        self.config = MCPGatewayConfig(
            server_name="concurrency-gateway",
            agent_id="concurrency-agent",
            policy=self.policy,
            policy_provenance=self.provenance,
            integrations=[self.integ_cfg],
            approval_store_path=self.store_path,
            disclosure_mode=DisclosureMode.DOG,
            approval_ttl=timedelta(minutes=10),
        )

        self.mock_client: ConcurrencyMockClient | None = None

        def client_factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            self.mock_client = ConcurrencyMockClient(cfg)
            return self.mock_client

        self.gateway = MCPGateway(
            self.config,
            client_factory=client_factory,
            approval_verifier=self.verifier,
        )
        await self.gateway.connect()

    async def asyncTearDown(self):
        await self.gateway.disconnect()
        self.temp_dir.cleanup()

    async def test_concurrent_independent_requests(self):
        """Gateway handles 20 concurrent tool calls without state collision."""
        tasks = [
            self.gateway.route_call(
                tool_name="read_data",
                arguments={"query_id": i},
                agent_id="concurrency-agent",
            )
            for i in range(20)
        ]
        results = await asyncio.gather(*tasks)

        self.assertEqual(len(results), 20)
        for res in results:
            self.assertFalse(res.is_error)
            self.assertIn("executed:read_data:", res.content[0].text)

        self.assertEqual(self.mock_client.call_count, 20)

    async def test_concurrent_replay_race_defense(self):
        """Two concurrent retry calls with identical approval token: exactly ONE executes downstream."""
        # 1. Trigger approval required
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await self.gateway.route_call(
                tool_name="delete_data",
                arguments={"table": "users"},
                agent_id="concurrency-agent",
            )
        approval_id = ctx.exception.approval_id
        fingerprint = ctx.exception.request_fingerprint

        # 2. Authority signs approval assertion and transitions record to APPROVED
        record = self.gateway.approval_store.get(approval_id)
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.gateway.approval_store.save_approved(record.approve(approver))
        cred_bytes = assertion.to_bytes()

        # 3. Two concurrent retries race to consume the approval
        async def do_retry():
            return await self.gateway.retry_call(
                tool_name="delete_data",
                arguments={"table": "users"},
                approval_credential=cred_bytes,
                agent_id="concurrency-agent",
            )

        results = await asyncio.gather(do_retry(), do_retry(), return_exceptions=True)

        # One should succeed (CallToolResult not is_error), the other must fail
        successes = [r for r in results if isinstance(r, types.CallToolResult) and not r.is_error]
        failures = [
            r for r in results if isinstance(r, Exception) or (isinstance(r, types.CallToolResult) and r.is_error)
        ]

        self.assertEqual(len(successes), 1, f"Expected exactly 1 success, got {len(successes)}")
        self.assertEqual(len(failures), 1, f"Expected exactly 1 failure, got {len(failures)}")

        # Verify downstream executed exactly once!
        self.assertEqual(self.mock_client.call_count, 1)

        # 4. Third retry also rejected (replay attack)
        third_res = await self.gateway._handle_call_tool(
            None,
            types.CallToolRequestParams(
                name="delete_data",
                arguments={"table": "users", "_dmint_approval": cred_bytes.decode("latin-1")},
            ),
        )
        self.assertTrue(third_res.is_error)
        self.assertEqual(self.mock_client.call_count, 1)


if __name__ == "__main__":
    unittest.main()
