"""Tests verifying the clean V1 contract between Dmint MCP and Dmint Core.

Verifies:
1. Complete decoupling from Core private internals (_dmint, __slots__, private fields).
2. End-to-end approval/retry handling over MCP tools/call protocol.
3. Clean MCP error translation (no -32603, no leaked tracebacks).
4. Bounded timeouts around downstream operations (initialize, list_tools, call_tool).
5. All security invariants (ALLOW, DENY, APPROVAL_REQUIRED, mutation rejection, replay prevention).
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

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
    ApprovalConsumedError,
    ApprovalExpiredError,
    ApprovalPolicyInvalidError,
    ApprovalRequestMismatchError,
    ApprovalRequiredError,
    AuthorizationError,
)
from dmint.models import AnyResource, Decision, TrustedContext
from dmint.policy import Policy, Rule, policy_digest
from dmint.storage import SQLiteApprovalStore
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    DmintMCPProxy,
    DownstreamMCPClient,
    EnforcementGate,
    MCPConfigurationError,
    MCPConnectionError,
    MCPError,
    MCPIntegrationConfig,
    MCPProtocolError,
    MCPTimeoutError,
    MCPToolBinding,
)


class MockHangingSession:
    """Mock ClientSession that hangs or raises to test timeouts and errors."""

    def __init__(self, hang_delay: float = 5.0) -> None:
        self.hang_delay = hang_delay

    async def initialize(self) -> None:
        await asyncio.sleep(self.hang_delay)

    async def list_tools(self) -> types.ListToolsResult:
        await asyncio.sleep(self.hang_delay)
        return types.ListToolsResult(tools=[])

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        await asyncio.sleep(self.hang_delay)
        return types.CallToolResult(content=[types.TextContent(type="text", text="delayed")])


class SpyDownstreamClient(DownstreamMCPClient):
    """Spy downstream client recording call counts and parameters."""

    def __init__(self, config: MCPIntegrationConfig, delay: float = 0.0) -> None:
        super().__init__(config)
        self.call_count = 0
        self.last_tool = None
        self.last_arguments = None
        self.delay = delay
        self.raise_on_call = None

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def list_tools(self) -> list[types.Tool]:
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        return [
            types.Tool(
                name="merge_pr",
                description="Merge a PR",
                inputSchema={"type": "object", "properties": {"pr_id": {"type": "string"}}},
            )
        ]

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        self.call_count += 1
        self.last_tool = name
        self.last_arguments = arguments
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        if self.raise_on_call is not None:
            raise self.raise_on_call
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"executed:{name}")])


AGENT_ID = "v1-test-agent"
TRUSTED_CTX = TrustedContext({"env": "prod", "cluster": "us-east"})
ISSUER = "v1-authority"
AUDIENCE = "v1-integration"


def make_config(**kwargs) -> MCPIntegrationConfig:
    base = dict(
        integration_id=AUDIENCE,
        command="python3",
        args=["-c", "pass"],
        tool_bindings={
            "merge_pr": MCPToolBinding(
                tool_name="merge_pr",
                capability="github.merge",
                resource_key="pr_id",
                discovery=DiscoveryMode.EXPOSED,
            ),
            "read_issue": MCPToolBinding(
                tool_name="read_issue",
                capability="github.read",
                discovery=DiscoveryMode.EXPOSED,
            ),
        },
        connect_timeout=0.1,
        call_timeout=0.1,
        list_timeout=0.1,
    )
    base.update(kwargs)
    return MCPIntegrationConfig(**base)


class MCPV1ContractTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "v1_approvals.db")
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="epoch_v1")
        self.authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE)
        self.verifier = ApprovalVerifier(trusted_issuers={ISSUER: self.authority.public_key}, audience=AUDIENCE)
        self.config = make_config()
        self.spy_client = SpyDownstreamClient(self.config)
        self.policy = Policy(
            rules=(
                Rule.allow("github", "read", resource=AnyResource()),
                Rule.approval_required("github", "merge", resource=AnyResource()),
            )
        )
        self.provenance = PolicyProvenance("v1", policy_digest(self.policy), datetime.now(timezone.utc))

    async def asyncTearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def create_proxy(self, policy=None, disclosure_mode=DisclosureMode.DOG, client=None) -> DmintMCPProxy:
        p = DmintMCPProxy(
            self.config,
            policy=policy or self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            approval_verifier=self.verifier,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=disclosure_mode,
        )
        p._gate = EnforcementGate(
            client or self.spy_client,
            self.config,
            policy=policy or self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            approval_verifier=self.verifier,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=disclosure_mode,
        )
        return p

    def approve_pending(self, record: ApprovalRecord) -> ApprovalAssertion:
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-admin", ApprovalAuthorityKind.HUMAN)
        assertion = self.authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))
        return assertion

    # -------------------------------------------------------------------------
    # 1. Zero Core Private Internals Coupling
    # -------------------------------------------------------------------------

    def test_zero_core_private_internals_access(self) -> None:
        """EnforcementGate must not store or access _dmint or Core private attributes."""
        proxy = self.create_proxy()
        gate = proxy.gate
        self.assertIsNotNone(gate)
        # Verify gate does not have _dmint
        self.assertFalse(hasattr(gate, "_dmint"), "EnforcementGate must not store _dmint")
        # Verify gate accesses public Policy and SQLiteApprovalStore
        self.assertIsInstance(gate.policy, Policy)
        self.assertIsInstance(gate._approval_store, SQLiteApprovalStore)
        self.assertIsInstance(gate._approval_verifier, ApprovalVerifier)

    # -------------------------------------------------------------------------
    # 2. Timeout Bounds on Downstream Operations
    # -------------------------------------------------------------------------

    async def test_call_tool_timeout_bounds_enforced(self) -> None:
        """A downstream call exceeding call_timeout raises MCPTimeoutError and produces a safe MCP error."""
        client = DownstreamMCPClient(self.config)
        client._session = MockHangingSession(hang_delay=1.0)  # call_timeout is 0.1
        proxy = self.create_proxy(client=client)

        params = types.CallToolRequestParams(name="read_issue", arguments={})
        result = await proxy._handle_call_tool(None, params)

        self.assertTrue(result.is_error)
        self.assertIn("DMT_MCP_TIMEOUT", result.content[0].text)
        self.assertIn("timed out", result.content[0].text)
        # Traceback must NOT be in the result
        self.assertNotIn("Traceback", result.content[0].text)

    async def test_config_timeout_validation(self) -> None:
        """Negative, zero, or boolean timeouts must be rejected."""
        with self.assertRaises(MCPConfigurationError):
            make_config(timeout=0)
        with self.assertRaises(MCPConfigurationError):
            make_config(timeout=-5)
        with self.assertRaises(MCPConfigurationError):
            make_config(call_timeout="not-a-number")
        with self.assertRaises(MCPConfigurationError):
            make_config(connect_timeout=True)

    # -------------------------------------------------------------------------
    # 3. Protocol-Level Approval and Retry in _handle_call_tool
    # -------------------------------------------------------------------------

    async def test_mcp_protocol_call_tool_approval_and_retry_flow(self) -> None:
        """Full round-trip approval and retry via tools/call protocol."""
        proxy = self.create_proxy()

        # Step 1: Initial call_tool returns approval_required structured payload
        initial_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={"pr_id": "PR-42", "title": "feature"},
        )
        res1 = await proxy._handle_call_tool(None, initial_params)
        self.assertTrue(res1.is_error)
        payload = json.loads(res1.content[0].text)
        self.assertEqual(payload["status"], "approval_required")
        self.assertEqual(payload["code"], "DMT_APPROVAL_REQUIRED")
        approval_id = payload["approval_id"]
        self.assertEqual(self.spy_client.call_count, 0)

        # Step 2: Out-of-band human approval
        record = self.store.get(approval_id)
        self.assertIsNotNone(record)
        assertion = self.approve_pending(record)

        # Step 3: Agent retries via tools/call with _dmint_approval in arguments (string)
        retry_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={
                "pr_id": "PR-42",
                "title": "feature",
                "_dmint_approval": assertion.to_bytes().decode("utf-8"),
            },
        )
        res2 = await proxy._handle_call_tool(None, retry_params)
        self.assertFalse(res2.is_error)
        self.assertEqual(res2.content[0].text, "executed:merge_pr")
        self.assertEqual(self.spy_client.call_count, 1)

        # Record is now CONSUMED
        self.assertEqual(self.store.get(approval_id).state, ApprovalState.CONSUMED)

    async def test_mcp_protocol_retry_with_dict_credential(self) -> None:
        """Retry via tools/call with approval credential passed as a parsed JSON dict."""
        proxy = self.create_proxy()
        params = types.CallToolRequestParams(name="merge_pr", arguments={"pr_id": "PR-50"})
        res1 = await proxy._handle_call_tool(None, params)
        data = json.loads(res1.content[0].text)
        record = self.store.get(data["approval_id"])
        assertion = self.approve_pending(record)

        # Retrying with dict format under approval_credential key
        retry_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={
                "pr_id": "PR-50",
                "approval_credential": json.loads(assertion.to_bytes()),
            },
        )
        res2 = await proxy._handle_call_tool(None, retry_params)
        self.assertFalse(res2.is_error)
        self.assertEqual(res2.content[0].text, "executed:merge_pr")
        self.assertEqual(self.spy_client.call_count, 1)

    async def test_mcp_protocol_retry_argument_mutation_rejected(self) -> None:
        """Attempting to alter arguments on retry via tools/call fails closed."""
        proxy = self.create_proxy()
        params = types.CallToolRequestParams(name="merge_pr", arguments={"pr_id": "PR-1"})
        res1 = await proxy._handle_call_tool(None, params)
        record = self.store.get(json.loads(res1.content[0].text)["approval_id"])
        assertion = self.approve_pending(record)

        # Retrying with mutated pr_id
        mutated_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={
                "pr_id": "PR-MUTATED",
                "_dmint_approval": assertion.to_bytes().decode("utf-8"),
            },
        )
        res2 = await proxy._handle_call_tool(None, mutated_params)
        self.assertTrue(res2.is_error)
        self.assertIn("DMT_APPROVAL_REQUEST_MISMATCH", res2.content[0].text)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_mcp_protocol_retry_replay_rejected(self) -> None:
        """Replaying an already consumed approval credential via tools/call fails closed."""
        proxy = self.create_proxy()
        params = types.CallToolRequestParams(name="merge_pr", arguments={"pr_id": "PR-ONCE"})
        res1 = await proxy._handle_call_tool(None, params)
        record = self.store.get(json.loads(res1.content[0].text)["approval_id"])
        assertion = self.approve_pending(record)

        retry_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={
                "pr_id": "PR-ONCE",
                "_dmint_approval": assertion.to_bytes().decode("utf-8"),
            },
        )
        # First retry: succeeds
        res2 = await proxy._handle_call_tool(None, retry_params)
        self.assertFalse(res2.is_error)
        self.assertEqual(self.spy_client.call_count, 1)

        # Second retry (replay): rejected
        res3 = await proxy._handle_call_tool(None, retry_params)
        self.assertTrue(res3.is_error)
        self.assertIn("DMT_APPROVAL_CONSUMED", res3.content[0].text)
        self.assertEqual(self.spy_client.call_count, 1)

    # -------------------------------------------------------------------------
    # 4. Clean Error Translation Boundary
    # -------------------------------------------------------------------------

    async def test_downstream_connection_failure_translation(self) -> None:
        """Downstream connection errors translate to clean MCP error results without -32603."""
        proxy = self.create_proxy()
        self.spy_client.raise_on_call = MCPConnectionError("downstream process pipe broken")

        params = types.CallToolRequestParams(name="read_issue", arguments={})
        result = await proxy._handle_call_tool(None, params)

        self.assertTrue(result.is_error)
        self.assertIn("DMT_MCP_CONNECTION_ERROR", result.content[0].text)
        self.assertIn("downstream process pipe broken", result.content[0].text)
        self.assertNotIn("Traceback", result.content[0].text)

    async def test_downstream_unexpected_error_sanitized(self) -> None:
        """Unexpected internal exceptions are sanitized and do not leak Python internals."""
        proxy = self.create_proxy()
        self.spy_client.raise_on_call = RuntimeError("unexpected database crash at /internal/db.sqlite")

        params = types.CallToolRequestParams(name="read_issue", arguments={})
        result = await proxy._handle_call_tool(None, params)

        self.assertTrue(result.is_error)
        self.assertIn("DMT_INTERNAL_ERROR", result.content[0].text)
        self.assertNotIn("Traceback", result.content[0].text)

    # -------------------------------------------------------------------------
    # 5. Security Invariants
    # -------------------------------------------------------------------------

    async def test_security_invariant_deny_zero_downstream_calls(self) -> None:
        """Policy DENY must result in zero downstream calls."""
        deny_policy = Policy(rules=(Rule.deny("github", "read", resource=AnyResource()),))
        proxy = self.create_proxy(policy=deny_policy)

        params = types.CallToolRequestParams(name="read_issue", arguments={})
        result = await proxy._handle_call_tool(None, params)

        self.assertTrue(result.is_error)
        self.assertIn("DMT_POLICY_DENIED", result.content[0].text)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_security_invariant_policy_change_invalidates_approved_retry(self) -> None:
        """If policy changes to DENY after approval, retry fails closed with zero calls."""
        proxy1 = self.create_proxy()
        params = types.CallToolRequestParams(name="merge_pr", arguments={"pr_id": "PR-DENIED-LATER"})
        res1 = await proxy1._handle_call_tool(None, params)
        record = self.store.get(json.loads(res1.content[0].text)["approval_id"])
        assertion = self.approve_pending(record)

        # New proxy with DENY policy
        deny_policy = Policy(rules=(Rule.deny("github", "merge", resource=AnyResource()),))
        proxy2 = self.create_proxy(policy=deny_policy)

        retry_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={
                "pr_id": "PR-DENIED-LATER",
                "_dmint_approval": assertion.to_bytes().decode("utf-8"),
            },
        )
        res2 = await proxy2._handle_call_tool(None, retry_params)
        self.assertTrue(res2.is_error)
        self.assertIn("DMT_APPROVAL_POLICY_INVALID", res2.content[0].text)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_security_invariant_allow_exactly_one_downstream_call(self) -> None:
        """Policy ALLOW must result in exactly one downstream call."""
        proxy = self.create_proxy()
        params = types.CallToolRequestParams(name="read_issue", arguments={})
        result = await proxy._handle_call_tool(None, params)
        self.assertFalse(result.is_error)
        self.assertEqual(result.content[0].text, "executed:read_issue")
        self.assertEqual(self.spy_client.call_count, 1)

    async def test_list_tools_timeout_bounds_enforced(self) -> None:
        """Downstream list_tools exceeding list_timeout raises MCPTimeoutError."""
        client = DownstreamMCPClient(self.config)
        client._session = MockHangingSession(hang_delay=1.0)  # list_timeout is 0.1
        with self.assertRaises(MCPTimeoutError):
            await client.list_tools()

    async def test_connect_timeout_bounds_enforced(self) -> None:
        """Downstream connect exceeding connect_timeout raises MCPTimeoutError."""
        # Test connect timeout by configuring a command that will hang or delay initialize
        config = make_config(
            command="python3",
            args=["-c", "import time; time.sleep(5)"],
            connect_timeout=0.05,
        )
        client = DownstreamMCPClient(config)
        with self.assertRaises((MCPTimeoutError, MCPConnectionError)):
            await client.connect()

    async def test_mcp_protocol_retry_tool_mismatch_rejected(self) -> None:
        """Retrying an approved credential against a different tool fails closed."""
        proxy = self.create_proxy()
        params = types.CallToolRequestParams(name="merge_pr", arguments={"pr_id": "PR-DIFF"})
        res1 = await proxy._handle_call_tool(None, params)
        record = self.store.get(json.loads(res1.content[0].text)["approval_id"])
        assertion = self.approve_pending(record)

        # Retrying against read_issue tool with merge_pr approval
        diff_tool_params = types.CallToolRequestParams(
            name="read_issue",
            arguments={"_dmint_approval": assertion.to_bytes().decode("utf-8")},
        )
        res2 = await proxy._handle_call_tool(None, diff_tool_params)
        self.assertTrue(res2.is_error)
        self.assertIn("DMT_APPROVAL_REQUEST_MISMATCH", res2.content[0].text)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_mcp_protocol_retry_expired_rejected(self) -> None:
        """Retrying an expired approval fails closed."""
        store_expired = SQLiteApprovalStore(
            self.db_path,
            deployment_epoch="epoch_v1",
            clock=lambda: datetime.now(timezone.utc) + timedelta(hours=5),
        )
        expired_proxy = DmintMCPProxy(
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=store_expired,
            approval_verifier=self.verifier,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            clock=lambda: datetime.now(timezone.utc) + timedelta(hours=5),
        )
        expired_proxy._gate = EnforcementGate(
            self.spy_client,
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=store_expired,
            approval_verifier=self.verifier,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            clock=lambda: datetime.now(timezone.utc) + timedelta(hours=5),
        )

        params = types.CallToolRequestParams(name="merge_pr", arguments={"pr_id": "PR-EXP"})
        proxy = self.create_proxy()
        res1 = await proxy._handle_call_tool(None, params)
        record = self.store.get(json.loads(res1.content[0].text)["approval_id"])
        assertion = self.approve_pending(record)

        # Retry on expired proxy
        retry_params = types.CallToolRequestParams(
            name="merge_pr",
            arguments={
                "pr_id": "PR-EXP",
                "_dmint_approval": assertion.to_bytes().decode("utf-8"),
            },
        )
        res2 = await expired_proxy._handle_call_tool(None, retry_params)
        self.assertTrue(res2.is_error)
        self.assertIn("DMT_APPROVAL_EXPIRED", res2.content[0].text)
        self.assertEqual(self.spy_client.call_count, 0)


if __name__ == "__main__":
    unittest.main()
