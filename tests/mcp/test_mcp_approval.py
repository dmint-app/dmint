"""Tests for MCP APPROVAL_REQUIRED persistence, disclosure, and security (MCP-7)."""

from datetime import datetime, timedelta, timezone
import asyncio
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock

from dmint.approvals import PolicyProvenance, ApprovalRecord, ApprovalState
from dmint.authority import LocalApprovalAuthority
from dmint.errors import ApprovalRequiredError, AuthorizationError
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    DmintMCPProxy,
    DownstreamMCPClient,
    EnforcementGate,
    MCPIntegrationConfig,
    MCPToolBinding,
)
from dmint.models import AnyResource, NO_RESOURCE, TrustedContext
from dmint.policy import Policy, Rule, policy_digest
from dmint.storage import SQLiteApprovalStore
from dmint.versions import REQUEST_BINDING_VERSION, CANONICALIZATION_PROFILE
from dmint.core.webhooks import WebhookNotifier


class SpyDownstreamClient(DownstreamMCPClient):
    """Spy downstream client recording call count."""

    def __init__(self, config: MCPIntegrationConfig) -> None:
        super().__init__(config)
        self.call_count = 0

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def call_tool(self, name: str, arguments: dict | None = None):
        self.call_count += 1
        return f"executed:{name}"


AGENT_ID = "trusted-agent"
TRUSTED_CTX = TrustedContext({"env": "prod", "dept": "finance"})


def make_config():
    return MCPIntegrationConfig(
        integration_id="github-prod",
        command="python3",
        args=["-c", "pass"],
        tool_bindings={
            "merge_pr": MCPToolBinding(
                tool_name="merge_pr",
                capability="github.merge",
                resource_key="pr_id",
                discovery=DiscoveryMode.EXPOSED,
            ),
            "delete_repo": MCPToolBinding(
                tool_name="delete_repo",
                capability="github.delete",
                resource_key="repo_id",
                discovery=DiscoveryMode.HIDDEN,
            ),
        },
    )


class MCPApprovalSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "approvals.db")
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="ep_1")
        self.config = make_config()
        self.spy_client = SpyDownstreamClient(self.config)
        self.policy = Policy(
            rules=(
                Rule.approval_required("github", "merge", resource=AnyResource()),
                Rule.approval_required("github", "delete", resource=AnyResource()),
            )
        )
        self.provenance = PolicyProvenance("v1", policy_digest(self.policy), datetime.now(timezone.utc))

    async def asyncTearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def create_gate(self, disclosure_mode=DisclosureMode.DOG, webhook_notifier=None) -> EnforcementGate:
        return EnforcementGate(
            self.spy_client,
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=disclosure_mode,
            webhook_notifier=webhook_notifier,
        )

    async def test_1_approval_required_creates_exactly_one_pending_workflow(self):
        gate = self.create_gate()
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100", "title": "fix bug"},
            )

        # Downstream call count MUST be 0
        self.assertEqual(self.spy_client.call_count, 0)

        # Verify record exists in SQLiteApprovalStore
        record = self.store.get(ctx.exception.approval_id)
        self.assertIsNotNone(record)
        self.assertEqual(record.state, ApprovalState.PENDING)

    async def test_2_returned_metadata_matches_persisted_record(self):
        gate = self.create_gate()
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )

        record = self.store.get(ctx.exception.approval_id)
        self.assertEqual(ctx.exception.request_id, record.request.request_id)
        self.assertEqual(ctx.exception.request_fingerprint, record.request_fingerprint)
        self.assertEqual(record.integration_id, "github-prod")
        self.assertEqual(record.capability_id, "github.merge")
        self.assertEqual(record.request.tool, "github")
        self.assertEqual(record.request.action, "merge")
        self.assertEqual(record.request.resource, "PR-100")
        self.assertEqual(record.request.agent_id, AGENT_ID)
        self.assertEqual(record.request.context.values, {"env": "prod", "dept": "finance"})
        self.assertEqual(record.policy_provenance.version_id, "v1")
        self.assertEqual(record.policy_provenance.policy_digest, policy_digest(self.policy))
        self.assertGreater(record.expires_at, record.created_at)

    async def test_3_persistence_failure_fails_closed_with_zero_downstream_calls(self):
        gate = self.create_gate()
        # Close database store to simulate persistence failure during route_call
        self.store.close()

        with self.assertRaises(AuthorizationError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )
        self.assertEqual(ctx.exception.code, "DMT_AUTHORIZATION_ERROR")
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_4_fake_agent_approval_attempts_are_ignored(self):
        gate = self.create_gate()
        # AI passes approved=True, approver="human", state="APPROVED" in tool args
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={
                    "pr_id": "PR-100",
                    "approved": True,
                    "approver": "admin",
                    "state": "APPROVED",
                },
            )

        record = self.store.get(ctx.exception.approval_id)
        self.assertEqual(record.state, ApprovalState.PENDING)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_5_idempotent_pending_requests_reuse_existing_pending_workflow(self):
        gate = self.create_gate()
        args = {"pr_id": "PR-100"}

        # First request
        with self.assertRaises(ApprovalRequiredError) as ctx1:
            await gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        # Repeated identical request
        with self.assertRaises(ApprovalRequiredError) as ctx2:
            await gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        # Identical pending record reused
        self.assertEqual(ctx1.exception.approval_id, ctx2.exception.approval_id)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_6_modified_arguments_create_different_workflow_fingerprint(self):
        gate = self.create_gate()
        with self.assertRaises(ApprovalRequiredError) as ctx1:
            await gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments={"pr_id": "PR-1"})
        with self.assertRaises(ApprovalRequiredError) as ctx2:
            await gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments={"pr_id": "PR-2"})

        self.assertNotEqual(ctx1.exception.approval_id, ctx2.exception.approval_id)
        self.assertNotEqual(ctx1.exception.request_fingerprint, ctx2.exception.request_fingerprint)
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_7_god_mode_discloses_minimal_opaque_error(self):
        proxy = DmintMCPProxy(
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.GOD,
        )
        proxy._gate = EnforcementGate(
            self.spy_client,
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.GOD,
        )
        res = await proxy._handle_call_tool(
            None,
            type("Params", (), {"name": "merge_pr", "arguments": {"pr_id": "PR-100"}})(),
        )
        self.assertTrue(res.is_error)
        self.assertEqual(res.content[0].text, "Dmint enforcement [DMT_403]: access denied")
        self.assertNotIn("approval_id", res.content[0].text)
        self.assertNotIn("request_fingerprint", res.content[0].text)

    async def test_8_dog_mode_discloses_useful_structured_recovery_payload(self):
        proxy = DmintMCPProxy(
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.DOG,
        )
        proxy._gate = EnforcementGate(
            self.spy_client,
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.DOG,
        )
        res = await proxy._handle_call_tool(
            None,
            type("Params", (), {"name": "merge_pr", "arguments": {"pr_id": "PR-100"}})(),
        )
        self.assertTrue(res.is_error)
        data = json.loads(res.content[0].text)
        self.assertEqual(data["status"], "approval_required")
        self.assertEqual(data["code"], "DMT_APPROVAL_REQUIRED")
        self.assertIn("approval_id", data)
        self.assertIn("request_id", data)
        self.assertIn("request_fingerprint", data)

    async def test_9_cat_mode_discloses_code_without_fingerprint_secrets(self):
        proxy = DmintMCPProxy(
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.CAT,
        )
        proxy._gate = EnforcementGate(
            self.spy_client,
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.CAT,
        )
        res = await proxy._handle_call_tool(
            None,
            type("Params", (), {"name": "merge_pr", "arguments": {"pr_id": "PR-100"}})(),
        )
        self.assertTrue(res.is_error)
        self.assertIn("DMT_APPROVAL_REQUIRED", res.content[0].text)
        self.assertNotIn("request_fingerprint", res.content[0].text)

    async def test_10_hidden_tool_still_generates_approval_required_with_zero_downstream_calls(self):
        gate = self.create_gate()
        # delete_repo is DiscoveryMode.HIDDEN
        with self.assertRaises(ApprovalRequiredError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="delete_repo",
                arguments={"repo_id": "repo-secret"},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_11_enforcement_gate_dispatches_webhook_on_approval_required(self):
        mock_notifier = MagicMock(spec=WebhookNotifier)
        gate = self.create_gate(webhook_notifier=mock_notifier)
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100", "title": "fix bug"},
            )
        self.assertEqual(self.spy_client.call_count, 0)
        self.assertEqual(mock_notifier.send_approval_required.call_count, 1)
        record = mock_notifier.send_approval_required.call_args[0][0]
        self.assertEqual(record.approval_id, ctx.exception.approval_id)

    async def test_12_enforcement_gate_resilient_to_webhook_failure(self):
        mock_notifier = MagicMock(spec=WebhookNotifier)
        mock_notifier.send_approval_required.side_effect = RuntimeError("Webhook crash")
        gate = self.create_gate(webhook_notifier=mock_notifier)
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100", "title": "fix bug"},
            )
        self.assertEqual(self.spy_client.call_count, 0)
        record = self.store.get(ctx.exception.approval_id)
        self.assertIsNotNone(record)
        self.assertEqual(record.state, ApprovalState.PENDING)

    async def test_12b_webhook_dispatch_is_off_loop_and_serialized(self):
        """Slow webhook I/O must not block the event loop and must not run concurrently."""
        mock_notifier = MagicMock(spec=WebhookNotifier)
        main_thread = threading.get_ident()
        dispatch_threads: list[int] = []
        active = 0
        max_active = 0
        lock = threading.Lock()

        def dispatch(record):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            dispatch_threads.append(threading.get_ident())
            time.sleep(0.08)
            with lock:
                active -= 1

        mock_notifier.send_approval_required.side_effect = dispatch
        gate = self.create_gate(webhook_notifier=mock_notifier)
        loop = asyncio.get_running_loop()
        ticks = 0
        stop = asyncio.Event()

        async def ticker() -> None:
            nonlocal ticks
            while not stop.is_set():
                ticks += 1
                await asyncio.sleep(0.005)

        async def request(pr_id: str) -> None:
            with self.assertRaises(ApprovalRequiredError):
                await gate.route_call(
                    integration_id="github-prod",
                    tool_name="merge_pr",
                    arguments={"pr_id": pr_id},
                )

        ticker_task = asyncio.create_task(ticker())
        await asyncio.gather(request("PR-200"), request("PR-201"))
        stop.set()
        await ticker_task

        self.assertEqual(len(dispatch_threads), 2)
        self.assertTrue(all(tid != main_thread for tid in dispatch_threads))
        self.assertEqual(max_active, 1)
        self.assertGreater(ticks, 0)
        self.assertIs(loop, asyncio.get_running_loop())

    async def test_13_enforcement_gate_dispatches_webhook_on_policy_denied(self):
        config = MCPIntegrationConfig(
            integration_id="github-prod",
            command="python3",
            args=["-c", "pass"],
            tool_bindings={
                "drop_db": MCPToolBinding(
                    tool_name="drop_db",
                    capability="github.drop_db",
                    resource_key="db_id",
                    discovery=DiscoveryMode.EXPOSED,
                ),
            },
        )
        mock_notifier = MagicMock(spec=WebhookNotifier)
        gate = EnforcementGate(
            self.spy_client,
            config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            webhook_notifier=mock_notifier,
        )
        with self.assertRaises(AuthorizationError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="drop_db",
                arguments={"db_id": "primary-db"},
            )
        self.assertEqual(ctx.exception.code, "DMT_POLICY_DENIED")
        self.assertEqual(self.spy_client.call_count, 0)
        self.assertEqual(mock_notifier.send_policy_denied.call_count, 1)
        req = mock_notifier.send_policy_denied.call_args[0][0]
        self.assertEqual(req.tool, "github")
        self.assertEqual(req.action, "drop_db")
        self.assertEqual(req.resource, "primary-db")
        self.assertEqual(req.agent_id, AGENT_ID)

    async def test_14_enforcement_gate_resilient_to_denial_webhook_failure(self):
        config = MCPIntegrationConfig(
            integration_id="github-prod",
            command="python3",
            args=["-c", "pass"],
            tool_bindings={
                "drop_db": MCPToolBinding(
                    tool_name="drop_db",
                    capability="github.drop_db",
                    resource_key="db_id",
                    discovery=DiscoveryMode.EXPOSED,
                ),
            },
        )
        mock_notifier = MagicMock(spec=WebhookNotifier)
        mock_notifier.send_policy_denied.side_effect = RuntimeError("Webhook network failure")
        gate = EnforcementGate(
            self.spy_client,
            config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            policy_provenance=self.provenance,
            approval_ttl=timedelta(hours=1),
            webhook_notifier=mock_notifier,
        )
        with self.assertRaises(AuthorizationError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="drop_db",
                arguments={"db_id": "primary-db"},
            )
        self.assertEqual(ctx.exception.code, "DMT_POLICY_DENIED")
        self.assertEqual(self.spy_client.call_count, 0)
