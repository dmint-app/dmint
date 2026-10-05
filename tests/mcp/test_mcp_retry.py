"""Comprehensive unit, security, and concurrency tests for MCP-8 approved retry."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest

from dmint.approvals import ApprovalAuthority, ApprovalAuthorityKind, ApprovalRecord, ApprovalState, PolicyProvenance
from dmint.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.errors import (
    ApprovalCredentialInvalidError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalIntegrationMismatchError,
    ApprovalPolicyInvalidError,
    ApprovalRequestMismatchError,
    ApprovalRequiredError,
    AuthorizationError,
    ExecutionError,
)
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    DmintMCPProxy,
    DownstreamMCPClient,
    EnforcementGate,
    MCPIntegrationConfig,
    MCPToolBinding,
)
from dmint.models import AnyResource, TrustedContext
from dmint.policy import Policy, Rule, policy_digest
from dmint.storage import SQLiteApprovalStore


class SpyDownstreamClient(DownstreamMCPClient):
    def __init__(self, config: MCPIntegrationConfig) -> None:
        super().__init__(config)
        self.call_count = 0
        self.last_tool = None
        self.last_arguments = None

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def call_tool(self, name: str, arguments: dict | None = None):
        self.call_count += 1
        self.last_tool = name
        self.last_arguments = arguments
        if name == "fail_tool":
            raise RuntimeError("downstream tool failure")
        return f"executed:{name}"


AGENT_ID = "trusted-agent"
TRUSTED_CTX = TrustedContext({"env": "prod"})
ISSUER = "trusted-authority"
AUDIENCE = "github-prod"


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
            "fail_tool": MCPToolBinding(
                tool_name="fail_tool",
                capability="github.fail",
                discovery=DiscoveryMode.EXPOSED,
            ),
        },
    )


class MCPRetrySecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "approvals.db")
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="ep_1")
        self.authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE)
        self.verifier = ApprovalVerifier(trusted_issuers={ISSUER: self.authority.public_key}, audience=AUDIENCE)
        self.config = make_config()
        self.spy_client = SpyDownstreamClient(self.config)
        self.policy = Policy(
            rules=(
                Rule.approval_required("github", "merge", resource=AnyResource()),
                Rule.approval_required("github", "fail", resource=AnyResource()),
            )
        )
        self.provenance = PolicyProvenance("v1", policy_digest(self.policy), datetime.now(timezone.utc))

    async def asyncTearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def create_proxy(self, policy=None, disclosure_mode=DisclosureMode.DOG) -> DmintMCPProxy:
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
            self.spy_client,
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

    async def test_1_approval_required_initial_call_zero_downstream_calls(self):
        proxy = self.create_proxy()
        with self.assertRaises(ApprovalRequiredError):
            await proxy.gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_2_and_3_trusted_human_approval_exact_retry_succeeds(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100", "reason": "approved"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Retry exact request
        result = await proxy.retry_call(
            tool_name="merge_pr",
            arguments=args,
            approval_credential=assertion,
        )
        self.assertEqual(result, "executed:merge_pr")
        self.assertEqual(self.spy_client.call_count, 1)

        # Record is now CONSUMED in store
        consumed_record = self.store.get(record.approval_id)
        self.assertEqual(consumed_record.state, ApprovalState.CONSUMED)

    async def test_4_and_5_modified_arguments_fail_closed(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100", "nested": {"a": [1, 2]}}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Modified top-level argument
        with self.assertRaises(ApprovalRequestMismatchError):
            await proxy.retry_call(
                tool_name="merge_pr",
                arguments={"pr_id": "PR-999", "nested": {"a": [1, 2]}},
                approval_credential=assertion,
            )

        # Modified nested argument
        with self.assertRaises(ApprovalRequestMismatchError):
            await proxy.retry_call(
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100", "nested": {"a": [1, 99]}},
                approval_credential=assertion,
            )

        self.assertEqual(self.spy_client.call_count, 0)

    async def test_6_to_10_modified_tool_resource_principal_integration_fail(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Modified tool
        with self.assertRaises(ApprovalRequestMismatchError):
            await proxy.retry_call(tool_name="fail_tool", arguments=args, approval_credential=assertion)

        # Modified resource
        with self.assertRaises(ApprovalRequestMismatchError):
            await proxy.retry_call(tool_name="merge_pr", arguments={"pr_id": "PR-OTHER"}, approval_credential=assertion)

        self.assertEqual(self.spy_client.call_count, 0)

    async def test_11_expired_approval_fails_closed(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Fast forward time past expiration
        store_expired = SQLiteApprovalStore(
            self.db_path, deployment_epoch="ep_1", clock=lambda: datetime.now(timezone.utc) + timedelta(hours=5)
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

        with self.assertRaises(ApprovalExpiredError):
            await expired_proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)

        self.assertEqual(self.spy_client.call_count, 0)

    async def test_12_consumed_approval_replay_fails_closed(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # First retry succeeds
        await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        self.assertEqual(self.spy_client.call_count, 1)

        # Second retry (replay attempt) fails
        with self.assertRaises((AuthorizationError, ApprovalError)):
            await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)

        self.assertEqual(self.spy_client.call_count, 1)

    async def test_13_to_15_forged_assertion_wrong_issuer_audience_fail(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)

        # Forged authority with different key
        bad_authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE)
        bad_approver = ApprovalAuthority._from_trusted_boundary("ui", "hacker", ApprovalAuthorityKind.HUMAN)
        bad_assertion = bad_authority.issue(record, bad_approver)
        self.store.save_approved(record.approve(bad_approver))

        with self.assertRaises((AuthorizationError, ApprovalError)):
            await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=bad_assertion)

        self.assertEqual(self.spy_client.call_count, 0)

    async def test_16_policy_changed_to_deny_invalidates_and_stops(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Update policy on new proxy to DENY
        deny_policy = Policy(rules=(Rule.deny("github", "merge", resource=AnyResource()),))
        deny_proxy = self.create_proxy(policy=deny_policy)

        with self.assertRaises(ApprovalPolicyInvalidError):
            await deny_proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)

        self.assertEqual(self.spy_client.call_count, 0)

    async def test_17_policy_provenance_mismatch_fails_closed(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-100"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # New proxy with different policy provenance version
        new_provenance = PolicyProvenance("v2", "b" * 64, datetime.now(timezone.utc))
        new_proxy = DmintMCPProxy(
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            approval_verifier=self.verifier,
            policy_provenance=new_provenance,
            approval_ttl=timedelta(hours=1),
        )
        new_proxy._gate = EnforcementGate(
            self.spy_client,
            self.config,
            policy=self.policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
            approval_store=self.store,
            approval_verifier=self.verifier,
            policy_provenance=new_provenance,
            approval_ttl=timedelta(hours=1),
        )

        with self.assertRaises(ApprovalPolicyInvalidError):
            await new_proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)

        self.assertEqual(self.spy_client.call_count, 0)

    async def test_21_concurrent_retries_exactly_one_succeeds(self):
        proxy = self.create_proxy()
        args = {"pr_id": "PR-CONCURRENT"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # 8 simultaneous retry attempts
        async def attempt():
            try:
                return await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
            except Exception as exc:
                return f"failed:{type(exc).__name__}"

        tasks = [attempt() for _ in range(8)]
        results = await asyncio.gather(*tasks)

        succeeded = [r for r in results if r == "executed:merge_pr"]
        failed = [r for r in results if r != "executed:merge_pr"]

        self.assertEqual(len(succeeded), 1)
        self.assertEqual(len(failed), 7)
        self.assertEqual(self.spy_client.call_count, 1)

    async def test_22_downstream_tool_error_after_consumption_keeps_approval_consumed(self):
        proxy = self.create_proxy()
        args = {"target": "x"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="fail_tool", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Downstream tool raises RuntimeError
        with self.assertRaises(RuntimeError):
            await proxy.retry_call(tool_name="fail_tool", arguments=args, approval_credential=assertion)

        # Approval remains CONSUMED in store
        consumed_record = self.store.get(record.approval_id)
        self.assertEqual(consumed_record.state, ApprovalState.CONSUMED)

    async def test_24_and_25_mcp_reconnect_and_new_session_during_retry(self):
        proxy1 = self.create_proxy()
        args = {"pr_id": "PR-RECONNECT"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy1.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # New proxy / session instance reading the same SQLite store
        proxy2 = self.create_proxy()
        result = await proxy2.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)

        self.assertEqual(result, "executed:merge_pr")
        self.assertEqual(self.spy_client.call_count, 1)

    async def test_26_and_27_secrets_not_leaked_and_disclosure_mode_semantics(self):
        proxy_god = self.create_proxy(disclosure_mode=DisclosureMode.GOD)
        args = {"pr_id": "PR-SECRET"}
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy_god.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)

        record = self.store.get(ctx.exception.approval_id)
        assertion = self.approve_pending(record)

        # Retrying with invalid args under GOD mode
        with self.assertRaises(ApprovalRequestMismatchError):
            await proxy_god.retry_call(
                tool_name="merge_pr", arguments={"pr_id": "PR-WRONG"}, approval_credential=assertion
            )

        self.assertEqual(self.spy_client.call_count, 0)
