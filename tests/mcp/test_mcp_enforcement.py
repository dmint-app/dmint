"""Comprehensive unit and security tests for MCP-6 real ALLOW/DENY enforcement."""

import asyncio
import unittest

from dmint.errors import AuthorizationError, RequestValidationError
from dmint.mcp.errors import MCPMappingError
from dmint.mcp import (
    DiscoveryMode,
    DownstreamMCPClient,
    EnforcementGate,
    MCPIntegrationConfig,
    MCPToolBinding,
)
from dmint.models import AnyResource, NO_RESOURCE, TrustedContext
from dmint.policy import Condition, Policy, Rule
from dmint.versions import MAX_REQUEST_BYTES


class SpyDownstreamClient(DownstreamMCPClient):
    """Spy downstream MCP client that records tool calls."""

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
        return f"executed:{name}"


AGENT_ID = "trusted-agent"
TRUSTED_CTX = TrustedContext({"env": "prod", "role": "admin"})


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
            "read_issue": MCPToolBinding(
                tool_name="read_issue",
                capability="github.read",
                discovery=DiscoveryMode.EXPOSED,
            ),
        },
    )


class MCPEnforcementSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = make_config()
        self.spy_client = SpyDownstreamClient(self.config)

    def create_gate(self, policy: Policy) -> EnforcementGate:
        return EnforcementGate(
            self.spy_client,
            self.config,
            policy=policy,
            agent_id=AGENT_ID,
            context=TRUSTED_CTX,
        )

    async def test_1_policy_allow_results_in_exactly_one_downstream_call(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource="PR-100"),))
        gate = self.create_gate(policy)

        res = await gate.route_call(
            integration_id="github-prod",
            tool_name="merge_pr",
            arguments={"pr_id": "PR-100", "reason": "LGTM"},
        )
        self.assertEqual(res, "executed:merge_pr")
        self.assertEqual(self.spy_client.call_count, 1)
        self.assertEqual(self.spy_client.last_tool, "merge_pr")

    async def test_2_policy_deny_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.deny("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(AuthorizationError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )
        self.assertEqual(ctx.exception.code, "DMT_POLICY_DENIED")
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_3_approval_required_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.approval_required("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(AuthorizationError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )
        self.assertEqual(ctx.exception.code, "DMT_APPROVAL_REQUIRED")
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_4_hidden_tool_direct_call_still_evaluates_policy(self):
        # delete_repo is DiscoveryMode.HIDDEN
        policy = Policy(rules=(Rule.deny("github", "delete", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(AuthorizationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="delete_repo",
                arguments={"repo_id": "my-repo"},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_5_exposed_tool_with_deny_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.deny("github", "read", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(AuthorizationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="read_issue",
                arguments={"id": 1},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_6_unknown_tool_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(MCPMappingError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="unknown_tool",
                arguments={},
            )
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_UNKNOWN")
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_7_unbound_tool_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(MCPMappingError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="unbound_tool",
                arguments={},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_8_resource_mismatch_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource="PR-100"),))
        gate = self.create_gate(policy)

        with self.assertRaises(AuthorizationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-999"},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_9_capability_substitution_attempt_results_in_zero_downstream_calls(self):
        # AI passes capability="github.read" in arguments to try to trick policy
        policy = Policy(rules=(Rule.deny("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(AuthorizationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100", "capability": "github.read"},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_10_integration_substitution_attempt_results_in_zero_downstream_calls(self):
        # AI passes a different integration_id
        policy = Policy(rules=(Rule.allow("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        # Gate maps using the trusted config integration_id ("github-prod")
        res = await gate.route_call(
            integration_id="fake-integration",
            tool_name="merge_pr",
            arguments={"pr_id": "PR-100"},
        )
        self.assertEqual(gate.last_mapped_request.integration_id, "github-prod")

    async def test_11_principal_substitution_attempt_results_in_zero_downstream_calls(self):
        # Policy requires trusted AGENT_ID
        policy = Policy(rules=(Rule.allow("github", "merge", agent_id="trusted-agent", resource=AnyResource()),))
        gate = self.create_gate(policy)

        # AI tries to inject agent_id="admin" in arguments
        res = await gate.route_call(
            integration_id="github-prod",
            tool_name="merge_pr",
            arguments={"pr_id": "PR-100", "agent_id": "admin"},
        )
        self.assertEqual(gate.last_mapped_request.tool_request.agent_id, AGENT_ID)

    async def test_12_trusted_context_substitution_attempt_fails_closed(self):
        # Policy requires condition env == "prod"
        policy = Policy(
            rules=(
                Rule.allow(
                    "github",
                    "merge",
                    resource=AnyResource(),
                    conditions=(Condition.equals("env", "prod"),),
                ),
            )
        )
        gate = self.create_gate(policy)

        # AI tries to pass env="dev" in arguments
        res = await gate.route_call(
            integration_id="github-prod",
            tool_name="merge_pr",
            arguments={"pr_id": "PR-100", "env": "dev"},
        )
        # Trusted context is "prod", condition matches, request allowed
        self.assertEqual(self.spy_client.call_count, 1)

    async def test_13_argument_mutation_between_authorization_and_call_impossible(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource="PR-100"),))
        gate = self.create_gate(policy)

        args = {"pr_id": "PR-100", "note": "initial"}
        await gate.route_call(
            integration_id="github-prod",
            tool_name="merge_pr",
            arguments=args,
        )
        # Mutating original input args dict post-call does not change the forwarded arguments
        args["pr_id"] = "PR-MUTATED"
        self.assertEqual(self.spy_client.last_arguments["pr_id"], "PR-100")

    async def test_14_numeric_edge_cases_reject_whole_integer_floats(self):
        policy = Policy(rules=(Rule.allow("github", "read", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(RequestValidationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="read_issue",
                arguments={"bad_float": 1.0},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_15_unicode_edge_cases_handled_safely(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource="PR-🚀"),))
        gate = self.create_gate(policy)

        res = await gate.route_call(
            integration_id="github-prod",
            tool_name="merge_pr",
            arguments={"pr_id": "PR-🚀"},
        )
        self.assertEqual(self.spy_client.call_count, 1)
        self.assertEqual(self.spy_client.last_arguments["pr_id"], "PR-🚀")

    async def test_16_oversized_input_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        huge = "X" * (MAX_REQUEST_BYTES + 500)
        with self.assertRaises(RequestValidationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-1", "huge": huge},
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_17_malformed_request_results_in_zero_downstream_calls(self):
        policy = Policy(rules=(Rule.allow("github", "merge", resource=AnyResource()),))
        gate = self.create_gate(policy)

        with self.assertRaises(MCPMappingError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments="not-a-dict",
            )
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_18_authorization_engine_failure_results_in_zero_downstream_calls(self):
        # A gate with a broken/raising policy evaluator
        class RaisingPolicy(Policy):
            def evaluate(self, request):
                raise RuntimeError("policy engine exception")

        gate = self.create_gate(RaisingPolicy())

        with self.assertRaises(AuthorizationError) as ctx:
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )
        self.assertEqual(ctx.exception.code, "DMT_AUTHORIZATION_ERROR")
        self.assertEqual(self.spy_client.call_count, 0)

    async def test_19_downstream_call_only_occurs_after_successful_allow(self):
        policy = Policy(rules=(Rule.allow("github", "read", resource=AnyResource()),))
        gate = self.create_gate(policy)

        # Denied tool
        with self.assertRaises(AuthorizationError):
            await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-100"},
            )
        self.assertEqual(self.spy_client.call_count, 0)

        # Allowed tool
        await gate.route_call(
            integration_id="github-prod",
            tool_name="read_issue",
            arguments={"id": 1},
        )
        self.assertEqual(self.spy_client.call_count, 1)

    async def test_20_multiple_concurrent_calls_preserve_request_isolation(self):
        policy = Policy(
            rules=(
                Rule.allow("github", "read", resource=AnyResource()),
                Rule.allow("github", "merge", resource="PR-ALLOW"),
                Rule.deny("github", "merge", resource="PR-DENY"),
            )
        )
        gate = self.create_gate(policy)

        async def call_allow():
            return await gate.route_call(
                integration_id="github-prod",
                tool_name="merge_pr",
                arguments={"pr_id": "PR-ALLOW"},
            )

        async def call_deny():
            try:
                await gate.route_call(
                    integration_id="github-prod",
                    tool_name="merge_pr",
                    arguments={"pr_id": "PR-DENY"},
                )
                return "unexpected_success"
            except AuthorizationError:
                return "denied_as_expected"

        async def call_read():
            return await gate.route_call(
                integration_id="github-prod",
                tool_name="read_issue",
                arguments={"id": 42},
            )

        results = await asyncio.gather(call_allow(), call_deny(), call_read())
        self.assertEqual(results[0], "executed:merge_pr")
        self.assertEqual(results[1], "denied_as_expected")
        self.assertEqual(results[2], "executed:read_issue")
        # Exactly 2 calls executed downstream (the 2 ALLOWs)
        self.assertEqual(self.spy_client.call_count, 2)
