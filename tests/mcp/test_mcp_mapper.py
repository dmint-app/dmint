"""Tests for MCP tools/call -> Dmint request mapping (MCP-5)."""

import sys
import unittest

from dmint.mcp.errors import MCPMappingError, MCPConfigurationError
from dmint.mcp import (
    MCPIntegrationConfig,
    MCPRequestMapper,
    MCPToolBinding,
    DiscoveryMode,
)
from dmint.models import NO_RESOURCE, TrustedContext
from dmint.request_binding import request_binding_fingerprint

AGENT = "trusted-agent"
CTX = TrustedContext({"env": "prod"})


def make_config(tool_bindings=None, integration_id="github-prod"):
    return MCPIntegrationConfig(
        integration_id=integration_id,
        command="python3",
        args=["-c", "pass"],
        tool_bindings=tool_bindings
        or {
            "merge_pull_request": MCPToolBinding(
                "merge_pull_request",
                "github.merge",
                resource_key="pull_number",
                discovery=DiscoveryMode.EXPOSED,
            ),
            "read_issue": MCPToolBinding(
                "read_issue",
                "github.read",
                discovery=DiscoveryMode.EXPOSED,
            ),
        },
    )


class MCPRequestMappingTests(unittest.TestCase):
    def test_valid_mcp_call_maps_to_dmint_request(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        mapped = mapper.map(
            tool_name="merge_pull_request",
            arguments={"pull_number": "123", "reason": "approved"},
        )
        req = mapped.tool_request
        # trusted capability -> tool/action (not the raw MCP name)
        self.assertEqual(req.tool, "github")
        self.assertEqual(req.action, "merge")
        self.assertEqual(mapped.capability, "github.merge")
        self.assertEqual(mapped.binding.tool_name, "merge_pull_request")
        self.assertEqual(mapped.integration_id, "github-prod")
        self.assertEqual(req.agent_id, AGENT)
        self.assertEqual(req.context.values, {"env": "prod"})
        self.assertEqual(req.arguments["reason"], "approved")
        self.assertEqual(req.resource, "123")

    def test_resource_is_derived_from_trusted_resource_key(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        mapped = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-42"})
        self.assertEqual(mapped.tool_request.resource, "PR-42")
        self.assertEqual(mapped.resource, "PR-42")

    def test_no_resource_when_not_configured(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        mapped = mapper.map(tool_name="read_issue", arguments={"id": 1})
        self.assertIs(mapped.tool_request.resource, NO_RESOURCE)

    def test_arguments_are_preserved_immutably(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        args = {"id": 7, "nested": {"a": [1, 2, 3]}}
        mapped = mapper.map(tool_name="read_issue", arguments=args)
        # Dmint freezes JSON: lists become tuples in the canonical form.
        self.assertEqual(mapped.tool_request.arguments["nested"]["a"], (1, 2, 3))
        self.assertEqual(mapped.tool_request.arguments["id"], 7)

    def test_unsupported_arguments_fail_closed(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        # non-object arguments
        with self.assertRaises(MCPMappingError):
            mapper.map(tool_name="read_issue", arguments=[1, 2])
        with self.assertRaises(MCPMappingError):
            mapper.map(tool_name="read_issue", arguments="nope")

    def test_missing_resource_argument_fails_closed(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        with self.assertRaises(MCPMappingError) as ctx:
            mapper.map(tool_name="merge_pull_request", arguments={"reason": "x"})
        self.assertEqual(ctx.exception.code, "DMT_MCP_RESOURCE_INVALID")

    def test_unknown_tool_fails_closed(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        with self.assertRaises(MCPMappingError) as ctx:
            mapper.map(tool_name="not_a_real_tool", arguments={})
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_UNKNOWN")

    def test_unbound_tool_fails_closed(self):
        # default discovery hidden + not bound -> not mapped
        mapper = MCPRequestMapper(
            MCPIntegrationConfig(
                integration_id="x",
                command="python3",
                tool_bindings={},
            ),
            agent_id=AGENT,
            context=CTX,
        )
        with self.assertRaises(MCPMappingError):
            mapper.map(tool_name="unbound_tool", arguments={})

    def test_agent_cannot_override_capability(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        # "safe.read" capability cannot be injected; only trusted binding rules.
        mapped = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "1"})
        self.assertEqual(mapped.capability, "github.merge")

    def test_agent_cannot_override_resource(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        # resource is derived from the trusted resource_key (pull_number)
        mapped = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1"})
        self.assertEqual(mapped.tool_request.resource, "PR-1")

    def test_agent_cannot_override_integration(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        self.assertEqual(mapper.integration_id, "github-prod")

    def test_agent_cannot_override_endpoint(self):
        config = make_config()
        with self.assertRaises(AttributeError):
            config.command = "other-cmd"
        with self.assertRaises(AttributeError):
            config.args = ("--evil",)

    def test_fingerprint_is_consistent_and_binds_semantics(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        a1 = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1", "r": "x"}, request_id="r1")
        a2 = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1", "r": "x"}, request_id="r2")
        # different request ids, same semantic content -> same fingerprint
        self.assertEqual(a1.fingerprint, a2.fingerprint)

    def test_changing_arguments_changes_fingerprint(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        a = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1"})
        b = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-2"})
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_changing_tool_changes_fingerprint(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        a = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1"}, request_id="r1")
        b = mapper.map(tool_name="read_issue", arguments={"id": 1}, request_id="r2")
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_changing_resource_changes_fingerprint(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        a = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1"})
        b = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-9"})
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_trusted_context_is_not_agent_controlled(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        mapped = mapper.map(tool_name="read_issue", arguments={"id": 1})
        # agent-supplied arguments cannot alter the trusted context
        self.assertEqual(mapped.tool_request.context.values, {"env": "prod"})

    def test_fingerprint_matches_core_request_binding_helper(self):
        config = make_config()
        mapper = MCPRequestMapper(config, agent_id=AGENT, context=CTX)
        mapped = mapper.map(tool_name="merge_pull_request", arguments={"pull_number": "PR-1"}, request_id="r1")
        expected = request_binding_fingerprint(
            mapped.tool_request,
            integration_id=config.integration_id,
            capability_id="github.merge",
        )
        self.assertEqual(mapped.fingerprint, expected)


class MCPMappingErrorTests(unittest.TestCase):
    def test_malformed_tool_name_rejected(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        with self.assertRaises(MCPMappingError):
            mapper.map(tool_name="", arguments={})
        with self.assertRaises(MCPMappingError):
            mapper.map(tool_name=123, arguments={})

    def test_missing_arguments_are_treated_as_empty(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        mapped = mapper.map(tool_name="read_issue", arguments=None)
        self.assertEqual(dict(mapped.tool_request.arguments), {})

    def test_nested_unsupported_values_fail_closed(self):
        mapper = MCPRequestMapper(make_config(), agent_id=AGENT, context=CTX)
        # sets are not valid JSON and must be rejected by the core canonicalizer
        with self.assertRaises(Exception):
            mapper.map(tool_name="read_issue", arguments={"bad": {1, 2, 3}})

    def test_invalid_config_rejected(self):
        with self.assertRaises(MCPConfigurationError):
            MCPRequestMapper("not-a-config", agent_id=AGENT, context=CTX)
        with self.assertRaises(MCPConfigurationError):
            MCPRequestMapper(make_config(), agent_id="", context=CTX)
        with self.assertRaises(MCPConfigurationError):
            MCPRequestMapper(make_config(), agent_id=AGENT, context={"not": "trusted"})
