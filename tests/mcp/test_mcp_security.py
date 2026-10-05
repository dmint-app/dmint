"""Adversarial security tests for MCP tools/call request mapping (MCP-5)."""

import unittest

from dmint.errors import RequestValidationError
from dmint.mcp.errors import MCPMappingError
from dmint.mcp import (
    DiscoveryMode,
    MCPIntegrationConfig,
    MCPRequestMapper,
    MCPToolBinding,
)
from dmint.models import NO_RESOURCE, TrustedContext
from dmint.versions import MAX_REQUEST_BYTES

AGENT = "untrusted-ai-agent"
CTX = TrustedContext({"environment": "production", "tier": "secure"})


def make_security_config():
    return MCPIntegrationConfig(
        integration_id="aws-prod",
        command="python3",
        args=["-c", "pass"],
        tool_bindings={
            "terminate_instance": MCPToolBinding(
                tool_name="terminate_instance",
                capability="aws.terminate",
                resource_key="instance_id",
                discovery=DiscoveryMode.EXPOSED,
            ),
            "read_logs": MCPToolBinding(
                tool_name="read_logs",
                capability="aws.read_logs",
                discovery=DiscoveryMode.EXPOSED,
            ),
        },
    )


class MCPSecurityMappingTests(unittest.TestCase):
    def setUp(self):
        self.config = make_security_config()
        self.mapper = MCPRequestMapper(self.config, agent_id=AGENT, context=CTX)

    def test_fake_capability_injection_in_arguments_ignored(self):
        # AI sends arguments containing capability="aws.read_logs" to reinterpret a dangerous tool
        args = {
            "instance_id": "i-1234567890abcdef0",
            "capability": "aws.read_logs",
            "action": "read",
            "tool": "safe_tool",
        }
        mapped = self.mapper.map(tool_name="terminate_instance", arguments=args)
        # Trusted binding determines capability, tool, action — NOT arguments!
        self.assertEqual(mapped.capability, "aws.terminate")
        self.assertEqual(mapped.tool_request.tool, "aws")
        self.assertEqual(mapped.tool_request.action, "terminate")
        self.assertEqual(mapped.tool_request.arguments["capability"], "aws.read_logs")

    def test_fake_integration_injection_in_arguments_ignored(self):
        # AI tries to specify integration_id in arguments
        args = {"instance_id": "i-1234", "integration_id": "dev-env"}
        mapped = self.mapper.map(tool_name="terminate_instance", arguments=args)
        self.assertEqual(mapped.integration_id, "aws-prod")

    def test_fake_principal_injection_in_arguments_ignored(self):
        # AI tries to specify agent_id/principal in arguments
        args = {"instance_id": "i-1234", "agent_id": "admin-human", "principal": "root"}
        mapped = self.mapper.map(tool_name="terminate_instance", arguments=args)
        self.assertEqual(mapped.tool_request.agent_id, AGENT)

    def test_fake_resource_injection_cannot_override_resource_key(self):
        # AI sends resource="i-safe" while pull_number / instance_id is "i-dangerous"
        args = {"instance_id": "i-dangerous", "resource": "i-safe"}
        mapped = self.mapper.map(tool_name="terminate_instance", arguments=args)
        # Resource is derived from trusted resource_key ("instance_id")
        self.assertEqual(mapped.tool_request.resource, "i-dangerous")
        self.assertEqual(mapped.resource, "i-dangerous")

    def test_oversized_arguments_fail_closed(self):
        # Payload exceeding MAX_REQUEST_BYTES must fail validation
        huge_string = "A" * (MAX_REQUEST_BYTES + 100)
        args = {"instance_id": "i-123", "data": huge_string}
        with self.assertRaises(RequestValidationError):
            self.mapper.map(tool_name="terminate_instance", arguments=args)

    def test_numeric_edge_cases_rejected(self):
        # whole-integer floats like 1.0 or -0.0 fail canonicalization
        args = {"instance_id": "i-123", "bad_float": 1.0}
        with self.assertRaises(RequestValidationError):
            self.mapper.map(tool_name="terminate_instance", arguments=args)

    def test_valid_finite_float_accepted(self):
        args = {"instance_id": "i-123", "valid_float": 1.5}
        mapped = self.mapper.map(tool_name="terminate_instance", arguments=args)
        self.assertEqual(mapped.tool_request.arguments["valid_float"], 1.5)

    def test_unicode_normalization_and_security(self):
        # Unicode in tool arguments preserved safely without corruption
        args = {"instance_id": "i-123", "comment": "Tëst 🚀 \u200b hidden"}
        mapped = self.mapper.map(tool_name="terminate_instance", arguments=args)
        self.assertIn("Tëst 🚀", mapped.tool_request.arguments["comment"])

    def test_session_metadata_does_not_mutate_request_identity(self):
        # Transport metadata (IP, headers, connection ID) are separate from semantic request identity
        mapped1 = self.mapper.map(tool_name="terminate_instance", arguments={"instance_id": "i-123"})
        mapped2 = self.mapper.map(tool_name="terminate_instance", arguments={"instance_id": "i-123"})
        self.assertEqual(mapped1.fingerprint, mapped2.fingerprint)

    def test_endpoint_and_binding_substitution_impossible(self):
        # Configuration is sealed and immutable
        with self.assertRaises(AttributeError):
            self.config.command = "sh"
        with self.assertRaises(AttributeError):
            self.config.tool_bindings = {}

    def test_empty_string_resource_key_fails_closed(self):
        args = {"instance_id": "   "}  # whitespace string
        with self.assertRaises(MCPMappingError) as ctx:
            self.mapper.map(tool_name="terminate_instance", arguments=args)
        self.assertEqual(ctx.exception.code, "DMT_MCP_RESOURCE_INVALID")

    def test_non_string_resource_key_value_fails_closed(self):
        args = {"instance_id": 12345}  # int instead of string
        with self.assertRaises(MCPMappingError) as ctx:
            self.mapper.map(tool_name="terminate_instance", arguments=args)
        self.assertEqual(ctx.exception.code, "DMT_MCP_RESOURCE_INVALID")
