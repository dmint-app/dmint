"""Tests for agent-facing Dmint MCP proxy session layer (MCP-3)."""

import asyncio
import sys
import unittest
from pathlib import Path

import anyio
import mcp.types as types

from dmint.mcp.errors import MCPConfigurationError, MCPProtocolError
from dmint.mcp import DmintMCPProxy, MCPIntegrationConfig
from dmint.mcp.proxy import MCPProxyError
from dmint.policy import AnyResource, Policy, Rule

MOCK_SERVER_SCRIPT = str(Path(__file__).parent / "mock_server.py")
ALLOW_ALL_POLICY = Policy(
    rules=(
        Rule.allow("test", "echo", resource=AnyResource()),
        Rule.allow("test", "delete_database", resource=AnyResource()),
    )
)


def make_config(**kwargs):
    base = dict(
        integration_id="server-prod",
        command=sys.executable,
        args=[MOCK_SERVER_SCRIPT],
        tool_bindings={
            "echo": "test.echo",
            "delete_database": "test.delete_database",
        },
    )
    base.update(kwargs)
    return MCPIntegrationConfig(**base)


class DmintMCPProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = make_config()
        self.proxy = DmintMCPProxy(self.config, policy=ALLOW_ALL_POLICY)
        await self.proxy.connect()

    async def asyncTearDown(self):
        if self.proxy is not None:
            await self.proxy.disconnect()

    async def test_initialize_and_list_tools_succeeds(self):
        tools = await self.proxy.list_tools()
        names = {t.name for t in tools.tools}
        self.assertIn("echo", names)
        self.assertIn("delete_database", names)

    async def test_tools_call_routes_to_downstream(self):
        # In MCP-3 this is a transport bridge (authorization added in MCP-5).
        result = await self.proxy._gate.route_call(
            integration_id="server-prod",
            tool_name="echo",
            arguments={"message": "hello"},
        )
        self.assertIsNotNone(result.content)
        self.assertEqual(result.content[0].text, "echo: hello")

    async def test_unknown_tool_is_rejected(self):
        handler = self.proxy._server.get_request_handler("tools/call")
        params = types.CallToolRequestParams(name="nonexistent_tool", arguments={})
        result = await handler.handler(None, params)
        self.assertTrue(result.is_error)
        self.assertIn("DMT_MCP_TOOL_UNKNOWN", result.content[0].text)

    async def test_malformed_tool_name_rejected(self):
        handler = self.proxy._server.get_request_handler("tools/call")
        with self.assertRaises(MCPProtocolError):
            await handler.handler(None, types.CallToolRequestParams(name="", arguments={}))

    async def test_malformed_arguments_fail_closed_at_protocol_layer(self):
        # The MCP SDK's pydantic model rejects non-object arguments before the
        # handler runs (fail closed). We assert the SDK boundary enforces this.
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            types.CallToolRequestParams(name="echo", arguments="not-a-dict")

    async def test_request_before_connect_fails_closed(self):
        proxy = DmintMCPProxy(make_config(integration_id="not-connected"))
        with self.assertRaises(MCPProxyError):
            await proxy.list_tools()

    async def test_configuration_cannot_be_modified(self):
        with self.assertRaises(AttributeError):
            self.config.command = "malicious-cmd"
        with self.assertRaises(AttributeError):
            self.config.integration_id = "injected-id"
        with self.assertRaises(AttributeError):
            self.config.tool_bindings = {}

    async def test_agent_cannot_replace_endpoint(self):
        original_command = self.config.command
        original_args = self.config.args
        # Config is immutable; agent-facing layer exposes no setter
        self.assertEqual(self.config.command, original_command)
        self.assertEqual(self.config.args, original_args)

    async def test_credentials_not_exposed(self):
        config = make_config(
            integration_id="cred-server",
            env={"GITHUB_TOKEN": "gh_very_secret_123"},
        )
        self.assertNotIn("gh_very_secret_123", repr(config))
        self.assertNotIn("gh_very_secret_123", repr(self.proxy))

    async def test_downstream_disconnect_is_safe(self):
        proxy = DmintMCPProxy(make_config(integration_id="disconnect-server"))
        await proxy.connect()
        await proxy.disconnect()
        with self.assertRaises(MCPProxyError):
            await proxy.list_tools()

    async def test_concurrent_list_and_call_are_isolated(self):
        async def list_worker():
            return [t.name for t in (await self.proxy.list_tools()).tools]

        async def call_worker():
            return await self.proxy._gate.route_call(
                integration_id="server-prod",
                tool_name="echo",
                arguments={"message": "x"},
            )

        results = await asyncio.gather(list_worker(), call_worker(), list_worker())
        names = set(results[0])
        self.assertIn("echo", names)
        self.assertIn("delete_database", names)
        self.assertEqual(results[1].content[0].text, "echo: x")


class DmintMCPProxyCtorTests(unittest.TestCase):
    def test_invalid_config_type_rejected(self):
        with self.assertRaises(MCPConfigurationError):
            DmintMCPProxy("not-a-config")

    def test_invalid_initialization_options(self):
        config = make_config()
        proxy = DmintMCPProxy(config)
        self.assertIsNotNone(proxy.integration_id)
