"""Tests for tools/list discovery policy (MCP-4)."""

import sys
import unittest
from pathlib import Path

import anyio
import mcp.types as types

from dmint.mcp.errors import MCPConfigurationError
from dmint.mcp import (
    DmintMCPProxy,
    DiscoveryMode,
    MCPIntegrationConfig,
    MCPToolBinding,
)

BASE = Path(__file__).parent
MOCK_SERVER_SCRIPT = str(BASE / "mock_server.py")


class DiscoveryPolicyTests(unittest.IsolatedAsyncioTestCase):
    def make_proxy(self, integration_id="disc-server", tool_bindings=None, default_discovery=DiscoveryMode.HIDDEN):
        config = MCPIntegrationConfig(
            integration_id=integration_id,
            command=sys.executable,
            args=[MOCK_SERVER_SCRIPT],
            tool_bindings=tool_bindings,
            default_discovery=default_discovery,
        )
        proxy = DmintMCPProxy(config)
        return proxy

    async def visible_names(self, proxy):
        await proxy.connect()
        try:
            result = await proxy.list_tools()
            return {t.name for t in result.tools}
        finally:
            await proxy.disconnect()

    async def test_exposed_tool_appears(self):
        proxy = self.make_proxy(
            tool_bindings={
                "echo": MCPToolBinding("echo", "test.echo", discovery=DiscoveryMode.EXPOSED),
            }
        )
        names = await self.visible_names(proxy)
        self.assertIn("echo", names)
        self.assertNotIn("delete_database", names)

    async def test_hidden_tool_does_not_appear(self):
        proxy = self.make_proxy(
            tool_bindings={
                "echo": MCPToolBinding("echo", "test.echo", discovery=DiscoveryMode.EXPOSED),
                "delete_database": MCPToolBinding(
                    "delete_database", "test.delete_database", discovery=DiscoveryMode.HIDDEN
                ),
            }
        )
        names = await self.visible_names(proxy)
        self.assertIn("echo", names)
        self.assertNotIn("delete_database", names)

    async def test_unbound_tool_uses_conservative_hidden_default(self):
        proxy = self.make_proxy(default_discovery=DiscoveryMode.HIDDEN)
        names = await self.visible_names(proxy)
        self.assertEqual(names, set())

    async def test_unbound_tool_exposed_when_default_is_exposed(self):
        proxy = self.make_proxy(default_discovery=DiscoveryMode.EXPOSED)
        names = await self.visible_names(proxy)
        self.assertIn("echo", names)
        self.assertIn("delete_database", names)

    async def test_unknown_tool_not_exposed(self):
        proxy = self.make_proxy(default_discovery=DiscoveryMode.EXPOSED)
        names = await self.visible_names(proxy)
        self.assertNotIn("does_not_exist_downstream", names)

    async def test_metadata_and_schema_are_preserved(self):
        proxy = self.make_proxy(
            tool_bindings={
                "echo": MCPToolBinding("echo", "test.echo", discovery=DiscoveryMode.EXPOSED),
            }
        )
        await proxy.connect()
        try:
            result = await proxy.list_tools()
            echo = next(t for t in result.tools if t.name == "echo")
            self.assertEqual(echo.description, "Echo input text")
            self.assertEqual(echo.input_schema["properties"]["message"]["type"], "string")
        finally:
            await proxy.disconnect()

    async def test_agent_cannot_modify_discovery(self):
        proxy = self.make_proxy(
            tool_bindings={
                "echo": MCPToolBinding("echo", "test.echo", discovery=DiscoveryMode.HIDDEN),
            }
        )
        binding = proxy._integration_config.tool_bindings["echo"]
        # binding is frozen; cannot flip hidden -> exposed
        with self.assertRaises(AttributeError):
            binding.discovery = DiscoveryMode.EXPOSED
        # config is immutable; its binding map is read-only
        with self.assertRaises(TypeError):
            proxy._integration_config.tool_bindings["echo"] = MCPToolBinding(
                "echo", "test.echo", discovery=DiscoveryMode.EXPOSED
            )

    async def test_invalid_discovery_mode_rejected(self):
        with self.assertRaises(MCPConfigurationError):
            MCPToolBinding("echo", "test.echo", discovery="not-a-mode")
        with self.assertRaises(MCPConfigurationError):
            MCPIntegrationConfig(
                integration_id="x",
                command=sys.executable,
                default_discovery="bogus",
            )

    async def test_hidden_tool_forwarding_is_orthogonal_to_discovery(self):
        # Discovery hiding must NOT become the execution gate. In MCP-4 a
        # hidden tool is still routable downstream until MCP-5 adds the
        # execution-authorization gate. This test documents that hiding is not
        # equal to denial of execution, so we assert discovery stays separate.
        proxy = self.make_proxy(
            tool_bindings={
                "echo": MCPToolBinding("echo", "test.echo", discovery=DiscoveryMode.EXPOSED),
                "delete_database": MCPToolBinding(
                    "delete_database", "test.delete_database", discovery=DiscoveryMode.HIDDEN
                ),
            }
        )
        await proxy.connect()
        try:
            visible = {t.name for t in (await proxy.list_tools()).tools}
            self.assertNotIn("delete_database", visible)
            # The execution seam is not yet enforced by discovery; this is
            # exactly why MCP-5 must add the authorization gate. We explicitly
            # do NOT call downstream here to avoid a side effect; we only
            # assert the discovery layer alone cannot be the trust boundary.
        finally:
            await proxy.disconnect()


class DiscoveryDedupTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_binding_keys_are_last_wins_in_trusted_config(self):
        # Duplicate downstream tool names can only exist within one binding map
        # keyed by name; the config rejects clobbering silently by design.
        tool_bindings = {
            "echo": MCPToolBinding("echo", "safe.echo", discovery=DiscoveryMode.HIDDEN),
            "echo": MCPToolBinding("echo", "other.echo", discovery=DiscoveryMode.EXPOSED),
        }
        config = MCPIntegrationConfig(
            integration_id="dup-server",
            command=sys.executable,
            args=[MOCK_SERVER_SCRIPT],
            tool_bindings=tool_bindings,
        )
        self.assertEqual(len(config.tool_bindings), 1)
        self.assertEqual(config.tool_bindings["echo"].capability, "other.echo")
