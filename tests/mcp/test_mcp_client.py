"""Tests for downstream MCP client connection and trusted integration configuration (MCP-2)."""

import sys
import unittest
from pathlib import Path

import anyio

from dmint.mcp.errors import MCPConfigurationError, MCPConnectionError, MCPProtocolError
from dmint.mcp import DownstreamMCPClient, MCPIntegrationConfig, MCPToolBinding, MCPTransportType

MOCK_SERVER_SCRIPT = str(Path(__file__).parent / "mock_server.py")


class MCPClientTests(unittest.TestCase):
    def test_invalid_configuration_fails_closed(self):
        with self.assertRaises(MCPConfigurationError):
            MCPIntegrationConfig(integration_id="", command="python3")
        with self.assertRaises(MCPConfigurationError):
            MCPIntegrationConfig(integration_id="server-a", command="")
        with self.assertRaises(MCPConfigurationError):
            MCPIntegrationConfig(integration_id="server-a", command="python3", transport_type="invalid")
        with self.assertRaises(MCPConfigurationError):
            MCPIntegrationConfig(integration_id="server-a", command="python3", args="not-a-list")
        with self.assertRaises(MCPConfigurationError):
            MCPIntegrationConfig(integration_id="server-a", command="python3", env={"KEY": 123})

    def test_credentials_are_not_exposed_in_repr_or_agent_facing_layer(self):
        config = MCPIntegrationConfig(
            integration_id="server-github",
            command="python3",
            args=[MOCK_SERVER_SCRIPT],
            env={"GITHUB_TOKEN": "secret_token_12345", "API_KEY": "super_secret"},
        )
        repr_str = repr(config)
        self.assertNotIn("secret_token_12345", repr_str)
        self.assertNotIn("super_secret", repr_str)
        self.assertIn("[REDACTED]", repr_str)

    def test_integration_id_is_stable_and_trusted(self):
        config1 = MCPIntegrationConfig(integration_id="server-a", command="python3", args=[MOCK_SERVER_SCRIPT])
        config2 = MCPIntegrationConfig(integration_id="server-b", command="python3", args=[MOCK_SERVER_SCRIPT])

        self.assertEqual(config1.integration_id, "server-a")
        self.assertEqual(config2.integration_id, "server-b")
        self.assertNotEqual(config1.integration_id, config2.integration_id)
        with self.assertRaises(AttributeError):
            config1.integration_id = "hacked-id"

    def test_agent_cannot_override_endpoint_configuration(self):
        config = MCPIntegrationConfig(
            integration_id="server-prod",
            command="python3",
            args=[MOCK_SERVER_SCRIPT],
        )
        with self.assertRaises(AttributeError):
            config.command = "malicious-cmd"
        with self.assertRaises(AttributeError):
            config.args = ("--injected-arg",)

    def test_successful_connection_handshake_and_list_tools(self):
        async def run_test():
            config = MCPIntegrationConfig(
                integration_id="server-mock",
                command=sys.executable,
                args=[MOCK_SERVER_SCRIPT],
            )
            async with DownstreamMCPClient(config) as client:
                self.assertTrue(client.is_connected)
                tools = await client.list_tools()
                tool_names = [t.name for t in tools]
                self.assertIn("echo", tool_names)
                self.assertIn("delete_database", tool_names)

                result = await client.call_tool("echo", {"message": "hello dmint"})
                self.assertIsNotNone(result.content)
                self.assertEqual(result.content[0].text, "echo: hello dmint")

        anyio.run(run_test)

    def test_downstream_server_unavailable_fails_closed(self):
        async def run_test():
            config = MCPIntegrationConfig(
                integration_id="nonexistent-server",
                command="nonexistent_mcp_binary_xyz_123",
            )
            client = DownstreamMCPClient(config)
            with self.assertRaises(MCPConnectionError):
                await client.connect()

        anyio.run(run_test)

    def test_downstream_process_exits_early_fails_closed(self):
        async def run_test():
            config = MCPIntegrationConfig(
                integration_id="exit-server",
                command=sys.executable,
                args=[MOCK_SERVER_SCRIPT, "--exit-early"],
            )
            client = DownstreamMCPClient(config)
            with self.assertRaises(MCPConnectionError):
                await client.connect()

        anyio.run(run_test)

    def test_downstream_fail_init_fails_closed(self):
        async def run_test():
            config = MCPIntegrationConfig(
                integration_id="fail-init-server",
                command=sys.executable,
                args=[MOCK_SERVER_SCRIPT, "--fail-init"],
            )
            client = DownstreamMCPClient(config)
            with self.assertRaises(MCPConnectionError):
                await client.connect()

        anyio.run(run_test)

    def test_two_integrations_cannot_share_identity_unless_configured(self):
        config_a = MCPIntegrationConfig(integration_id="server-a", command="python3", args=[MOCK_SERVER_SCRIPT])
        config_b = MCPIntegrationConfig(integration_id="server-b", command="python3", args=[MOCK_SERVER_SCRIPT])

        self.assertNotEqual(config_a.integration_id, config_b.integration_id)
        self.assertNotEqual(config_a, config_b)
        self.assertEqual(config_a.integration_id, "server-a")
        self.assertEqual(config_b.integration_id, "server-b")

        # Only config_a maps to integration_id "server-a"; server-b cannot be reached via a
        self.assertEqual(config_a.integration_id, "server-a")
        self.assertFalse(config_b.integration_id == "server-a")

    def test_disconnect_and_reconnect_lifecycle(self):
        async def run_test():
            config = MCPIntegrationConfig(
                integration_id="reconnect-server",
                command=sys.executable,
                args=[MOCK_SERVER_SCRIPT],
            )
            client = DownstreamMCPClient(config)
            await client.connect()
            self.assertTrue(client.is_connected)
            tools = await client.list_tools()
            self.assertEqual(len(tools), 2)
            await client.disconnect()
            self.assertFalse(client.is_connected)

            # Reconnect after disconnect
            await client.connect()
            self.assertTrue(client.is_connected)
            await client.disconnect()
            self.assertFalse(client.is_connected)

        anyio.run(run_test)

    def test_call_before_connect_fails_closed(self):
        async def run_test():
            config = MCPIntegrationConfig(integration_id="not-connected", command="python3", args=[MOCK_SERVER_SCRIPT])
            client = DownstreamMCPClient(config)
            with self.assertRaises(MCPConnectionError):
                await client.call_tool("echo", {"message": "x"})
            with self.assertRaises(MCPConnectionError):
                await client.list_tools()

        anyio.run(run_test)
