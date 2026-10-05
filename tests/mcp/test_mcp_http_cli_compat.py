"""Integration test verifying dmint-cli Streamable HTTP protection artifact compatibility.

Verifies end-to-end that CLI-generated mcp_protection.json containing Streamable HTTP
integrations passes dmint-cli validation, loads into dmint-mcp via load_protection_config,
and executes through MCPGateway.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest


from dmint.cli.create_mcp_policy import validate_mcp_protection_config
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport
import mcp.types as types

from dmint.mcp import (
    DownstreamMCPClient,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPTransportType,
    load_protection_config,
)


class MockDownstreamClient(DownstreamMCPClient):
    def __init__(self, config: MCPIntegrationConfig, tools: list[types.Tool] | None = None) -> None:
        super().__init__(config)
        self._connected = False
        self._tools = tools or []
        self.call_log: list[tuple[str, dict]] = []

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_tools(self) -> list[types.Tool]:
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        self.call_log.append((name, arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"executed {self.config.integration_id}:{name}")]
        )


class TestStreamableHTTPCLICompatibility(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # 1. Use real CLI MCPIntegration models for STDIO and Streamable HTTP
        self.integ_stdio = MCPIntegration(
            integration_id="local_files",
            transport=MCPTransport.STDIO,
            connection={
                "command": "mcp-server-fs",
                "args": [str(self.tmppath / "docs")],
                "timeout": 20.0,
            },
            discovered_tools=[
                {
                    "name": "read_doc",
                    "description": "Read document",
                    "inputSchema": {"type": "object"},
                }
            ],
        )

        self.integ_http = MCPIntegration(
            integration_id="remote_service",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={
                "url": "http://localhost:8080/mcp",
                "headers": {
                    "X-App-ID": "dmint-test",
                    "X-Custom-Header": "header-val",
                },
                "timeout": 30.0,
            },
            discovered_tools=[
                {
                    "name": "lookup_user",
                    "description": "Lookup user by ID",
                    "inputSchema": {"type": "object"},
                }
            ],
        )

        # 2. Policy JSON
        self.policy_data = {
            "rules": [
                {"tool": "mcp", "action": "local_files.read_doc", "effect": "allow"},
                {"tool": "mcp", "action": "remote_service.lookup_user", "effect": "allow"},
            ]
        }
        self.policy_file = self.tmppath / "policy.json"
        self.policy_file.write_text(json.dumps(self.policy_data, indent=2), encoding="utf-8")

        # 3. Canonical CLI protection config
        self.protection_config_data = {
            "policy_file": "policy.json",
            "agent_id": "test-cli-agent",
            "disclosure_mode": "dog",
            "integrations": [
                self.integ_stdio.to_dict(),
                self.integ_http.to_dict(),
            ],
        }

    async def asyncTearDown(self) -> None:
        self.tmpdir.cleanup()

    async def test_cli_artifact_validation_and_gateway_execution(self) -> None:
        """CLI protection config with Streamable HTTP passes CLI validator, loads, and executes."""
        # 1. Verify dmint-cli validate_mcp_protection_config accepts the artifact
        validate_mcp_protection_config(self.protection_config_data)

        # 2. Write to disk as canonical mcp_protection.json
        config_path = self.tmppath / "mcp_protection.json"
        config_path.write_text(json.dumps(self.protection_config_data, indent=2), encoding="utf-8")

        # 3. Load via dmint-mcp loader
        gateway_config = load_protection_config(config_path)
        self.assertIsInstance(gateway_config, MCPGatewayConfig)
        self.assertEqual(len(gateway_config.integrations), 2)

        http_cfg = gateway_config.get_integration("remote_service")
        self.assertIsNotNone(http_cfg)
        self.assertEqual(http_cfg.transport_type, MCPTransportType.STREAMABLE_HTTP)
        self.assertEqual(http_cfg.url, "http://localhost:8080/mcp")
        self.assertEqual(http_cfg.headers["X-Custom-Header"], "header-val")
        self.assertEqual(http_cfg.headers["X-App-ID"], "dmint-test")
        self.assertEqual(http_cfg.call_timeout, 30.0)

        # 4. Instantiate MCPGateway with mock clients
        clients: dict[str, MockDownstreamClient] = {}

        def client_factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            tools = [
                types.Tool(name=b.tool_name, description=f"{cfg.integration_id} {b.tool_name}", input_schema={})
                for b in cfg.tool_bindings.values()
            ]
            client = MockDownstreamClient(cfg, tools=tools)
            clients[cfg.integration_id] = client
            return client

        gateway = MCPGateway(gateway_config, client_factory=client_factory)
        await gateway.connect()
        try:
            # 5. Discover tools
            tools_res = await gateway.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            self.assertIn("read_doc", tool_names)
            self.assertIn("lookup_user", tool_names)

            # 6. Call HTTP tool via bare name
            http_res = await gateway._handle_call_tool(
                None,
                types.CallToolRequestParams(name="lookup_user", arguments={"uid": "123"}),
            )
            self.assertFalse(http_res.is_error)
            self.assertEqual(clients["remote_service"].call_log[-1], ("lookup_user", {"uid": "123"}))

            # 7. Call STDIO tool via namespaced name
            stdio_res = await gateway._handle_call_tool(
                None,
                types.CallToolRequestParams(name="local_files.read_doc", arguments={"path": "file.txt"}),
            )
            self.assertFalse(stdio_res.is_error)
            self.assertEqual(clients["local_files"].call_log[-1], ("read_doc", {"path": "file.txt"}))
        finally:
            await gateway.disconnect()


if __name__ == "__main__":
    unittest.main()
