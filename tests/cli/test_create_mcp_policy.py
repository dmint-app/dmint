"""Unit and security tests for create-mcp-policy command (src/dmint_cli/create_mcp_policy.py)."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.policy import Policy
from dmint.cli.__main__ import main
from dmint.cli.create_mcp_policy import (
    main_create_mcp,
    run_create_mcp_policy_wizard,
)
from dmint.cli.errors import CLIError
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport


class CreateMCPPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.config_file = self.base_path / "mcp_protection.json"

        self.md_file.write_text("# Requirements\n- Allow postgres query.", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_run_create_mcp_policy_wizard_generates_policy_and_config(self, mock_client_cls, mock_discover):
        mock_discover.return_value = [
            {
                "name": "query",
                "description": "Run SQL query",
                "input_schema": {"type": "object"},
                "integration_id": "postgres",
            }
        ]
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [{"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"}],
            }
        )
        mock_client_cls.return_value = mock_client

        policy, config = run_create_mcp_policy_wizard(
            command="mcp-server-postgres",
            integration_id="postgres",
            args=["postgresql://localhost/db"],
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            config_output_file=self.config_file,
            api_key="sk-test",
            non_interactive=True,
            auto_confirm=True,
        )

        self.assertIsInstance(policy, Policy)
        self.assertTrue(self.json_file.exists())
        self.assertTrue(self.config_file.exists())
        self.assertIn("integrations", config)
        self.assertEqual(config["integrations"][0]["connection"]["command"], "mcp-server-postgres")
        self.assertIn("query", config["integrations"][0]["tool_bindings"])

    def test_mcp_integration_model_to_dict_preserves_identity(self):
        integ = MCPIntegration(
            integration_id="github",
            transport="stdio",
            connection={"command": "npx", "args": ["-y", "@example/github-mcp"]},
            discovered_tools=[
                {"name": "get_repository", "description": "Get repo details"},
                {"name": "create_issue", "description": "Create issue"},
            ],
        )
        d = integ.to_dict()
        self.assertEqual(d["integration_id"], "github")
        self.assertEqual(d["transport"], "stdio")
        self.assertIn("get_repository", d["tool_bindings"])
        self.assertEqual(d["tool_bindings"]["get_repository"]["capability"], "mcp.github.get_repository")

    def test_distinct_cross_server_tool_identities(self):
        # Two servers exposing the same tool name "query"
        integ1 = MCPIntegration(
            integration_id="postgres",
            transport="stdio",
            connection={"command": "mcp-server-postgres"},
            discovered_tools=[{"name": "query", "description": "Execute DB query"}],
        )
        integ2 = MCPIntegration(
            integration_id="analytics",
            transport="stdio",
            connection={"command": "mcp-server-analytics"},
            discovered_tools=[{"name": "query", "description": "Execute analytics query"}],
        )
        d1 = integ1.to_dict()
        d2 = integ2.to_dict()
        self.assertNotEqual(
            d1["tool_bindings"]["query"]["capability"],
            d2["tool_bindings"]["query"]["capability"],
        )
        self.assertEqual(d1["tool_bindings"]["query"]["capability"], "mcp.postgres.query")
        self.assertEqual(d2["tool_bindings"]["query"]["capability"], "mcp.analytics.query")

    def test_npx_stdio_integration(self):
        integ = MCPIntegration(
            integration_id="filesystem",
            transport=MCPTransport.STDIO,
            connection={"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "./data"]},
        )
        integ.validate_connection()
        integ.validate_transport()
        self.assertEqual(integ.connection["command"], "npx")
        self.assertEqual(integ.transport, MCPTransport.STDIO)

    def test_streamable_http_configuration(self):
        integ = MCPIntegration(
            integration_id="remote-crm",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
            authentication={"api_key": "sk-secret-12345"},
        )
        integ.validate_connection()
        integ.validate_transport()
        self.assertEqual(integ.transport, MCPTransport.STREAMABLE_HTTP)

    @patch("mcp.client.streamable_http.streamable_http_client")
    @patch("mcp.ClientSession")
    def test_streamable_http_discovery_success_and_no_call_tool_invocation(self, mock_session_cls, mock_http_client):
        mock_session = AsyncMock()
        mock_tool1 = MagicMock(name="get_customer", description="Get customer details", input_schema={"type": "object"})
        mock_tool1.name = "get_customer"
        mock_tool1.description = "Get customer details"
        mock_tool1.input_schema = {"type": "object"}

        mock_tool2 = MagicMock(name="list_orders", description="List orders", input_schema={"type": "object"})
        mock_tool2.name = "list_orders"
        mock_tool2.description = "List orders"
        mock_tool2.input_schema = {"type": "object"}

        mock_session.list_tools.return_value = MagicMock(tools=[mock_tool1, mock_tool2])
        mock_session_cls.return_value.__aenter__.return_value = mock_session

        mock_read, mock_write = MagicMock(), MagicMock()
        mock_http_client.return_value.__aenter__.return_value = (mock_read, mock_write)

        integ = MCPIntegration(
            integration_id="crm",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
            authentication={"api_key": "sk-secret-12345"},
        )

        from dmint.cli.mcp_connections import discover_mcp_tools_generic
        import asyncio

        tools = asyncio.run(discover_mcp_tools_generic(integ))
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[0]["capability"], "mcp.crm.get_customer")
        self.assertEqual(tools[1]["capability"], "mcp.crm.list_orders")

        # ASSERTION: call_tool must NEVER be invoked during discovery
        mock_session.call_tool.assert_not_called()

    @patch("mcp.client.streamable_http.streamable_http_client")
    def test_streamable_http_discovery_401_unauthorized(self, mock_http_client):
        mock_http_client.side_effect = Exception("HTTP 401 Unauthorized Bearer sk-secret-token-123")

        integ = MCPIntegration(
            integration_id="crm",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
            authentication={"api_key": "sk-secret-token-123"},
        )

        from dmint.cli.mcp_connections import discover_mcp_tools_generic
        import asyncio

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(discover_mcp_tools_generic(integ))

        self.assertIn("401 Unauthorized", str(ctx.exception))
        # Verify secret token was redacted in error message
        self.assertNotIn("sk-secret-token-123", str(ctx.exception))

    @patch("mcp.client.streamable_http.streamable_http_client")
    def test_streamable_http_discovery_403_forbidden(self, mock_http_client):
        mock_http_client.side_effect = Exception("HTTP 403 Forbidden")

        integ = MCPIntegration(
            integration_id="crm",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        from dmint.cli.mcp_connections import discover_mcp_tools_generic
        import asyncio

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(discover_mcp_tools_generic(integ))

        self.assertIn("403 Forbidden", str(ctx.exception))

    @patch("mcp.client.streamable_http.streamable_http_client")
    def test_streamable_http_discovery_500_server_error(self, mock_http_client):
        mock_http_client.side_effect = Exception("HTTP 500 Internal Server Error")

        integ = MCPIntegration(
            integration_id="crm",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        from dmint.cli.mcp_connections import discover_mcp_tools_generic
        import asyncio

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(discover_mcp_tools_generic(integ))

        self.assertIn("server error", str(ctx.exception))

    def test_invalid_transport_raises_error(self):
        integ = MCPIntegration(
            integration_id="custom",
            transport="invalid-transport",
            connection={"command": "ls"},
        )
        with self.assertRaises(CLIError) as ctx:
            integ.validate_transport()
        self.assertIn("Unknown MCP transport type 'invalid-transport'", str(ctx.exception))

    def test_malformed_connection_structure_raises_error(self):
        # Missing command for stdio
        bad_stdio = MCPIntegration(
            integration_id="bad",
            transport=MCPTransport.STDIO,
            connection={},
        )
        with self.assertRaises(CLIError) as ctx:
            bad_stdio.validate_connection()
        self.assertIn("missing or invalid 'command'", str(ctx.exception))

        # Missing url for streamable-http
        bad_http = MCPIntegration(
            integration_id="bad_http",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={},
        )
        with self.assertRaises(CLIError) as ctx:
            bad_http.validate_connection()
        self.assertIn("missing or invalid 'url'", str(ctx.exception))

    def test_secret_redaction(self):
        integ = MCPIntegration(
            integration_id="secure-integration",
            transport=MCPTransport.STDIO,
            connection={"command": "npx", "password": "super-secret-password"},
            authentication={"api_key": "sk-secret-12345", "token": "oauth-token"},
        )
        repr_str = repr(integ)
        self.assertNotIn("super-secret-password", repr_str)
        self.assertNotIn("sk-secret-12345", repr_str)
        self.assertNotIn("oauth-token", repr_str)
        self.assertIn("<redacted>", repr_str)

        d = integ.to_dict()
        dict_str = json.dumps(d)
        self.assertNotIn("sk-secret-12345", dict_str)
        self.assertNotIn("oauth-token", dict_str)

    def test_protect_mcp_alias_normalizes_to_create_mcp_policy(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["protect-mcp", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("create-mcp-policy", buf.getvalue())

    def test_main_create_mcp_usage_error(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main_create_mcp(["--invalid-flag"])
        self.assertEqual(code, 2)
