"""Unit and security tests for MCP Protection Configuration (Section 9)."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.cli.create_mcp_policy import (
    _assert_no_secrets_in_dict,
    run_create_mcp_policy_wizard,
    validate_mcp_protection_config,
)
from dmint.cli.errors import CLIError
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport


class MCPProtectionConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.config_file = self.base_path / "mcp_protection.json"

        self.md_file.write_text("# Security Requirements\n- Allow query", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generated_config_parsed_by_actual_dmint_mcp(self):
        integ = MCPIntegration(
            integration_id="postgres",
            transport=MCPTransport.STDIO,
            connection={"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres"]},
            discovered_tools=[{"name": "query", "description": "Postgres Query"}],
        )

        config = {
            "policy_file": "policy.json",
            "integrations": [integ.to_dict()],
        }

        # Validate using dmint-cli validator which calls dmint_mcp.MCPIntegrationConfig
        validate_mcp_protection_config(config)

        # Import directly from dmint_mcp runtime to verify 100% compatibility
        from dmint.mcp import MCPIntegrationConfig, MCPToolBinding

        i_cfg = config["integrations"][0]
        tool_bindings_objs = {
            tname: MCPToolBinding(
                tool_name=b["tool_name"],
                capability=b["capability"],
                discovery=b.get("discovery", "exposed"),
            )
            for tname, b in i_cfg["tool_bindings"].items()
        }
        mcp_cfg = MCPIntegrationConfig(
            integration_id=i_cfg["integration_id"],
            command=i_cfg["connection"]["command"],
            args=i_cfg["connection"]["args"],
            transport_type=i_cfg["transport"],
            tool_bindings=tool_bindings_objs,
        )
        self.assertEqual(mcp_cfg.integration_id, "postgres")
        self.assertIn("query", mcp_cfg.tool_bindings)
        self.assertEqual(mcp_cfg.tool_bindings["query"].capability, "mcp.postgres.query")

    def test_no_plaintext_secrets_in_generated_config(self):
        invalid_config = {
            "policy_file": "policy.json",
            "integrations": [
                {
                    "integration_id": "postgres",
                    "transport": "stdio",
                    "connection": {"command": "pg"},
                    "authentication": {"access_token": "secret-token-123"},
                    "tool_bindings": {},
                }
            ],
        }

        with self.assertRaises(CLIError) as ctx:
            validate_mcp_protection_config(invalid_config)

        self.assertIn("Security violation: Plaintext secret field 'access_token'", str(ctx.exception))

    def test_tool_binding_maps_name_to_capability(self):
        integ = MCPIntegration(
            integration_id="postgres",
            transport=MCPTransport.STDIO,
            connection={"command": "pg"},
            discovered_tools=[{"name": "execute_query", "description": "Exec Query"}],
        )

        d = integ.to_dict()
        binding = d["tool_bindings"]["execute_query"]
        self.assertEqual(binding["tool_name"], "execute_query")
        self.assertEqual(binding["capability"], "mcp.postgres.execute_query")
        self.assertEqual(binding["discovery"], "exposed")

    def test_unsupported_transport_fails_explicitly(self):
        unsupported_config = {
            "policy_file": "policy.json",
            "integrations": [
                {
                    "integration_id": "remote-server",
                    "transport": "invalid_custom_transport",
                    "connection": {"url": "http://localhost:8080"},
                    "tool_bindings": {},
                }
            ],
        }

        with self.assertRaises(CLIError) as ctx:
            validate_mcp_protection_config(unsupported_config)

        self.assertIn("dmint-mcp configuration validation failed", str(ctx.exception))

    def test_multi_integration_isolation_in_config(self):
        i1 = MCPIntegration(
            integration_id="postgres",
            transport=MCPTransport.STDIO,
            connection={"command": "pg"},
            discovered_tools=[{"name": "query", "description": "SQL Query"}],
        )
        i2 = MCPIntegration(
            integration_id="analytics",
            transport=MCPTransport.STDIO,
            connection={"command": "analytics-mcp"},
            discovered_tools=[{"name": "query", "description": "Analytics Query"}],
        )

        config = {
            "policy_file": "policy.json",
            "integrations": [i1.to_dict(), i2.to_dict()],
        }

        validate_mcp_protection_config(config)

        self.assertEqual(len(config["integrations"]), 2)
        self.assertEqual(config["integrations"][0]["integration_id"], "postgres")
        self.assertEqual(config["integrations"][1]["integration_id"], "analytics")
        self.assertEqual(config["integrations"][0]["tool_bindings"]["query"]["capability"], "mcp.postgres.query")
        self.assertEqual(config["integrations"][1]["tool_bindings"]["query"]["capability"], "mcp.analytics.query")

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_atomic_write_and_readback_validation(self, mock_client_cls, mock_discover):
        mock_discover.return_value = [
            {"name": "query", "description": "PG Query", "input_schema": {}, "integration_id": "postgres"}
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
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            config_output_file=self.config_file,
            api_key="sk-test",
            non_interactive=True,
            auto_confirm=True,
        )

        self.assertTrue(self.config_file.exists())
        written_data = json.loads(self.config_file.read_text(encoding="utf-8"))
        self.assertEqual(written_data["policy_file"], "policy.json")
        self.assertEqual(written_data["integrations"][0]["integration_id"], "postgres")
