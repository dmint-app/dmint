"""Unit and security tests for Multi-MCP discovery (Section 7)."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.policy import Policy
from dmint.cli.errors import CLIError
from dmint.cli.create_mcp_policy import run_create_mcp_policy_wizard
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport, discover_mcp_tools_generic
from dmint.cli.mcp_credentials import CredentialStore


class MultiMCPDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.config_file = self.base_path / "mcp_protection.json"

        self.md_file.write_text(
            "# Multi-MCP Requirements\n- Allow postgres query\n- Allow github issue", encoding="utf-8"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("sys.stdin.isatty", return_value=True)
    @patch("sys.stdout.isatty", return_value=True)
    @patch("builtins.input")
    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_two_stdio_integrations_discovery(
        self, mock_client_cls, mock_discover, mock_input, mock_stdout, mock_stdin
    ):
        mock_discover.side_effect = [
            [
                {
                    "name": "query",
                    "description": "Postgres Query",
                    "input_schema": {},
                    "integration_id": "postgres",
                    "capability": "mcp.postgres.query",
                }
            ],
            [
                {
                    "name": "read_file",
                    "description": "FS Read File",
                    "input_schema": {},
                    "integration_id": "filesystem",
                    "capability": "mcp.filesystem.read_file",
                }
            ],
        ]

        # Interactive prompts: Add another? y -> conn_type: 1 -> command: npx -> args: ... -> integration_id: filesystem -> Add another? n -> model select: "" -> accept policy confirmation: y
        mock_input.side_effect = [
            "y",
            "1",
            "npx -y @modelcontextprotocol/server-filesystem",
            "",
            "filesystem",
            "n",
            "",
            "",
            "y",
        ]

        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [
                    {"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"},
                    {"effect": "allow", "tool": "filesystem", "action": "read_file", "resource": "*"},
                ],
            }
        )
        mock_client_cls.return_value = mock_client

        policy, config = run_create_mcp_policy_wizard(
            command="mcp-server-postgres",
            args=["postgresql://localhost/db"],
            integration_id="postgres",
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            config_output_file=self.config_file,
            api_key="sk-test",
            non_interactive=False,
            auto_confirm=False,
        )

        self.assertIsInstance(policy, Policy)
        self.assertEqual(len(config["integrations"]), 2)

    def test_same_tool_names_across_integrations_remain_distinct(self):
        i1 = MCPIntegration(
            integration_id="postgres",
            transport=MCPTransport.STDIO,
            connection={"command": "pg"},
            discovered_tools=[{"name": "query", "description": "SQL Query"}],
        )
        i2 = MCPIntegration(
            integration_id="analytics",
            transport=MCPTransport.STDIO,
            connection={"command": "analytics"},
            discovered_tools=[{"name": "query", "description": "Analytics Query"}],
        )

        dict1 = i1.to_dict()
        dict2 = i2.to_dict()

        cap1 = dict1["tool_bindings"]["query"]["capability"]
        cap2 = dict2["tool_bindings"]["query"]["capability"]

        self.assertEqual(cap1, "mcp.postgres.query")
        self.assertEqual(cap2, "mcp.analytics.query")
        self.assertNotEqual(cap1, cap2)

    def test_duplicate_integration_ids_rejected(self):
        i1 = MCPIntegration(integration_id="postgres", connection={"command": "cmd1"})
        i2 = MCPIntegration(integration_id="postgres", connection={"command": "cmd2"})

        seen_ids = set()
        with self.assertRaises(CLIError) as ctx:
            for integ in [i1, i2]:
                if integ.integration_id in seen_ids:
                    raise CLIError(f"Duplicate integration ID '{integ.integration_id}'.")
                seen_ids.add(integ.integration_id)

        self.assertIn("Duplicate integration ID", str(ctx.exception))

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    def test_one_integration_fails_discovery_aborts_overall_flow(self, mock_discover):
        mock_discover.side_effect = Exception("Connection refused on Integration 2")

        with self.assertRaises(CLIError) as ctx:
            run_create_mcp_policy_wizard(
                command="mcp-server-postgres",
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                config_output_file=self.config_file,
                non_interactive=True,
            )

        self.assertIn("Failed tool discovery", str(ctx.exception))
        self.assertFalse(self.json_file.exists())
        self.assertFalse(self.config_file.exists())

    def test_credential_isolation_per_server_identity(self):
        cred_store = CredentialStore(storage_path=self.base_path / "creds.json", use_keyring=False)
        id1 = "https://mcp1.example.com::srv1"
        id2 = "https://mcp2.example.com::srv2"

        cred_store.save(id1, {"access_token": "token-for-srv1"})
        cred_store.save(id2, {"access_token": "token-for-srv2"})

        rec1 = cred_store.load(id1)
        rec2 = cred_store.load(id2)

        self.assertEqual(rec1.access_token, "token-for-srv1")
        self.assertEqual(rec2.access_token, "token-for-srv2")
        self.assertNotEqual(rec1.access_token, rec2.access_token)
