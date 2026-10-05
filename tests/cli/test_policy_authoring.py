"""Unit and security tests for MCP capability-aware policy authoring (Section 8)."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dmint.policy import Policy
from dmint.cli.create_mcp_policy import (
    run_create_mcp_policy_wizard,
    validate_policy_against_discovered_capabilities,
)
from dmint.cli.errors import PolicyValidationError
from dmint.cli.mcp_connections import MCPIntegration


class MCPPolicyAuthoringTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.config_file = self.base_path / "mcp_protection.json"

        self.md_file.write_text("# Requirements\n- Allow postgres query.", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unknown_tool_requested_by_llm_raises_policy_error(self):
        discovered = [{"name": "query", "capability": "mcp.postgres.query"}]
        invalid_mapping = {
            "rules": [{"effect": "allow", "tool": "unknown_hack_tool", "action": "query", "resource": "*"}]
        }

        from dmint.policy import PolicyError

        with self.assertRaises(PolicyError) as ctx:
            validate_policy_against_discovered_capabilities(invalid_mapping, discovered)

        self.assertIn("specifies tool 'unknown_hack_tool' which was not in discovered capabilities", str(ctx.exception))

    def test_unknown_integration_requested_by_llm_raises_policy_error(self):
        discovered = [{"name": "query", "capability": "mcp.postgres.query"}]
        invalid_mapping = {
            "rules": [{"effect": "allow", "tool": "mcp.fake_integration.query", "action": "query", "resource": "*"}]
        }

        from dmint.policy import PolicyError

        with self.assertRaises(PolicyError) as ctx:
            validate_policy_against_discovered_capabilities(invalid_mapping, discovered)

        self.assertIn("specifies tool 'mcp.fake_integration.query'", str(ctx.exception))

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic")
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_validation_retry_recovers_when_llm_fixes_unknown_tool(self, mock_client_cls, mock_discover):
        mock_discover.return_value = [
            {"name": "query", "description": "SQL query", "input_schema": {}, "integration_id": "postgres"}
        ]

        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        # Turn 1 returns unknown tool, Turn 2 recovers with valid tool
        mock_client.chat_completion.side_effect = [
            json.dumps(
                {
                    "type": "policy_ready",
                    "rules": [{"effect": "allow", "tool": "nonexistent_tool", "action": "query", "resource": "*"}],
                }
            ),
            json.dumps(
                {
                    "type": "policy_ready",
                    "rules": [{"effect": "allow", "tool": "query", "action": "query", "resource": "*"}],
                }
            ),
        ]
        mock_client_cls.return_value = mock_client

        policy, config = run_create_mcp_policy_wizard(
            command="mcp-server-postgres",
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            config_output_file=self.config_file,
            api_key="sk-test",
            non_interactive=True,
            auto_confirm=True,
        )

        self.assertIsInstance(policy, Policy)
        self.assertEqual(mock_client.chat_completion.call_count, 2)

    @patch("sys.stdin.isatty", return_value=True)
    @patch("sys.stdout.isatty", return_value=True)
    @patch("builtins.input")
    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic")
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_authoring_multiple_integrations_with_duplicate_tool_names(
        self, mock_client_cls, mock_discover, mock_input, mock_stdout, mock_stdin
    ):
        # Two servers exposing tool "query"
        mock_discover.side_effect = [
            [
                {
                    "name": "query",
                    "description": "PG Query",
                    "input_schema": {},
                    "integration_id": "postgres",
                    "capability": "mcp.postgres.query",
                }
            ],
            [
                {
                    "name": "query",
                    "description": "Analytics Query",
                    "input_schema": {},
                    "integration_id": "analytics",
                    "capability": "mcp.analytics.query",
                }
            ],
        ]

        mock_input.side_effect = ["y", "1", "mcp-server-analytics", "", "analytics", "n", "", "", "y"]

        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [
                    {"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"},
                    {"effect": "allow", "tool": "analytics", "action": "query", "resource": "*"},
                ],
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
            non_interactive=False,
            auto_confirm=False,
        )

        self.assertIsInstance(policy, Policy)
        self.assertEqual(len(policy.rules), 2)
