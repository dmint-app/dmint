"""Unit and end-to-end UX tests for Production CLI UX (Section 10)."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.cli.create_mcp_policy import main_create_mcp, run_create_mcp_policy_wizard
from dmint.cli.errors import CLIError


class ProductionUXTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.config_file = self.base_path / "mcp_protection.json"

        self.md_file.write_text("# Requirements\n- Allow query", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_explicit_stdio_flags(self, mock_client_cls, mock_discover):
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

        out_stream = io.StringIO()
        with patch("sys.stdout", out_stream):
            exit_code = main_create_mcp(
                [
                    "--command",
                    "npx",
                    "--args",
                    "@modelcontextprotocol/server-postgres",
                    "--integration-id",
                    "postgres",
                    "-f",
                    str(self.md_file),
                    "-o",
                    str(self.json_file),
                    "--config-output",
                    str(self.config_file),
                    "--non-interactive",
                    "-y",
                    "-api_key",
                    "sk-test",
                ]
            )

        self.assertEqual(exit_code, 0)
        output_text = out_stream.getvalue()
        self.assertIn("✓ Connected to MCP server for integration 'postgres'", output_text)
        self.assertIn("✓ MCP session initialized for integration 'postgres'", output_text)
        self.assertIn("✓ Discovered 1 tool(s) for 'postgres'", output_text)
        self.assertIn("✓ Policy validated", output_text)
        self.assertIn("✓ Protection config validated", output_text)
        self.assertIn("✓ Saved policy.json + mcp_protection.json", output_text)

    @patch.dict("sys.modules", {"dmint.mcp": None, "dmint_mcp": None})
    @patch("dmint.cli.create_mcp_policy.discover_mcp_auth_requirements")
    @patch("dmint.cli.create_mcp_policy.perform_oauth_flow")
    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_auth_required_ux_flow(self, mock_client_cls, mock_discover, mock_oauth, mock_auth_req):
        mock_req = MagicMock()
        mock_req.required = True
        mock_auth_req.return_value = mock_req

        mock_discover.return_value = [
            {"name": "query", "description": "Remote Query", "input_schema": {}, "integration_id": "remote"}
        ]

        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [{"effect": "allow", "tool": "remote", "action": "query", "resource": "*"}],
            }
        )
        mock_client_cls.return_value = mock_client

        out_stream = io.StringIO()
        with patch("sys.stdout", out_stream):
            with self.assertRaises(CLIError) as ctx:
                policy, config = run_create_mcp_policy_wizard(
                    url="https://example.com/mcp",
                    integration_id="remote",
                    access_md_file=self.md_file,
                    output_json_file=self.json_file,
                    config_output_file=self.config_file,
                    api_key="sk-test",
                    non_interactive=True,
                    auto_confirm=True,
                )

        self.assertIn("unsupported MCP transport type", str(ctx.exception))
        output_text = out_stream.getvalue()
        self.assertIn("✓ Authentication required for integration 'remote'", output_text)
        self.assertIn("✓ Authentication completed for integration 'remote'", output_text)

    @patch("dmint.cli.create_mcp_policy.discover_mcp_auth_requirements")
    def test_auth_failure_explains_recovery_and_preserves_server_error(self, mock_auth_req):
        mock_auth_req.side_effect = CLIError("Server rejected client (403): Client registration disabled by provider.")

        with self.assertRaises(CLIError) as ctx:
            run_create_mcp_policy_wizard(
                url="https://example.com/mcp",
                integration_id="remote",
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                config_output_file=self.config_file,
                api_key="sk-test",
                non_interactive=True,
                auto_confirm=True,
            )

        # Must preserve actual server error clearly
        self.assertIn("Server rejected client (403): Client registration disabled by provider.", str(ctx.exception))
