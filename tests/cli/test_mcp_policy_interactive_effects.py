"""Regression: unrecognized effect input in the MCP policy wizard must never become ALLOW (SRC-08).

When the requirements file is missing, the wizard asks for an effect per discovered tool.
Unrecognized input (e.g. ``DEN``, ``block``) used to be silently converted to ALLOW — a typo
produced an explicit allow rule. It must re-prompt instead; only a blank answer takes the
documented ``[default ALLOW]``.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.cli.create_mcp_policy import run_create_mcp_policy_wizard


class TestInteractiveEffectPrompt(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        # Deliberately absent: the wizard must interactively collect effects.
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.config_file = self.base_path / "mcp_protection.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @patch("sys.stdin.isatty", return_value=True)
    @patch("sys.stdout.isatty", return_value=True)
    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    @patch("builtins.input")
    def test_unrecognized_effect_is_re_prompted_never_allow(
        self, mock_input, mock_client_cls, mock_discover, mock_stdout, mock_stdin
    ):
        mock_discover.return_value = [
            {
                "name": "query",
                "description": "Postgres Query",
                "input_schema": {},
                "integration_id": "postgres",
                "capability": "mcp.postgres.query",
            }
        ]

        # 1. "Add another MCP server?" -> n
        # 2. Unrecognized effect "DEN" -> must re-prompt (never silently ALLOW)
        # 3. Valid effect "DENY"
        mock_input.side_effect = ["n", "DEN", "DENY"]

        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [{"effect": "deny", "tool": "postgres", "action": "query", "resource": "*"}],
            }
        )
        mock_client_cls.return_value = mock_client

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            run_create_mcp_policy_wizard(
                command="mcp-server-postgres",
                args=["postgresql://localhost/db"],
                integration_id="postgres",
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                config_output_file=self.config_file,
                provider="openai",
                api_key="sk-test",
                model="gpt-4o-mini",
                non_interactive=False,
                auto_confirm=True,
            )

        # The generated requirements must reflect the explicitly typed DENY, not the typo.
        requirements_text = self.md_file.read_text(encoding="utf-8")
        self.assertIn("DENY", requirements_text)
        self.assertNotIn("ALLOW", requirements_text)

        # The user must have been told the input was not recognized.
        self.assertIn("unrecognized", out.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
