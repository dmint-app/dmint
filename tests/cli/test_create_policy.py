"""Unit and security tests for interactive policy wizard (src/dmint_cli/create_policy.py)."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dmint.policy import Policy
from dmint.cli.errors import (
    CLIError,
    JSONExtractionError,
    PolicyValidationError,
)
from dmint.cli.create_policy import (
    discover_local_tools_ast,
    main_create,
    parse_tool_declarations_ast,
    run_create_policy_wizard,
)


class PolicyCreateWizardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.md_file = self.base_path / "access.md"
        self.json_file = self.base_path / "policy.json"
        self.md_file.write_text("# Access Policy\n- Agents may read database records.", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ast_tool_discovery_is_static_and_safe(self):
        # Source file containing malicious executable code outside tool AST nodes
        malicious_tool = self.base_path / "malicious.py"
        malicious_tool.write_text(
            'types.Tool(name="read_data", description="Safe tool")\nraise RuntimeError("THIS MUST NEVER EXECUTE")\n',
            encoding="utf-8",
        )

        # AST discovery MUST parse without triggering code execution (no RuntimeError raised)
        tools = parse_tool_declarations_ast(malicious_tool)
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "read_data")

    def test_ast_tool_discovery_multiple_files_and_directories(self):
        tools_dir = self.base_path / "tools"
        tools_dir.mkdir()
        file1 = tools_dir / "github.py"
        file2 = tools_dir / "database.py"

        file1.write_text(
            'types.Tool(name="create_issue", description="Create issue")\n'
            'raise RuntimeError("THIS MUST NEVER EXECUTE IN FILE 1")\n',
            encoding="utf-8",
        )
        file2.write_text(
            'types.Tool(name="query_db", description="Query DB")\n'
            'raise RuntimeError("THIS MUST NEVER EXECUTE IN FILE 2")\n',
            encoding="utf-8",
        )

        discovered = discover_local_tools_ast([tools_dir])
        self.assertEqual(len(discovered), 2)
        names = {t["name"] for t in discovered}
        self.assertIn("create_issue", names)
        self.assertIn("query_db", names)

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_non_interactive_policy_ready_success(self, mock_client_cls):
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

        policy = run_create_policy_wizard(
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            api_key="sk-test",
            non_interactive=True,
            auto_confirm=True,
        )

        self.assertIsInstance(policy, Policy)
        self.assertEqual(len(policy.rules), 1)
        self.assertTrue(self.json_file.exists())

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_model_discovery_fallback_on_404(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.list_models.side_effect = RuntimeError("HTTP 404 Not Found")
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [{"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"}],
            }
        )
        mock_client_cls.return_value = mock_client

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="custom-model"):
                policy = run_create_policy_wizard(
                    access_md_file=self.md_file,
                    output_json_file=self.json_file,
                    api_key="sk-test",
                    auto_confirm=True,
                )

        self.assertIsInstance(policy, Policy)
        self.assertIn("[!] Could not list models", buf.getvalue())

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_envelope_parser_malformed_json_retries_and_fails(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = "NOT_JSON_RESPONSE"
        mock_client_cls.return_value = mock_client

        with self.assertRaises(JSONExtractionError):
            run_create_policy_wizard(
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                api_key="sk-test",
                non_interactive=True,
                auto_confirm=True,
            )

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_envelope_parser_unrecognized_type_retries_and_fails(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps({"type": "unrecognized_type"})
        mock_client_cls.return_value = mock_client

        with self.assertRaises(JSONExtractionError):
            run_create_policy_wizard(
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                api_key="sk-test",
                non_interactive=True,
                auto_confirm=True,
            )

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_clarification_loop_multi_turn_reaches_policy_ready(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.side_effect = [
            json.dumps({"type": "clarification_needed", "questions": ["Question 1?"]}),
            json.dumps({"type": "clarification_needed", "questions": ["Question 2?"]}),
            json.dumps({"type": "policy_ready", "rules": [{"effect": "allow", "tool": "postgres", "action": "query"}]}),
        ]
        mock_client_cls.return_value = mock_client

        policy = run_create_policy_wizard(
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            api_key="sk-test",
            non_interactive=True,
            auto_confirm=True,
        )

        self.assertIsInstance(policy, Policy)
        self.assertEqual(mock_client.chat_completion.call_count, 3)

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_validation_retry_loop_recovers_on_second_attempt(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.side_effect = [
            # First attempt returns invalid effect
            json.dumps(
                {"type": "policy_ready", "rules": [{"effect": "INVALID_EFFECT", "tool": "postgres", "action": "query"}]}
            ),
            # Second attempt returns valid policy
            json.dumps({"type": "policy_ready", "rules": [{"effect": "allow", "tool": "postgres", "action": "query"}]}),
        ]
        mock_client_cls.return_value = mock_client

        policy = run_create_policy_wizard(
            access_md_file=self.md_file,
            output_json_file=self.json_file,
            api_key="sk-test",
            non_interactive=True,
            auto_confirm=True,
        )

        self.assertIsInstance(policy, Policy)
        self.assertEqual(mock_client.chat_completion.call_count, 2)

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_validation_retry_loop_exhausts_cap_fails_closed(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        # Always returns invalid effect
        mock_client.chat_completion.return_value = json.dumps(
            {"type": "policy_ready", "rules": [{"effect": "INVALID_EFFECT", "tool": "postgres", "action": "query"}]}
        )
        mock_client_cls.return_value = mock_client

        with self.assertRaises(PolicyValidationError):
            run_create_policy_wizard(
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                api_key="sk-test",
                non_interactive=True,
                auto_confirm=True,
            )

        self.assertFalse(self.json_file.exists())

    @patch("dmint.cli.create_policy.OpenAICompatClient")
    def test_wizard_user_aborts_confirmation_does_not_write_final_json(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {"type": "policy_ready", "rules": [{"effect": "allow", "tool": "postgres", "action": "query"}]}
        )
        mock_client_cls.return_value = mock_client

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="n"):
                with self.assertRaises(CLIError):
                    run_create_policy_wizard(
                        access_md_file=self.md_file,
                        output_json_file=self.json_file,
                        api_key="sk-test",
                        auto_confirm=False,
                    )

        self.assertFalse(self.json_file.exists())

    def test_cli_main_create_usage_error(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main_create([])
        self.assertEqual(code, 2)
