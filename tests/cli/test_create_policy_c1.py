"""Tests for dmint.cli.create_policy AST tool discovery, prompts, and CLI error handling."""

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dmint.cli.create_policy import (
    _prompt_password,
    _prompt_select,
    _prompt_text,
    discover_local_tools_ast,
    main_create,
    parse_tool_declarations_ast,
)
from dmint.cli.errors import PolicyValidationError


class CreatePolicyC1Tests(unittest.TestCase):
    """Test AST parsing, prompt fallbacks, and execution paths in create_policy.py."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_parse_tool_declarations_ast_missing_file_raises(self) -> None:
        """parse_tool_declarations_ast raises FileNotFoundError for missing files."""
        with self.assertRaises(FileNotFoundError):
            parse_tool_declarations_ast(self.tmp_path / "absent.py")

    def test_parse_tool_declarations_ast_syntax_error_raises(self) -> None:
        """parse_tool_declarations_ast raises ValueError for syntax errors."""
        broken = self.tmp_path / "broken.py"
        broken.write_text("def broken_syntax(:\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            parse_tool_declarations_ast(broken)
        self.assertIn("failed to parse AST", str(ctx.exception))

    def test_parse_tool_declarations_ast_positional_and_keywords(self) -> None:
        """parse_tool_declarations_ast extracts Tool and MCPToolBinding with positional or keyword args."""
        code = """
t1 = Tool("tool_positional", description="Positional tool")
t2 = Tool(name="tool_kw", description="Keyword tool")
t3 = MCPToolBinding("mcp_pos", "mcp.test")
t4 = MCPToolBinding(tool_name="mcp_kw", capability="mcp.cap")
t5 = Tool(name="tool_positional")  # duplicate name should be skipped
other = func("not_a_tool")
"""
        f = self.tmp_path / "tools.py"
        f.write_text(code, encoding="utf-8")

        tools = parse_tool_declarations_ast(f)
        names = [t["name"] for t in tools]
        self.assertIn("tool_positional", names)
        self.assertIn("tool_kw", names)
        self.assertIn("mcp_pos", names)
        self.assertIn("mcp_kw", names)
        self.assertEqual(names.count("tool_positional"), 1)

    def test_discover_local_tools_ast_handles_missing_paths_and_dirs(self) -> None:
        """discover_local_tools_ast warns on missing paths and parses python files in directories."""
        sub = self.tmp_path / "pkg"
        sub.mkdir()
        (sub / "mod.py").write_text('t = Tool("sub_tool", description="Inside dir")\n', encoding="utf-8")
        (sub / "ignore.txt").write_text('Tool("ignored")\n', encoding="utf-8")
        (sub / "bad.py").write_text("def syntax_err(\n", encoding="utf-8")

        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            tools = discover_local_tools_ast(
                [
                    self.tmp_path / "nonexistent",
                    sub,
                ]
            )
        names = [t["name"] for t in tools]
        self.assertIn("sub_tool", names)
        err = stderr.getvalue()
        self.assertIn("Path does not exist", err)
        self.assertIn("Could not parse AST for bad.py", err)

    def test_prompt_select_fallback_without_questionary(self) -> None:
        """_prompt_select falls back to numeric text prompt when questionary is unavailable."""
        with patch.dict("sys.modules", {"questionary": None}):
            # 1. Valid numeric choice
            with patch("builtins.input", return_value="2"):
                res = _prompt_select("Pick one", choices=["apple", "banana", "cherry"], default="apple")
                self.assertEqual(res, "banana")

            # 2. Empty input defaults to default choice
            with patch("builtins.input", return_value=""):
                res_def = _prompt_select("Pick one", choices=["apple", "banana", "cherry"], default="cherry")
                self.assertEqual(res_def, "cherry")

    def test_prompt_password_fallback(self) -> None:
        """_prompt_password falls back to getpass when questionary is unavailable."""
        with patch.dict("sys.modules", {"questionary": None}):
            with patch("getpass.getpass", return_value="secret123"):
                res = _prompt_password("API Key:")
                self.assertEqual(res, "secret123")

    def test_prompt_text_fallback(self) -> None:
        """_prompt_text falls back to input() when questionary is unavailable."""
        with patch.dict("sys.modules", {"questionary": None}):
            # Provided value
            with patch("builtins.input", return_value="my-val"):
                self.assertEqual(_prompt_text("Name", default="default-name"), "my-val")
            # Empty input falls back to default
            with patch("builtins.input", return_value=""):
                self.assertEqual(_prompt_text("Name", default="default-name"), "default-name")

    def test_run_create_policy_wizard_file_validations(self) -> None:
        """run_create_policy_wizard validates file existence, emptiness, and size limit."""
        from dmint.cli.errors import InputFileError
        from dmint.cli.create_policy import run_create_policy_wizard

        # Missing file
        with self.assertRaises(InputFileError):
            run_create_policy_wizard(
                access_md_file=self.tmp_path / "missing.md",
                output_json_file=self.tmp_path / "out.json",
            )

        # Empty file
        empty_md = self.tmp_path / "empty.md"
        empty_md.write_text("   \n", encoding="utf-8")
        with self.assertRaises(InputFileError):
            run_create_policy_wizard(
                access_md_file=empty_md,
                output_json_file=self.tmp_path / "out.json",
            )

        # File too large (> 64KB)
        big_md = self.tmp_path / "big.md"
        big_md.write_text("x" * (65 * 1024), encoding="utf-8")
        with self.assertRaises(InputFileError):
            run_create_policy_wizard(
                access_md_file=big_md,
                output_json_file=self.tmp_path / "out.json",
            )

    def test_run_create_policy_wizard_mode_1_mcp(self) -> None:
        """run_create_policy_wizard delegates to run_create_mcp_policy_wizard when mode 1 chosen."""
        from dmint.cli.create_policy import run_create_policy_wizard

        req_md = self.tmp_path / "access.md"
        req_md.write_text("Requirements", encoding="utf-8")
        mock_policy = MagicMock()

        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", return_value="1"),
            patch(
                "dmint.cli.create_mcp_policy.run_create_mcp_policy_wizard", return_value=(mock_policy, [])
            ) as mock_mcp,
        ):
            res = run_create_policy_wizard(
                access_md_file=req_md,
                output_json_file=self.tmp_path / "out.json",
                non_interactive=False,
            )
            self.assertEqual(res, mock_policy)
            mock_mcp.assert_called_once()

    def test_run_create_policy_wizard_success_and_user_abort(self) -> None:
        """run_create_policy_wizard handles user abort and successful confirmation."""
        import json
        from dmint.cli.create_policy import run_create_policy_wizard
        from dmint.cli.errors import CLIError

        req_md = self.tmp_path / "access.md"
        req_md.write_text("Allow read on file", encoding="utf-8")
        out_json = self.tmp_path / "out.json"

        valid_policy_resp = json.dumps(
            {
                "type": "policy_ready",
                "rules": [{"tool": "read_file", "action": "read", "resource": "/data/*", "effect": "allow"}],
            }
        )

        mock_client = MagicMock()
        mock_client.chat_completion.return_value = valid_policy_resp
        mock_client.model = "gpt-4o"
        mock_client.base_url = "https://api.openai.com/v1"

        # User aborts with 'n'
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("dmint.cli.create_policy.OpenAICompatClient", return_value=mock_client),
            patch("builtins.input", side_effect=["2", "", "n"]),
        ):  # mode 2, empty src path, abort 'n'
            with self.assertRaises(CLIError) as ctx:
                run_create_policy_wizard(
                    access_md_file=req_md,
                    output_json_file=out_json,
                    provider="openai",
                    api_key="sk-test",
                    model="gpt-4o",
                    auto_confirm=False,
                )
            self.assertIn("aborted by user", str(ctx.exception))

        # User confirms with 'y'
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("dmint.cli.create_policy.OpenAICompatClient", return_value=mock_client),
            patch("builtins.input", side_effect=["2", "", "y"]),
        ):
            pol = run_create_policy_wizard(
                access_md_file=req_md,
                output_json_file=out_json,
                provider="openai",
                api_key="sk-test",
                model="gpt-4o",
                auto_confirm=False,
            )
            self.assertEqual(len(pol.rules), 1)
            self.assertTrue(out_json.exists())

    def test_run_create_policy_wizard_clarification_loop(self) -> None:
        """run_create_policy_wizard handles clarification_needed from model."""
        import json
        from dmint.cli.create_policy import run_create_policy_wizard

        req_md = self.tmp_path / "access.md"
        req_md.write_text("Allow read on file", encoding="utf-8")
        out_json = self.tmp_path / "out.json"

        clarify_resp = json.dumps({"type": "clarification_needed", "questions": ["Which directory?"]})
        policy_resp = json.dumps(
            {
                "type": "policy_ready",
                "rules": [{"tool": "read_file", "action": "read", "resource": "/data/*", "effect": "allow"}],
            }
        )

        mock_client = MagicMock()
        mock_client.chat_completion.side_effect = [clarify_resp, policy_resp]
        mock_client.model = "gpt-4o"
        mock_client.base_url = "https://api.openai.com/v1"

        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("dmint.cli.create_policy.OpenAICompatClient", return_value=mock_client),
            patch("builtins.input", side_effect=["2", "", "only /data", "y"]),
        ):
            pol = run_create_policy_wizard(
                access_md_file=req_md,
                output_json_file=out_json,
                provider="openai",
                api_key="sk-test",
                model="gpt-4o",
            )
            self.assertEqual(len(pol.rules), 1)

    def test_main_create_successful_run(self) -> None:
        """main_create runs successfully and returns 0."""
        with patch("dmint.cli.create_policy.run_create_policy_wizard", return_value=MagicMock()):
            code = main_create(
                [
                    "-f",
                    "access.md",
                    "-o",
                    "policy.json",
                    "-model",
                    "gpt-4o",
                    "-api_key",
                    "sk-test",
                ]
            )
        self.assertEqual(code, 0)

    def test_main_create_cli_error(self) -> None:
        """main_create catches CLIError and returns exc.exit_code."""
        stderr = io.StringIO()
        with patch("dmint.cli.create_policy.run_create_policy_wizard", side_effect=PolicyValidationError("bad rules")):
            with patch("sys.stderr", stderr):
                code = main_create(
                    [
                        "-f",
                        "access.md",
                        "-o",
                        "policy.json",
                    ]
                )
        self.assertNotEqual(code, 0)
        self.assertIn("Policy creation failed: bad rules", stderr.getvalue())

    def test_main_create_unexpected_error(self) -> None:
        """main_create catches unexpected Exception and returns 1."""
        stderr = io.StringIO()
        with patch("dmint.cli.create_policy.run_create_policy_wizard", side_effect=RuntimeError("unknown crash")):
            with patch("sys.stderr", stderr):
                code = main_create(
                    [
                        "-f",
                        "access.md",
                        "-o",
                        "policy.json",
                    ]
                )
        self.assertEqual(code, 1)
        self.assertIn("Unexpected error: unknown crash", stderr.getvalue())

    def test_main_create_argparse_error_returns_code(self) -> None:
        """main_create returns exit code on invalid arguments."""
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            code = main_create(["--unknown-option-xyz"])
        self.assertEqual(code, 2)
