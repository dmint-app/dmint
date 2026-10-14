"""Tests for dmint.cli.compile_policy CLI wrapper and execution paths."""

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dmint.cli.compile_policy import compile_policy_file, main_compile
from dmint.cli.errors import PolicyValidationError


class CompilePolicyC1Tests(unittest.TestCase):
    """Test compile_policy wrapper and CLI entrypoint."""

    def test_compile_policy_file_delegates_to_wizard(self) -> None:
        """compile_policy_file delegates to run_create_policy_wizard with non-interactive=True."""
        mock_policy = MagicMock()
        with patch("dmint.cli.create_policy.run_create_policy_wizard", return_value=mock_policy) as mock_wiz:
            res = compile_policy_file(
                input_file="access.md",
                output_file="policy.json",
                base_url="https://api.test.com/v1",
                api_key="sk-test",
                model="gpt-4o",
                provider="openai",
                timeout=45.0,
            )
            self.assertIs(res, mock_policy)
            mock_wiz.assert_called_once_with(
                access_md_file="access.md",
                output_json_file="policy.json",
                base_url="https://api.test.com/v1",
                api_key="sk-test",
                model="gpt-4o",
                provider="openai",
                non_interactive=True,
                auto_confirm=True,
                timeout=45.0,
            )

    def test_main_compile_success(self) -> None:
        """main_compile succeeds, prints success confirmation, returns 0."""
        stdout = io.StringIO()
        with patch("dmint.cli.compile_policy.compile_policy_file") as mock_comp:
            with patch("sys.stdout", stdout):
                code = main_compile(
                    [
                        "-f",
                        "access.md",
                        "-o",
                        "policy.json",
                        "-model",
                        "gpt-4o-mini",
                        "-api_key",
                        "sk-test",
                    ]
                )
        self.assertEqual(code, 0)
        out = stdout.getvalue()
        self.assertIn("✓ Policy generated", out)
        self.assertIn("✓ Dmint schema validation passed", out)
        self.assertIn("→ policy.json", out)

    def test_main_compile_cli_error(self) -> None:
        """main_compile catches CLIError, prints to stderr, returns exc.exit_code."""
        stderr = io.StringIO()
        with patch("dmint.cli.compile_policy.compile_policy_file", side_effect=PolicyValidationError("invalid rules")):
            with patch("sys.stderr", stderr):
                code = main_compile(
                    [
                        "-f",
                        "access.md",
                        "-o",
                        "policy.json",
                    ]
                )
        self.assertNotEqual(code, 0)
        self.assertIn("✗ Policy compilation failed: invalid rules", stderr.getvalue())

    def test_main_compile_unexpected_error(self) -> None:
        """main_compile catches unexpected Exception, prints to stderr, returns 1."""
        stderr = io.StringIO()
        with patch(
            "dmint.cli.compile_policy.compile_policy_file", side_effect=RuntimeError("unexpected disk explosion")
        ):
            with patch("sys.stderr", stderr):
                code = main_compile(
                    [
                        "-f",
                        "access.md",
                        "-o",
                        "policy.json",
                    ]
                )
        self.assertEqual(code, 1)
        self.assertIn("✗ Unexpected error: unexpected disk explosion", stderr.getvalue())

    def test_main_compile_invalid_arguments_returns_exit_code(self) -> None:
        """main_compile returns exit code on invalid CLI flags (SystemExit from argparse)."""
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            code = main_compile(["--invalid-unknown-flag"])
        self.assertEqual(code, 2)
