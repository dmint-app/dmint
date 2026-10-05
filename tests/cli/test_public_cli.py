"""Tests for Phase 11 — Public CLI Surface & Workflow Invariants.

Verifies:
1. create-policy = general policy authoring.
2. create-mcp-policy = MCP-specific discovery + policy + protection artifact workflow.
3. verify-policy = deterministic offline validation.
4. compile-policy: retained only as compatibility, not competing workflow.
5. protect-mcp: retained only as documented compatibility alias.
6. Help output makes recommended workflow obvious.
7. Error messages are deterministic and actionable.
8. Exit codes are documented and stable (0-8).
9. No command silently performs unexpected network operations.
10. --help works without credentials or network.
11. verify-policy remains offline and LLM-free.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dmint.cli.__main__ import main
from dmint.cli.errors import (
    APIError,
    CLIError,
    EXIT_CODES,
    InputFileError,
    JSONExtractionError,
    OutputWriteError,
    PolicyValidationError,
    ResourceExhaustionError,
)
from dmint.cli.verify_policy import main_verify, verify_policy_file


class TestPublicCLISurface(unittest.TestCase):
    """Verify intentional CLI surface, recommended workflows, stable exit codes, and offline guarantees."""

    def test_help_makes_recommended_workflow_obvious(self):
        """Top-level --help must clearly present the recommended workflow and separate primary from compatibility commands."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["--help"])
        self.assertEqual(code, 0)
        output = buf.getvalue()

        # Recommended workflow guidance
        self.assertIn("Recommended Workflow", output)
        self.assertIn("create-mcp-policy", output)
        self.assertIn("create-policy", output)
        self.assertIn("verify-policy", output)

        # Primary commands section
        self.assertIn("Primary Commands", output)

        # Compatibility commands section
        self.assertIn("Compatibility Commands", output)
        self.assertIn("compile-policy", output)
        self.assertIn("protect-mcp", output)

    def test_compile_policy_presented_as_compatibility_only(self):
        """compile-policy must be marked as compatibility, not as modern authoring workflow."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["compile-policy", "--help"])
        self.assertEqual(code, 0)
        output = buf.getvalue()

        self.assertIn("[Compatibility]", output)
        self.assertIn("create-policy", output)

    def test_protect_mcp_documented_as_compatibility_alias(self):
        """protect-mcp must be documented as compatibility alias and invoke create-mcp-policy."""
        # Check top-level help documents the alias
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("[Compatibility alias]", buf.getvalue())

        # Check protect-mcp --help displays create-mcp-policy usage
        buf_alias = io.StringIO()
        with contextlib.redirect_stdout(buf_alias):
            code = main(["protect-mcp", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("create-mcp-policy", buf_alias.getvalue())

    def test_help_works_without_credentials_or_network(self):
        """--help for all commands must succeed with exit code 0 with zero network access and no credentials."""
        commands_to_test = [
            [],
            ["--help"],
            ["-h"],
            ["create-policy", "--help"],
            ["create-mcp-policy", "--help"],
            ["verify-policy", "--help"],
            ["compile-policy", "--help"],
            ["protect-mcp", "--help"],
            ["pending", "--help"],
            ["approve", "--help"],
            ["reject", "--help"],
        ]

        def no_network_socket(*args, **kwargs):
            raise AssertionError("Network socket attempted during --help command!")

        # Clear environment credentials and block network
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(socket, "socket", side_effect=no_network_socket):
                for cmd in commands_to_test:
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        exit_code = main(cmd)
                    self.assertEqual(
                        exit_code, 0, f"Command 'dmint {' '.join(cmd)}' failed without credentials/network"
                    )
                    self.assertIn("usage:", buf.getvalue().lower())

    def test_verify_policy_is_strictly_offline_and_llm_free(self):
        """verify-policy must validate policies completely offline without network sockets or LLM calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.json"
            policy_data = {
                "rules": [
                    {"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"},
                    {"effect": "deny", "tool": "aws", "action": "delete"},
                ]
            }
            policy_file.write_text(json.dumps(policy_data), encoding="utf-8")

            def no_network_socket(*args, **kwargs):
                raise AssertionError("Network socket opened during verify-policy!")

            with patch.dict(os.environ, {}, clear=True):
                with patch.object(socket, "socket", side_effect=no_network_socket):
                    # 1. API function call
                    policy = verify_policy_file(policy_file)
                    self.assertEqual(len(policy.rules), 2)

                    # 2. CLI main_verify call
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        code = main_verify([str(policy_file)])
                    self.assertEqual(code, 0)
                    self.assertIn("Verified", buf.getvalue())

    def test_stable_exit_codes_contract(self):
        """Exit codes must match documented specification (0 to 8)."""
        expected = {
            "SUCCESS": 0,
            "GENERAL_ERROR": 1,
            "USAGE_ERROR": 2,
            "INPUT_FILE_ERROR": 3,
            "API_ERROR": 4,
            "JSON_EXTRACTION_ERROR": 5,
            "POLICY_VALIDATION_ERROR": 6,
            "OUTPUT_WRITE_ERROR": 7,
            "RESOURCE_EXHAUSTION_ERROR": 8,
        }
        self.assertEqual(EXIT_CODES, expected)

        # Verify each error exception class sets its stable exit code
        self.assertEqual(CLIError("err").exit_code, 1)
        self.assertEqual(InputFileError("err").exit_code, 3)
        self.assertEqual(APIError("err").exit_code, 4)
        self.assertEqual(JSONExtractionError("err").exit_code, 5)
        self.assertEqual(PolicyValidationError("err").exit_code, 6)
        self.assertEqual(OutputWriteError("err").exit_code, 7)
        self.assertEqual(ResourceExhaustionError("err").exit_code, 8)

    def test_deterministic_and_actionable_error_messages(self):
        """Error outputs must be deterministic and include actionable guidance."""
        # 1. Unknown subcommand -> exit code 2 with usage
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(["nonexistent-command"])
        self.assertEqual(code, 2)
        self.assertIn("Available Commands", err_buf.getvalue())

        # 2. Missing policy argument in verify-policy -> exit code 2 with actionable message
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main_verify([])
        self.assertEqual(code, 2)
        self.assertIn("missing policy file argument", err_buf.getvalue())
        self.assertIn("dmint verify-policy", err_buf.getvalue())

        # 3. Missing file path in verify-policy -> exit code 3 with actionable message
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main_verify(["missing_nonexistent_policy.json"])
        self.assertEqual(code, 3)
        self.assertIn("policy file not found", err_buf.getvalue())

    def test_no_silent_unexpected_network_operations(self):
        """Commands must never open network connections unless explicitly configured for remote servers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.json"
            policy_file.write_text(json.dumps({"rules": [{"effect": "allow", "tool": "test", "action": "run"}]}))

            # Running verify-policy with socket patched ensures no network calls occur
            network_opened = False
            orig_socket = socket.socket

            def tracking_socket(*args, **kwargs):
                nonlocal network_opened
                network_opened = True
                return orig_socket(*args, **kwargs)

            with patch.object(socket, "socket", side_effect=tracking_socket):
                code = main(["verify-policy", str(policy_file)])
                self.assertEqual(code, 0)
                self.assertFalse(network_opened, "Silent network operation detected in verify-policy!")

    def test_version_flag_behavior(self):
        """dmint --version, -V, and version must display canonical version without network or credentials."""
        from dmint.cli.version import __version__

        for flag in ["--version", "-V", "-v", "version"]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main([flag])
            self.assertEqual(code, 0)
            self.assertEqual(buf.getvalue().strip(), f"dmint {__version__}")


if __name__ == "__main__":
    unittest.main()
