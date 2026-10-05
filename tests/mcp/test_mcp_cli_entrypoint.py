"""Tests for Dmint MCP standalone CLI entrypoint (__main__.py)."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from dmint.mcp.__main__ import main


class TestMCPCLIEntrypoint(unittest.TestCase):
    """Test suite for the dmint-mcp CLI command."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create valid policy and config
        self.policy_file = self.tmppath / "policy.json"
        self.policy_file.write_text(
            json.dumps({"rules": [{"tool": "srv", "action": "q", "effect": "allow"}]}),
            encoding="utf-8",
        )

        self.valid_config = {
            "policy_file": "policy.json",
            "integrations": [
                {
                    "integration_id": "srv",
                    "connection": {"command": "echo"},
                    "tool_bindings": {"q": {"tool_name": "q", "capability": "srv.q"}},
                }
            ],
        }
        self.config_file = self.tmppath / "mcp_protection.json"
        self.config_file.write_text(json.dumps(self.valid_config), encoding="utf-8")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_missing_config_file_exits_nonzero(self) -> None:
        """Missing config file prints error and exits with code 1."""
        non_existent = str(self.tmppath / "non_existent.json")
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf), patch("sys.exit") as mock_exit:
            main(["run", "--config", non_existent])
            mock_exit.assert_called_once_with(1)
        self.assertIn("not found", stderr_buf.getvalue().lower())

    def test_invalid_config_exits_nonzero(self) -> None:
        """Invalid config file prints error and exits with code 1."""
        invalid_cfg = self.tmppath / "invalid.json"
        invalid_cfg.write_text(json.dumps({"integrations": []}), encoding="utf-8")

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf), patch("sys.exit") as mock_exit:
            main(["run", "--config", str(invalid_cfg)])
            mock_exit.assert_called_once_with(1)
        self.assertIn("error", stderr_buf.getvalue().lower())

    def test_valid_config_invokes_serve_stdio(self) -> None:
        """Valid config file instantiates MCPGateway and invokes serve_stdio."""
        with patch("dmint.mcp.gateway.MCPGateway.serve_stdio", new_callable=AsyncMock) as mock_serve:
            main(["run", "--config", str(self.config_file)])
            mock_serve.assert_called_once()


if __name__ == "__main__":
    unittest.main()
