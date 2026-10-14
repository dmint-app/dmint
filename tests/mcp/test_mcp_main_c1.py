"""Tests for dmint.mcp.__main__ CLI entrypoint error and execution paths."""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.mcp.__main__ import main
from dmint.mcp.errors import MCPConfigurationError


class MCPMainC1Tests(unittest.TestCase):
    """Test dmint.mcp.__main__ CLI entrypoint paths."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_config_file_exits(self) -> None:
        """Missing config file prints error and exits with code 1."""
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as ctx:
                main(["--config", str(self.tmp_path / "absent.json")])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("configuration file not found", stderr.getvalue())

    def test_config_loader_mcp_configuration_error_exits(self) -> None:
        """MCPConfigurationError during config load prints error and exits 1."""
        cfg_file = self.tmp_path / "bad.json"
        cfg_file.write_text("{}", encoding="utf-8")

        stderr = io.StringIO()
        with patch("dmint.mcp.__main__.load_protection_config", side_effect=MCPConfigurationError("bad schema")):
            with patch("sys.stderr", stderr):
                with self.assertRaises(SystemExit) as ctx:
                    main(["--config", str(cfg_file)])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Configuration error: bad schema", stderr.getvalue())

    def test_config_loader_generic_exception_exits(self) -> None:
        """Unexpected exception during config load prints error and exits 1."""
        cfg_file = self.tmp_path / "bad.json"
        cfg_file.write_text("{}", encoding="utf-8")

        stderr = io.StringIO()
        with patch("dmint.mcp.__main__.load_protection_config", side_effect=RuntimeError("unexpected disk error")):
            with patch("sys.stderr", stderr):
                with self.assertRaises(SystemExit) as ctx:
                    main(["--config", str(cfg_file)])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Failed to load protection configuration", stderr.getvalue())

    def test_http_public_host_without_auth_token_rejected(self) -> None:
        """Binding HTTP transport to public IP without auth token is rejected."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        stderr = io.StringIO()
        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch.dict(os.environ, {}, clear=True):
                with patch("sys.stderr", stderr):
                    with self.assertRaises(SystemExit) as ctx:
                        main(
                            [
                                "--config",
                                str(cfg_file),
                                "--transport",
                                "http",
                                "--host",
                                "0.0.0.0",
                            ]
                        )
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Cannot bind public host '0.0.0.0' without transport authentication", stderr.getvalue())

    def test_import_error_on_mcp_gateway_exits(self) -> None:
        """Missing optional dependencies raises ImportError and exits 1."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        stderr = io.StringIO()
        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch.dict("sys.modules", {"dmint.mcp.gateway": None}):
                with patch("sys.stderr", stderr):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["--config", str(cfg_file)])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("requires additional dependencies", stderr.getvalue())

    def test_stdio_serve_successful_run(self) -> None:
        """Default stdio transport runs gateway.serve_stdio()."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        mock_gw = MagicMock()
        mock_gw.serve_stdio = AsyncMock(return_value=None)

        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch("dmint.mcp.gateway.MCPGateway", return_value=mock_gw):
                main(["--config", str(cfg_file), "--transport", "stdio"])
        mock_gw.serve_stdio.assert_called_once()

    def test_http_serve_successful_run(self) -> None:
        """HTTP transport runs gateway.serve_http() with host, port, auth_token, log_level."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        mock_gw = MagicMock()
        mock_gw.serve_http = AsyncMock(return_value=None)

        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch("dmint.mcp.gateway.MCPGateway", return_value=mock_gw):
                main(
                    [
                        "--config",
                        str(cfg_file),
                        "--transport",
                        "http",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "8888",
                        "--auth-token",
                        "test-token",
                        "--log-level",
                        "debug",
                    ]
                )
        mock_gw.serve_http.assert_called_once_with(
            host="127.0.0.1",
            port=8888,
            auth_token="test-token",
            log_level="debug",
        )

    def test_keyboard_interrupt_clean_exit(self) -> None:
        """KeyboardInterrupt cleanly exits with code 0."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        mock_gw = MagicMock()
        mock_gw.serve_stdio = AsyncMock(side_effect=KeyboardInterrupt)

        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch("dmint.mcp.gateway.MCPGateway", return_value=mock_gw):
                with self.assertRaises(SystemExit) as ctx:
                    main(["--config", str(cfg_file)])
        self.assertEqual(ctx.exception.code, 0)

    def test_mcp_configuration_error_during_serve(self) -> None:
        """MCPConfigurationError during serve prints error and exits 1."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        mock_gw = MagicMock()
        mock_gw.serve_stdio = AsyncMock(side_effect=MCPConfigurationError("runtime config fail"))

        stderr = io.StringIO()
        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch("dmint.mcp.gateway.MCPGateway", return_value=mock_gw):
                with patch("sys.stderr", stderr):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["--config", str(cfg_file)])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Configuration error: runtime config fail", stderr.getvalue())

    def test_generic_exception_during_serve(self) -> None:
        """Generic exception during serve prints runtime error and exits 1."""
        cfg_file = self.tmp_path / "mcp_protection.json"
        cfg_file.write_text("{}", encoding="utf-8")

        mock_config = MagicMock()
        mock_gw = MagicMock()
        mock_gw.serve_stdio = AsyncMock(side_effect=RuntimeError("connection broke"))

        stderr = io.StringIO()
        with patch("dmint.mcp.__main__.load_protection_config", return_value=mock_config):
            with patch("dmint.mcp.gateway.MCPGateway", return_value=mock_gw):
                with patch("sys.stderr", stderr):
                    with self.assertRaises(SystemExit) as ctx:
                        main(["--config", str(cfg_file)])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Runtime error: connection broke", stderr.getvalue())
