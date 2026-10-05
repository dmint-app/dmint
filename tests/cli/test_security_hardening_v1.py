"""Verification tests for Final Release Audit security hardening fixes."""

from __future__ import annotations

import http.client
import io
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.parse
import urllib.request

from dmint.cli.errors import CLIError
from dmint.cli.install_skill import install_skill_file, resolve_target_file_path
from dmint.cli.mcp_auth import _is_private_or_metadata_ip, _validate_https_endpoint
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport
from dmint.cli.mcp_oauth import (
    IsolatedCallbackHandler,
    OAuthCallbackHandler,
    OAuthCallbackServer,
    OAuthCallbackState,
)


class TestSecurityHardeningV1(unittest.TestCase):
    """Test suite confirming vulnerability mitigations for v1 release audit."""

    def test_streamable_http_insecure_url_rejected_in_validate_connection(self) -> None:
        """MCPIntegration.validate_connection must reject non-HTTPS URLs for streamable-http."""
        integ = MCPIntegration(
            integration_id="test-http",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "http://example.com/mcp"},
        )
        with self.assertRaises(CLIError) as ctx:
            integ.validate_connection()
        self.assertIn("must use HTTPS", str(ctx.exception))

    def test_streamable_http_cloud_metadata_ip_rejected(self) -> None:
        """_is_private_or_metadata_ip and validate_connection must block cloud metadata endpoints."""
        self.assertTrue(_is_private_or_metadata_ip("169.254.169.254"))
        self.assertTrue(_is_private_or_metadata_ip("metadata.google.internal"))
        self.assertTrue(_is_private_or_metadata_ip("instance-data"))
        self.assertTrue(_is_private_or_metadata_ip("0"))

        integ = MCPIntegration(
            integration_id="test-ssrf",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://169.254.169.254/mcp"},
        )
        with self.assertRaises(CLIError) as ctx:
            integ.validate_connection()
        self.assertIn("private or link-local IP endpoint", str(ctx.exception))

    def test_install_skill_path_traversal_rejected(self) -> None:
        """install_skill must reject traversal characters in skill name."""
        with self.assertRaises(CLIError) as ctx:
            resolve_target_file_path("/tmp", "../../evil_skill")
        self.assertIn("Invalid skill name", str(ctx.exception))

        with self.assertRaises(CLIError) as ctx:
            install_skill_file(dest="/tmp", skill_name="../bad")
        self.assertIn("Invalid skill name", str(ctx.exception))

    def test_oauth_callback_server_host_header_validation_and_security_headers(self) -> None:
        """OAuthCallbackServer must reject forged Host headers and send defensive response headers."""
        state = OAuthCallbackState(expected_state="valid-state", callback_path="/callback")
        server = OAuthCallbackServer(state, host="127.0.0.1", port=0)
        port = server.selected_port

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # 1. Test DNS rebinding attack (forged Host header: evil.com)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/callback?code=abc&state=valid-state", headers={"Host": "evil.com"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            body = resp.read().decode("utf-8")
            self.assertIn("Invalid Host header", body)
            conn.close()

            # 2. Test valid request with expected Host header: check defensive security headers
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/callback?code=abc&state=valid-state", headers={"Host": f"127.0.0.1:{port}"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertIn("frame-ancestors 'none'", resp.getheader("Content-Security-Policy", ""))
            self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
            self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
            self.assertIn("no-store", resp.getheader("Cache-Control", ""))
            conn.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
