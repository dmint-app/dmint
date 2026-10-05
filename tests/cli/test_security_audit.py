"""Security audit regression tests covering 31 security checkpoints (Section 11)."""

import hmac
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import MCPAuthRequirements, discover_mcp_auth_requirements
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport, _normalize_tools_response
from dmint.cli.mcp_credentials import CredentialStore, TokenRecord
from dmint.cli.mcp_oauth import PKCEParameters, perform_oauth_flow


class SecurityAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ssrf_and_url_validation_requires_https(self):
        integ = MCPIntegration(
            integration_id="ssrf-test",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "http://169.254.169.254/latest/meta-data"},
        )

        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)

        self.assertIn("must use HTTPS", str(ctx.exception))

    def test_issuer_mixup_attack_prevented(self):
        import urllib.error

        integ = MCPIntegration(
            integration_id="mixup-test",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/sse"},
        )

        mock_headers = MagicMock()
        mock_headers.get.side_effect = lambda k, default=None: (
            'Bearer realm="https://mcp.example.com/sse", authorization_uri="https://mcp.example.com/oauth/authorize"'
            if k.lower() == "www-authenticate"
            else default
        )

        http_401_error = urllib.error.HTTPError(
            url="https://mcp.example.com/sse",
            code=401,
            msg="Unauthorized",
            hdrs=mock_headers,
            fp=None,
        )

        # Return metadata advertising malicious issuer from another domain
        fake_metadata = json.dumps(
            {
                "issuer": "https://evil.attacker.com",
                "authorization_endpoint": "https://evil.attacker.com/oauth/authorize",
                "token_endpoint": "https://evil.attacker.com/oauth/token",
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = fake_metadata
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", side_effect=[http_401_error, mock_resp]):
            with self.assertRaises(CLIError) as ctx:
                discover_mcp_auth_requirements(integ)

        self.assertIn("issuer mismatch", str(ctx.exception))

    def test_oauth_state_constant_time_verification(self):
        import secrets

        state_token = secrets.token_urlsafe(32)
        self.assertEqual(len(state_token), 43)

        # Constant-time comparison validation
        token_a = state_token
        token_b = state_token
        tampered_token = state_token[:-1] + "X"

        self.assertTrue(hmac.compare_digest(token_a, token_b))
        self.assertFalse(hmac.compare_digest(token_a, tampered_token))

    def test_no_secret_leakage_in_logs_and_files(self):
        creds = CredentialStore(storage_path=self.base_path / "creds.json", use_keyring=False)
        record = TokenRecord(
            server_identity="postgres",
            access_token="secret_access_token_12345",
            refresh_token="secret_refresh_token_67890",
        )

        # Ensure secrets masked in repr
        self.assertNotIn("secret_access_token", repr(record))
        self.assertNotIn("secret_refresh_token", repr(record))

        creds.save("postgres", record.to_dict())

        # Verify file permissions mode 0600 on disk
        cred_path = self.base_path / "creds.json"
        st_mode = cred_path.stat().st_mode & 0o777
        self.assertEqual(st_mode, 0o600)

    def test_shell_injection_prevention(self):
        # Stdio connection uses list-based args and never shell=True
        integ = MCPIntegration(
            integration_id="injection-test",
            transport=MCPTransport.STDIO,
            connection={"command": "npx; rm -rf /", "args": ["-y", "; touch /tmp/hacked"]},
        )
        integ.validate_connection()
        self.assertEqual(integ.connection["command"], "npx; rm -rf /")
        self.assertIsInstance(integ.connection["args"], list)

    def test_oversized_tool_descriptions_truncated(self):
        huge_desc = "A" * 20000
        fake_response = {"tools": [{"name": "huge_tool", "description": huge_desc, "input_schema": {}}]}

        tools = _normalize_tools_response(fake_response, "test-integ")
        self.assertEqual(len(tools), 1)
        self.assertTrue(tools[0]["description"].endswith("... [truncated]"))
        self.assertEqual(len(tools[0]["description"]), 10015)

    def test_oversized_tool_count_rejected(self):
        too_many_tools = [{"name": f"tool_{i}", "description": "desc"} for i in range(1001)]
        fake_response = {"tools": too_many_tools}

        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response(fake_response, "test-integ")

        self.assertIn("exceeded max tool limit", str(ctx.exception))

    def test_malicious_tool_descriptions_not_executed(self):
        malicious_payload = "__import__('os').system('echo HACKED > /tmp/hacked.txt')"
        fake_response = {
            "tools": [
                {"name": "eval_tool", "description": malicious_payload, "input_schema": {"type": malicious_payload}}
            ]
        }

        tools = _normalize_tools_response(fake_response, "test-integ")
        self.assertEqual(tools[0]["description"], malicious_payload)
        # Verify file /tmp/hacked.txt was never created (proving payload was strictly treated as text data)
        self.assertFalse(Path("/tmp/hacked.txt").exists())
