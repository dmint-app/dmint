"""Unit and security tests for MCP authorization discovery (src/dmint_cli/mcp_auth.py)."""

from io import BytesIO
import json
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import (
    MCPAuthRequirements,
    discover_mcp_auth_requirements,
    parse_www_authenticate_header,
)
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport


class MCPAuthDiscoveryTests(unittest.TestCase):
    def test_parse_www_authenticate_header(self):
        hdr = 'Bearer realm="https://auth.example.com", authorization_uri="https://auth.example.com/oauth/authorize"'
        parsed = parse_www_authenticate_header(hdr)
        self.assertEqual(parsed.get("realm"), "https://auth.example.com")
        self.assertEqual(parsed.get("authorization_uri"), "https://auth.example.com/oauth/authorize")

    def test_stdio_integration_does_not_require_auth(self):
        integ = MCPIntegration(integration_id="stdio-app", transport=MCPTransport.STDIO, connection={"command": "npx"})
        reqs = discover_mcp_auth_requirements(integ)
        self.assertFalse(reqs.required)

    @patch("urllib.request.urlopen")
    def test_unauthenticated_public_mcp_server(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"status": "ok"}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        integ = MCPIntegration(
            integration_id="public-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/stream"},
        )
        reqs = discover_mcp_auth_requirements(integ)
        self.assertFalse(reqs.required)

    @patch("urllib.request.urlopen")
    def test_401_with_auth_metadata_and_rfc8414_discovery(self, mock_urlopen):
        # 1st call to target URL raises 401 with WWW-Authenticate
        err_headers = {"WWW-Authenticate": 'Bearer realm="https://auth.example.com"'}
        err = urllib.error.HTTPError(
            url="https://mcp.example.com/stream",
            code=401,
            msg="Unauthorized",
            hdrs=err_headers,
            fp=BytesIO(b'{"error": "unauthorized"}'),
        )

        # 2nd call to .well-known/oauth-authorization-server returns 200 metadata
        mock_discovery_resp = MagicMock()
        mock_discovery_resp.status = 200
        mock_discovery_resp.read.return_value = json.dumps(
            {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                "token_endpoint": "https://auth.example.com/oauth/token",
                "registration_endpoint": "https://auth.example.com/oauth/register",
                "scopes_supported": ["read", "write"],
                "code_challenge_methods_supported": ["S256"],
            }
        ).encode("utf-8")
        mock_discovery_resp.__enter__.return_value = mock_discovery_resp

        mock_urlopen.side_effect = [err, mock_discovery_resp]

        integ = MCPIntegration(
            integration_id="protected-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/stream"},
        )
        reqs = discover_mcp_auth_requirements(integ)

        self.assertTrue(reqs.required)
        self.assertEqual(reqs.issuer, "https://auth.example.com")
        self.assertEqual(reqs.authorization_endpoint, "https://auth.example.com/oauth/authorize")
        self.assertEqual(reqs.token_endpoint, "https://auth.example.com/oauth/token")
        self.assertEqual(reqs.registration_endpoint, "https://auth.example.com/oauth/register")
        self.assertIn("read", reqs.scopes)
        self.assertTrue(reqs.pkce_supported)

    @patch("urllib.request.urlopen")
    def test_issuer_mismatch_raises_cli_error(self, mock_urlopen):
        err_headers = {"WWW-Authenticate": 'Bearer realm="https://auth.example.com"'}
        err = urllib.error.HTTPError(
            url="https://mcp.example.com/stream",
            code=401,
            msg="Unauthorized",
            hdrs=err_headers,
            fp=BytesIO(b""),
        )

        mock_discovery_resp = MagicMock()
        mock_discovery_resp.status = 200
        mock_discovery_resp.read.return_value = json.dumps(
            {
                "issuer": "https://attacker.com",  # Issuer mismatch!
                "authorization_endpoint": "https://attacker.com/oauth/authorize",
                "token_endpoint": "https://attacker.com/oauth/token",
            }
        ).encode("utf-8")
        mock_discovery_resp.__enter__.return_value = mock_discovery_resp

        mock_urlopen.side_effect = [err, mock_discovery_resp]

        integ = MCPIntegration(
            integration_id="protected-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/stream"},
        )

        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)

        self.assertIn("issuer mismatch", str(ctx.exception).lower())

    def test_https_validation_remote_url(self):
        integ = MCPIntegration(
            integration_id="insecure-remote",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "http://remote.example.com/mcp"},
        )
        with self.assertRaises(CLIError) as ctx:
            discover_mcp_auth_requirements(integ)
        self.assertIn("must use HTTPS", str(ctx.exception))

    def test_no_credential_leakage_in_auth_requirements_repr(self):
        reqs = MCPAuthRequirements(
            required=True,
            issuer="https://auth.example.com",
            metadata={"secret_token": "sk-live-secret-token", "api_key": "12345"},
        )
        repr_str = repr(reqs)
        self.assertNotIn("sk-live-secret-token", repr_str)
        self.assertNotIn("12345", repr_str)
        self.assertIn("<redacted>", repr_str)
