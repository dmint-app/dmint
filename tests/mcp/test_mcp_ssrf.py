"""Tests for SSRF validation in dmint-mcp."""

import socket
import unittest
from unittest.mock import patch

from dmint.mcp.errors import MCPConfigurationError
from dmint.mcp.ssrf import (
    is_loopback_host,
    is_private_or_metadata_ip,
    parse_ip_literal,
    validate_mcp_url,
)


class TestMCPSSRF(unittest.TestCase):
    def test_loopback_host_detection(self):
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("127.0.0.2"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("[::1]"))
        self.assertFalse(is_loopback_host("10.0.0.1"))
        self.assertFalse(is_loopback_host("example.com"))

    def test_disallowed_schemes(self):
        disallowed = [
            "file:///etc/passwd",
            "ftp://files.example.com/test",
            "gopher://gopher.floodgap.com/",
            "data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==",
            "blob:https://example.com/uuid",
            "javascript:alert(1)",
            "ldap://ldap.internal/dc=example",
        ]
        for url in disallowed:
            with self.assertRaises(MCPConfigurationError) as ctx:
                validate_mcp_url(url)
            self.assertIn("disallowed", str(ctx.exception).lower())

    def test_embedded_userinfo_rejected(self):
        with self.assertRaises(MCPConfigurationError) as ctx:
            validate_mcp_url("https://user:pass@example.com/mcp", resolve_dns=False)
        self.assertIn("userinfo", str(ctx.exception).lower())

    def test_http_rejected_for_remote_endpoints(self):
        with self.assertRaises(MCPConfigurationError) as ctx:
            validate_mcp_url("http://api.remote-mcp.com/mcp", resolve_dns=False)
        self.assertIn("must use https", str(ctx.exception).lower())

    def test_http_allowed_for_loopback(self):
        url = validate_mcp_url("http://localhost:8000/mcp", allow_loopback=True)
        self.assertEqual(url, "http://localhost:8000/mcp")

        url2 = validate_mcp_url("http://127.0.0.1:8080/mcp", allow_loopback=True)
        self.assertEqual(url2, "http://127.0.0.1:8080/mcp")

        url3 = validate_mcp_url("http://[::1]:9000/mcp", allow_loopback=True)
        self.assertEqual(url3, "http://[::1]:9000/mcp")

    def test_loopback_rejected_when_disallowed(self):
        with self.assertRaises(MCPConfigurationError) as ctx:
            validate_mcp_url("http://localhost:8000/mcp", allow_loopback=False)
        self.assertIn("disallowed", str(ctx.exception).lower())

    def test_private_ipv4_literals_blocked(self):
        private_urls = [
            "https://10.0.0.1/mcp",
            "https://10.255.255.255/mcp",
            "https://172.16.0.1/mcp",
            "https://172.31.255.255/mcp",
            "https://192.168.1.1/mcp",
            "https://192.168.100.50/mcp",
            "https://169.254.169.254/mcp",
            "https://169.254.1.1/mcp",
            "https://100.64.0.1/mcp",  # Carrier grade NAT
            "https://0.0.0.0/mcp",
        ]
        for url in private_urls:
            with self.subTest(url=url):
                with self.assertRaises(MCPConfigurationError) as ctx:
                    validate_mcp_url(url, resolve_dns=False)
                self.assertIn("prohibited ip", str(ctx.exception).lower())

    def test_integer_ip_representation_blocked(self):
        # 2130706433 is 127.0.0.1; 2886729729 is 172.16.0.1
        with self.assertRaises(MCPConfigurationError) as ctx:
            validate_mcp_url("https://2886729729/mcp", resolve_dns=False)
        self.assertIn("prohibited ip", str(ctx.exception).lower())

    def test_private_ipv6_literals_blocked(self):
        private_ipv6 = [
            "https://[fe80::1]/mcp",  # link-local
            "https://[fc00::1]/mcp",  # unique local
            "https://[fd00::1]/mcp",  # unique local
            "https://[::ffff:192.168.1.1]/mcp",  # IPv4-mapped private
            "https://[::ffff:10.0.0.1]/mcp",  # IPv4-mapped private
        ]
        for url in private_ipv6:
            with self.subTest(url=url):
                with self.assertRaises(MCPConfigurationError) as ctx:
                    validate_mcp_url(url, resolve_dns=False)
                self.assertIn("prohibited ip", str(ctx.exception).lower())

    def test_cloud_metadata_hostnames_blocked(self):
        metadata_hosts = [
            "https://metadata.google.internal/computeMetadata/v1",
            "https://metadata.google/computeMetadata/v1",
            "https://instance-data/latest/meta-data",
            "https://metadata/latest/meta-data",
            "https://corp.internal/mcp",
            "https://my-host.local/mcp",
        ]
        for url in metadata_hosts:
            with self.subTest(url=url):
                with self.assertRaises(MCPConfigurationError) as ctx:
                    validate_mcp_url(url, resolve_dns=False)
                self.assertIn("prohibited internal or metadata host", str(ctx.exception).lower())

    def test_dns_resolution_to_private_ip_blocked(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 443))]
            with self.assertRaises(MCPConfigurationError) as ctx:
                validate_mcp_url("https://malicious-dns.example.com/mcp", resolve_dns=True)
            self.assertIn("ssrf violation", str(ctx.exception).lower())
            self.assertIn("192.168.1.50", str(ctx.exception))

    def test_dns_resolution_failure_handled(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
            with self.assertRaises(MCPConfigurationError) as ctx:
                validate_mcp_url("https://nonexistent-domain-xyz123.com/mcp", resolve_dns=True)
            self.assertIn("dns resolution failed", str(ctx.exception).lower())

    def test_valid_remote_https_endpoint(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            url = validate_mcp_url("https://example.com/mcp", resolve_dns=True)
            self.assertEqual(url, "https://example.com/mcp")


if __name__ == "__main__":
    unittest.main()
