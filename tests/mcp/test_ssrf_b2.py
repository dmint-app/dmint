"""Comprehensive tests for Group B2: SSRF Hardening and IP Pinning."""

import ipaddress
import socket
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.mcp.errors import MCPConfigurationError
from dmint.mcp.ssrf import (
    PinnedAsyncNetworkBackend,
    ValidatedURL,
    create_pinned_async_transport,
    is_obfuscated_or_short_ip,
    is_private_or_metadata_ip,
    validate_mcp_url,
)


class SSRFB2Tests(unittest.IsolatedAsyncioTestCase):
    # -------------------------------------------------------------------------
    # (b) Trailing-dot hosts and octal/hex/short IP forms rejected in static check
    # -------------------------------------------------------------------------
    def test_trailing_dot_hosts_rejected_in_static_check(self) -> None:
        trailing_dot_urls = [
            "https://metadata.google.internal./computeMetadata/v1",
            "https://example.com./mcp",
            "https://127.0.0.1./mcp",
            "https://internal.corp./mcp",
            "https://foo..bar.com/mcp",
        ]
        for url in trailing_dot_urls:
            with self.subTest(url=url):
                with self.assertRaises(MCPConfigurationError) as ctx:
                    validate_mcp_url(url, resolve_dns=False)
                self.assertIn("trailing-dot or empty-label hostnames are prohibited", str(ctx.exception))

    def test_octal_hex_and_short_ips_rejected_in_static_check(self) -> None:
        obfuscated_urls = [
            ("https://0177.0.0.1/mcp", "0177.0.0.1"),
            ("https://0x7f000001/mcp", "0x7f000001"),
            ("https://127.1/mcp", "127.1"),
            ("https://127.0.1/mcp", "127.0.1"),
            ("https://0x7f.0.0.1/mcp", "0x7f.0.0.1"),
            ("https://10.1/mcp", "10.1"),
            ("https://012.0.0.1/mcp", "012.0.0.1"),
        ]
        for url, expected_host in obfuscated_urls:
            with self.subTest(url=url):
                self.assertTrue(is_obfuscated_or_short_ip(expected_host))
                with self.assertRaises(MCPConfigurationError) as ctx:
                    validate_mcp_url(url, resolve_dns=False)
                self.assertIn("octal, hex, or short-form ip literals are prohibited", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # (c) IPv4-mapped IPv6 branch reachability & correctness
    # -------------------------------------------------------------------------
    def test_ipv4_mapped_ipv6_classification(self) -> None:
        # Public IPv4 mapped to IPv6 (should be allowed: False)
        public_mapped = ipaddress.ip_address("::ffff:8.8.8.8")
        self.assertFalse(is_private_or_metadata_ip(public_mapped, allow_loopback=False))

        # Private IPv4 mapped to IPv6 (should be rejected: True)
        private_mapped = ipaddress.ip_address("::ffff:192.168.1.1")
        self.assertTrue(is_private_or_metadata_ip(private_mapped, allow_loopback=False))

        # Loopback IPv4 mapped to IPv6
        loopback_mapped = ipaddress.ip_address("::ffff:127.0.0.1")
        self.assertFalse(is_private_or_metadata_ip(loopback_mapped, allow_loopback=True))
        self.assertTrue(is_private_or_metadata_ip(loopback_mapped, allow_loopback=False))

        # Metadata IPv4 mapped to IPv6 (169.254.169.254)
        metadata_mapped = ipaddress.ip_address("::ffff:169.254.169.254")
        self.assertTrue(is_private_or_metadata_ip(metadata_mapped, allow_loopback=False))

    # -------------------------------------------------------------------------
    # (a) IP Pinning and DNS Rebinding Defense
    # -------------------------------------------------------------------------
    def test_validate_mcp_url_returns_validated_url_with_pinned_ip(self) -> None:
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ]
            res = validate_mcp_url("https://example.com/mcp", resolve_dns=True)
            self.assertIsInstance(res, ValidatedURL)
            self.assertEqual(res, "https://example.com/mcp")
            self.assertEqual(res.pinned_ip, "93.184.216.34")
            self.assertEqual(res.hostname, "example.com")
            self.assertEqual(res.port, 443)

    async def test_pinned_async_network_backend_connects_to_pinned_ip(self) -> None:
        mock_base = MagicMock()
        mock_stream = AsyncMock()
        mock_base.connect_tcp = AsyncMock(return_value=mock_stream)

        backend = PinnedAsyncNetworkBackend("example.com", "93.184.216.34", base_backend=mock_base)
        stream = await backend.connect_tcp("example.com", 443, timeout=5.0)

        self.assertIs(stream, mock_stream)
        mock_base.connect_tcp.assert_called_once_with(
            "93.184.216.34",  # Pinned IP used instead of target hostname!
            443,
            timeout=5.0,
            local_address=None,
            socket_options=None,
        )

    async def test_dns_rebinding_simulation_retains_first_pinned_ip(self) -> None:
        # Resolver returns public IP first, and private IP on second call
        resolution_counts = 0

        def fake_resolver(host, port, **kwargs):
            nonlocal resolution_counts
            resolution_counts += 1
            if resolution_counts == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", port))]

        with patch("socket.getaddrinfo", side_effect=fake_resolver):
            validated = validate_mcp_url("https://attacker-rebind.com/mcp", resolve_dns=True)
            self.assertEqual(validated.pinned_ip, "93.184.216.34")

            # Resolver rebinding now triggers private IP
            second_lookup = fake_resolver("attacker-rebind.com", 443)
            self.assertEqual(second_lookup[0][4][0], "192.168.1.1")

            # But the pinned transport connects to the first pinned IP ("93.184.216.34")!
            mock_base = MagicMock()
            mock_stream = AsyncMock()
            mock_base.connect_tcp = AsyncMock(return_value=mock_stream)

            backend = PinnedAsyncNetworkBackend(validated.hostname, validated.pinned_ip, base_backend=mock_base)
            await backend.connect_tcp("attacker-rebind.com", 443)

            mock_base.connect_tcp.assert_called_once_with(
                "93.184.216.34",
                443,
                timeout=None,
                local_address=None,
                socket_options=None,
            )
