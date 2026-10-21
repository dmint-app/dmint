"""IDN and fail-closed transport tests for MCP SSRF protection."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.mcp.errors import MCPConfigurationError, MCPConnectionError
from dmint.mcp.ssrf import (
    PinnedAsyncNetworkBackend,
    canonicalize_hostname,
    create_pinned_async_transport,
    validate_mcp_url,
)


class IDNPinningTests(unittest.IsolatedAsyncioTestCase):
    def test_idna_and_punycode_are_equivalent(self) -> None:
        self.assertEqual(canonicalize_hostname("münich.example"), "xn--mnich-kva.example")
        self.assertEqual(canonicalize_hostname("XN--MNICH-KVA.EXAMPLE"), "xn--mnich-kva.example")
        self.assertEqual(canonicalize_hostname("münich.example."), "xn--mnich-kva.example")
        self.assertEqual(canonicalize_hostname("[::1]"), "::1")

    def test_unicode_host_validation_pins_resolved_address(self) -> None:
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            validated = validate_mcp_url("https://münich.example/mcp", resolve_dns=True)
            self.assertEqual(validated.hostname, "xn--mnich-kva.example")
            self.assertEqual(validated.pinned_ip, "93.184.216.34")
            self.assertEqual(str(validated), "https://münich.example/mcp")

    def test_unicode_host_private_dns_answer_is_rejected(self) -> None:
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]
            with self.assertRaises(MCPConfigurationError):
                validate_mcp_url("https://münich.example/mcp", resolve_dns=True)

    async def test_punycode_connection_uses_pinned_ip(self) -> None:
        base = MagicMock()
        base.connect_tcp = AsyncMock(return_value=object())
        backend = PinnedAsyncNetworkBackend("münich.example", "93.184.216.34", base_backend=base)
        await backend.connect_tcp("xn--mnich-kva.example", 443)
        base.connect_tcp.assert_awaited_once_with(
            "93.184.216.34",
            443,
            timeout=None,
            local_address=None,
            socket_options=None,
        )

    async def test_unexpected_host_fails_closed_without_resolution(self) -> None:
        base = MagicMock()
        base.connect_tcp = AsyncMock()
        backend = PinnedAsyncNetworkBackend("example.com", "93.184.216.34", base_backend=base)
        with self.assertRaises(MCPConnectionError):
            await backend.connect_tcp("attacker.example", 443)
        base.connect_tcp.assert_not_called()

    async def test_unix_socket_is_not_allowed(self) -> None:
        base = MagicMock()
        backend = PinnedAsyncNetworkBackend("example.com", "93.184.216.34", base_backend=base)
        with self.assertRaises(MCPConnectionError):
            await backend.connect_unix_socket("/tmp/socket")

    def test_pin_installation_failure_fails_closed(self) -> None:
        class _UnpinnableTransport:
            def close(self) -> None:
                return None

        with patch("httpx2.AsyncHTTPTransport", return_value=_UnpinnableTransport()):
            with self.assertRaises(MCPConfigurationError) as ctx:
                create_pinned_async_transport("example.com", "93.184.216.34")
            self.assertIn("pinning transport could not be installed", str(ctx.exception))

    def test_pin_installation_sets_backend(self) -> None:
        class _Pool:
            _network_backend = object()

        class _Transport:
            def __init__(self) -> None:
                self._pool = _Pool()

        with patch("httpx2.AsyncHTTPTransport", return_value=_Transport()):
            transport = create_pinned_async_transport("münich.example", "93.184.216.34")
            self.assertIsInstance(transport._pool._network_backend, PinnedAsyncNetworkBackend)
            self.assertEqual(transport._pool._network_backend._target_host, "xn--mnich-kva.example")


if __name__ == "__main__":
    unittest.main()
