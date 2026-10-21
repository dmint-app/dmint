"""OAuth discovery/token SSRF regressions: loopback, private DNS, and pinning."""

from __future__ import annotations

import socket
import ssl
import unittest
import urllib.request
from unittest.mock import MagicMock, patch

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import (
    _PinnedHTTPSConnection,
    _PinnedHTTPSHandler,
    _open_url,
    _resolve_pinned_ip,
    _validate_https_endpoint,
)


class OAuthSSRFTests(unittest.TestCase):
    def test_remote_oauth_endpoint_must_not_be_loopback(self) -> None:
        for endpoint in (
            "http://127.0.0.1:8080/token",
            "http://localhost:8080/token",
            "http://[::1]:8080/token",
            "https://127.0.0.1/token",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(CLIError, msg=endpoint):
                    _validate_https_endpoint(endpoint, "token_endpoint", allow_loopback=False)

    def test_local_mcp_server_may_use_loopback_oauth_endpoint(self) -> None:
        _validate_https_endpoint("http://127.0.0.1:8080/token", "token_endpoint", allow_loopback=True)

    def test_private_dns_answer_is_rejected(self) -> None:
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 443))]
            with self.assertRaises(CLIError) as ctx:
                _resolve_pinned_ip("https://auth.example.com/token", allow_loopback=False)
            self.assertIn("prohibited IP", str(ctx.exception))

    def test_metadata_ip_literal_is_rejected(self) -> None:
        with self.assertRaises(CLIError):
            _resolve_pinned_ip("https://169.254.169.254/token", allow_loopback=False)

    def test_public_dns_is_pinned_once(self) -> None:
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            host, pinned = _resolve_pinned_ip("https://auth.example.com/token", allow_loopback=False)
            self.assertEqual(host, "auth.example.com")
            self.assertEqual(pinned, "93.184.216.34")

    def test_open_url_installs_pinned_https_handler(self) -> None:
        captured: dict[str, object] = {}

        class _Opener:
            def open(self, req: urllib.request.Request, timeout: float = 0) -> object:
                captured["timeout"] = timeout
                return object()

        def fake_build_opener(*handlers: object) -> _Opener:
            captured["handlers"] = handlers
            return _Opener()

        with (
            patch("dmint.cli.mcp_auth._resolve_pinned_ip", return_value=("auth.example.com", "93.184.216.34")),
            patch("urllib.request.build_opener", side_effect=fake_build_opener),
        ):
            response = _open_url(
                urllib.request.Request("https://auth.example.com/token"),
                timeout=4.0,
                allow_loopback=False,
            )
        self.assertIsNotNone(response)
        handlers = captured["handlers"]
        assert isinstance(handlers, tuple)
        pinned_handlers = [handler for handler in handlers if isinstance(handler, _PinnedHTTPSHandler)]
        self.assertEqual(len(pinned_handlers), 1)
        self.assertEqual(pinned_handlers[0]._pinned_ip, "93.184.216.34")

    def test_pinned_https_preserves_sni_and_uses_pinned_ip(self) -> None:
        created: list[tuple[object, ...]] = []
        wrapped: list[dict[str, object]] = []

        class _Socket:
            def __init__(self, *args: object, **kwargs: object) -> None:
                created.append((args, kwargs))

        class _Context:
            def wrap_socket(self, sock: object, *, server_hostname: str) -> object:
                wrapped.append({"sock": sock, "server_hostname": server_hostname})
                return "wrapped-socket"

        connection = _PinnedHTTPSConnection("auth.example.com", pinned_ip="93.184.216.34")
        connection._context = _Context()  # type: ignore[assignment]
        with patch("socket.create_connection", side_effect=_Socket):
            connection.connect()
        self.assertEqual(created[0][0][0], ("93.184.216.34", 443))
        self.assertEqual(wrapped[0]["server_hostname"], "auth.example.com")
        self.assertEqual(connection.sock, "wrapped-socket")

    def test_redirect_to_private_destination_is_rejected(self) -> None:
        from dmint.cli.mcp_auth import StrictSameOriginRedirectHandler

        handler = StrictSameOriginRedirectHandler()
        with self.assertRaises(CLIError):
            handler.redirect_request(
                urllib.request.Request("https://auth.example.com/token"),
                None,
                302,
                "Found",
                {},
                "https://169.254.169.254/token",
            )


class PinnedConnectionContextTests(unittest.TestCase):
    def test_default_context_is_real_ssl_context(self) -> None:
        connection = _PinnedHTTPSConnection("auth.example.com", pinned_ip="93.184.216.34")
        self.assertIsInstance(connection._context, ssl.SSLContext)


if __name__ == "__main__":
    unittest.main()
