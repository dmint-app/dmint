"""Regression tests: every OAuth HTTP call path must refuse cross-origin redirects (SRC-02).

Dynamic client registration, token exchange, and token refresh previously used bare
``urllib.request.urlopen``, which follows a 302 across origins (re-targeting the
request and dropping/replacing the response). They must instead use the same-origin
redirect guard that discovery already uses.
"""

from __future__ import annotations

import http.server
import json
import threading
from typing import Any
import unittest
from unittest.mock import MagicMock, patch

from dmint.cli.errors import CLIError
from dmint.cli.mcp_auth import MCPAuthRequirements
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport
from dmint.cli.mcp_credentials import TokenRecord, refresh_token
from dmint.cli.mcp_oauth import OAuthCallbackHandler, perform_oauth_flow, register_dynamic_client


def _drain_body(handler: http.server.BaseHTTPRequestHandler) -> None:
    length = int(handler.headers.get("Content-Length", 0) or 0)
    if length > 0:
        handler.rfile.read(length)


def _write_json(handler: http.server.BaseHTTPRequestHandler, payload: dict[str, Any]) -> None:
    _drain_body(handler)
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _start_server(handler_cls: type[http.server.BaseHTTPRequestHandler]) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _stop_servers(servers: list[http.server.ThreadingHTTPServer]) -> None:
    for server in servers:
        server.shutdown()
        server.server_close()


def _start_cross_origin_redirect_pair(
    payload: dict[str, Any],
) -> tuple[str, list[http.server.ThreadingHTTPServer]]:
    """Serve ``payload`` on a target origin and 302-redirect to it from a different origin."""

    class TargetHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            _write_json(self, payload)

        def do_POST(self) -> None:
            _write_json(self, payload)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    target = _start_server(TargetHandler)
    target_url = f"http://127.0.0.1:{target.server_address[1]}/stolen"

    class RedirectorHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            _drain_body(self)
            self.send_response(302)
            self.send_header("Location", target_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self) -> None:
            self.do_GET()

        def log_message(self, format: str, *args: Any) -> None:
            pass

    redirector = _start_server(RedirectorHandler)
    return f"http://127.0.0.1:{redirector.server_address[1]}", [target, redirector]


class TestOAuthSameOriginRedirects(unittest.TestCase):
    """Cross-origin 30x responses must be refused on registration, token exchange, and refresh."""

    def test_registration_refuses_cross_origin_redirect(self) -> None:
        redirector_url, servers = _start_cross_origin_redirect_pair({"client_id": "attacker-client-id"})
        self.addCleanup(_stop_servers, servers)

        with self.assertRaises(CLIError) as ctx:
            register_dynamic_client(f"{redirector_url}/register", "http://127.0.0.1:9/callback")

        self.assertIn("cross-origin redirect", str(ctx.exception))

    def test_token_exchange_refuses_cross_origin_redirect(self) -> None:
        redirector_url, servers = _start_cross_origin_redirect_pair(
            {"access_token": "attacker-access-token", "token_type": "Bearer"}
        )
        self.addCleanup(_stop_servers, servers)

        auth_reqs = MCPAuthRequirements(
            required=True,
            authorization_endpoint=f"{redirector_url}/authorize",
            token_endpoint=f"{redirector_url}/token",
        )
        integ = MCPIntegration(
            integration_id="redirect-test",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "http://127.0.0.1:9/mcp"},
        )
        store = MagicMock()

        OAuthCallbackHandler.callback_code = "valid-code"
        OAuthCallbackHandler.callback_state = "mock-state"
        OAuthCallbackHandler.received_event.set()
        self.addCleanup(OAuthCallbackHandler.received_event.clear)

        with patch.object(OAuthCallbackHandler.received_event, "wait", return_value=True):
            with patch("secrets.token_urlsafe", return_value="mock-state"):
                with self.assertRaises(CLIError) as ctx:
                    perform_oauth_flow(
                        auth_reqs,
                        integ,
                        client_id="client-123",
                        open_browser=False,
                        credential_store=store,
                    )

        self.assertIn("cross-origin redirect", str(ctx.exception))
        store.save.assert_not_called()

    def test_token_refresh_refuses_cross_origin_redirect(self) -> None:
        redirector_url, servers = _start_cross_origin_redirect_pair(
            {"access_token": "attacker-access-token", "refresh_token": "attacker-refresh-token"}
        )
        self.addCleanup(_stop_servers, servers)

        record = TokenRecord(
            server_identity="https://example.com/mcp::redirect-test",
            access_token="old-access-token",
            refresh_token="old-refresh-token",
        )
        store = MagicMock()

        with self.assertRaises(CLIError) as ctx:
            refresh_token(
                record,
                f"{redirector_url}/token",
                client_id="client-123",
                client_secret="client-secret",
                credential_store=store,
                allow_loopback=True,
            )

        self.assertIn("cross-origin redirect", str(ctx.exception))
        store.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
