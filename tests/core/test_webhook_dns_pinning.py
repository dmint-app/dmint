"""Webhook DNS-rebinding regressions: validate once, connect to the pinned IP."""

from __future__ import annotations

import socket
import ssl
import urllib.request
from typing import Any

import pytest

from dmint.core.webhooks import (
    ValidatedWebhookURL,
    _PinnedHTTPSConnection,
    _PinnedHTTPSHandler,
    _post_json,
    validate_webhook_url,
)


def _gai(address: str, port: int = 443) -> list[tuple[Any, ...]]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]


def test_validation_pins_public_dns_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", lambda *_a, **_k: _gai("93.184.216.34"))
    validated = validate_webhook_url("https://hooks.example.com/services/T000/B000/secret")
    assert isinstance(validated, ValidatedWebhookURL)
    assert validated.pinned_ip == "93.184.216.34"
    assert validated.hostname == "hooks.example.com"


def test_private_dns_answer_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", lambda *_a, **_k: _gai("10.0.0.7"))
    with pytest.raises(ValueError, match="prohibited IP"):
        validate_webhook_url("https://hooks.example.com/services/secret")


def test_idn_host_is_canonicalized_and_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", lambda *_a, **_k: _gai("93.184.216.34"))
    validated = validate_webhook_url("https://münich.example/hook")
    assert validated.hostname == "xn--mnich-kva.example"
    assert validated.pinned_ip == "93.184.216.34"


def test_connection_rebinding_cannot_change_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"resolve": 0}

    def public_then_private(*_a: Any, **_k: Any) -> list[tuple[Any, ...]]:
        calls["resolve"] += 1
        return _gai("93.184.216.34" if calls["resolve"] == 1 else "10.0.0.7")

    monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", public_then_private)
    validated = validate_webhook_url("https://hooks.example.com/services/secret")

    # A later DNS answer must not be consulted by the POST at all.
    def unexpected_resolution(*_a: Any, **_k: Any) -> list[tuple[Any, ...]]:
        raise AssertionError("webhook POST performed a second DNS lookup")

    monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", unexpected_resolution)
    captured: dict[str, Any] = {}

    class _Response:
        status = 200
        headers: dict[str, str] = {}

        def getcode(self) -> int:
            return 200

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    class _Opener:
        def open(self, req: urllib.request.Request, timeout: float = 0) -> _Response:
            captured["url"] = req.full_url
            return _Response()

    def fake_build(*handlers: Any) -> _Opener:
        captured["handlers"] = handlers
        return _Opener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build)
    _post_json(validated, {"text": "hello"})
    assert captured["url"].startswith("https://hooks.example.com/")
    handlers = captured["handlers"]
    pinned = [handler for handler in handlers if isinstance(handler, _PinnedHTTPSHandler)]
    assert len(pinned) == 1
    assert pinned[0]._pinned_ip == "93.184.216.34"


def test_allowlisted_loopback_is_explicitly_allowed_and_pinned() -> None:
    validated = validate_webhook_url("http://127.0.0.1:9999/hook", allowed_hosts=("127.0.0.1",))
    assert validated.pinned_ip == "127.0.0.1"


def test_non_allowlisted_loopback_is_rejected() -> None:
    with pytest.raises(ValueError):
        validate_webhook_url("https://127.0.0.1/hook")


def test_https_connection_preserves_sni_and_hostname() -> None:
    created: list[tuple[Any, ...]] = []
    wrapped: list[dict[str, Any]] = []

    class _Socket:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            created.append((args, kwargs))

    class _Context:
        def wrap_socket(self, sock: Any, *, server_hostname: str) -> Any:
            wrapped.append({"sock": sock, "server_hostname": server_hostname})
            return "wrapped"

    conn = _PinnedHTTPSConnection("hooks.example.com", pinned_ip="93.184.216.34")
    conn._context = _Context()  # type: ignore[assignment]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("socket.create_connection", _Socket)
        conn.connect()
    assert created[0][0][0] == ("93.184.216.34", 443)
    assert wrapped[0]["server_hostname"] == "hooks.example.com"


def test_default_context_validates_certificates() -> None:
    conn = _PinnedHTTPSConnection("hooks.example.com", pinned_ip="93.184.216.34")
    assert isinstance(conn._context, ssl.SSLContext)
    assert conn._context.verify_mode == ssl.CERT_REQUIRED
