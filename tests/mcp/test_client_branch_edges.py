"""Branch-coverage edges for the downstream MCP client (SRC-18).

The Phase-6 branch report flagged `dmint.mcp.client` below the production
branch-coverage gate. These tests cover transport dispatch, fail-closed guards
for malformed configuration, header environment-variable expansion, sensitive
token redaction, and MCP error propagation.
"""

from __future__ import annotations

import asyncio

import pytest

from dmint.mcp import DownstreamMCPClient, MCPIntegrationConfig, MCPTransportType
from dmint.mcp.client import _sanitize_error_text
from dmint.mcp.errors import MCPConfigurationError, MCPConnectionError, MCPProtocolError


def _force_config(**overrides) -> MCPIntegrationConfig:
    """Build a config while bypassing constructor validation.

    Production code cannot create these shapes, but the client still carries
    defensive guards for them; the guards must keep failing closed.
    """
    config = MCPIntegrationConfig(integration_id="forced", command="python3")
    for name, value in overrides.items():
        object.__setattr__(config, f"_{name}", value)
    return config


def test_sanitize_error_text_redacts_tokens_and_ignores_short_or_absent_ones() -> None:
    assert _sanitize_error_text("token abc-secret here", ["abc-secret"]) == "token [REDACTED] here"
    assert _sanitize_error_text("token ab here", ["ab", ""]) == "token ab here"
    assert _sanitize_error_text("no tokens", ["missing-token"]) == "no tokens"


def test_client_rejects_foreign_config_type() -> None:
    with pytest.raises(TypeError, match="config must be an MCPIntegrationConfig"):
        DownstreamMCPClient(object())  # type: ignore[arg-type]


def test_connect_is_idempotent_when_session_already_established() -> None:
    client = DownstreamMCPClient(MCPIntegrationConfig(integration_id="srv", command="python3"))
    client._session = object()  # type: ignore[assignment]
    asyncio.run(client.connect())


def test_connect_rejects_unsupported_transport_forced_past_validation() -> None:
    client = DownstreamMCPClient(_force_config(transport_type="grpc"))
    with pytest.raises(MCPConnectionError, match="unsupported transport"):
        asyncio.run(client.connect())


def test_streamable_http_connect_without_url_fails_closed() -> None:
    client = DownstreamMCPClient(_force_config(transport_type=MCPTransportType.STREAMABLE_HTTP, url=None))
    with pytest.raises(MCPConnectionError, match="requires a valid url"):
        asyncio.run(client.connect())


def test_streamable_http_validation_failure_is_wrapped(monkeypatch) -> None:
    client = DownstreamMCPClient(
        _force_config(transport_type=MCPTransportType.STREAMABLE_HTTP, url="https://mcp.example.net/rpc")
    )

    def _reject(url, **_kwargs):
        raise MCPConfigurationError("blocked endpoint")

    monkeypatch.setattr("dmint.mcp.client.validate_mcp_url", _reject)
    with pytest.raises(MCPConnectionError, match="SSRF or URL validation failed"):
        asyncio.run(client.connect())


def test_streamable_http_expands_env_var_headers(monkeypatch) -> None:
    monkeypatch.setenv("DMINT_TEST_MCP_TOKEN", "Bearer s3cret")
    captured: dict[str, object] = {}

    class _StubValidated:
        pinned_ip = None
        hostname = None

    monkeypatch.setattr("dmint.mcp.client.validate_mcp_url", lambda url, **_kw: _StubValidated())

    class _FailingTransport:
        async def __aenter__(self):
            raise RuntimeError("transport exploded")

        async def __aexit__(self, *_exc):
            return False

    def _fake_streamable_http_client(url, *, http_client=None, **_kwargs):
        captured["http_client"] = http_client
        return _FailingTransport()

    monkeypatch.setattr("dmint.mcp.client.streamable_http_client", _fake_streamable_http_client)

    config = _force_config(
        transport_type=MCPTransportType.STREAMABLE_HTTP,
        url="https://mcp.example.net/rpc",
        headers={"Authorization": "$DMINT_TEST_MCP_TOKEN", "X-Plain": "plain"},
    )
    client = DownstreamMCPClient(config)
    with pytest.raises(MCPConnectionError, match="could not connect or initialize downstream MCP server"):
        asyncio.run(client.connect())

    http_client = captured["http_client"]
    assert http_client.headers["Authorization"] == "Bearer s3cret"
    assert http_client.headers["X-Plain"] == "plain"


def test_stdio_connect_merges_config_env(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class _FailingStdio:
        async def __aenter__(self):
            raise RuntimeError("stdio exploded")

        async def __aexit__(self, *_exc):
            return False

    def _fake_stdio_client(server_params):
        captured["server_params"] = server_params
        return _FailingStdio()

    monkeypatch.setattr("dmint.mcp.client.stdio_client", _fake_stdio_client)

    config = MCPIntegrationConfig(integration_id="srv", command="python3", env={"DMINT_PROBE_ENV": "1"})
    client = DownstreamMCPClient(config)
    with pytest.raises(MCPConnectionError, match="could not connect or initialize downstream MCP server"):
        asyncio.run(client.connect())

    server_params = captured["server_params"]
    assert server_params.env["DMINT_PROBE_ENV"] == "1"
    assert "PATH" in server_params.env


def test_stdio_connect_propagates_mcp_errors_unwrapped(monkeypatch) -> None:
    class _ProtocolErrorStdio:
        async def __aenter__(self):
            raise MCPProtocolError("bad handshake")

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr("dmint.mcp.client.stdio_client", lambda _params: _ProtocolErrorStdio())

    client = DownstreamMCPClient(MCPIntegrationConfig(integration_id="srv", command="python3"))
    with pytest.raises(MCPProtocolError, match="bad handshake"):
        asyncio.run(client.connect())
