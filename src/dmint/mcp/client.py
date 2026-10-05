"""Downstream MCP client connection abstraction supporting STDIO and Streamable HTTP transports."""

from __future__ import annotations

import asyncio
import os
from contextlib import AsyncExitStack
from typing import Any, Iterable

import mcp.types as types
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.streamable_http import httpx2, streamable_http_client

from .errors import MCPConnectionError, MCPError, MCPProtocolError, MCPTimeoutError
from .config import MCPIntegrationConfig, MCPTransportType
from .ssrf import validate_mcp_url


def _sanitize_error_text(text: str, sensitive_tokens: Iterable[str]) -> str:
    """Strip sensitive tokens (such as bearer tokens or auth headers) from error messages."""
    sanitized = text
    for tok in sensitive_tokens:
        if tok and len(tok) >= 3 and tok in sanitized:
            sanitized = sanitized.replace(tok, "[REDACTED]")
    return sanitized


def _extract_leaf_exceptions(exc: BaseException) -> list[BaseException]:
    """Recursively extract underlying leaf exceptions from ExceptionGroups."""
    if hasattr(exc, "exceptions"):
        res: list[BaseException] = []
        for sub in getattr(exc, "exceptions"):
            res.extend(_extract_leaf_exceptions(sub))
        return res
    return [exc]


class DownstreamMCPClient:
    """Connection layer managing communication with one downstream MCP server."""

    def __init__(self, config: MCPIntegrationConfig) -> None:
        if type(config) is not MCPIntegrationConfig:
            raise TypeError("config must be an MCPIntegrationConfig")
        self._config = config
        self._exit_stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    @property
    def config(self) -> MCPIntegrationConfig:
        return self._config

    @property
    def is_connected(self) -> bool:
        return self._session is not None

    def _get_sensitive_tokens(self) -> list[str]:
        """Extract configured secret values for redaction in error reporting."""
        tokens: list[str] = []
        if self._config.headers:
            for k, v in self._config.headers.items():
                tokens.append(v)
                if v.lower().startswith("bearer "):
                    tokens.append(v[7:].strip())
        return [t for t in tokens if t and len(t) >= 3]

    async def connect(self) -> None:
        """Connect to downstream MCP server, run session handshake and initialize."""
        if self.is_connected:
            return

        if self._config.transport_type == MCPTransportType.STDIO:
            await self._connect_stdio()
        elif self._config.transport_type == MCPTransportType.STREAMABLE_HTTP:
            await self._connect_streamable_http()
        else:
            raise MCPConnectionError(f"unsupported transport: {self._config.transport_type}")

    async def _connect_stdio(self) -> None:
        env = dict(os.environ)
        if self._config.env:
            env.update(self._config.env)

        server_params = StdioServerParameters(
            command=self._config.command or "",
            args=list(self._config.args),
            env=env,
            cwd=self._config.cwd,
        )

        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(server_params))
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            await asyncio.wait_for(session.initialize(), timeout=self._config.connect_timeout)
            self._exit_stack = stack
            self._session = session
        except asyncio.TimeoutError as exc:
            await stack.aclose()
            self._exit_stack = None
            self._session = None
            raise MCPTimeoutError(
                f"connection to downstream MCP server timed out after {self._config.connect_timeout}s"
            ) from exc
        except Exception as exc:
            await stack.aclose()
            self._exit_stack = None
            self._session = None
            if isinstance(exc, (MCPError, MCPTimeoutError)):
                raise
            raise MCPConnectionError("could not connect or initialize downstream MCP server") from exc

    async def _connect_streamable_http(self) -> None:
        if not self._config.url:
            raise MCPConnectionError("streamable_http transport requires a valid url")

        # 1. Enforce SSRF pre-connection validation with DNS resolution
        try:
            validated_url = validate_mcp_url(
                self._config.url,
                allow_loopback=True,
                resolve_dns=True,
            )
        except Exception as exc:
            raise MCPConnectionError(f"SSRF or URL validation failed for endpoint '{self._config.url}': {exc}") from exc

        # 2. Prepare headers (resolving env vars if specified via $VAR)
        headers: dict[str, str] = {}
        for k, v in (self._config.headers or {}).items():
            val = v
            if val.startswith("$"):
                var_name = val[1:].strip("{}")
                val = os.environ.get(var_name, val)
            headers[k] = val

        sensitive_tokens = self._get_sensitive_tokens()
        last_response_status: list[int] = []

        async def _capture_response(resp: httpx2.Response) -> None:
            last_response_status.append(resp.status_code)

        http_timeout = httpx2.Timeout(
            timeout=self._config.call_timeout,
            connect=self._config.connect_timeout,
            read=max(self._config.call_timeout, 300.0),
            write=self._config.call_timeout,
        )

        http_client = httpx2.AsyncClient(
            headers=headers,
            timeout=http_timeout,
            verify=True,
            follow_redirects=False,
            event_hooks={"response": [_capture_response]},
        )

        stack = AsyncExitStack()
        try:
            await stack.enter_async_context(http_client)
            read_stream, write_stream = await stack.enter_async_context(
                streamable_http_client(validated_url, http_client=http_client)
            )
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            await asyncio.wait_for(session.initialize(), timeout=self._config.connect_timeout)
            self._exit_stack = stack
            self._session = session
        except BaseException as exc:
            close_exc = None
            try:
                await stack.aclose()
            except BaseException as ce:
                close_exc = ce
            self._exit_stack = None
            self._session = None

            if isinstance(exc, asyncio.TimeoutError):
                raise MCPTimeoutError(
                    f"connection to downstream MCP server timed out after {self._config.connect_timeout}s"
                ) from exc

            target_exc = close_exc if (close_exc is not None and not isinstance(exc, MCPError)) else exc
            leaves = _extract_leaf_exceptions(target_exc)

            if any(isinstance(leaf, (asyncio.TimeoutError, MCPTimeoutError)) for leaf in leaves):
                raise MCPTimeoutError(
                    f"connection to downstream MCP server timed out after {self._config.connect_timeout}s"
                ) from target_exc

            for leaf in leaves:
                if isinstance(leaf, MCPError):
                    raise leaf

            err_strings = [str(leaf) for leaf in leaves]
            combined_err = " | ".join(err_strings) if err_strings else str(target_exc)
            raw_err = _sanitize_error_text(combined_err, sensitive_tokens)
            err_lower = raw_err.lower()

            status = last_response_status[-1] if last_response_status else None
            if status == 401 or "401" in err_lower or "unauthorized" in err_lower:
                raise MCPConnectionError("downstream HTTP authentication failed (401 Unauthorized)") from target_exc
            if status == 403 or "403" in err_lower or "forbidden" in err_lower:
                raise MCPConnectionError("downstream HTTP access forbidden (403 Forbidden)") from target_exc
            if status == 404:
                raise MCPConnectionError("downstream HTTP endpoint not found (404 Not Found)") from target_exc
            if status and status >= 500:
                raise MCPConnectionError(f"downstream HTTP server error ({status})") from target_exc
            raise MCPConnectionError(
                f"could not connect or initialize downstream MCP server: {raw_err}"
            ) from target_exc

    async def disconnect(self) -> None:
        """Disconnect and cleanup downstream streams and process context."""
        if self._exit_stack is not None:
            try:
                await self._exit_stack.aclose()
            except Exception:
                pass
            finally:
                self._exit_stack = None
                self._session = None

    async def __aenter__(self) -> "DownstreamMCPClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.disconnect()

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise MCPConnectionError("downstream MCP client is not connected")
        return self._session

    async def list_tools(self) -> list[types.Tool]:
        """Fetch downstream tool declarations."""
        session = self._require_session()
        try:
            result = await asyncio.wait_for(session.list_tools(), timeout=self._config.list_timeout)
            if not isinstance(result, types.ListToolsResult) or not hasattr(result, "tools"):
                raise MCPProtocolError("invalid tools/list response from downstream server")
            return list(result.tools)
        except asyncio.TimeoutError as exc:
            raise MCPTimeoutError(f"downstream tools/list timed out after {self._config.list_timeout}s") from exc
        except MCPError:
            raise
        except BaseException as exc:
            leaves = _extract_leaf_exceptions(exc)
            if any(isinstance(leaf, (asyncio.TimeoutError, MCPTimeoutError)) for leaf in leaves):
                raise MCPTimeoutError(f"downstream tools/list timed out after {self._config.list_timeout}s") from exc
            sensitive = self._get_sensitive_tokens()
            combined_err = " | ".join(str(leaf) for leaf in leaves)
            safe_msg = _sanitize_error_text(combined_err, sensitive)
            raise MCPConnectionError(f"failed to retrieve downstream tools list: {safe_msg}") from exc

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> types.CallToolResult:
        """Forward low-level tool invocation call downstream."""
        session = self._require_session()
        try:
            result = await asyncio.wait_for(
                session.call_tool(name, arguments=arguments),
                timeout=self._config.call_timeout,
            )
            if not isinstance(result, types.CallToolResult):
                raise MCPProtocolError("invalid tools/call response from downstream server")
            return result
        except asyncio.TimeoutError as exc:
            raise MCPTimeoutError(
                f"downstream tool call '{name}' timed out after {self._config.call_timeout}s"
            ) from exc
        except MCPError:
            raise
        except BaseException as exc:
            leaves = _extract_leaf_exceptions(exc)
            if any(isinstance(leaf, (asyncio.TimeoutError, MCPTimeoutError)) for leaf in leaves):
                raise MCPTimeoutError(
                    f"downstream tool call '{name}' timed out after {self._config.call_timeout}s"
                ) from exc
            sensitive = self._get_sensitive_tokens()
            combined_err = " | ".join(str(leaf) for leaf in leaves)
            safe_msg = _sanitize_error_text(combined_err, sensitive)
            raise MCPConnectionError(f"downstream tool call execution failed: {safe_msg}") from exc
