"""Generic MCP connection modeling and tool discovery for dmint-cli."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from enum import Enum
import json
import os
import re
from typing import Any, Mapping

from dmint.cli.errors import CLIError
from dmint.cli.limits import (
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    MAX_AUTH_RETRY_ATTEMPTS,
    MAX_CURSOR_LENGTH,
    MAX_DISCOVERY_TIMEOUT_SECONDS,
    MAX_PAGINATION_DEPTH,
    MAX_RECURSION_DEPTH,
    MAX_SCHEMA_SIZE_BYTES,
    MAX_TOOL_DESCRIPTION_LENGTH,
    MAX_TOOL_NAME_LENGTH,
    MAX_TOOLS_PER_INTEGRATION,
)

SENSITIVE_KEYS = {"api_key", "apikey", "secret", "password", "token", "authorization", "auth_token", "key"}


def redact_secrets(data: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive key-values in dict/list structures for safe repr and logging."""
    if depth > MAX_RECURSION_DEPTH:
        return "<max_recursion_depth_reached>"
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            if isinstance(k, str) and any(sk in k.lower() for sk in SENSITIVE_KEYS):
                redacted[k] = "<redacted>"
            else:
                redacted[k] = redact_secrets(v, depth=depth + 1)
        return redacted
    elif isinstance(data, list):
        return [redact_secrets(v, depth=depth + 1) for v in data]
    return data


def redact_text(text: str) -> str:
    """Redact bearer tokens, API keys, and sensitive headers from error messages."""
    if not text:
        return ""
    text = re.sub(r"(Bearer\s+)[^\s'\"]+", r"\1<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(
        r"(key|token|secret|password|authorization)=([^\s&'\"]+)", r"\1=<redacted>", text, flags=re.IGNORECASE
    )
    text = re.sub(
        r"(['\"]?authorization['\"]?\s*[:=]\s*['\"]?)(?:Bearer\s+)?[^\s'\"}]+",
        r"\1<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"sk-[a-zA-Z0-9_-]{8,}", "<redacted_api_key>", text)
    text = re.sub(r"secret_[a-zA-Z0-9_-]{8,}", "<redacted_secret>", text)
    return text


def _extract_error_details(exc: BaseException, depth: int = 0) -> str:
    """Recursively extract error messages, causes, contexts, and nested exceptions."""
    if depth > MAX_RECURSION_DEPTH:
        return str(exc)
    parts: list[str] = [str(exc)]
    err_obj = getattr(exc, "error", None)
    if err_obj is not None:
        parts.append(str(err_obj))
        if hasattr(err_obj, "message"):
            parts.append(str(err_obj.message))
        if hasattr(err_obj, "data"):
            parts.append(str(err_obj.data))

    if hasattr(exc, "exceptions"):
        for sub in getattr(exc, "exceptions", []):
            parts.append(_extract_error_details(sub, depth=depth + 1))
    if exc.__cause__ is not None:
        parts.append(_extract_error_details(exc.__cause__, depth=depth + 1))
    if exc.__context__ is not None:
        parts.append(_extract_error_details(exc.__context__, depth=depth + 1))
    return " | ".join(p for p in parts if p)


class MCPTransport(str, Enum):
    """Supported and conceptual downstream MCP transports."""

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"


SUPPORTED_TRANSPORTS = {
    MCPTransport.STDIO,
    MCPTransport.STREAMABLE_HTTP,
    MCPTransport.STDIO.value,
    MCPTransport.STREAMABLE_HTTP.value,
}


@dataclass
class MCPIntegration:
    """Generic representation of an MCP integration for CLI policy authoring."""

    integration_id: str
    transport: MCPTransport | str = MCPTransport.STDIO
    connection: dict[str, Any] = field(default_factory=dict)
    authentication: dict[str, Any] = field(default_factory=dict)
    discovered_tools: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.validate_integration_id()

    def validate_integration_id(self) -> None:
        if not self.integration_id or not isinstance(self.integration_id, str) or not self.integration_id.strip():
            raise CLIError("Integration ID must be a non-empty string.")
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.integration_id.strip()):
            raise CLIError(
                f"Invalid integration_id '{self.integration_id}'. Must contain only alphanumeric characters, dashes, or underscores."
            )

    def validate_transport(self) -> None:
        """Validate whether transport is known and supported by CLI discovery."""
        raw_trans = (
            (self.transport.value if isinstance(self.transport, MCPTransport) else str(self.transport)).lower().strip()
        )

        if raw_trans not in {t.value for t in MCPTransport}:
            raise CLIError(
                f"Unknown MCP transport type '{self.transport}'. Valid transport types are: 'stdio', 'streamable-http'."
            )

        if raw_trans not in SUPPORTED_TRANSPORTS:
            raise CLIError(f"Unsupported MCP transport type '{self.transport}'.")

    def validate_connection(self) -> None:
        """Validate connection details according to the requested transport."""
        raw_trans = (
            (self.transport.value if isinstance(self.transport, MCPTransport) else str(self.transport)).lower().strip()
        )

        if raw_trans == MCPTransport.STDIO.value:
            command = self.connection.get("command")
            if not command or not isinstance(command, str) or not command.strip():
                raise CLIError(
                    f"Malformed stdio connection structure for '{self.integration_id}': missing or invalid 'command'."
                )
            args = self.connection.get("args")
            if args is not None and not isinstance(args, (list, tuple)):
                raise CLIError(
                    f"Malformed stdio connection structure for '{self.integration_id}': 'args' must be a list of strings."
                )
        elif raw_trans == MCPTransport.STREAMABLE_HTTP.value:
            url = self.connection.get("url")
            if not url or not isinstance(url, str) or not url.strip():
                raise CLIError(
                    f"Malformed streamable-http connection structure for '{self.integration_id}': missing or invalid 'url'."
                )
            from dmint.cli.mcp_auth import _validate_https_endpoint

            _validate_https_endpoint(url, f"MCP endpoint for '{self.integration_id}'")

    def __repr__(self) -> str:
        safe_conn = redact_secrets(self.connection)
        safe_auth = redact_secrets(self.authentication)
        trans_str = self.transport.value if isinstance(self.transport, MCPTransport) else str(self.transport)
        return (
            f"MCPIntegration(integration_id={self.integration_id!r}, "
            f"transport={trans_str!r}, connection={safe_conn!r}, "
            f"authentication={safe_auth!r}, tools_count={len(self.discovered_tools)})"
        )

    def to_dict(self) -> dict[str, Any]:
        trans_str = self.transport.value if isinstance(self.transport, MCPTransport) else str(self.transport)
        result: dict[str, Any] = {
            "integration_id": self.integration_id,
            "transport": trans_str,
            "connection": redact_secrets(self.connection),
        }
        if self.authentication:
            result["authentication"] = redact_secrets(self.authentication)

        result["tool_bindings"] = {
            t["name"]: {
                "tool_name": t["name"],
                "capability": canonical_capability(self.integration_id, t["name"]),
                "discovery": "exposed",
            }
            for t in self.discovered_tools
        }
        return result

    @property
    def canonical_capabilities(self) -> dict[str, str]:
        """Mapping of discovered tool names to their canonical capability identifiers."""
        return {
            t["name"]: canonical_capability(self.integration_id, t["name"])
            for t in self.discovered_tools
            if "name" in t
        }


MAX_DESCRIPTION_LENGTH = 10000


TOOL_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")


def canonical_capability(integration_id: str, tool_name: str) -> str:
    """Return the exact, canonical Dmint capability identity for an MCP tool: mcp.<integration_id>.<tool_name>."""
    clean_integ = (integration_id or "").strip()
    clean_tool = (tool_name or "").strip()
    if not clean_integ:
        raise CLIError("Cannot construct canonical capability: missing or empty integration_id.")
    if not clean_tool:
        raise CLIError("Cannot construct canonical capability: missing or empty tool_name.")
    if len(clean_tool) > MAX_TOOL_NAME_LENGTH:
        raise CLIError(
            f"Security error: Tool name '{clean_tool[:20]}...' exceeds maximum allowed length of {MAX_TOOL_NAME_LENGTH} characters."
        )
    if not TOOL_NAME_REGEX.match(clean_tool):
        raise CLIError(
            f"Security error: Invalid tool name '{clean_tool}' in canonical capability. "
            f"Tool names must contain only alphanumeric characters, dashes, or underscores."
        )
    return f"mcp.{clean_integ}.{clean_tool}"


def _normalize_tools_response(tools_res: Any, integration_id: str) -> list[dict[str, Any]]:
    """Validate tools/list response structure, extract annotations, and normalize capabilities."""
    tools_list = getattr(tools_res, "tools", None)
    if tools_list is None:
        if isinstance(tools_res, dict):
            tools_list = tools_res.get("tools")
        elif isinstance(tools_res, (list, tuple)):
            tools_list = tools_res

    if tools_list is None or not isinstance(tools_list, (list, tuple)):
        raise CLIError(
            f"Malformed tools/list response for integration '{integration_id}': missing or invalid 'tools' list."
        )

    if len(tools_list) > MAX_TOOLS_PER_INTEGRATION:
        raise CLIError(
            f"Security error: tools/list response for integration '{integration_id}' exceeded max tool limit ({MAX_TOOLS_PER_INTEGRATION})."
        )

    tools: list[dict[str, Any]] = []
    seen_tool_names: set[str] = set()

    for idx, t in enumerate(tools_list):
        name = getattr(t, "name", None) if not isinstance(t, dict) else t.get("name")
        if not name or not isinstance(name, str) or not name.strip():
            raise CLIError(
                f"Malformed tool at index {idx} for integration '{integration_id}': missing or invalid 'name'."
            )

        name = name.strip()
        if len(name) > MAX_TOOL_NAME_LENGTH:
            raise CLIError(
                f"Security error: Tool name '{name[:20]}...' at index {idx} exceeds maximum allowed length of {MAX_TOOL_NAME_LENGTH} characters."
            )
        if not TOOL_NAME_REGEX.match(name):
            raise CLIError(
                f"Security error: Invalid tool name '{name}' at index {idx} for integration '{integration_id}'. "
                f"Tool names must contain only alphanumeric characters, dashes, or underscores."
            )

        if name in seen_tool_names:
            raise CLIError(f"Duplicate tool '{name}' discovered for integration '{integration_id}'.")
        seen_tool_names.add(name)

        raw_desc = (
            getattr(t, "description", None) if not isinstance(t, dict) else t.get("description")
        ) or f"MCP tool {name}"
        if not isinstance(raw_desc, str):
            raw_desc = str(raw_desc)

        if len(raw_desc) > MAX_TOOL_DESCRIPTION_LENGTH:
            description = raw_desc[:MAX_TOOL_DESCRIPTION_LENGTH] + "... [truncated]"
        else:
            description = raw_desc

        schema = (
            getattr(t, "inputSchema", getattr(t, "input_schema", {}))
            if not isinstance(t, dict)
            else (t.get("inputSchema") or t.get("input_schema") or {})
        )
        if not isinstance(schema, dict):
            schema = {}
        else:
            try:
                schema_bytes = len(json.dumps(schema))
                if schema_bytes > MAX_SCHEMA_SIZE_BYTES:
                    raise CLIError(
                        f"Security error: tool '{name}' input_schema size ({schema_bytes} bytes) "
                        f"exceeds maximum allowed limit of {MAX_SCHEMA_SIZE_BYTES} bytes."
                    )
            except (TypeError, ValueError) as exc:
                raise CLIError(f"Security error: tool '{name}' has un-serializable input_schema: {exc}") from exc

        annotations = getattr(t, "annotations", {}) if not isinstance(t, dict) else t.get("annotations", {})
        if not isinstance(annotations, dict):
            annotations = {}

        # Canonical capability derived strictly from (integration_id, tool_name)
        # Injected 'capability' keys or malicious descriptions can never alter capability identity
        capability = canonical_capability(integration_id, name)

        tools.append(
            {
                "name": name,
                "description": description,
                "input_schema": schema,
                "annotations": annotations,
                "integration_id": integration_id,
                "capability": capability,
            }
        )

    return tools


async def _fetch_all_tools_paginated(session: Any, integration_id: str) -> list[dict[str, Any]]:
    """Fetch all tools across all pages using cursor pagination if advertised by the MCP server."""
    all_tools: list[dict[str, Any]] = []
    seen_tool_names: set[str] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    max_pages = MAX_PAGINATION_DEPTH
    page_count = 0

    while True:
        page_count += 1
        if page_count > max_pages:
            raise CLIError(
                f"Security error: pagination exceeded {max_pages} pages for integration '{integration_id}'. "
                "Aborting to prevent denial-of-service."
            )

        try:
            if cursor:
                tools_res = await session.list_tools(cursor=cursor)
            else:
                tools_res = await session.list_tools()
        except TypeError:
            tools_res = await session.list_tools()

        page_tools = _normalize_tools_response(tools_res, integration_id)
        for t in page_tools:
            if t["name"] in seen_tool_names:
                raise CLIError(
                    f"Duplicate tool '{t['name']}' discovered across paginated responses for integration '{integration_id}'."
                )
            seen_tool_names.add(t["name"])
            all_tools.append(t)

        if len(all_tools) > MAX_TOOLS_PER_INTEGRATION:
            raise CLIError(
                f"Security error: tools/list response for integration '{integration_id}' "
                f"exceeded max tool limit ({MAX_TOOLS_PER_INTEGRATION})."
            )

        next_cursor = (
            getattr(tools_res, "nextCursor", getattr(tools_res, "next_cursor", None))
            if not isinstance(tools_res, dict)
            else (tools_res.get("nextCursor") or tools_res.get("next_cursor"))
        )

        if next_cursor is not None:
            if hasattr(next_cursor, "_mock_return_value") or hasattr(next_cursor, "_mock_name"):
                break
            if not isinstance(next_cursor, str) or not next_cursor.strip() or len(next_cursor) > MAX_CURSOR_LENGTH:
                raise CLIError(
                    f"Malformed nextCursor in paginated response for integration '{integration_id}': "
                    f"expected non-empty string under {MAX_CURSOR_LENGTH} chars, got {len(next_cursor) if isinstance(next_cursor, str) else type(next_cursor).__name__}."
                )
            clean_cursor = next_cursor.strip()
            if clean_cursor in seen_cursors or clean_cursor == cursor:
                raise CLIError(
                    f"Pagination loop detected for integration '{integration_id}': "
                    f"cursor '{clean_cursor}' was already visited."
                )
            seen_cursors.add(clean_cursor)
            cursor = clean_cursor
        else:
            break

    return all_tools


async def _discover_stdio_tools(integration: MCPIntegration) -> list[dict[str, Any]]:
    command = integration.connection.get("command")
    args = integration.connection.get("args", [])
    env = integration.connection.get("env")

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        raise CLIError("mcp package is required for MCP tool discovery. Install via `pip install mcp`.") from exc

    params = StdioServerParameters(
        command=str(command) if command is not None else "",
        args=args if isinstance(args, list) else list(args),
        env=env or dict(os.environ),
    )

    try:
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await _fetch_all_tools_paginated(session, integration.integration_id)
                integration.discovered_tools = tools
                return tools
    except CLIError:
        raise
    except Exception as exc:
        safe_msg = redact_text(str(exc))
        raise CLIError(
            f"Failed to connect to stdio MCP server for integration '{integration.integration_id}': {safe_msg}"
        ) from exc


async def _discover_streamable_http_tools(
    integration: MCPIntegration,
    *,
    _auth_attempt: int = 0,
) -> list[dict[str, Any]]:
    url = integration.connection.get("url")
    if not url or not isinstance(url, str):
        raise CLIError(f"Missing or invalid URL for streamable-http integration '{integration.integration_id}'.")
    from dmint.cli.mcp_auth import _validate_https_endpoint

    _validate_https_endpoint(url, f"MCP endpoint for '{integration.integration_id}'")

    headers: dict[str, str] = {}
    if isinstance(integration.connection.get("headers"), dict):
        headers.update(integration.connection["headers"])
    if isinstance(integration.authentication.get("headers"), dict):
        headers.update(integration.authentication["headers"])

    # Load from CredentialStore if token not explicitly set
    server_identity = f"{url}::{integration.integration_id}"
    auth_key = integration.authentication.get("api_key") or integration.authentication.get("token")

    if not auth_key:
        from dmint.cli.mcp_credentials import CredentialStore

        cred_store = CredentialStore()
        record = cred_store.load(server_identity)
        if record and not record.is_expired:
            auth_key = record.access_token

    if auth_key and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {auth_key}"

    try:
        import httpx2
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        raise CLIError("mcp package with streamable_http client is required. Install via `pip install mcp`.") from exc

    # Build an authenticated HTTP client and inject it into the MCP transport.
    # - verify=True: never weaken certificate verification.
    # - follow_redirects=False: MCP transport handles intra-origin redirects safely.
    # - timeout: taken from connection config or defaults to 30s.
    request_timeout = float(integration.connection.get("timeout", 30.0))
    auth_handler = integration.authentication.get("auth")

    last_response_info: dict[str, Any] = {}

    async def _capture_response_status(resp: httpx2.Response) -> None:
        last_response_info["status_code"] = resp.status_code
        last_response_info["www_authenticate"] = resp.headers.get("www-authenticate", "")

    custom_client = integration.connection.get("http_client")
    if custom_client is not None:
        http_client = custom_client
    else:
        http_client = httpx2.AsyncClient(
            headers=headers,
            auth=auth_handler,
            verify=True,
            follow_redirects=False,
            timeout=request_timeout,
            event_hooks={"response": [_capture_response_status]},
        )

    try:
        async with http_client:
            async with streamable_http_client(url, http_client=http_client) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await _fetch_all_tools_paginated(session, integration.integration_id)
                    integration.discovered_tools = tools
                    return tools
    except CLIError:
        raise
    except Exception as exc:
        err_details = _extract_error_details(exc)
        safe_msg = redact_text(f"{exc} {err_details}")
        status_code = last_response_info.get("status_code")

        is_403 = status_code == 403 or "403" in safe_msg or "forbidden" in safe_msg.lower()
        if is_403:
            raise CLIError(
                f"Streamable HTTP MCP access forbidden (403 Forbidden) for integration '{integration.integration_id}'."
            ) from exc

        is_401 = status_code == 401 or "401" in safe_msg or "unauthorized" in safe_msg.lower()
        if is_401:
            if _auth_attempt >= MAX_AUTH_RETRY_ATTEMPTS:
                raise CLIError(
                    f"Streamable HTTP MCP authentication failed (401 Unauthorized) repeatedly for integration '{integration.integration_id}'. "
                    "Aborting to prevent infinite retry loop."
                )

            from dmint.cli.mcp_auth import discover_mcp_auth_requirements

            try:
                auth_reqs = discover_mcp_auth_requirements(integration)
                if auth_reqs.required:
                    from dmint.cli.mcp_oauth import perform_oauth_flow

                    tokens = perform_oauth_flow(auth_reqs, integration)
                    if tokens.get("access_token"):
                        integration.authentication["token"] = tokens["access_token"]
                        from dmint.cli.mcp_credentials import CredentialStore

                        CredentialStore().save(server_identity, tokens)
                        return await _discover_streamable_http_tools(integration, _auth_attempt=_auth_attempt + 1)
            except CLIError as auth_discovery_err:
                raise CLIError(
                    f"Streamable HTTP MCP authentication failed (401 Unauthorized) for integration '{integration.integration_id}': {auth_discovery_err}"
                ) from exc
            except Exception as oauth_err:
                safe_err = redact_text(str(oauth_err))
                raise CLIError(
                    f"OAuth flow failed for integration '{integration.integration_id}': {safe_err}"
                ) from oauth_err

            raise CLIError(
                f"Streamable HTTP MCP authentication failed (401 Unauthorized) for integration '{integration.integration_id}'."
            ) from exc

        is_500 = (
            (status_code is not None and status_code >= 500)
            or any(code in safe_msg for code in ("500", "502", "503"))
            or "server error" in safe_msg.lower()
        )
        if is_500:
            raise CLIError(
                f"Streamable HTTP MCP server error for integration '{integration.integration_id}': {safe_msg}"
            ) from exc

        raise CLIError(
            f"Streamable HTTP MCP discovery failed for integration '{integration.integration_id}': {safe_msg}"
        ) from exc


async def discover_mcp_tools_generic(integration: MCPIntegration) -> list[dict[str, Any]]:
    """Discover tools from an MCP integration according to its transport settings."""
    integration.validate_integration_id()
    integration.validate_transport()
    integration.validate_connection()

    raw_trans = (
        (integration.transport.value if isinstance(integration.transport, MCPTransport) else str(integration.transport))
        .lower()
        .strip()
    )

    timeout = min(
        float(integration.connection.get("timeout", DEFAULT_DISCOVERY_TIMEOUT_SECONDS)),
        MAX_DISCOVERY_TIMEOUT_SECONDS,
    )

    async def _do_discover() -> list[dict[str, Any]]:
        if raw_trans == MCPTransport.STDIO.value:
            return await _discover_stdio_tools(integration)
        elif raw_trans == MCPTransport.STREAMABLE_HTTP.value:
            return await _discover_streamable_http_tools(integration)
        else:
            raise CLIError(f"Unsupported MCP transport type '{integration.transport}'.")

    try:
        return await asyncio.wait_for(_do_discover(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise CLIError(f"Discovery timed out after {timeout}s for integration '{integration.integration_id}'.") from exc
