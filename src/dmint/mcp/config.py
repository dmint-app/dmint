"""Trusted MCP integration and capability configuration."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from dmint.core.canonicalize import DEFAULT_SENSITIVE_KEYS, redact_sensitive_data
from dmint.models import validate_text
from .errors import MCPConfigurationError
from .ssrf import validate_mcp_url


class MCPTransportType(str, Enum):
    """Supported downstream MCP transports."""

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"

    @classmethod
    def from_value(cls, val: Any) -> "MCPTransportType":
        if isinstance(val, cls):
            return val
        if isinstance(val, str):
            normalized = val.strip().lower().replace("-", "_")
            for member in cls:
                if member.value == normalized:
                    return member
        raise ValueError(f"unsupported MCP transport type: {val}")


class DiscoveryMode(str, Enum):
    """Trusted discovery policy for exposing a tool through tools/list.

    Discovery controls whether the agent can *see* a tool. It is NOT an
    execution authorization boundary. Execution is always enforced
    independently by the tools/call authorization gate (MCP-5+).
    """

    EXPOSED = "exposed"
    HIDDEN = "hidden"


class DisclosureMode(str, Enum):
    """Information disclosure mode for agent-facing responses (AGENTS.md #22).

    DOG: Useful structured information (approval_id, request_id, fingerprint).
    GOD: Minimal opaque response (DMT_403).
    CAT: Structured code (DMT_APPROVAL_REQUIRED) without internal fingerprints.
    """

    DOG = "dog"
    GOD = "god"
    CAT = "cat"


@dataclass(frozen=True)
class MCPToolBinding:
    """Immutable binding mapping one downstream MCP tool to a Dmint capability."""

    tool_name: str
    capability: str
    resource_key: str | None = None
    discovery: DiscoveryMode | str = DiscoveryMode.EXPOSED

    def __post_init__(self) -> None:
        validate_text(self.tool_name, "tool_name")
        validate_text(self.capability, "capability")
        if self.resource_key is not None:
            validate_text(self.resource_key, "resource_key")
        if type(self.discovery) is str:
            try:
                object.__setattr__(self, "discovery", DiscoveryMode(self.discovery))
            except ValueError as exc:
                raise MCPConfigurationError("invalid discovery mode") from exc
        elif type(self.discovery) is not DiscoveryMode:
            raise MCPConfigurationError("invalid discovery mode")


class MCPIntegrationConfig:
    """Trusted server configuration for connecting to one downstream MCP server."""

    __slots__ = (
        "_integration_id",
        "_transport_type",
        "_command",
        "_args",
        "_url",
        "_headers",
        "_env",
        "_cwd",
        "_tool_bindings",
        "_default_discovery",
        "_redact_keys",
        "_connect_timeout",
        "_call_timeout",
        "_list_timeout",
        "_sealed",
    )

    _integration_id: str
    _transport_type: MCPTransportType
    _command: str | None
    _args: tuple[str, ...]
    _url: str | None
    _headers: MappingProxyType[str, str]
    _env: MappingProxyType[str, str]
    _cwd: str | None
    _tool_bindings: MappingProxyType[str, MCPToolBinding]
    _default_discovery: DiscoveryMode
    _redact_keys: Collection[str]
    _connect_timeout: float
    _call_timeout: float
    _list_timeout: float
    _sealed: bool

    def __init__(
        self,
        *,
        integration_id: str,
        command: str | None = None,
        args: tuple[str, ...] | list[str] = (),
        url: str | None = None,
        headers: Mapping[str, str] | None = None,
        transport_type: MCPTransportType | str = MCPTransportType.STDIO,
        env: Mapping[str, str] | None = None,
        cwd: str | Path | None = None,
        tool_bindings: Mapping[str, str | MCPToolBinding] | list[MCPToolBinding] | None = None,
        default_discovery: DiscoveryMode | str = DiscoveryMode.HIDDEN,
        redact_keys: Collection[str] | None = None,
        timeout: float | None = None,
        connect_timeout: float | None = None,
        call_timeout: float | None = None,
        list_timeout: float | None = None,
    ) -> None:
        try:
            integration_id = validate_text(integration_id, "integration_id")
        except Exception as exc:
            raise MCPConfigurationError("invalid integration_id") from exc

        try:
            transport_type = MCPTransportType.from_value(transport_type)
        except ValueError as exc:
            raise MCPConfigurationError("unsupported MCP transport type") from exc

        if type(default_discovery) is str:
            try:
                default_discovery = DiscoveryMode(default_discovery)
            except ValueError as exc:
                raise MCPConfigurationError("invalid default discovery mode") from exc
        elif type(default_discovery) is not DiscoveryMode:
            raise MCPConfigurationError("invalid default discovery mode")

        clean_url: str | None = None
        clean_headers: dict[str, str] = {}
        clean_command: str | None = None
        clean_args: list[str] = []
        clean_env: dict[str, str] = {}
        clean_cwd: str | None = None

        if transport_type == MCPTransportType.STDIO:
            if not command:
                raise MCPConfigurationError("stdio transport requires 'command'")
            try:
                clean_command = validate_text(command, "command")
            except Exception as exc:
                raise MCPConfigurationError("invalid command") from exc

            if url is not None:
                raise MCPConfigurationError("url is not supported for stdio transport")
            if headers:
                raise MCPConfigurationError("headers are not supported for stdio transport")

            if isinstance(args, (list, tuple)):
                for item in args:
                    if type(item) is not str:
                        raise MCPConfigurationError("command args must be strings")
                    clean_args.append(item)
            else:
                raise MCPConfigurationError("args must be a tuple or list of strings")

            if env is not None:
                if not isinstance(env, Mapping):
                    raise MCPConfigurationError("env must be a mapping of string key-values")
                for k, v in env.items():
                    if type(k) is not str or type(v) is not str:
                        raise MCPConfigurationError("env keys and values must be strings")
                    clean_env[k] = v

            clean_cwd = str(cwd) if cwd is not None else None

        elif transport_type == MCPTransportType.STREAMABLE_HTTP:
            target_url = url
            if target_url is None and command:
                if command.startswith(("http://", "https://")):
                    target_url = command
                elif command == "http-remote":
                    target_url = None
                else:
                    raise MCPConfigurationError("streamable_http transport requires 'url'")

            if target_url is not None:
                try:
                    clean_url = validate_mcp_url(target_url, allow_loopback=True, resolve_dns=False)
                except Exception as exc:
                    raise MCPConfigurationError(f"invalid streamable_http url: {exc}") from exc
            elif command != "http-remote":
                raise MCPConfigurationError("streamable_http transport requires 'url'")

            if cwd is not None:
                raise MCPConfigurationError("cwd is not supported for streamable_http transport")
            if env:
                raise MCPConfigurationError("env is not supported for streamable_http transport")
            if args:
                raise MCPConfigurationError("args are not supported for streamable_http transport")

            if headers is not None:
                if not isinstance(headers, Mapping):
                    raise MCPConfigurationError("headers must be a mapping of string key-values")
                for k, v in headers.items():
                    if type(k) is not str or type(v) is not str:
                        raise MCPConfigurationError("headers keys and values must be strings")
                    clean_headers[k] = v

        clean_bindings: dict[str, MCPToolBinding] = {}
        if tool_bindings is not None:
            if isinstance(tool_bindings, Mapping):
                for tool_name, spec in tool_bindings.items():
                    if type(tool_name) is not str:
                        raise MCPConfigurationError("tool_name key must be a string")
                    if type(spec) is str:
                        binding = MCPToolBinding(tool_name=tool_name, capability=spec)
                    elif type(spec) is MCPToolBinding:
                        binding = spec
                    else:
                        raise MCPConfigurationError("tool binding spec must be a capability string or MCPToolBinding")
                    clean_bindings[tool_name] = binding
            elif isinstance(tool_bindings, (list, tuple)):
                for spec in tool_bindings:
                    if type(spec) is not MCPToolBinding:
                        raise MCPConfigurationError("tool binding spec must be an MCPToolBinding")
                    clean_bindings[spec.tool_name] = spec
            else:
                raise MCPConfigurationError("tool_bindings must be a mapping or sequence of MCPToolBinding")

        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
                raise MCPConfigurationError("timeout must be a positive number")
            timeout = float(timeout)

        if connect_timeout is None:
            connect_timeout = timeout if timeout is not None else 10.0
        elif isinstance(connect_timeout, bool) or not isinstance(connect_timeout, (int, float)) or connect_timeout <= 0:
            raise MCPConfigurationError("connect_timeout must be a positive number")
        else:
            connect_timeout = float(connect_timeout)

        if call_timeout is None:
            call_timeout = timeout if timeout is not None else 30.0
        elif isinstance(call_timeout, bool) or not isinstance(call_timeout, (int, float)) or call_timeout <= 0:
            raise MCPConfigurationError("call_timeout must be a positive number")
        else:
            call_timeout = float(call_timeout)

        if list_timeout is None:
            list_timeout = timeout if timeout is not None else 10.0
        elif isinstance(list_timeout, bool) or not isinstance(list_timeout, (int, float)) or list_timeout <= 0:
            raise MCPConfigurationError("list_timeout must be a positive number")
        else:
            list_timeout = float(list_timeout)

        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_command", clean_command)
        object.__setattr__(self, "_args", tuple(clean_args))
        object.__setattr__(self, "_url", clean_url)
        object.__setattr__(self, "_headers", MappingProxyType(clean_headers))
        object.__setattr__(self, "_transport_type", transport_type)
        object.__setattr__(self, "_env", MappingProxyType(clean_env))
        object.__setattr__(self, "_cwd", clean_cwd)
        object.__setattr__(self, "_tool_bindings", MappingProxyType(clean_bindings))
        object.__setattr__(self, "_default_discovery", default_discovery)
        object.__setattr__(self, "_redact_keys", redact_keys or DEFAULT_SENSITIVE_KEYS)
        object.__setattr__(self, "_connect_timeout", connect_timeout)
        object.__setattr__(self, "_call_timeout", call_timeout)
        object.__setattr__(self, "_list_timeout", list_timeout)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("MCPIntegrationConfig is immutable")
        object.__setattr__(self, name, value)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def connect_timeout(self) -> float:
        return self._connect_timeout

    @property
    def call_timeout(self) -> float:
        return self._call_timeout

    @property
    def list_timeout(self) -> float:
        return self._list_timeout

    @property
    def command(self) -> str | None:
        return self._command

    @property
    def args(self) -> tuple[str, ...]:
        return self._args

    @property
    def url(self) -> str | None:
        return self._url

    @property
    def headers(self) -> MappingProxyType[str, str]:
        return self._headers

    @property
    def transport_type(self) -> MCPTransportType:
        return self._transport_type

    @property
    def env(self) -> MappingProxyType[str, str]:
        return self._env

    @property
    def cwd(self) -> str | None:
        return self._cwd

    @property
    def tool_bindings(self) -> MappingProxyType[str, MCPToolBinding]:
        return self._tool_bindings

    @property
    def default_discovery(self) -> DiscoveryMode:
        return self._default_discovery

    @property
    def redact_keys(self) -> Collection[str]:
        return self._redact_keys

    def __repr__(self) -> str:
        if self._transport_type == MCPTransportType.STDIO:
            redacted_env = redact_sensitive_data(dict(self._env), self._redact_keys)
            return (
                f"MCPIntegrationConfig(integration_id={self._integration_id!r}, "
                f"command={self._command!r}, transport={self._transport_type.value!r}, "
                f"env={redacted_env!r})"
            )
        else:
            redacted_headers = redact_sensitive_data(dict(self._headers), self._redact_keys)
            return (
                f"MCPIntegrationConfig(integration_id={self._integration_id!r}, "
                f"url={self._url!r}, transport={self._transport_type.value!r}, "
                f"headers={redacted_headers!r})"
            )
