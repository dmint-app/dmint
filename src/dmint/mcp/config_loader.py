"""Configuration loader for Dmint MCP protection configuration artifacts (mcp_protection.json)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any

from dmint.approvals import PolicyProvenance
from dmint.models import TrustedContext, validate_text
from dmint.policy import Policy, policy_digest
from .config import DiscoveryMode, DisclosureMode, MCPIntegrationConfig, MCPToolBinding, MCPTransportType
from .errors import MCPConfigurationError

MAX_MCP_INTEGRATIONS = 50
INTEGRATION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
SECRET_SUBSTRINGS = ("bearer ", "sk-", "api_key=", "token=", "password=")


def _assert_no_secrets(data: Any) -> None:
    """Scan configuration recursively to ensure no embedded secrets or credentials exist."""
    if isinstance(data, dict):
        for k, v in data.items():
            if any(s in k.lower() for s in ("token", "secret", "password", "key", "credential")):
                if isinstance(v, str) and v and not v.startswith("[") and not v.startswith("$"):
                    # Only raise if value looks like an actual hardcoded secret rather than a placeholder/env var
                    if any(pat in v.lower() for pat in SECRET_SUBSTRINGS) or len(v) > 20:
                        raise MCPConfigurationError(
                            f"Security violation: field '{k}' appears to contain a hardcoded credential. "
                            f"Protection configuration files must never contain secrets."
                        )
            _assert_no_secrets(v)
    elif isinstance(data, list):
        for item in data:
            _assert_no_secrets(item)
    elif isinstance(data, str):
        if any(pat in data.lower() for pat in SECRET_SUBSTRINGS):
            raise MCPConfigurationError(
                "Security violation: protection configuration appears to contain an embedded credential."
            )


@dataclass(frozen=True)
class MCPGatewayConfig:
    """Immutable runtime configuration for the Dmint MCP Gateway."""

    policy: Policy
    policy_provenance: PolicyProvenance
    integrations: tuple[MCPIntegrationConfig, ...]
    policy_file: str | None = None
    approval_store_path: str | None = None
    approval_ttl: timedelta | None = None
    disclosure_mode: DisclosureMode = DisclosureMode.DOG
    agent_id: str = "mcp-agent"
    context: TrustedContext = TrustedContext({})
    server_name: str = "dmint-mcp-gateway"

    def get_integration(self, integration_id: str) -> MCPIntegrationConfig | None:
        """Lookup an integration configuration by ID."""
        for integ in self.integrations:
            if integ.integration_id == integration_id:
                return integ
        return None


def parse_protection_config(
    data: dict[str, Any],
    *,
    base_dir: Path | None = None,
) -> MCPGatewayConfig:
    """Parse and strictly validate a protection configuration dictionary.

    Args:
        data: dictionary loaded from mcp_protection.json.
        base_dir: directory used to resolve relative file paths (e.g. policy_file).

    Returns:
        Immutable, typed MCPGatewayConfig.

    Raises:
        MCPConfigurationError: on any validation failure.
    """
    if not isinstance(data, dict):
        raise MCPConfigurationError("protection config must be a JSON dictionary")

    _assert_no_secrets(data)

    # 1. Validate & load Policy
    policy_file = data.get("policy_file")
    raw_policy = data.get("policy")
    policy: Policy | None = None

    if policy_file is not None and raw_policy is not None:
        raise MCPConfigurationError("cannot specify both 'policy_file' and 'policy'")

    if policy_file is not None:
        if not isinstance(policy_file, str) or not policy_file.strip():
            raise MCPConfigurationError("policy_file must be a non-empty string")
        policy_path = Path(policy_file)
        if not policy_path.is_absolute():
            if base_dir is None:
                raise MCPConfigurationError("base_dir is required to resolve relative policy_file")
            policy_path = (base_dir / policy_path).resolve()

        if not policy_path.exists():
            raise MCPConfigurationError(f"policy file '{policy_path}' does not exist")

        try:
            policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
            policy = Policy.from_mapping(policy_data)
        except Exception as exc:
            raise MCPConfigurationError(f"failed to load policy from '{policy_path}': {exc}") from exc
    elif raw_policy is not None:
        if not isinstance(raw_policy, dict):
            raise MCPConfigurationError("embedded 'policy' must be a dictionary")
        try:
            policy = Policy.from_mapping(raw_policy)
        except Exception as exc:
            raise MCPConfigurationError(f"failed to parse embedded policy: {exc}") from exc
    else:
        raise MCPConfigurationError("mcp_protection config missing valid 'policy_file' or 'policy'")

    digest = policy_digest(policy)
    provenance = PolicyProvenance("v1", digest, datetime.now(timezone.utc))

    # 2. Validate Integrations
    raw_integrations = data.get("integrations")
    if not isinstance(raw_integrations, list) or not raw_integrations:
        raise MCPConfigurationError("mcp_protection config must contain a non-empty 'integrations' list")
    if len(raw_integrations) > MAX_MCP_INTEGRATIONS:
        raise MCPConfigurationError(
            f"number of integrations ({len(raw_integrations)}) exceeds maximum limit of {MAX_MCP_INTEGRATIONS}"
        )

    seen_ids: set[str] = set()
    parsed_integrations: list[MCPIntegrationConfig] = []

    for idx, integ_raw in enumerate(raw_integrations):
        if not isinstance(integ_raw, dict):
            raise MCPConfigurationError(f"integration at index {idx} must be a dictionary")

        integ_id = integ_raw.get("integration_id")
        if not integ_id or not isinstance(integ_id, str) or not integ_id.strip():
            raise MCPConfigurationError(f"integration at index {idx} missing valid 'integration_id'")
        integ_id = integ_id.strip()

        if not INTEGRATION_ID_PATTERN.match(integ_id):
            raise MCPConfigurationError(
                f"invalid integration_id '{integ_id}'. Must contain only alphanumeric characters, dashes, or underscores."
            )

        if integ_id in seen_ids:
            raise MCPConfigurationError(f"duplicate integration ID '{integ_id}' found in protection configuration")
        seen_ids.add(integ_id)

        transport_str = integ_raw.get("transport", "stdio")
        if not isinstance(transport_str, str):
            raise MCPConfigurationError(f"transport for integration '{integ_id}' must be a string")
        transport_str = transport_str.lower().strip()

        try:
            transport_type = MCPTransportType.from_value(transport_str)
        except ValueError as exc:
            raise MCPConfigurationError(
                f"unsupported transport '{transport_str}' for integration '{integ_id}'. "
                f"Currently supported transports: '{MCPTransportType.STDIO.value}', '{MCPTransportType.STREAMABLE_HTTP.value}'."
            ) from exc

        conn = integ_raw.get("connection", {})
        if not isinstance(conn, dict):
            raise MCPConfigurationError(f"connection for integration '{integ_id}' must be a dictionary")

        cmd: str | None = None
        args: list[str] = []
        env: dict[str, str] | None = None
        cwd: str | None = None
        url: str | None = None
        headers: dict[str, str] | None = None

        if transport_type == MCPTransportType.STDIO:
            cmd = conn.get("command")
            if not cmd or not isinstance(cmd, str) or not cmd.strip():
                raise MCPConfigurationError(f"connection for integration '{integ_id}' missing valid 'command'")

            raw_args = conn.get("args", [])
            if not isinstance(raw_args, (list, tuple)):
                raise MCPConfigurationError(f"connection.args for integration '{integ_id}' must be a list of strings")
            for arg in raw_args:
                if not isinstance(arg, str):
                    raise MCPConfigurationError(f"connection.args for integration '{integ_id}' must be strings")
                args.append(arg)

            env = conn.get("env")
            if env is not None and not isinstance(env, dict):
                raise MCPConfigurationError(f"connection.env for integration '{integ_id}' must be a dictionary")

            cwd = conn.get("cwd")

            if "url" in conn:
                raise MCPConfigurationError(f"connection.url is not supported for stdio integration '{integ_id}'")
            if "headers" in conn:
                raise MCPConfigurationError(f"connection.headers is not supported for stdio integration '{integ_id}'")

        elif transport_type == MCPTransportType.STREAMABLE_HTTP:
            url = conn.get("url")
            if not url or not isinstance(url, str) or not url.strip():
                raise MCPConfigurationError(
                    f"connection for streamable-http integration '{integ_id}' missing valid 'url'"
                )
            url = url.strip()

            if "command" in conn and conn["command"] not in (None, "", "http-remote"):
                raise MCPConfigurationError(
                    f"connection.command is not supported for streamable-http integration '{integ_id}'"
                )
            if "args" in conn and conn["args"]:
                raise MCPConfigurationError(
                    f"connection.args is not supported for streamable-http integration '{integ_id}'"
                )
            if "env" in conn and conn["env"]:
                raise MCPConfigurationError(
                    f"connection.env is not supported for streamable-http integration '{integ_id}'"
                )
            if "cwd" in conn and conn["cwd"]:
                raise MCPConfigurationError(
                    f"connection.cwd is not supported for streamable-http integration '{integ_id}'"
                )

            raw_headers = conn.get("headers")
            if raw_headers is not None:
                if not isinstance(raw_headers, dict):
                    raise MCPConfigurationError(f"connection.headers for integration '{integ_id}' must be a dictionary")
                headers = {}
                for hk, hv in raw_headers.items():
                    if not isinstance(hk, str) or not isinstance(hv, str):
                        raise MCPConfigurationError(
                            f"connection.headers for integration '{integ_id}' must have string keys and values"
                        )
                    headers[hk] = hv

        # Timeouts: check connection first, then integration level, then top-level
        timeout = (
            conn.get("timeout")
            if "timeout" in conn
            else integ_raw.get("timeout")
            if "timeout" in integ_raw
            else data.get("timeout")
        )
        connect_timeout = conn.get("connect_timeout") if "connect_timeout" in conn else integ_raw.get("connect_timeout")
        call_timeout = conn.get("call_timeout") if "call_timeout" in conn else integ_raw.get("call_timeout")
        list_timeout = conn.get("list_timeout") if "list_timeout" in conn else integ_raw.get("list_timeout")

        for t_name, t_val in [
            ("timeout", timeout),
            ("connect_timeout", connect_timeout),
            ("call_timeout", call_timeout),
            ("list_timeout", list_timeout),
        ]:
            if t_val is not None:
                if isinstance(t_val, bool) or not isinstance(t_val, (int, float)) or t_val <= 0:
                    raise MCPConfigurationError(f"{t_name} must be a positive number")

        # Parse tool bindings
        raw_bindings = integ_raw.get("tool_bindings")
        if not isinstance(raw_bindings, (dict, list)) or not raw_bindings:
            raise MCPConfigurationError(f"integration '{integ_id}' must define at least one tool binding")
        tool_bindings_list: list[MCPToolBinding] = []

        if isinstance(raw_bindings, dict):
            for tname, spec in raw_bindings.items():
                if not isinstance(tname, str) or not tname.strip():
                    raise MCPConfigurationError(f"tool_name key must be a string in integration '{integ_id}'")
                if isinstance(spec, dict):
                    cap = spec.get("capability")
                    if not cap or not isinstance(cap, str) or not cap.strip():
                        raise MCPConfigurationError(
                            f"tool binding for '{tname}' in integration '{integ_id}' must specify a capability"
                        )
                    tool_bindings_list.append(
                        MCPToolBinding(
                            tool_name=spec.get("tool_name", tname),
                            capability=cap,
                            resource_key=spec.get("resource_key"),
                            discovery=spec.get("discovery", DiscoveryMode.EXPOSED),
                        )
                    )
                elif isinstance(spec, str):
                    if not spec.strip():
                        raise MCPConfigurationError(f"capability must be non-empty string in integration '{integ_id}'")
                    tool_bindings_list.append(MCPToolBinding(tool_name=tname, capability=spec))
                else:
                    raise MCPConfigurationError(
                        f"invalid tool binding spec for tool '{tname}' in integration '{integ_id}'"
                    )
        elif isinstance(raw_bindings, list):
            for spec in raw_bindings:
                if isinstance(spec, dict) and "tool_name" in spec and "capability" in spec:
                    cap = spec["capability"]
                    if not isinstance(cap, str) or not cap.strip():
                        raise MCPConfigurationError(f"capability must be non-empty string in integration '{integ_id}'")
                    tool_bindings_list.append(
                        MCPToolBinding(
                            tool_name=spec["tool_name"],
                            capability=cap,
                            resource_key=spec.get("resource_key"),
                            discovery=spec.get("discovery", DiscoveryMode.EXPOSED),
                        )
                    )
                else:
                    raise MCPConfigurationError(f"invalid tool binding in list for integration '{integ_id}'")

        seen_tool_names: set[str] = set()
        for binding in tool_bindings_list:
            if binding.tool_name in seen_tool_names:
                raise MCPConfigurationError(f"duplicate tool name '{binding.tool_name}' in integration '{integ_id}'")
            seen_tool_names.add(binding.tool_name)

        integ_cfg = MCPIntegrationConfig(
            integration_id=integ_id,
            command=cmd,
            args=list(args),
            url=url,
            headers=headers,
            transport_type=transport_type,
            env=env,
            cwd=cwd,
            tool_bindings=tool_bindings_list,
            default_discovery=DiscoveryMode.HIDDEN,
            timeout=timeout,
            connect_timeout=connect_timeout,
            call_timeout=call_timeout,
            list_timeout=list_timeout,
        )
        parsed_integrations.append(integ_cfg)

    # 3. Top-level Gateway settings
    approval_db = data.get("approval_db") or data.get("approval_store")
    if approval_db is not None:
        if not isinstance(approval_db, str) or not approval_db.strip():
            raise MCPConfigurationError("approval_db must be a non-empty string")
        db_path = Path(approval_db)
        if not db_path.is_absolute() and base_dir is not None:
            db_path = (base_dir / db_path).resolve()
        approval_db = str(db_path)

    raw_ttl = data.get("approval_ttl")
    approval_ttl: timedelta | None = None
    if raw_ttl is not None:
        if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, (int, float)) or raw_ttl <= 0:
            raise MCPConfigurationError("approval_ttl must be a positive number of seconds")
        approval_ttl = timedelta(seconds=float(raw_ttl))

    disclosure_mode = data.get("disclosure_mode", DisclosureMode.DOG)
    if isinstance(disclosure_mode, str):
        try:
            disclosure_mode = DisclosureMode(disclosure_mode.lower())
        except ValueError as exc:
            raise MCPConfigurationError(f"invalid disclosure_mode '{disclosure_mode}'") from exc
    elif not isinstance(disclosure_mode, DisclosureMode):
        raise MCPConfigurationError("invalid disclosure_mode")

    agent_id = data.get("agent_id", "mcp-agent")
    try:
        agent_id = validate_text(agent_id, "agent_id")
    except Exception as exc:
        raise MCPConfigurationError(f"invalid agent_id: {exc}") from exc

    raw_context = data.get("context", {})
    if not isinstance(raw_context, dict):
        raise MCPConfigurationError("context must be a dictionary")
    trusted_context = TrustedContext(raw_context)

    server_name = data.get("server_name", "dmint-mcp-gateway")

    return MCPGatewayConfig(
        policy=policy,
        policy_file=str(policy_file) if policy_file else None,
        policy_provenance=provenance,
        integrations=tuple(parsed_integrations),
        approval_store_path=approval_db,
        approval_ttl=approval_ttl,
        disclosure_mode=disclosure_mode,
        agent_id=agent_id,
        context=trusted_context,
        server_name=server_name,
    )


def load_protection_config(config_path: str | Path) -> MCPGatewayConfig:
    """Load, parse, and validate an mcp_protection.json file from disk.

    Args:
        config_path: path to the mcp_protection.json file.

    Returns:
        Immutable, typed MCPGatewayConfig.

    Raises:
        MCPConfigurationError: on missing file, malformed JSON, or validation errors.
    """
    path = Path(config_path).resolve()
    if not path.exists():
        raise MCPConfigurationError(f"configuration file '{path}' does not exist")
    if not path.is_file():
        raise MCPConfigurationError(f"configuration path '{path}' is not a file")

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise MCPConfigurationError(f"failed to read configuration file '{path}': {exc}") from exc

    try:
        data = json.loads(content)
    except Exception as exc:
        raise MCPConfigurationError(f"malformed JSON in configuration file '{path}': {exc}") from exc

    return parse_protection_config(data, base_dir=path.parent)
