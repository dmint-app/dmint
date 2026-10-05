"""Wizard for dmint create-mcp-policy (specialized for external MCP servers)."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dmint.policy import Policy, PolicyError
from dmint.cli.api import OpenAICompatClient, resolve_api_key
from dmint.cli.errors import (
    APIError,
    CLIError,
    InputFileError,
    JSONExtractionError,
    OutputWriteError,
    PolicyValidationError,
)
from dmint.cli.io_utils import atomic_write_json, atomic_write_policy_json, load_system_prompt
from dmint.cli.limits import (
    MAX_MCP_INTEGRATIONS,
    MAX_POLICY_FILE_SIZE_BYTES,
    MAX_RECURSION_DEPTH,
    MAX_TOTAL_DISCOVERED_TOOLS,
    MAX_TOTAL_OPERATION_TIMEOUT_SECONDS,
)
from dmint.cli.mcp_auth import discover_mcp_auth_requirements
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport, discover_mcp_tools_generic
from dmint.cli.mcp_oauth import perform_oauth_flow
from dmint.cli.verify_policy import verify_policy_file


SENSITIVE_SECRET_KEYS = {
    "access_token",
    "refresh_token",
    "bearer_token",
    "client_secret",
    "authorization_code",
    "id_token",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "credentials",
    "auth",
    "authorization",
    "passwd",
    "ssn",
}


def _assert_no_secrets_in_dict(obj: Any, path: str = "config", depth: int = 0) -> None:
    """Recursively ensure no plaintext tokens or secrets exist in configuration dict."""
    if depth > MAX_RECURSION_DEPTH:
        raise CLIError(
            f"Security violation: Object structure exceeds maximum allowed recursion depth "
            f"of {MAX_RECURSION_DEPTH} at {path}."
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in SENSITIVE_SECRET_KEYS:
                raise CLIError(
                    f"Security violation: Plaintext secret field '{k}' found at {path}. Credentials must be stored in CredentialStore, not config artifacts."
                )
            if (
                isinstance(v, str)
                and len(v) > 4
                and any(pat in v.lower() for pat in ("bearer ", "sk-", "api_key=", "token=", "password="))
            ):
                raise CLIError(
                    f"Security violation: Field '{k}' at {path} appears to contain an embedded credential. Secrets must never be stored in config artifacts."
                )
            _assert_no_secrets_in_dict(v, f"{path}.{k}", depth=depth + 1)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _assert_no_secrets_in_dict(item, f"{path}[{idx}]", depth=depth + 1)


# Keys that Policy.from_mapping() requires in every rule.
_REQUIRED_RULE_FIELDS = frozenset({"effect", "tool", "action"})
# Valid effect values accepted by Policy.from_mapping().
_VALID_EFFECTS = frozenset({"allow", "deny", "approval_required"})


def _validate_rule_completeness(rules: list[Any]) -> None:
    """Deterministic gate: every generated rule must have required fields before Policy.from_mapping().

    Enforces Phase-7 requirements:
    - Required fields: effect, tool, action.
    - effect must be one of the accepted Dmint values (not truthy approximations).
    - No authorization delegation to LLM: if any field is missing, reject entirely.
    - resource is present and is a string when supplied (None is disallowed by policy engine).
    """
    for idx, r in enumerate(rules):
        if not isinstance(r, dict):
            raise PolicyError(f"rule at index {idx} must be a mapping, got {type(r).__name__}.")
        missing = _REQUIRED_RULE_FIELDS - r.keys()
        if missing:
            raise PolicyError(
                f"rule at index {idx} is incomplete: missing required fields {sorted(missing)}. "
                f"Every generated rule must contain effect, tool, and action."
            )
        effect = r.get("effect")
        if effect not in _VALID_EFFECTS:
            raise PolicyError(
                f"rule at index {idx} has invalid effect '{effect}'. Must be one of: {sorted(_VALID_EFFECTS)}."
            )
        if "resource" in r and r["resource"] is None:
            raise PolicyError(
                f"rule at index {idx} has 'resource': null which is disallowed. "
                f'Use "resource": "*" for any resource, or omit \'resource\' entirely.'
            )


def _assert_no_secrets_in_policy(policy_dict: dict[str, Any]) -> None:
    """Ensure no plaintext secrets appear inside the policy rules dict (Req 13)."""
    rules = policy_dict.get("rules", [])
    for idx, r in enumerate(rules):
        if isinstance(r, dict):
            for k, v in r.items():
                if k.lower() in SENSITIVE_SECRET_KEYS:
                    raise CLIError(
                        f"Security violation: secret field '{k}' found in rule at index {idx}. "
                        f"Policy files must never contain credentials."
                    )
                if (
                    isinstance(v, str)
                    and len(v) > 4
                    and any(pat in v.lower() for pat in ("bearer ", "sk-", "api_key=", "token=", "password="))
                ):
                    raise CLIError(
                        f"Security violation: rule at index {idx} field '{k}' appears to contain "
                        f"an embedded credential. Policy files must never contain secrets."
                    )


def _sort_tools_deterministically(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return tools list sorted by name, deterministically."""
    return sorted(tools, key=lambda t: t.get("name", ""))


def _sort_integrations_deterministically(integrations: list[Any]) -> list[Any]:
    """Return integrations sorted by integration_id, deterministically."""
    return sorted(integrations, key=lambda i: i.integration_id)


def _prompt_select(message: str, choices: list[str], default: str) -> str:
    try:
        import questionary

        res = questionary.select(message, choices=choices, default=default).ask()
        if res is not None:
            return str(res)
    except Exception:
        pass
    print(f"\n{message}:")
    for idx, c in enumerate(choices, 1):
        print(f"  {idx}) {c}")
    val = input(f"Select [1-{len(choices)}, default: {default}]: ").strip()
    if val.isdigit() and 1 <= int(val) <= len(choices):
        return choices[int(val) - 1]
    return val or default


def _prompt_password(message: str) -> str:
    try:
        import questionary

        res = questionary.password(message).ask()
        if res is not None:
            return str(res)
    except Exception:
        pass
    return getpass.getpass(f"{message} ").strip()


def _prompt_text(message: str, default: str = "") -> str:
    try:
        import questionary

        res = questionary.text(message, default=default).ask()
        if res is not None:
            return str(res)
    except Exception:
        pass
    val = input(f"{message} [default: {default}]: ").strip()
    return val or default


def validate_mcp_protection_config(config: dict[str, Any]) -> None:
    """Validate mcp_protection.json dictionary structure against dmint_mcp parser if available."""
    if not isinstance(config, dict):
        raise CLIError("mcp_protection config must be a JSON dictionary.")

    policy_file = config.get("policy_file")
    if not policy_file or not isinstance(policy_file, str):
        raise CLIError("mcp_protection config missing valid 'policy_file'.")

    integrations = config.get("integrations")
    if not isinstance(integrations, list) or not integrations:
        raise CLIError("mcp_protection config must contain a non-empty 'integrations' list.")
    if len(integrations) > MAX_MCP_INTEGRATIONS:
        raise CLIError(
            f"Resource exhaustion error: number of integrations in protection config ({len(integrations)}) "
            f"exceeds maximum allowed limit of {MAX_MCP_INTEGRATIONS}."
        )

    _assert_no_secrets_in_dict(config)

    seen_integration_ids: set[str] = set()
    for idx, integ_dict in enumerate(integrations):
        if not isinstance(integ_dict, dict):
            raise CLIError(f"integration at index {idx} must be a dictionary.")

        integ_id = integ_dict.get("integration_id", "")
        if not integ_id or not isinstance(integ_id, str):
            raise CLIError(f"integration at index {idx} missing valid 'integration_id'.")
        if integ_id in seen_integration_ids:
            raise CLIError(f"Duplicate integration ID '{integ_id}' found in protection configuration.")
        seen_integration_ids.add(integ_id)

        transport_str = integ_dict.get("transport", "stdio")
        conn = integ_dict.get("connection", {})

        try:
            from dmint.mcp import MCPIntegrationConfig, MCPToolBinding
        except ImportError:
            # dmint_mcp not installed — do lightweight transport validation
            known_transports = {"stdio", "streamable-http"}
            if transport_str not in known_transports:
                raise CLIError(
                    f"dmint-mcp configuration validation failed for integration '{integ_id}': "
                    f"unsupported transport type '{transport_str}'. Valid types: {sorted(known_transports)}."
                )
            continue

        raw_bindings = integ_dict.get("tool_bindings")
        tool_bindings_dict = {}
        if isinstance(raw_bindings, list):
            for b in raw_bindings:
                if isinstance(b, dict) and "tool_name" in b and "capability" in b:
                    tool_bindings_dict[b["tool_name"]] = MCPToolBinding(
                        tool_name=b["tool_name"],
                        capability=b["capability"],
                        discovery=b.get("discovery", "exposed"),
                    )
        elif isinstance(raw_bindings, dict):
            for tname, b in raw_bindings.items():
                if isinstance(b, dict):
                    tool_bindings_dict[tname] = MCPToolBinding(
                        tool_name=str(b.get("tool_name") or tname),
                        capability=str(b.get("capability") or f"mcp.{integ_id}.{tname}"),
                        discovery=str(b.get("discovery") or "exposed"),
                    )

        cmd = conn.get("command", "") or "http-remote"
        args = conn.get("args", [])

        try:
            MCPIntegrationConfig(
                integration_id=integ_id,
                command=cmd,
                args=args if isinstance(args, list) else [],
                transport_type=transport_str,
                tool_bindings=tool_bindings_dict,
            )
        except Exception as exc:
            raise CLIError(f"dmint-mcp configuration validation failed for integration '{integ_id}': {exc}") from exc


def validate_policy_against_discovered_capabilities(
    policy_mapping: dict[str, Any],
    all_discovered_tools: list[dict[str, Any]],
) -> None:
    """Validate that policy rules strictly reference discovered capabilities.

    Enforces exact capability identity (Phase 6):
    1. Every discovered tool has a canonical identity: mcp.<integration_id>.<tool_name>.
    2. Prohibits partial integration IDs (no splitting on '-' or '_').
    3. Prohibits fuzzy, prefix, or substring capability matching.
    4. Prohibits ambiguous bare tool names when multiple integrations expose the same tool name.
    5. Rejects rules specifying unknown tools, unknown actions, or mismatched integrations.
    """
    if not all_discovered_tools:
        return

    if len(all_discovered_tools) > MAX_TOTAL_DISCOVERED_TOOLS:
        raise CLIError(
            f"Resource exhaustion error: total discovered tools ({len(all_discovered_tools)}) "
            f"exceeds maximum allowed limit of {MAX_TOTAL_DISCOVERED_TOOLS}."
        )

    tool_name_counts: dict[str, int] = {}
    discovered_pairs: set[tuple[str, str]] = set()  # (integration_id, tool_name)
    discovered_capabilities: set[str] = set()  # canonical capability strings
    discovered_integrations: set[str] = set()

    for t in all_discovered_tools:
        name = (t.get("name") or "").strip()
        integ = (t.get("integration_id") or "").strip()
        cap = (t.get("capability") or "").strip()
        if not cap and integ and name:
            cap = f"mcp.{integ}.{name}"

        if name:
            tool_name_counts[name] = tool_name_counts.get(name, 0) + 1
        if integ and name:
            discovered_pairs.add((integ, name))
        if cap:
            discovered_capabilities.add(cap)
        if integ:
            discovered_integrations.add(integ)

    rules = policy_mapping.get("rules", [])
    for idx, r in enumerate(rules):
        if not isinstance(r, dict):
            continue

        rule_tool = (r.get("tool") or "").strip()
        rule_action = (r.get("action") or "").strip()

        # Wildcard rule matches all tools
        if rule_tool == "*":
            continue

        # Form 1: tool is "mcp" and action is "<integration_id>.<tool_name>"
        if rule_tool == "mcp":
            if rule_action == "*":
                continue
            if "." in rule_action:
                integ_part, _, tool_part = rule_action.partition(".")
                if (
                    integ_part,
                    tool_part,
                ) not in discovered_pairs and f"mcp.{rule_action}" not in discovered_capabilities:
                    raise PolicyError(
                        f"rule at index {idx} specifies tool 'mcp.{rule_action}' which was not in discovered capabilities."
                    )
            else:
                raise PolicyError(
                    f"rule at index {idx} specifies MCP action '{rule_action}' without integration namespace."
                )
            continue

        # Form 2: tool is canonical capability string "mcp.<integration_id>.<tool_name>"
        if rule_tool.startswith("mcp."):
            if rule_tool not in discovered_capabilities:
                raise PolicyError(
                    f"rule at index {idx} specifies tool '{rule_tool}' which was not in discovered capabilities."
                )
            continue

        # Form 3: tool is exact integration ID
        if rule_tool in discovered_integrations:
            if rule_action != "*" and (rule_tool, rule_action) not in discovered_pairs:
                raise PolicyError(
                    f"rule at index {idx} specifies unknown action '{rule_action}' for integration '{rule_tool}'."
                )
            continue

        # Form 4: tool is bare tool name
        if rule_tool in tool_name_counts:
            if tool_name_counts[rule_tool] > 1:
                matching_integs = sorted([i for (i, tname) in discovered_pairs if tname == rule_tool])
                raise PolicyError(
                    f"rule at index {idx} specifies ambiguous tool '{rule_tool}' discovered across multiple integrations {matching_integs}. "
                    f"Integration identity must remain attached."
                )
            # For single tool with tool == name: verify action is valid
            matching_pairs = [p for p in discovered_pairs if p[1] == rule_tool]
            if (
                matching_pairs
                and rule_action != "*"
                and rule_action != rule_tool
                and rule_action != matching_pairs[0][1]
            ):
                raise PolicyError(
                    f"rule at index {idx} specifies unknown action '{rule_action}' for tool '{rule_tool}'."
                )
            continue

        # If none of the exact forms matched, fail closed!
        raise PolicyError(f"rule at index {idx} specifies tool '{rule_tool}' which was not in discovered capabilities.")


def run_create_mcp_policy_wizard(
    *,
    command: str | None = None,
    args: list[str] | None = None,
    integration_id: str | None = None,
    transport: str = "stdio",
    url: str | None = None,
    access_md_file: str | Path = "access.md",
    output_json_file: str | Path = "policy.json",
    config_output_file: str | Path = "mcp_protection.json",
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    non_interactive: bool = False,
    auto_confirm: bool = False,
    timeout: float = 60.0,
) -> tuple[Policy, dict[str, Any]]:
    """Wizard to discover tools from one or more existing MCP servers, create policy, and output MCP protection config."""
    md_path = Path(access_md_file).resolve()
    json_path = Path(output_json_file).resolve()
    config_path = Path(config_output_file).resolve()

    start_time = time.monotonic()
    is_tty = sys.stdin.isatty() and not non_interactive

    print("==================================================")
    print("      Dmint External MCP Policy Creation Wizard   ")
    print("==================================================")

    integrations: list[MCPIntegration] = []

    # 1. Initial MCP Integration setup (from parameters or interactive prompt)
    if url or (transport and transport.lower() not in ("stdio", "")):
        # Remote URL transport requested
        integ = MCPIntegration(
            integration_id=integration_id or "remote-mcp",
            transport=transport if transport and transport.lower() != "stdio" else MCPTransport.STREAMABLE_HTTP,
            connection={"url": url or "https://example.com/mcp"},
        )
        integ.validate_transport()  # Fails closed with explicit unsupported error
        integrations.append(integ)
    else:
        mcp_cmd = command
        mcp_args = args or []

        if is_tty and not mcp_cmd:
            print("\nAdd MCP Server\n")
            print("Connection type:")
            print("  1. Local process / stdio")
            print("  2. Remote MCP server (URL)\n")
            conn_type = input("Select [1/2, default 1]: ").strip()

            if conn_type == "2":
                r_url = input("Enter Remote MCP URL (e.g. https://example.com/mcp): ").strip()
                r_id = input("Enter Integration ID [default: remote-mcp]: ").strip() or "remote-mcp"
                integ = MCPIntegration(
                    integration_id=r_id,
                    transport=MCPTransport.STREAMABLE_HTTP,
                    connection={"url": r_url},
                )
                integ.validate_transport()  # Fails closed explicitly
                integrations.append(integ)
            else:
                mcp_cmd = input("Command (e.g. npx, mcp-server-postgres): ").strip() or "npx"
                args_str = input("Arguments (e.g. -y @modelcontextprotocol/server-postgres ...): ").strip()
                if args_str:
                    mcp_args = args_str.split()
                r_id = (
                    input(f"Integration ID [default: {mcp_cmd.replace('/', '-')[:20]}]: ").strip()
                    or mcp_cmd.replace("/", "-")[:20]
                )
                integrations.append(
                    MCPIntegration(
                        integration_id=r_id,
                        transport=MCPTransport.STDIO,
                        connection={"command": mcp_cmd, "args": mcp_args},
                    )
                )
        else:
            mcp_cmd = mcp_cmd or "npx"
            r_id = integration_id or f"mcp-{mcp_cmd.replace('/', '-').replace(':', '-')}"
            integrations.append(
                MCPIntegration(
                    integration_id=r_id,
                    transport=MCPTransport.STDIO,
                    connection={"command": mcp_cmd, "args": mcp_args},
                )
            )

    # Support adding additional MCP servers interactively
    if is_tty:
        while True:
            add_more = input("\nAdd another MCP server? [y/N]: ").strip().lower()
            if add_more not in ("y", "yes"):
                break
            print("\nAdd Additional MCP Server")
            print("Connection type:")
            print("  1. Local process / stdio")
            print("  2. Remote MCP server (URL)\n")
            conn_type = input("Select [1/2, default 1]: ").strip()
            if conn_type == "2":
                r_url = input("Enter Remote MCP URL: ").strip()
                r_id = input("Enter Integration ID: ").strip() or f"remote-mcp-{len(integrations) + 1}"
                integ = MCPIntegration(
                    integration_id=r_id,
                    transport=MCPTransport.STREAMABLE_HTTP,
                    connection={"url": r_url},
                )
                integ.validate_transport()
                integrations.append(integ)
            else:
                next_cmd = input("Command: ").strip() or "npx"
                next_args = input("Arguments: ").strip().split()
                default_id = f"{next_cmd.replace('/', '-')[:15]}-{len(integrations) + 1}"
                next_id = input(f"Integration ID [default: {default_id}]: ").strip() or default_id
                integrations.append(
                    MCPIntegration(
                        integration_id=next_id,
                        transport=MCPTransport.STDIO,
                        connection={"command": next_cmd, "args": next_args},
                    )
                )

    # Validate unique integration IDs across all requested MCP servers
    if len(integrations) > MAX_MCP_INTEGRATIONS:
        raise CLIError(
            f"Resource exhaustion error: number of MCP integrations ({len(integrations)}) "
            f"exceeds maximum allowed limit of {MAX_MCP_INTEGRATIONS}."
        )

    seen_ids: set[str] = set()
    for integ in integrations:
        if integ.integration_id in seen_ids:
            raise CLIError(
                f"Duplicate integration ID '{integ.integration_id}'. Integration IDs must be unique across all MCP servers."
            )
        seen_ids.add(integ.integration_id)

    def _check_op_timeout() -> None:
        if time.monotonic() - start_time > MAX_TOTAL_OPERATION_TIMEOUT_SECONDS:
            raise CLIError(
                f"Resource exhaustion error: total wizard operation timeout exceeded "
                f"maximum limit of {MAX_TOTAL_OPERATION_TIMEOUT_SECONDS}s."
            )

    # 2. Perform authentication check & tool discovery for each MCP server
    all_discovered_tools: list[dict[str, Any]] = []
    for integ in integrations:
        _check_op_timeout()
        print(f"\nConnecting to MCP server for integration '{integ.integration_id}'...")
        try:
            # Check authentication requirements for remote HTTP servers
            auth_req = discover_mcp_auth_requirements(integ)
            if auth_req.required:
                print(f"✓ Authentication required for integration '{integ.integration_id}'")
                try:
                    perform_oauth_flow(integ, auth_req)
                    print(f"✓ Authentication completed for integration '{integ.integration_id}'")
                except Exception as exc:
                    raise CLIError(
                        f"Authentication failed for integration '{integ.integration_id}': {exc}\n"
                        f"Recovery: Run 'dmint create-mcp-policy' again to re-authenticate or manage credentials in ~/.config/dmint/credentials.json."
                    ) from exc
            else:
                print(f"✓ Connected to MCP server for integration '{integ.integration_id}'")

            print(f"✓ MCP session initialized for integration '{integ.integration_id}'")
            tools = asyncio.run(discover_mcp_tools_generic(integ))
            # Requirement 10: Sort tools deterministically by name within each integration.
            tools = _sort_tools_deterministically(tools)
            integ.discovered_tools = tools
            print(f"✓ Discovered {len(tools)} tool(s) for '{integ.integration_id}':")
            for t in tools:
                print(f"    - {t['name']}: {t['description']}")
            all_discovered_tools.extend(tools)
            if len(all_discovered_tools) > MAX_TOTAL_DISCOVERED_TOOLS:
                raise CLIError(
                    f"Resource exhaustion error: total discovered tools ({len(all_discovered_tools)}) "
                    f"exceeds maximum allowed limit of {MAX_TOTAL_DISCOVERED_TOOLS}."
                )
        except CLIError:
            raise
        except Exception as exc:
            # Requirement 15: if any server cannot be securely discovered, abort rather than
            # generate an incomplete artifact covering only the successfully discovered servers.
            raise CLIError(
                f"Failed tool discovery for integration '{integ.integration_id}': {exc}. "
                f"Aborting policy generation — all requested MCP servers must be securely discoverable "
                f"before a policy artifact can be produced."
            ) from exc

    # Requirement 14: Missing MCP source must fail closed rather than silently generating a partial policy.
    # If integrations were requested but none yielded tools AND at least one integration exists,
    # this may indicate a discovery failure that was swallowed. Warn explicitly.
    if integrations and not all_discovered_tools:
        raise CLIError(
            f"No tools discovered across {len(integrations)} requested MCP server(s). "
            f"Cannot generate a policy without a complete tool inventory. "
            f"Verify each server is reachable and exposing tools before retrying."
        )

    # Display grouped capability inventory
    print("\n--- Discovered MCP Capabilities ---")
    for integ in integrations:
        print(f"\nIntegration '{integ.integration_id}' ({integ.transport}):")
        if integ.discovered_tools:
            for t in integ.discovered_tools:
                print(f"  - {t['name']}: {t['description']}")
        else:
            print("  (no tools exposed)")

    # 3. Requirements file handling
    if not md_path.exists():
        if is_tty:
            print(f"\nRequirements file '{md_path.name}' not found. Please enter security rules for discovered tools:")
            req_lines = []
            for t in all_discovered_tools:
                ans = (
                    input(
                        f"Effect for '{t['integration_id']}.{t['name']}' (ALLOW / DENY / APPROVAL_REQUIRED) [default ALLOW]: "
                    )
                    .strip()
                    .upper()
                )
                eff = ans if ans in ("ALLOW", "DENY", "APPROVAL_REQUIRED") else "ALLOW"
                req_lines.append(f"- Tool '{t['name']}' under integration '{t['integration_id']}': {eff}")
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text("# MCP Security Requirements\n" + "\n".join(req_lines) + "\n", encoding="utf-8")
        else:
            raise InputFileError(f"requirements file not found: {md_path}")

    st = md_path.stat()
    if st.st_size > MAX_POLICY_FILE_SIZE_BYTES:
        raise CLIError(
            f"Resource exhaustion error: requirements file '{md_path}' size ({st.st_size} bytes) "
            f"exceeds maximum allowed limit of {MAX_POLICY_FILE_SIZE_BYTES} bytes."
        )

    try:
        policy_text = md_path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise InputFileError(f"failed to read requirements file: {exc}") from exc

    if not policy_text:
        raise InputFileError(f"input requirements file is empty: {md_path}")

    # Build prompt context preserving integration identity & tool metadata
    if all_discovered_tools:
        mcp_summary_lines = []
        for integ in integrations:
            mcp_summary_lines.append(f"\nIntegration '{integ.integration_id}' ({integ.transport}):")
            for t in integ.discovered_tools:
                schema_str = json.dumps(t["input_schema"])
                mcp_summary_lines.append(
                    f"  - tool_name: '{t['name']}', capability: 'mcp.{integ.integration_id}.{t['name']}', description: '{t['description']}', schema: {schema_str}"
                )
        mcp_summary = "\n".join(mcp_summary_lines)
        policy_text = (
            f"[DISCOVERED EXTERNAL MCP CAPABILITIES]\n{mcp_summary}\n\n[HUMAN SECURITY REQUIREMENTS]\n{policy_text}"
        )

    # 4. Provider & Model Selection
    selected_provider = (provider or "").lower().strip()
    if is_tty and not selected_provider:
        selected_provider = _prompt_select(
            "Select provider", ["openai", "gemini", "groq", "openrouter", "ollama", "custom"], "openai"
        )
    elif not selected_provider:
        selected_provider = "openai"

    resolved_key = resolve_api_key(api_key, selected_provider)
    if is_tty and not resolved_key and selected_provider != "ollama":
        key_in = _prompt_password(f"Enter API Key for {selected_provider} (leave blank if using env var):")
        if key_in:
            resolved_key = key_in

    client = OpenAICompatClient(
        base_url=base_url,
        api_key=resolved_key,
        model=model,
        provider=selected_provider,
        timeout=timeout,
    )

    selected_model = model
    if is_tty and not selected_model:
        try:
            available_models = client.list_models()
            default_model = (
                "gpt-4o-mini"
                if "gpt-4o-mini" in available_models
                else (available_models[0] if available_models else "gpt-4o-mini")
            )
            selected_model = _prompt_select(
                "Select model",
                available_models if available_models else ["gpt-4o-mini"],
                default_model,
            )
        except Exception as exc:
            print(f"\n[!] Could not list models: {exc}. Please enter model ID manually.")
            selected_model = _prompt_text("Enter model ID", "gpt-4o-mini")
    elif not selected_model:
        selected_model = "gpt-4o-mini"

    client = OpenAICompatClient(
        base_url=base_url,
        api_key=resolved_key,
        model=selected_model,
        provider=selected_provider,
        timeout=timeout,
    )

    # 5. Multi-turn conversation & validation
    system_prompt = load_system_prompt()
    messages: list[Mapping[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": policy_text},
    ]

    shape_retry_attempts = 0
    policy_error_attempts = 0

    while True:
        _check_op_timeout()
        try:
            raw_response = client.chat_completion(messages, temperature=0.0)
        except Exception as exc:
            raise APIError(str(exc)) from exc

        try:
            response_data = json.loads(raw_response)
        except json.JSONDecodeError:
            response_data = None

        if not isinstance(response_data, dict) or "type" not in response_data:
            shape_retry_attempts += 1
            if shape_retry_attempts >= 3:
                raise JSONExtractionError(f"Model failed to match output contract. Raw:\n{raw_response}")
            messages.append({"role": "assistant", "content": raw_response})
            messages.append(
                {
                    "role": "user",
                    "content": "Your last response did not match the required output contract, resend as one of the two exact JSON shapes",
                }
            )
            continue

        msg_type = response_data.get("type")

        if msg_type == "clarification_needed":
            questions = response_data.get("questions") or ["Clarify tool scope?"]
            print("\n--- Clarification Needed from Assistant ---")
            answers = []
            for idx, q in enumerate(questions, start=1):
                print(f"Q{idx}: {q}")
                ans = input("A: ").strip() if is_tty else "Apply least-privilege defaults."
                answers.append(f"Q{idx}: {q}\nA{idx}: {ans}")
            messages.append({"role": "assistant", "content": json.dumps(response_data)})
            messages.append({"role": "user", "content": "\n".join(answers)})
            continue

        elif msg_type == "policy_ready":
            rules = response_data.get("rules")
            if not isinstance(rules, list):
                shape_retry_attempts += 1
                if shape_retry_attempts >= 3:
                    raise JSONExtractionError("policy_ready missing rules list.")
                messages.append({"role": "assistant", "content": raw_response})
                messages.append(
                    {
                        "role": "user",
                        "content": "Your last response did not match the required output contract, resend as one of the two exact JSON shapes",
                    }
                )
                continue

            policy_mapping = {"rules": rules}

            try:
                # Requirement 7: LLM output is untrusted. Deterministic validation is authoritative.
                # Gate 1: completeness — every rule must have required fields (effect, tool, action).
                _validate_rule_completeness(rules)
                # Gate 2: no secrets embedded in LLM-generated policy rules.
                _assert_no_secrets_in_policy(policy_mapping)
                # Gate 3: capability identity — all referenced tools must match discovered inventory.
                validate_policy_against_discovered_capabilities(policy_mapping, all_discovered_tools)
                # Gate 4: Dmint Policy engine validates full schema conformance.
                verified_policy = Policy.from_mapping(policy_mapping)
                print("✓ Policy validated")
            except (PolicyError, CLIError) as exc:
                policy_error_attempts += 1
                if policy_error_attempts >= 4:
                    raise PolicyValidationError(f"Dmint validation failed: {exc}") from exc
                messages.append({"role": "assistant", "content": json.dumps(response_data)})
                messages.append({"role": "user", "content": f"Dmint validation failed: {exc}. Fix it and resend."})
                continue

            print("\n--- Candidate Policy Review ---")
            print(f"Verified {len(verified_policy.rules)} rules:")
            for r in verified_policy.rules:
                res_str = r.resource if isinstance(r.resource, str) else type(r.resource).__name__
                print(f"  [{r.effect.value.upper()}] tool='{r.tool}', action='{r.action}', resource='{res_str}'")

            if not auto_confirm and is_tty:
                confirm = (
                    input("\nAccept candidate policy and write policy.json + mcp_protection.json? [y/N]: ")
                    .strip()
                    .lower()
                )
                if confirm not in ("y", "yes"):
                    raise CLIError("policy creation aborted by user", exit_code=1)

            # Requirement 1 & 12: Serialize via Policy.to_dict() (canonical Dmint schema), not raw LLM dict.
            # This guarantees deterministic, byte-equivalent JSON for identical policies.
            atomic_write_policy_json(json_path, verified_policy)
            verify_policy_file(json_path)

            # Requirement 11: Sort integrations deterministically for reproducible config output.
            sorted_integrations = _sort_integrations_deterministically(integrations)
            protection_config = {
                "policy_file": json_path.name,
                "integrations": [integ.to_dict() for integ in sorted_integrations],
            }

            # Pre-write validation against dmint-mcp parser & secret rules
            validate_mcp_protection_config(protection_config)

            # Atomic write
            atomic_write_json(config_path, protection_config)

            # Post-write read-back validation
            try:
                read_back_data = json.loads(config_path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise OutputWriteError(f"Post-write read-back failed for '{config_path}': {exc}") from exc

            validate_mcp_protection_config(read_back_data)
            print("✓ Protection config validated")

            print(f"\n✓ Saved {json_path.name} + {config_path.name}\n")

            # Check runtime proxy transport compatibility.
            # Policy + config artifacts are written and valid. Warn if any integration
            # uses a transport the dmint-mcp runtime cannot yet execute as a proxy.
            http_integrations = [
                integ
                for integ in integrations
                if (
                    integ.transport.value if isinstance(integ.transport, MCPTransport) else str(integ.transport)
                ).lower()
                == MCPTransport.STREAMABLE_HTTP.value
            ]
            if http_integrations:
                try:
                    from dmint.mcp import MCPIntegrationConfig  # noqa: F401
                except ImportError:
                    # dmint-mcp not installed — cannot run proxy at all
                    raise CLIError(
                        "unsupported MCP transport type for dmint-mcp runtime proxy: "
                        "streamable-http integrations were discovered and config was saved, "
                        "but the dmint-mcp runtime does not yet support running a "
                        "streamable-http proxy. Install dmint-mcp and verify support before deploying."
                    )

            return verified_policy, protection_config

        else:
            shape_retry_attempts += 1
            if shape_retry_attempts >= 3:
                raise JSONExtractionError(f"Unrecognized response type '{msg_type}'.")
            messages.append({"role": "assistant", "content": raw_response})
            messages.append(
                {
                    "role": "user",
                    "content": "Your last response did not match the required output contract, resend as one of the two exact JSON shapes",
                }
            )
            continue


def main_create_mcp(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dmint create-mcp-policy",
        description="Specialized wizard to discover tools from existing MCP servers, create Dmint policy, and generate protection artifacts.",
    )
    parser.add_argument("--command", help="MCP server executable command (e.g. npx, mcp-server-postgres)")
    parser.add_argument("--args", nargs="*", help="Arguments for MCP server executable")
    parser.add_argument("--integration-id", help="Unique integration ID for this MCP server")
    parser.add_argument("--transport", default="stdio", help="MCP transport type (default: stdio)")
    parser.add_argument("--url", help="Remote MCP server URL (if transport is remote)")
    parser.add_argument(
        "-f", "--file", default="access.md", help="Input requirements markdown file (default: access.md)"
    )
    parser.add_argument(
        "-o", "--output", default="policy.json", help="Output verified policy JSON file (default: policy.json)"
    )
    parser.add_argument(
        "--config-output",
        default="mcp_protection.json",
        help="Output MCP protection configuration JSON file (default: mcp_protection.json)",
    )
    parser.add_argument("-provider", "--provider", help="LLM provider (e.g. openai, gemini, groq, openrouter, ollama)")
    parser.add_argument("-base_url", "--base-url", help="OpenAI-compatible base URL")
    parser.add_argument("-api_key", "--api-key", help="API key")
    parser.add_argument("-model", "--model", help="Model name")
    parser.add_argument("--non-interactive", action="store_true", help="Run without terminal input prompts")
    parser.add_argument("-y", "--yes", action="store_true", help="Auto-confirm candidate policy without prompting")
    parser.add_argument("--timeout", type=float, default=60.0, help="API request timeout in seconds (default: 60.0)")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    try:
        run_create_mcp_policy_wizard(
            command=parsed.command,
            args=parsed.args,
            integration_id=parsed.integration_id,
            transport=parsed.transport,
            url=parsed.url,
            access_md_file=parsed.file,
            output_json_file=parsed.output,
            config_output_file=parsed.config_output,
            base_url=parsed.base_url,
            api_key=parsed.api_key,
            model=parsed.model,
            provider=parsed.provider,
            non_interactive=parsed.non_interactive,
            auto_confirm=parsed.yes,
            timeout=parsed.timeout,
        )
        return 0
    except CLIError as exc:
        print(f"✗ MCP Policy creation failed: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:
        print(f"✗ Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main_create_mcp())
