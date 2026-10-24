"""Multi-harness pre-execution hooks, zero-config project init, and offline policy checker.

Provides first-class runtime tool interception for popular AI coding harnesses:
  - claude-code : Anthropic Claude Code (.claude/settings.json PreToolUse hook)
  - codex       : OpenAI Codex CLI (.codex/hooks.json & .codex/dmint-hook.sh)
  - opencode    : OpenCode (.opencode/plugin/dmint-guard.ts tool.execute.before plugin)
  - cursor      : Cursor (.cursor/hooks.json preToolUse hook)
  - windsurf    : Windsurf (.windsurf/hooks.json preToolUse hook)
  - cline       : Cline / Roo Code (.clinerules/hooks.json preToolUse hook)
  - generic     : Standard JSON stdin/stdout pre-tool hook protocol

Also provides:
  - dmint init  : 1-command zero-config setup (keys + starter policy.json + optional harness hooks)
  - dmint check : Instant CLI policy simulator (test ALLOW / APPROVAL_REQUIRED / DENY from terminal)
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import getpass
import json
import os
from pathlib import Path
import shlex
import stat
import sys
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.core.approvals import ApprovalRecord, ApprovalState, PolicyProvenance, new_request_id
from dmint.core.keys import (
    load_integrity_key_from_file,
    load_private_key_from_file,
    public_key_hex,
    write_integrity_key_atomic,
    write_private_key_atomic,
)
from dmint.core.models import Decision, NO_RESOURCE, NoResource, ToolRequest, TrustedContext
from dmint.core.policy import Policy, policy_digest
from dmint.core.request_binding import request_binding_fingerprint
from dmint.core.storage.sqlite import SQLiteApprovalStore
from dmint.core.verification import ApprovalVerifier, DEFAULT_APPROVAL_AUDIENCE
from dmint.core.webhooks import WebhookNotifier
from dmint.templates import AVAILABLE_TEMPLATES, deduplicate_policy_dict, get_template_dict

SUPPORTED_HARNESSES: tuple[str, ...] = (
    "claude-code",
    "codex",
    "opencode",
    "cursor",
    "windsurf",
    "cline",
    "generic",
)

HARNESS_ALIASES: dict[str, str] = {
    "claude": "claude-code",
    "claude-code": "claude-code",
    "claudecode": "claude-code",
    "codex": "codex",
    "openai-codex": "codex",
    "opencode": "opencode",
    "open-code": "opencode",
    "cursor": "cursor",
    "windsurf": "windsurf",
    "cline": "cline",
    "roo": "cline",
    "roocode": "cline",
    "roo-code": "cline",
    "generic": "generic",
}

_SHELL_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "shell",
        "exec",
        "exec_command",
        "execute_command",
        "run_terminal_cmd",
        "run_command",
        "terminal",
        "command",
        "cmd",
    }
)

_FS_READ_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "read",
        "read_file",
        "view_file",
        "cat",
        "get_file_contents",
        "open_file",
        "read_text_file",
    }
)

_FS_WRITE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "write",
        "write_file",
        "write_to_file",
        "edit",
        "edit_file",
        "multiedit",
        "multi_edit",
        "notebookedit",
        "notebook_edit",
        "str_replace_editor",
        "replace_in_file",
        "apply_patch",
        "patch",
        "create_file",
        "insert_text",
    }
)

_FS_DELETE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "delete",
        "delete_file",
        "remove_file",
        "rm",
        "unlink",
    }
)

_FS_LIST_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "ls",
        "list",
        "list_dir",
        "list_directory",
        "list_files",
        "glob",
        "grep",
        "search_files",
        "find_by_name",
    }
)

_FS_MKDIR_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "mkdir",
        "create_directory",
        "make_directory",
    }
)


def normalize_harness_name(name: str) -> str:
    clean = name.strip().lower()
    if clean not in HARNESS_ALIASES:
        raise ValueError(
            f"Unsupported harness '{name}'. Supported harnesses: {', '.join(SUPPORTED_HARNESSES)}"
        )
    return HARNESS_ALIASES[clean]


def ensure_local_dmint_environment(
    workspace_dir: Path | None = None,
    *,
    policy_path: Path | None = None,
    templates: list[str] | None = None,
    force_policy: bool = False,
) -> dict[str, Path]:
    """Ensure .dmint/ keys, approval DB path, and starter policy.json exist."""
    base = (workspace_dir or Path.cwd()).resolve()
    dmint_dir = base / ".dmint"
    dmint_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(str(dmint_dir), 0o700)
    except OSError:
        pass

    signing_key_path = dmint_dir / "signing.key"
    integrity_key_path = dmint_dir / "integrity.key"
    db_path = dmint_dir / "approvals.sqlite3"
    target_policy_path = (policy_path or (base / "policy.json")).resolve()

    if not signing_key_path.exists():
        write_private_key_atomic(signing_key_path, Ed25519PrivateKey.generate())

    if not integrity_key_path.exists():
        write_integrity_key_atomic(integrity_key_path, os.urandom(32))

    if not target_policy_path.exists() or force_policy:
        chosen_templates = templates or ["shell", "filesystem"]
        combined_rules: list[dict[str, Any]] = []
        for tpl_name in chosen_templates:
            tpl_dict = get_template_dict(tpl_name)
            combined_rules.extend(tpl_dict.get("rules", []))
        merged_policy = deduplicate_policy_dict({"rules": combined_rules, "strict_arguments": False})
        target_policy_path.parent.mkdir(parents=True, exist_ok=True)
        target_policy_path.write_text(json.dumps(merged_policy, indent=2) + "\n", encoding="utf-8")

    return {
        "dmint_dir": dmint_dir,
        "signing_key": signing_key_path,
        "integrity_key": integrity_key_path,
        "db_path": db_path,
        "policy_path": target_policy_path,
    }


def _normalize_workspace_path(raw_path: str, workspace_dir: Path | None = None) -> str:
    """Convert absolute workspace paths to relative POSIX paths when inside workspace_dir."""
    clean = raw_path.strip()
    if not clean:
        return clean
    base = (workspace_dir or Path.cwd()).resolve()
    try:
        p = Path(clean)
        if p.is_absolute():
            resolved = p.resolve()
            try:
                rel = resolved.relative_to(base)
                rel_str = rel.as_posix()
                return rel_str if rel_str != "." else "*"
            except ValueError:
                return resolved.as_posix()
    except Exception:
        pass
    if clean.startswith("./"):
        clean = clean[2:]
    return clean


def _extract_path_from_args(args: Mapping[str, Any], workspace_dir: Path | None = None) -> str | NoResource:
    for key in (
        "file_path",
        "filePath",
        "dirPath",
        "path",
        "target_file",
        "TargetFile",
        "AbsolutePath",
        "notebook_path",
        "directory",
        "dir_path",
        "pattern",
        "uri",
        "resource",
    ):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return _normalize_workspace_path(val, workspace_dir)
    return "*"


def _extract_command_from_args(args: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    for key in ("command", "cmd", "script", "shell_command"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, list) and val:
            # Handle Codex-style ["bash", "-lc", "git status"] or ["sh", "-c", "ls"]
            if len(val) >= 3 and val[0] in ("bash", "sh", "zsh", "/bin/bash", "/bin/sh") and val[1] in ("-c", "-lc"):
                return str(val[2]).strip()
            return " ".join(str(x) for x in val).strip()
    top_cmd = payload.get("command")
    if isinstance(top_cmd, str) and top_cmd.strip():
        return top_cmd.strip()
    if isinstance(top_cmd, list) and top_cmd:
        if len(top_cmd) >= 3 and top_cmd[0] in ("bash", "sh", "zsh", "/bin/bash", "/bin/sh") and top_cmd[1] in ("-c", "-lc"):
            return str(top_cmd[2]).strip()
        return " ".join(str(x) for x in top_cmd).strip()
    return ""


def normalize_harness_payload(
    payload: Mapping[str, Any],
    *,
    policy: Policy | None = None,
    workspace_dir: Path | None = None,
) -> tuple[str, str, str | NoResource, dict[str, Any]]:
    """Normalize a tool-call payload from Claude Code, Codex, OpenCode, Cursor, or generic JSON.

    Returns:
        (tool, action, resource, normalized_arguments)
    """
    raw_tool_name = (
        payload.get("tool_name")
        or payload.get("tool")
        or payload.get("name")
        or payload.get("capability")
        or ""
    )
    if not isinstance(raw_tool_name, str) or not raw_tool_name.strip():
        if "command" in payload:
            raw_tool_name = "shell.execute"
        else:
            raise ValueError("Hook payload missing 'tool_name' or 'tool' field")

    clean_name = raw_tool_name.strip()
    raw_args = (
        payload.get("tool_input")
        if isinstance(payload.get("tool_input"), Mapping)
        else payload.get("arguments")
        if isinstance(payload.get("arguments"), Mapping)
        else payload.get("args")
        if isinstance(payload.get("args"), Mapping)
        else payload.get("input")
        if isinstance(payload.get("input"), Mapping)
        else {}
    )
    args: dict[str, Any] = dict(raw_args) if isinstance(raw_args, Mapping) else {}

    # Explicit resource override in top-level payload
    explicit_res = payload.get("resource")
    explicit_resource: str | NoResource | None = (
        explicit_res.strip() if isinstance(explicit_res, str) and explicit_res.strip() else None
    )

    lower_name = clean_name.lower()

    # 1. MCP-prefixed tools in Claude Code / OpenCode: mcp__<server>__<tool>
    if clean_name.startswith("mcp__"):
        parts = clean_name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            server_id, mcp_action = parts[1], parts[2]
            res = explicit_resource or _extract_path_from_args(args, workspace_dir)
            if policy is not None and any(
                r.tool == "mcp" and r.action == f"{server_id}.{mcp_action}" for r in policy.rules
            ):
                return "mcp", f"{server_id}.{mcp_action}", res, args
            return server_id, mcp_action, res, args

    # 2. Explicit dotted capability: e.g. "shell.execute", "filesystem.read_file", "postgres.select"
    if "." in clean_name:
        tool_part, _, action_part = clean_name.partition(".")
        if tool_part == "shell":
            cmd_str = explicit_resource or _extract_command_from_args(args, payload)
            if cmd_str and "command" not in args:
                args["command"] = cmd_str
            return tool_part, action_part, (cmd_str or NO_RESOURCE), args
        if tool_part == "filesystem":
            f_res = explicit_resource or _extract_path_from_args(args, workspace_dir)
            return tool_part, action_part, f_res, args
        res_val = explicit_resource if explicit_resource is not None else _extract_path_from_args(args, workspace_dir)
        return tool_part, action_part, res_val, args

    # 3. Shell / Terminal tools (Bash, exec_command, run_terminal_cmd, etc.)
    if lower_name in _SHELL_TOOL_NAMES:
        cmd_str = explicit_resource or _extract_command_from_args(args, payload)
        if cmd_str and "command" not in args:
            args["command"] = cmd_str
        return "shell", "execute", (cmd_str if cmd_str else NO_RESOURCE), args

    # 4. Filesystem Read tools (Read, read_file, view_file, etc.)
    if lower_name in _FS_READ_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, workspace_dir)
        return "filesystem", "read_file", f_res, args

    # 5. Filesystem Write / Edit tools (Write, Edit, MultiEdit, apply_patch, etc.)
    if lower_name in _FS_WRITE_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, workspace_dir)
        return "filesystem", "write_file", f_res, args

    # 6. Filesystem Delete tools
    if lower_name in _FS_DELETE_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, workspace_dir)
        return "filesystem", "delete_file", f_res, args

    # 7. Filesystem List / Search tools (LS, Glob, Grep, list_directory)
    if lower_name in _FS_LIST_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, workspace_dir)
        return "filesystem", "list_directory", f_res, args

    # 8. Filesystem Mkdir tools
    if lower_name in _FS_MKDIR_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, workspace_dir)
        return "filesystem", "create_directory", f_res, args

    # 9. Fallback for other single-word tools: "<tool>.execute"
    action_str = str(payload.get("action", "execute")).strip() or "execute"
    res_fallback = explicit_resource if explicit_resource is not None else NO_RESOURCE
    return lower_name, action_str, res_fallback, args


def evaluate_hook_request(
    payload: Mapping[str, Any],
    *,
    harness: str = "claude-code",
    policy_path: Path | str = "policy.json",
    db_path: Path | str | None = None,
    agent_id: str | None = None,
    deployment_epoch: str | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, Any]:
    """Evaluate a pre-tool hook event deterministically against policy and approval store.

    Returns a dictionary containing:
      - decision: "ALLOW" | "DENY" | "APPROVAL_REQUIRED"
      - code: Dmint decision/error code
      - tool: normalized tool name
      - action: normalized action name
      - resource: normalized resource string or None
      - approval_id: approval ID if APPROVAL_REQUIRED or consumed
      - consumed_approval: True if an existing APPROVED record was consumed single-use
      - reason: human-readable explanation
      - harness_output: harness-specific JSON response payload
    """
    norm_harness = normalize_harness_name(harness)
    base = (workspace_dir or Path.cwd()).resolve()
    p_path = Path(policy_path)
    if not p_path.is_absolute():
        p_path = (base / p_path).resolve()

    policy = Policy.from_file(p_path)
    tool, action, resource, arguments = normalize_harness_payload(
        payload,
        policy=policy,
        workspace_dir=base,
    )

    effective_agent = (
        agent_id
        or str(payload.get("agent_id") or f"{norm_harness}-agent").strip()
    )
    req = ToolRequest(
        request_id=new_request_id(),
        agent_id=effective_agent,
        tool=tool,
        action=action,
        resource=resource,
        arguments=arguments,
        context=TrustedContext({}),
    )

    decision, code = policy.evaluate_detailed(req)
    res_display = resource if isinstance(resource, str) else "(none)"
    capability_id = f"{tool}.{action}"

    if decision is Decision.ALLOW:
        reason = f"Dmint ALLOW: {capability_id} on '{res_display}'"
        return _build_hook_result(
            harness=norm_harness,
            decision=Decision.ALLOW,
            code=code or "DMT_ALLOWED",
            tool=tool,
            action=action,
            resource=resource if isinstance(resource, str) else None,
            reason=reason,
        )

    if decision is Decision.DENY:
        err_code = code or "DMT_POLICY_DENIED"
        reason = f"Dmint DENY [{err_code}]: {capability_id} on '{res_display}' is blocked by policy."
        return _build_hook_result(
            harness=norm_harness,
            decision=Decision.DENY,
            code=err_code,
            tool=tool,
            action=action,
            resource=resource if isinstance(resource, str) else None,
            reason=reason,
        )

    # Decision.APPROVAL_REQUIRED: Check or persist in SQLiteApprovalStore
    env_paths = ensure_local_dmint_environment(base, policy_path=p_path)
    target_db = Path(db_path).resolve() if db_path else env_paths["db_path"]
    target_epoch = deployment_epoch or os.environ.get("DMINT_DEPLOYMENT_EPOCH", "default")

    integrity_key: bytes | Path | str | None = None
    if not os.environ.get("DMINT_INTEGRITY_KEY") and not os.environ.get("DMINT_INTEGRITY_KEY_FILE"):
        if env_paths["integrity_key"].exists():
            integrity_key = env_paths["integrity_key"]

    now = datetime.now(timezone.utc)
    prov = PolicyProvenance("v1", policy_digest(policy), now)
    integration_id = f"hook-{norm_harness}"

    store = SQLiteApprovalStore(
        target_db,
        deployment_epoch=target_epoch,
        integrity_key=integrity_key,
        clock=lambda: now,
    )
    try:
        store.set_authoritative_policy(policy, prov)
        candidate_fp = request_binding_fingerprint(
            req,
            integration_id=integration_id,
            capability_id=capability_id,
        )
        matched = store.get_approved_assertion_for_request(
            request_fingerprint=candidate_fp,
            principal_id=effective_agent,
            integration_id=integration_id,
        )
        if matched is not None:
            approved_rec, assertion = matched
            signing_key_file = env_paths["signing_key"]
            trusted_issuers: dict[str, Any] = {}
            issuer_key = assertion.issuer
            if signing_key_file.exists():
                priv = load_private_key_from_file(signing_key_file)
                pub = priv.public_key()
                trusted_issuers[issuer_key] = pub
                trusted_issuers["dmint-cli"] = pub
                trusted_issuers["dmint-authority"] = pub
                trusted_issuers["dmint-dashboard"] = pub
            default_key_file = Path.home() / ".config" / "dmint" / "signing.key"
            if default_key_file.exists() and not signing_key_file.exists():
                try:
                    priv_def = load_private_key_from_file(default_key_file)
                    trusted_issuers[issuer_key] = priv_def.public_key()
                except Exception:
                    pass

            if trusted_issuers:
                verifier = ApprovalVerifier(
                    trusted_issuers=trusted_issuers,
                    audience=assertion.audience,
                    clock=lambda: now,
                )
                expected_req = ToolRequest(
                    request_id=approved_rec.request.request_id,
                    agent_id=effective_agent,
                    tool=tool,
                    action=action,
                    resource=resource,
                    arguments=arguments,
                    context=TrustedContext({}),
                )
                store.consume_approved(
                    approval_id=approved_rec.approval_id,
                    credential=assertion,
                    expected_request=expected_req,
                    verifier=verifier,
                    now=now,
                )
                reason = (
                    f"Dmint ALLOW (Approved retry consumed single-use credential {approved_rec.approval_id}): "
                    f"{capability_id} on '{res_display}'"
                )
                return _build_hook_result(
                    harness=norm_harness,
                    decision=Decision.ALLOW,
                    code="DMT_APPROVAL_CONSUMED_ALLOW",
                    tool=tool,
                    action=action,
                    resource=resource if isinstance(resource, str) else None,
                    reason=reason,
                    approval_id=approved_rec.approval_id,
                    consumed_approval=True,
                )

        # Otherwise persist pending approval record
        record = ApprovalRecord.create(
            request=req,
            integration_id=integration_id,
            capability_id=capability_id,
            policy_provenance=prov,
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        persisted = store.save_pending(record)
        notifier = WebhookNotifier(deployment_epoch=target_epoch)
        if notifier.is_configured:
            notifier.send_approval_required(persisted)

        approve_cmd = f"dmint approve {persisted.approval_id}"
        reason = (
            f"Dmint APPROVAL_REQUIRED [{persisted.approval_id}]: {capability_id} on '{res_display}' "
            f"requires human sign-off. To approve, run: `{approve_cmd}` (or use `dmint dashboard`), then retry."
        )
        return _build_hook_result(
            harness=norm_harness,
            decision=Decision.APPROVAL_REQUIRED,
            code="DMT_APPROVAL_REQUIRED",
            tool=tool,
            action=action,
            resource=resource if isinstance(resource, str) else None,
            reason=reason,
            approval_id=persisted.approval_id,
        )
    finally:
        store.close()


def _build_hook_result(
    *,
    harness: str,
    decision: Decision,
    code: str,
    tool: str,
    action: str,
    resource: str | None,
    reason: str,
    approval_id: str | None = None,
    consumed_approval: bool = False,
) -> dict[str, Any]:
    dmint_meta: dict[str, Any] = {
        "decision": decision.value,
        "code": code,
        "tool": tool,
        "action": action,
        "resource": resource,
        "approval_id": approval_id,
        "consumed_approval": consumed_approval,
    }
    perm_map = {
        Decision.ALLOW: "allow",
        Decision.DENY: "deny",
        Decision.APPROVAL_REQUIRED: "ask",
    }
    if harness == "claude-code":
        harness_output: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": perm_map[decision],
                "permissionDecisionReason": reason,
            },
            "dmint": dmint_meta,
        }
    else:
        harness_output = {
            "decision": perm_map[decision] if decision is not Decision.APPROVAL_REQUIRED else "approval_required",
            "allow": decision is Decision.ALLOW,
            "permission": perm_map[decision],
            "permissionDecision": "allow" if decision is Decision.ALLOW else "deny",
            "code": code,
            "tool": tool,
            "action": action,
            "resource": resource,
            "reason": reason,
            "dmint": dmint_meta,
        }
        if approval_id:
            harness_output["approval_id"] = approval_id

    return {
        "decision": decision.value,
        "code": code,
        "tool": tool,
        "action": action,
        "resource": resource,
        "approval_id": approval_id,
        "consumed_approval": consumed_approval,
        "reason": reason,
        "harness_output": harness_output,
    }


def install_harness_hooks(
    harnesses: list[str],
    *,
    workspace_dir: Path | None = None,
    global_install: bool = False,
    policy_path: Path | None = None,
    db_path: Path | None = None,
    templates: list[str] | None = None,
) -> dict[str, Path]:
    """Install Dmint pre-tool hooks for one or more AI coding harnesses."""
    base = (workspace_dir or Path.cwd()).resolve()
    env_paths = ensure_local_dmint_environment(base, policy_path=policy_path, templates=templates)
    resolved_policy = env_paths["policy_path"]
    resolved_db = (Path(db_path).resolve() if db_path else env_paths["db_path"])
    root_dir = Path.home() if global_install else base

    installed: dict[str, Path] = {}
    for h in harnesses:
        norm = normalize_harness_name(h)
        hook_cmd = (
            f'dmint hook run --harness {norm} '
            f'--policy "{resolved_policy}" '
            f'--db-path "{resolved_db}"'
        )

        if norm == "claude-code":
            settings_file = root_dir / ".claude" / "settings.json"
            settings_file.parent.mkdir(parents=True, exist_ok=True)
            existing: dict[str, Any] = {}
            if settings_file.exists():
                try:
                    existing = json.loads(settings_file.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}
            hooks_section = existing.setdefault("hooks", {})
            pre_tool_list = hooks_section.setdefault("PreToolUse", [])
            # Remove any older dmint hook entry before adding fresh one
            pre_tool_list = [
                entry
                for entry in pre_tool_list
                if not any("dmint hook run" in str(hk.get("command", "")) for hk in entry.get("hooks", []))
            ]
            pre_tool_list.append(
                {
                    "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch|mcp__.*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_cmd,
                        }
                    ],
                }
            )
            hooks_section["PreToolUse"] = pre_tool_list
            settings_file.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
            installed["claude-code"] = settings_file

        elif norm == "codex":
            codex_dir = root_dir / ".codex"
            codex_dir.mkdir(parents=True, exist_ok=True)
            hooks_file = codex_dir / "hooks.json"
            sh_file = codex_dir / "dmint-hook.sh"
            hooks_payload = {
                "version": 1,
                "hooks": {
                    "pre_tool_use": {
                        "command": "dmint",
                        "args": [
                            "hook",
                            "run",
                            "--harness",
                            "codex",
                            "--policy",
                            str(resolved_policy),
                            "--db-path",
                            str(resolved_db),
                        ],
                    }
                },
            }
            hooks_file.write_text(json.dumps(hooks_payload, indent=2) + "\n", encoding="utf-8")
            sh_file.write_text(
                f"#!/usr/bin/env sh\n# Dmint Pre-Execution Hook for OpenAI Codex CLI\nexec {hook_cmd}\n",
                encoding="utf-8",
            )
            try:
                sh_file.chmod(sh_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass
            installed["codex"] = hooks_file

        elif norm == "opencode":
            opencode_dir = (
                (Path.home() / ".config" / "opencode" / "plugin")
                if global_install
                else (root_dir / ".opencode" / "plugin")
            )
            opencode_dir.mkdir(parents=True, exist_ok=True)
            plugin_file = opencode_dir / "dmint-guard.ts"
            plugin_code = f"""// Dmint Deterministic Security Guard Plugin for OpenCode
// Automatically generated by `dmint hook install --harness opencode`
import {{ spawnSync }} from "node:child_process";

export const DmintGuardPlugin = async (_ctx: any) => {{
  return {{
    "tool.execute.before": async (input: any, output: any) => {{
      const payload = JSON.stringify({{
        tool_name: input?.tool ?? "",
        session_id: input?.sessionID ?? "opencode-session",
        call_id: input?.callID ?? "",
        tool_input: output?.args ?? {{}},
      }});
      const res = spawnSync(
        "dmint",
        [
          "hook",
          "run",
          "--harness",
          "opencode",
          "--policy",
          {json.dumps(str(resolved_policy))},
          "--db-path",
          {json.dumps(str(resolved_db))},
        ],
        {{ input: payload, encoding: "utf-8" }}
      );
      if (res.status !== 0) {{
        let reason = (res.stderr || res.stdout || "Blocked by Dmint policy").trim();
        try {{
          const parsed = JSON.parse(res.stdout);
          if (parsed && parsed.reason) reason = parsed.reason;
        }} catch {{}}
        throw new Error(reason);
      }}
    }},
  }};
}};

export default DmintGuardPlugin;
"""
            plugin_file.write_text(plugin_code, encoding="utf-8")
            installed["opencode"] = plugin_file

        elif norm == "cursor":
            cursor_file = root_dir / ".cursor" / "hooks.json"
            cursor_file.parent.mkdir(parents=True, exist_ok=True)
            cursor_payload = {
                "hooks": {
                    "preToolUse": [
                        {
                            "matcher": "*",
                            "command": hook_cmd,
                        }
                    ]
                }
            }
            cursor_file.write_text(json.dumps(cursor_payload, indent=2) + "\n", encoding="utf-8")
            installed["cursor"] = cursor_file

        elif norm == "windsurf":
            ws_file = root_dir / ".windsurf" / "hooks.json"
            ws_file.parent.mkdir(parents=True, exist_ok=True)
            ws_payload = {
                "hooks": {
                    "preToolUse": [
                        {
                            "matcher": "*",
                            "command": hook_cmd,
                        }
                    ]
                }
            }
            ws_file.write_text(json.dumps(ws_payload, indent=2) + "\n", encoding="utf-8")
            installed["windsurf"] = ws_file

        elif norm == "cline":
            cline_file = root_dir / ".clinerules" / "hooks.json"
            cline_file.parent.mkdir(parents=True, exist_ok=True)
            cline_payload = {
                "hooks": {
                    "preToolUse": [
                        {
                            "matcher": "*",
                            "command": hook_cmd,
                        }
                    ]
                }
            }
            cline_file.write_text(json.dumps(cline_payload, indent=2) + "\n", encoding="utf-8")
            installed["cline"] = cline_file

    return installed


def uninstall_harness_hooks(
    harnesses: list[str] | None = None,
    *,
    workspace_dir: Path | None = None,
    global_install: bool = False,
) -> list[str]:
    """Remove installed Dmint hook configurations for the specified harnesses."""
    base = Path.home() if global_install else (workspace_dir or Path.cwd()).resolve()
    targets = [normalize_harness_name(h) for h in harnesses] if harnesses else list(SUPPORTED_HARNESSES)
    removed: list[str] = []

    if "claude-code" in targets:
        s_file = base / ".claude" / "settings.json"
        if s_file.exists():
            try:
                data = json.loads(s_file.read_text(encoding="utf-8"))
                pre = data.get("hooks", {}).get("PreToolUse", [])
                filtered = [
                    entry
                    for entry in pre
                    if not any("dmint hook run" in str(hk.get("command", "")) for hk in entry.get("hooks", []))
                ]
                if len(filtered) != len(pre):
                    data["hooks"]["PreToolUse"] = filtered
                    s_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                    removed.append("claude-code")
            except Exception:
                pass

    for name, rel_paths in (
        ("codex", [Path(".codex/hooks.json"), Path(".codex/dmint-hook.sh")]),
        ("opencode", [Path(".opencode/plugin/dmint-guard.ts"), Path(".config/opencode/plugin/dmint-guard.ts")]),
        ("cursor", [Path(".cursor/hooks.json")]),
        ("windsurf", [Path(".windsurf/hooks.json")]),
        ("cline", [Path(".clinerules/hooks.json")]),
    ):
        if name in targets:
            for rp in rel_paths:
                fp = base / rp
                if fp.exists():
                    fp.unlink(missing_ok=True)
                    if name not in removed:
                        removed.append(name)
    return removed


def get_harness_hook_status(workspace_dir: Path | None = None) -> dict[str, bool]:
    """Check which AI coding harnesses currently have Dmint hooks configured in workspace_dir."""
    base = (workspace_dir or Path.cwd()).resolve()
    status: dict[str, bool] = {
        "claude-code": False,
        "codex": (base / ".codex" / "hooks.json").exists(),
        "opencode": (base / ".opencode" / "plugin" / "dmint-guard.ts").exists(),
        "cursor": (base / ".cursor" / "hooks.json").exists(),
        "windsurf": (base / ".windsurf" / "hooks.json").exists(),
        "cline": (base / ".clinerules" / "hooks.json").exists(),
    }
    claude_settings = base / ".claude" / "settings.json"
    if claude_settings.exists():
        try:
            text = claude_settings.read_text(encoding="utf-8")
            status["claude-code"] = "dmint hook run" in text
        except Exception:
            pass
    return status


# ============================================================================
# CLI Entrypoints: main_hook, main_check, main_init
# ============================================================================


def main_hook(args: list[str] | None = None) -> int:
    """CLI entrypoint for `dmint hook <install|run|status|uninstall>`."""
    parser = argparse.ArgumentParser(
        prog="dmint hook",
        description="Manage and execute Dmint pre-tool hooks for Claude Code, Codex, OpenCode, Cursor, Windsurf, and Cline.",
    )
    sub = parser.add_subparsers(dest="subcommand", help="Hook subcommand")

    # dmint hook install
    p_install = sub.add_parser("install", help="Install pre-tool hooks for one or more AI coding harnesses")
    p_install.add_argument(
        "--harness",
        "--agent",
        default="all",
        help="Target harness: claude-code, codex, opencode, cursor, windsurf, cline, or 'all' (default: all)",
    )
    p_install.add_argument("--global", dest="global_install", action="store_true", help="Install into user home config")
    p_install.add_argument("--dir", default=None, help="Target workspace directory (default: current directory)")
    p_install.add_argument("--policy", default="policy.json", help="Path to policy.json (default: policy.json)")
    p_install.add_argument(
        "--db-path",
        default=None,
        help="Path to SQLite approval store (default: .dmint/approvals.sqlite3)",
    )
    p_install.add_argument(
        "--templates",
        default="shell,filesystem",
        help="Comma-separated built-in templates if creating starter policy.json (default: shell,filesystem)",
    )

    # dmint hook run
    p_run = sub.add_parser("run", help="Evaluate a pre-tool hook JSON payload from stdin or --input")
    p_run.add_argument(
        "--harness",
        "--agent",
        default="claude-code",
        help="Harness protocol format: claude-code, codex, opencode, cursor, windsurf, cline, generic",
    )
    p_run.add_argument("--policy", default="policy.json", help="Path to policy.json")
    p_run.add_argument("--db-path", default=None, help="Path to SQLite approval store")
    p_run.add_argument("--agent-id", default=None, help="Override principal/agent ID")
    p_run.add_argument("--deployment-epoch", default=None, help="Deployment epoch (default: 'default')")
    p_run.add_argument("--input", dest="input_json", default=None, help="Inline JSON payload (defaults to stdin)")
    p_run.add_argument(
        "--block-on-approval",
        action="store_true",
        help="Exit with code 2 on APPROVAL_REQUIRED even for harnesses supporting interactive 'ask'",
    )

    # dmint hook status
    p_status = sub.add_parser("status", help="Show installed harness hooks in the current workspace")
    p_status.add_argument("--dir", default=None, help="Target workspace directory (default: current directory)")
    p_status.add_argument("--json", dest="output_json", action="store_true", help="Output status as JSON")

    # dmint hook uninstall
    p_un = sub.add_parser("uninstall", help="Remove Dmint hooks from harness configuration files")
    p_un.add_argument("--harness", "--agent", default="all", help="Harness to uninstall (default: all)")
    p_un.add_argument("--global", dest="global_install", action="store_true", help="Uninstall from user home config")
    p_un.add_argument("--dir", default=None, help="Target workspace directory (default: current directory)")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    if not parsed.subcommand:
        parser.print_help()
        return 0

    if parsed.subcommand == "install":
        raw_h = parsed.harness.strip().lower()
        if raw_h == "all":
            target_harnesses = ["claude-code", "codex", "opencode", "cursor", "windsurf", "cline"]
        else:
            target_harnesses = [x.strip() for x in raw_h.split(",") if x.strip()]
        tpl_list = [t.strip() for t in parsed.templates.split(",") if t.strip()]
        try:
            ws_dir = Path(parsed.dir).resolve() if parsed.dir else None
            p_file = (ws_dir / parsed.policy) if (ws_dir and not Path(parsed.policy).is_absolute()) else Path(parsed.policy)
            installed = install_harness_hooks(
                target_harnesses,
                workspace_dir=ws_dir,
                global_install=parsed.global_install,
                policy_path=p_file,
                db_path=Path(parsed.db_path) if parsed.db_path else None,
                templates=tpl_list,
            )
        except Exception as exc:
            print(f"Error installing hooks: {exc}", file=sys.stderr)
            return 1

        print("✓ Dmint Pre-Tool Execution Hooks Installed:")
        for h_name, h_path in installed.items():
            print(f"  - {h_name:<12} -> {h_path}")
        print(f"  - Policy       -> {Path(parsed.policy).resolve()}")
        return 0

    if parsed.subcommand == "status":
        ws_dir = Path(parsed.dir).resolve() if parsed.dir else Path.cwd().resolve()
        st = get_harness_hook_status(ws_dir)
        payload_out = {
            "workspace": str(ws_dir),
            "harnesses": {h_name: {"installed": active} for h_name, active in st.items()},
        }
        print(json.dumps(payload_out, indent=2))
        return 0

    if parsed.subcommand == "uninstall":
        raw_h = parsed.harness.strip().lower()
        targets = None if raw_h == "all" else [x.strip() for x in raw_h.split(",") if x.strip()]
        ws_dir = Path(parsed.dir).resolve() if parsed.dir else None
        removed = uninstall_harness_hooks(targets, workspace_dir=ws_dir, global_install=parsed.global_install)
        if removed:
            print(f"✓ Removed Dmint hooks for: {', '.join(removed)}")
        else:
            print("No Dmint hooks found to remove.")
        return 0

    if parsed.subcommand == "run":
        raw_input = parsed.input_json
        if raw_input is None:
            raw_input = sys.stdin.read()
        if not raw_input or not raw_input.strip():
            print("Error: Empty hook payload on stdin", file=sys.stderr)
            return 2

        try:
            payload = json.loads(raw_input)
            if not isinstance(payload, dict):
                raise ValueError("Hook payload must be a JSON object")
            result = evaluate_hook_request(
                payload,
                harness=parsed.harness,
                policy_path=parsed.policy,
                db_path=parsed.db_path,
                agent_id=parsed.agent_id,
                deployment_epoch=parsed.deployment_epoch,
            )
        except Exception as exc:
            # Fail closed on any malformed input or missing policy
            err_msg = f"Dmint fail-closed hook error: {exc}"
            print(err_msg, file=sys.stderr)
            print(json.dumps({"decision": "deny", "reason": err_msg}))
            return 2

        print(json.dumps(result["harness_output"]))
        dec_str = result["decision"]
        if dec_str == "ALLOW":
            return 0
        if dec_str == "APPROVAL_REQUIRED":
            print(result["reason"], file=sys.stderr)
            norm_h = normalize_harness_name(parsed.harness)
            if norm_h == "claude-code" and not parsed.block_on_approval:
                # Claude Code reads permissionDecision: "ask" when exit code is 0
                return 0
            return 2
        # DENY
        print(result["reason"], file=sys.stderr)
        return 2

    return 1


def main_check(args: list[str] | None = None) -> int:
    """CLI entrypoint for `dmint check` / `dmint test-policy`."""
    parser = argparse.ArgumentParser(
        prog="dmint check",
        description="Simulate and test a tool call against a Dmint policy.json from the terminal.",
    )
    parser.add_argument("--policy", "-p", default="policy.json", help="Path to policy.json (default: policy.json)")
    parser.add_argument(
        "--tool",
        "-t",
        required=True,
        help="Tool and action (e.g. 'shell.execute' or 'filesystem') — if no dot, provide --action",
    )
    parser.add_argument("--action", "-a", default=None, help="Action name if --tool does not contain a dot")
    parser.add_argument("--resource", "-r", default=None, help="Target resource (e.g. 'git status', 'src/main.py')")
    parser.add_argument("--args", default="{}", help="JSON object of tool arguments (default: '{}')")
    parser.add_argument("--agent-id", default="cli-tester", help="Agent identity (default: cli-tester)")
    parser.add_argument("--context", default="{}", help="JSON object of trusted context (default: '{}')")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output result as JSON")
    parser.add_argument(
        "--fail-on-deny",
        action="store_true",
        help="Exit with non-zero status code when decision is DENY or APPROVAL_REQUIRED",
    )

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    try:
        policy = Policy.from_file(parsed.policy)
        if "." in parsed.tool and not parsed.action:
            tool_name, _, action_name = parsed.tool.partition(".")
        else:
            tool_name = parsed.tool
            action_name = parsed.action or "execute"

        call_args = json.loads(parsed.args)
        ctx_data = json.loads(parsed.context)
        res_val: str | NoResource = parsed.resource if parsed.resource is not None else NO_RESOURCE

        req = ToolRequest(
            request_id=new_request_id(),
            agent_id=parsed.agent_id,
            tool=tool_name,
            action=action_name,
            resource=res_val,
            arguments=call_args,
            context=TrustedContext(ctx_data),
        )
        decision, code = policy.evaluate_detailed(req)
        matched_rules = [
            idx + 1
            for idx, r in enumerate(policy.rules)
            if r.matches_tool_action(req) and r.matches(req)
        ]
    except Exception as exc:
        print(f"Error evaluating policy: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "verdict": decision.value,
                "decision": decision.value,
                "code": code,
                "tool": tool_name,
                "action": action_name,
                "resource": parsed.resource,
                "matched_rules": matched_rules,
            },
            indent=2,
        )
    )
    if decision is Decision.ALLOW:
        return 0
    if decision is Decision.APPROVAL_REQUIRED:
        return 1
    return 2


def main_init(args: list[str] | None = None) -> int:
    """CLI entrypoint for `dmint init`: zero-config 1-command project bootstrap."""
    parser = argparse.ArgumentParser(
        prog="dmint init",
        description="Initialize Dmint in the current project (keys, starter policy.json, and agent harness hooks).",
    )
    parser.add_argument("--policy", "-o", default="policy.json", help="Output policy file (default: policy.json)")
    parser.add_argument(
        "--templates",
        "-t",
        default="shell,filesystem",
        help=f"Comma-separated starter templates ({', '.join( sorted(AVAILABLE_TEMPLATES.keys()) )})",
    )
    parser.add_argument(
        "--harness",
        "--agent",
        default="all",
        help="Install pre-tool hooks for harnesses: claude-code, codex, opencode, cursor, windsurf, cline, all, or none",
    )
    parser.add_argument("--dir", default=None, help="Target workspace directory (default: current directory)")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing policy.json")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    tpl_list = [t.strip() for t in parsed.templates.split(",") if t.strip()]
    try:
        ws_dir = Path(parsed.dir).resolve() if parsed.dir else Path.cwd().resolve()
        p_path = (ws_dir / parsed.policy) if not Path(parsed.policy).is_absolute() else Path(parsed.policy)
        env_paths = ensure_local_dmint_environment(
            workspace_dir=ws_dir,
            policy_path=p_path,
            templates=tpl_list,
            force_policy=parsed.force,
        )
        raw_h = parsed.harness.strip().lower()
        installed: dict[str, Path] = {}
        if raw_h != "none":
            target_harnesses = (
                ["claude-code", "codex", "opencode", "cursor", "windsurf", "cline"]
                if raw_h == "all"
                else [x.strip() for x in raw_h.split(",") if x.strip()]
            )
            installed = install_harness_hooks(
                target_harnesses,
                workspace_dir=ws_dir,
                policy_path=env_paths["policy_path"],
                db_path=env_paths["db_path"],
                templates=tpl_list,
            )
    except Exception as exc:
        print(f"Error initializing Dmint: {exc}", file=sys.stderr)
        return 1

    priv = load_private_key_from_file(env_paths["signing_key"])
    pub_hex = public_key_hex(priv.public_key())
    policy_obj = Policy.from_file(env_paths["policy_path"])

    print("✓ Dmint initialized in current workspace!")
    print(f"  - Policy file   : {env_paths['policy_path']} ({len(policy_obj.rules)} rules from {', '.join(tpl_list)})")
    print(f"  - Signing key   : {env_paths['signing_key']} (0600, public_key_hex={pub_hex[:16]}...)")
    print(f"  - Integrity key : {env_paths['integrity_key']} (0600)")
    print(f"  - Approval DB   : {env_paths['db_path']}")
    if installed:
        print(f"  - Agent hooks   : {', '.join(installed.keys())}")
    print("\nTry testing your policy right now:")
    print(f'  dmint check -p {parsed.policy} -t shell.execute -r "git status"          # -> ALLOW')
    print(f'  dmint check -p {parsed.policy} -t shell.execute -r "docker ps"           # -> APPROVAL_REQUIRED')
    print(f'  dmint check -p {parsed.policy} -t shell.execute -r "rm -rf /etc"         # -> DENY')
    return 0
