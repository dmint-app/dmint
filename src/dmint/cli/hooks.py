"""Multi-harness pre-execution hooks, zero-config project init, and offline policy checker.

Provides first-class runtime tool interception for popular AI coding harnesses:
  - claude-code : Anthropic Claude Code (.claude/settings.json PreToolUse hook)
  - codex       : OpenAI Codex CLI (.codex/hooks.json PreToolUse & .codex/dmint-hook.sh)
  - opencode    : OpenCode (.opencode/plugins/dmint-guard.ts & .opencode/plugin/dmint-guard.ts)
  - cursor      : Cursor (.cursor/hooks.json version 1 preToolUse, beforeShellExecution, beforeReadFile, beforeMCPExecution, subagentStart)
  - windsurf    : Windsurf Cascade (.windsurf/hooks.json pre_run_command, pre_read_code, pre_write_code, pre_mcp_tool_use)
  - cline       : Cline / Roo Code (.clinerules/hooks/PreToolUse, .cline/hooks/PreToolUse.sh, .clinerules/hooks.json)
  - generic     : Standard JSON stdin/stdout pre-tool hook protocol

Each harness automatically receives its own dedicated built-in policy file in
`.dmint/policies/<harness>.policy.json` tailored to every built-in tool shipped by that harness.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.core.approvals import ApprovalRecord, PolicyProvenance, new_request_id
from dmint.core.canonicalize import thaw_json
from dmint.core.keys import (
    load_private_key_from_file,
    public_key_hex,
    write_integrity_key_atomic,
    write_private_key_atomic,
)
from dmint.core.models import Decision, NO_RESOURCE, NoResource, ToolRequest, TrustedContext
from dmint.core.policy import Policy, policy_digest
from dmint.core.request_binding import request_binding_fingerprint
from dmint.core.storage.sqlite import SQLiteApprovalStore
from dmint.core.verification import ApprovalVerifier
from dmint.core.webhooks import WebhookNotifier
from dmint.templates import (
    AVAILABLE_TEMPLATES,
    HARNESS_TEMPLATES,
    deduplicate_policy_dict,
    get_harness_template_dict,
    get_template_dict,
)

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
    "cascade": "windsurf",
    "cline": "cline",
    "roo": "cline",
    "roocode": "cline",
    "roo-code": "cline",
    "generic": "generic",
}

_SHELL_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "bash",
        "powershell",
        "monitor",
        "sh",
        "zsh",
        "shell",
        "exec",
        "exec_command",
        "execute_command",
        "run_commands",
        "run_terminal_cmd",
        "run_command",
        "pre_run_command",
        "beforeshellexecution",
        "write_stdin",
        "terminal",
        "command",
        "cmd",
    }
)

_FS_READ_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "read",
        "read_file",
        "read_files",
        "notebookread",
        "notebook_read",
        "view_file",
        "view_code_item",
        "view_image",
        "pre_read_code",
        "beforereadfile",
        "beforetabfileread",
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
        "editor",
        "edit_file",
        "multiedit",
        "multi_edit",
        "notebookedit",
        "notebook_edit",
        "str_replace_editor",
        "replace_in_file",
        "replace_file_content",
        "multi_replace_file_content",
        "search_replace",
        "apply_patch",
        "apply_diff",
        "patch",
        "create_file",
        "insert_text",
        "insert_content",
        "pre_write_code",
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
        "list_code_definition_names",
        "glob",
        "grep",
        "grep_files",
        "grep_search",
        "file_search",
        "codebase_search",
        "search_files",
        "find_by_name",
        "lsp",
    }
)

_FS_MKDIR_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "mkdir",
        "create_directory",
        "make_directory",
    }
)

_PATCH_HEADER_RE = re.compile(
    r"^\*\*\*\s+(?:Add File|Update File|Delete File|Move to):\s+(.+?)\s*$",
    re.MULTILINE,
)


def normalize_harness_name(name: str) -> str:
    clean = name.strip().lower()
    if clean not in HARNESS_ALIASES:
        raise ValueError(
            f"Unsupported harness '{name}'. Supported harnesses: {', '.join(SUPPORTED_HARNESSES)}"
        )
    return HARNESS_ALIASES[clean]


def get_harness_policy_path(workspace_dir: Path, harness: str) -> Path:
    """Return the canonical path to a harness's dedicated policy file inside .dmint/policies/."""
    norm = normalize_harness_name(harness)
    return workspace_dir.resolve() / ".dmint" / "policies" / f"{norm}.policy.json"


def ensure_harness_policy_file(
    workspace_dir: Path,
    harness: str,
    *,
    extra_templates: list[str] | None = None,
    force: bool = False,
) -> Path:
    """Ensure `.dmint/policies/<harness>.policy.json` exists with all built-in tools for that harness."""
    norm = normalize_harness_name(harness)
    policies_dir = workspace_dir.resolve() / ".dmint" / "policies"
    policies_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target_path = policies_dir / f"{norm}.policy.json"

    if not target_path.exists() or force:
        combined_rules: list[dict[str, Any]] = []
        if norm in HARNESS_TEMPLATES:
            combined_rules.extend(get_harness_template_dict(norm).get("rules", []))
        else:
            for base_tpl in ("shell", "filesystem"):
                combined_rules.extend(get_template_dict(base_tpl).get("rules", []))

        for tpl_name in (extra_templates or []):
            clean_tpl = tpl_name.strip().lower()
            if clean_tpl and clean_tpl not in ("shell", "filesystem", norm):
                tpl_dict = get_template_dict(clean_tpl)
                combined_rules.extend(tpl_dict.get("rules", []))

        merged = deduplicate_policy_dict({"rules": combined_rules, "strict_arguments": False})
        target_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")

    return target_path


def ensure_local_dmint_environment(
    workspace_dir: Path | None = None,
    *,
    policy_path: Path | None = None,
    templates: list[str] | None = None,
    harnesses: list[str] | None = None,
    force_policy: bool = False,
) -> dict[str, Any]:
    """Ensure .dmint/ keys, approval DB path, starter policy.json, and per-harness policies exist."""
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

    chosen_templates = templates or ["shell", "filesystem"]
    harness_policies: dict[str, Path] = {}
    target_harnesses = [normalize_harness_name(h) for h in (harnesses or []) if h.strip().lower() != "generic"]
    for h_norm in target_harnesses:
        harness_policies[h_norm] = ensure_harness_policy_file(
            base,
            h_norm,
            extra_templates=chosen_templates,
            force=force_policy,
        )

    if not target_policy_path.exists() or force_policy:
        combined_rules: list[dict[str, Any]] = []
        for tpl_name in chosen_templates:
            tpl_dict = get_template_dict(tpl_name)
            combined_rules.extend(tpl_dict.get("rules", []))
        for h_norm in target_harnesses:
            if h_norm in HARNESS_TEMPLATES:
                combined_rules.extend(get_harness_template_dict(h_norm).get("rules", []))
        merged_policy = deduplicate_policy_dict({"rules": combined_rules, "strict_arguments": False})
        target_policy_path.parent.mkdir(parents=True, exist_ok=True)
        target_policy_path.write_text(json.dumps(merged_policy, indent=2) + "\n", encoding="utf-8")

    return {
        "dmint_dir": dmint_dir,
        "signing_key": signing_key_path,
        "integrity_key": integrity_key_path,
        "db_path": db_path,
        "policy_path": target_policy_path,
        "harness_policies": harness_policies,
    }


def _dejson(val: Any) -> Any:
    """Parse JSON-stringified parameter values (used by Cline VS Code extension and Cursor MCP hooks)."""
    if isinstance(val, str):
        stripped = val.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                return json.loads(stripped)
            except Exception:
                return val
    return val


def _normalize_workspace_path(raw_path: str, workspace_dir: Path | None = None) -> str:
    """Convert workspace paths (including relative symlinks and '..' segments) to canonical relative POSIX paths."""
    clean = raw_path.strip()
    if not clean:
        return clean
    base = (workspace_dir or Path.cwd()).resolve()
    # Resolve both absolute paths and concrete relative paths (without glob wildcards) via os.path.realpath / Path.resolve()
    if "*" not in clean and "?" not in clean:
        try:
            p = Path(clean)
            candidate = p if p.is_absolute() else (base / p)
            resolved = candidate.resolve()
            try:
                rel = resolved.relative_to(base)
                rel_str = rel.as_posix()
                return rel_str if rel_str != "." else "*"
            except ValueError:
                return resolved.as_posix()
        except Exception:
            pass
    while clean.startswith("./"):
        clean = clean[2:]
    return clean or "*"


def _split_compound_shell_commands(cmd: str) -> list[str]:
    """Split a compound shell command on unquoted &&, ||, ;, |, or newline operators."""
    segments: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            escaped = True
            buf.append(ch)
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            if cmd[i : i + 2] in ("&&", "||", "|&"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 2
                continue
            if ch in (";", "|", "\n", "\r"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)
    return segments if segments else ([cmd.strip()] if cmd.strip() else [])


def _extract_patch_paths(patch_text: str, workspace_dir: Path | None = None) -> list[str]:
    """Extract all file paths from Codex / OpenCode / Cline unified patch headers."""
    paths: list[str] = []
    for match in _PATCH_HEADER_RE.finditer(patch_text):
        raw_p = match.group(1).strip()
        if raw_p:
            norm_p = _normalize_workspace_path(raw_p, workspace_dir)
            if norm_p not in paths:
                paths.append(norm_p)
    return paths


def _extract_all_paths_from_args(args: Mapping[str, Any], workspace_dir: Path | None = None) -> list[str]:
    """Extract one or more target file paths from tool arguments (including patch bodies and Cline file arrays)."""
    collected: list[str] = []

    # 1. Check unified patch text (OpenCode patchText, Codex/Cline input/patch/command)
    for patch_key in ("patchText", "patch", "diff", "input", "command"):
        pval = _dejson(args.get(patch_key))
        if isinstance(pval, str) and "*** " in pval:
            for pp in _extract_patch_paths(pval, workspace_dir):
                if pp not in collected:
                    collected.append(pp)

    # 2. Check multi-file list fields (Cline read_files: {files: [{path: ...}]}, paths: [...], file_paths: [...])
    for list_key in ("files", "paths", "file_paths"):
        lval = _dejson(args.get(list_key))
        if isinstance(lval, list):
            for item in lval:
                item_parsed = _dejson(item)
                if isinstance(item_parsed, str) and item_parsed.strip():
                    np = _normalize_workspace_path(item_parsed, workspace_dir)
                    if np not in collected:
                        collected.append(np)
                elif isinstance(item_parsed, Mapping):
                    for k in ("path", "file_path", "filePath"):
                        sub = item_parsed.get(k)
                        if isinstance(sub, str) and sub.strip():
                            np = _normalize_workspace_path(sub, workspace_dir)
                            if np not in collected:
                                collected.append(np)

    # 3. Check standard single-path keys
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
        "url",
        "uri",
        "resource",
    ):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            np = _normalize_workspace_path(val, workspace_dir) if key not in ("url", "uri") else val.strip()
            if np not in collected:
                collected.append(np)

    return collected


def _extract_path_from_args(args: Mapping[str, Any], workspace_dir: Path | None = None) -> str | NoResource:
    paths = _extract_all_paths_from_args(args, workspace_dir)
    return paths[0] if paths else "*"


def _extract_all_commands_from_args(args: Mapping[str, Any], payload: Mapping[str, Any]) -> list[str]:
    """Extract one or more shell command strings from tool arguments (including Cline run_commands arrays)."""
    commands: list[str] = []

    # Cline run_commands uses {"commands": [...]}
    raw_cmds = _dejson(args.get("commands"))
    if isinstance(raw_cmds, list):
        for item in raw_cmds:
            item_parsed = _dejson(item)
            if isinstance(item_parsed, str) and item_parsed.strip():
                commands.append(item_parsed.strip())
            elif isinstance(item_parsed, Mapping):
                c_str = item_parsed.get("command") or item_parsed.get("cmd")
                if isinstance(c_str, str) and c_str.strip():
                    commands.append(c_str.strip())

    for key in ("command", "command_line", "cmd", "script", "shell_command", "chars"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            c_clean = val.strip()
            if c_clean not in commands:
                commands.append(c_clean)
        elif isinstance(val, list) and val:
            if len(val) >= 3 and val[0] in ("bash", "sh", "zsh", "/bin/bash", "/bin/sh") and val[1] in ("-c", "-lc"):
                c_clean = str(val[2]).strip()
            else:
                c_clean = " ".join(str(x) for x in val).strip()
            if c_clean and c_clean not in commands:
                commands.append(c_clean)

    for top_key in ("command", "command_line"):
        top_cmd = payload.get(top_key)
        if isinstance(top_cmd, str) and top_cmd.strip():
            c_clean = top_cmd.strip()
            if c_clean not in commands:
                commands.append(c_clean)
        elif isinstance(top_cmd, list) and top_cmd:
            if (
                len(top_cmd) >= 3
                and top_cmd[0] in ("bash", "sh", "zsh", "/bin/bash", "/bin/sh")
                and top_cmd[1] in ("-c", "-lc")
            ):
                c_clean = str(top_cmd[2]).strip()
            else:
                c_clean = " ".join(str(x) for x in top_cmd).strip()
            if c_clean and c_clean not in commands:
                commands.append(c_clean)

    return commands


def _extract_command_from_args(args: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    cmds = _extract_all_commands_from_args(args, payload)
    return cmds[0] if cmds else ""


def _unpack_harness_envelope(
    payload: Mapping[str, Any],
) -> tuple[str, dict[str, Any], Path | None]:
    """Unpack harness-specific outer envelopes (Windsurf Cascade, Cline VS Code/CLI, Cursor events)."""
    detected_ws: Path | None = None
    ws_roots = payload.get("workspaceRoots") or payload.get("workspace_roots")
    if isinstance(ws_roots, list) and ws_roots and isinstance(ws_roots[0], str) and ws_roots[0].strip():
        try:
            detected_ws = Path(ws_roots[0].strip()).resolve()
        except Exception:
            detected_ws = None

    # 1. Windsurf Cascade envelope: {"agent_action_name": "pre_run_command", "tool_info": {...}}
    agent_action = payload.get("agent_action_name")
    if isinstance(agent_action, str) and agent_action.strip():
        tool_info = payload.get("tool_info")
        info_dict: dict[str, Any] = dict(tool_info) if isinstance(tool_info, Mapping) else {}
        if agent_action.strip() == "pre_mcp_tool_use":
            server_name = str(info_dict.get("mcp_server_name") or "mcp").strip()
            mcp_tool = str(info_dict.get("mcp_tool_name") or "execute").strip()
            mcp_args = info_dict.get("mcp_tool_arguments")
            args_out = dict(mcp_args) if isinstance(mcp_args, Mapping) else info_dict
            return f"mcp__{server_name}__{mcp_tool}", args_out, detected_ws
        return agent_action.strip(), info_dict, detected_ws

    # 2. Cline VS Code extension envelope: {"preToolUse": {"toolName": "...", "parameters": {...}}}
    cline_ext = payload.get("preToolUse")
    if isinstance(cline_ext, Mapping):
        t_name = str(cline_ext.get("toolName") or cline_ext.get("tool_name") or "").strip()
        raw_params = _dejson(cline_ext.get("parameters") or cline_ext.get("input") or {})
        params_dict: dict[str, Any] = {}
        if isinstance(raw_params, Mapping):
            params_dict = {str(k): _dejson(v) for k, v in raw_params.items()}
        return t_name, params_dict, detected_ws

    # 3. Cline CLI / SDK envelope: {"tool_call": {"name": "...", "input": {...}}}
    cline_cli = payload.get("tool_call")
    if isinstance(cline_cli, Mapping):
        t_name = str(cline_cli.get("name") or cline_cli.get("tool_name") or "").strip()
        raw_in = _dejson(cline_cli.get("input") or cline_cli.get("parameters") or {})
        in_dict: dict[str, Any] = {}
        if isinstance(raw_in, Mapping):
            in_dict = {str(k): _dejson(v) for k, v in raw_in.items()}
        return t_name, in_dict, detected_ws

    # 4. Cursor specific hook events (beforeShellExecution, beforeReadFile, beforeTabFileRead, beforeMCPExecution, subagentStart)
    hook_event = str(payload.get("hook_event_name") or "").strip()
    if hook_event == "beforeMCPExecution":
        server_name = str(payload.get("mcp_server_name") or "mcp").strip()
        mcp_tool = str(payload.get("tool_name") or "execute").strip()
        raw_ti = _dejson(payload.get("tool_input") or {})
        ti_dict = dict(raw_ti) if isinstance(raw_ti, Mapping) else {}
        return f"mcp__{server_name}__{mcp_tool}", ti_dict, detected_ws

    if hook_event in ("beforeShellExecution", "beforeReadFile", "beforeTabFileRead", "subagentStart") and not payload.get(
        "tool_name"
    ):
        args_copy: dict[str, Any] = {}
        for k in ("command", "cwd", "file_path", "subagent_type", "task", "subagent_model"):
            if k in payload:
                args_copy[k] = payload[k]
        return hook_event, args_copy, detected_ws

    # 5. Standard Claude Code / Codex / OpenCode / Cursor preToolUse / Generic envelope
    raw_tool_name = (
        payload.get("tool_name")
        or payload.get("tool")
        or payload.get("name")
        or payload.get("capability")
        or ""
    )
    if not isinstance(raw_tool_name, str) or not raw_tool_name.strip():
        if "command" in payload or "command_line" in payload:
            raw_tool_name = "shell.execute"
        elif "file_path" in payload:
            raw_tool_name = "beforeReadFile"
        else:
            raise ValueError("Hook payload missing 'tool_name' or 'tool' field")

    raw_args = (
        _dejson(payload.get("tool_input"))
        if payload.get("tool_input") is not None
        else _dejson(payload.get("arguments"))
        if payload.get("arguments") is not None
        else _dejson(payload.get("args"))
        if payload.get("args") is not None
        else _dejson(payload.get("input"))
        if payload.get("input") is not None
        else {}
    )
    args: dict[str, Any] = dict(raw_args) if isinstance(raw_args, Mapping) else {}
    return raw_tool_name.strip(), args, detected_ws


def normalize_harness_payload(
    payload: Mapping[str, Any],
    *,
    policy: Policy | None = None,
    workspace_dir: Path | None = None,
) -> tuple[str, str, str | NoResource, dict[str, Any]]:
    """Normalize a tool-call payload from Claude Code, Codex, OpenCode, Cursor, Windsurf, Cline, or generic JSON.

    Returns:
        (tool, action, resource, normalized_arguments)
    """
    clean_name, args, detected_ws = _unpack_harness_envelope(payload)
    eff_ws = workspace_dir or detected_ws

    explicit_res = payload.get("resource")
    explicit_resource: str | NoResource | None = (
        explicit_res.strip() if isinstance(explicit_res, str) and explicit_res.strip() else None
    )

    lower_name = clean_name.lower()

    # 1a. Cursor HTTP MCP prefix: "MCP:<tool_name>"
    if clean_name.startswith("MCP:"):
        mcp_action = clean_name.split(":", 1)[1].strip() or "execute"
        res = explicit_resource or _extract_path_from_args(args, eff_ws)
        return "mcp", mcp_action, res, args

    # 1b. MCP-prefixed tools in Claude Code / Codex / OpenCode: mcp__<server>__<tool>
    if clean_name.startswith("mcp__"):
        parts = clean_name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            server_id, mcp_action = parts[1], parts[2]
            res = explicit_resource or _extract_path_from_args(args, eff_ws)
            if policy is not None and any(
                r.tool == "mcp" and r.action == f"{server_id}.{mcp_action}" for r in policy.rules
            ):
                return "mcp", f"{server_id}.{mcp_action}", res, args
            return server_id, mcp_action, res, args

    # 1c. Cline use_mcp_tool: {"server_name": "...", "tool_name": "...", "arguments": {...}}
    if lower_name == "use_mcp_tool":
        server_id = str(args.get("server_name") or "mcp").strip()
        mcp_action = str(args.get("tool_name") or "execute").strip()
        sub_args = _dejson(args.get("arguments") or {})
        merged_args = dict(sub_args) if isinstance(sub_args, Mapping) else dict(args)
        res = explicit_resource or _extract_path_from_args(merged_args, eff_ws)
        if policy is not None and any(
            r.tool == server_id and r.action == mcp_action for r in policy.rules
        ):
            return server_id, mcp_action, res, merged_args
        return "use_mcp_tool", "execute", res, merged_args

    # 2. Explicit dotted capability: e.g. "shell.execute", "filesystem.read_file", "postgres.select"
    if "." in clean_name:
        tool_part, _, action_part = clean_name.partition(".")
        if tool_part == "shell":
            cmd_str = explicit_resource or _extract_command_from_args(args, payload)
            if cmd_str and "command" not in args:
                args["command"] = cmd_str
            return tool_part, action_part, (cmd_str or NO_RESOURCE), args
        if tool_part == "filesystem":
            f_res = explicit_resource or _extract_path_from_args(args, eff_ws)
            return tool_part, action_part, f_res, args
        res_val = explicit_resource if explicit_resource is not None else _extract_path_from_args(args, eff_ws)
        return tool_part, action_part, res_val, args

    # 3. Shell / Terminal tools (Bash, PowerShell, exec_command, run_commands, pre_run_command, beforeShellExecution)
    if lower_name in _SHELL_TOOL_NAMES:
        cmd_str = explicit_resource or _extract_command_from_args(args, payload)
        if cmd_str and "command" not in args:
            args["command"] = cmd_str
        return "shell", "execute", (cmd_str if cmd_str else NO_RESOURCE), args

    # 4. Filesystem Read tools (Read, read_file, read_files, pre_read_code, beforeReadFile)
    if lower_name in _FS_READ_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, eff_ws)
        return "filesystem", "read_file", f_res, args

    # 5. Filesystem Write / Edit tools (Write, Edit, MultiEdit, apply_patch, editor, pre_write_code)
    if lower_name in _FS_WRITE_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, eff_ws)
        return "filesystem", "write_file", f_res, args

    # 6. Filesystem Delete tools
    if lower_name in _FS_DELETE_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, eff_ws)
        return "filesystem", "delete_file", f_res, args

    # 7. Filesystem List / Search tools (LS, Glob, Grep, list_directory, search_files)
    if lower_name in _FS_LIST_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, eff_ws)
        return "filesystem", "list_directory", f_res, args

    # 8. Filesystem Mkdir tools
    if lower_name in _FS_MKDIR_TOOL_NAMES:
        f_res = explicit_resource or _extract_path_from_args(args, eff_ws)
        return "filesystem", "create_directory", f_res, args

    # 9. Subagent / Task / Skill / Web / Session built-in tools
    action_str = str(payload.get("action", "execute")).strip() or "execute"
    if lower_name in ("subagentstart", "task", "agent"):
        sub_res = explicit_resource or str(args.get("subagent_type") or args.get("description") or "*").strip() or "*"
        return clean_name, action_str, sub_res, args

    res_fallback = explicit_resource if explicit_resource is not None else _extract_path_from_args(args, eff_ws)
    return clean_name, action_str, res_fallback, args


def _evaluate_dual_policy(
    policy: Policy,
    *,
    norm_req: ToolRequest,
    native_tool_name: str,
) -> tuple[Decision, str]:
    """Evaluate policy against both canonical capability (e.g. shell.execute) and native tool name (e.g. Bash.execute).

    Enforces strict Dmint precedence across all matching rules:
      1. DENY overrides everything
      2. APPROVAL_REQUIRED overrides ALLOW
      3. ALLOW if at least one rule matched
      4. Default DENY (DMT_DEFAULT_DENY) if no rule matched
    """
    candidates = [norm_req]
    clean_native = native_tool_name.strip()
    if clean_native and "." not in clean_native and not clean_native.startswith("mcp__"):
        if (clean_native, "execute") != (norm_req.tool, norm_req.action):
            candidates.append(
                ToolRequest(
                    request_id=norm_req.request_id,
                    agent_id=norm_req.agent_id,
                    tool=clean_native,
                    action="execute",
                    resource=norm_req.resource,
                    arguments=thaw_json(norm_req.arguments),
                    context=norm_req.context,
                )
            )

    decisions: list[tuple[Decision, str]] = []
    for cand in candidates:
        has_match = any(r.matches_tool_action(cand) and r.matches(cand) for r in policy.rules)
        dec, code = policy.evaluate_detailed(cand)
        if has_match or code != "DMT_DEFAULT_DENY":
            decisions.append((dec, code))

    if not decisions:
        return Decision.DENY, "DMT_DEFAULT_DENY"

    for dec, code in decisions:
        if dec is Decision.DENY:
            return Decision.DENY, code
    for dec, code in decisions:
        if dec is Decision.APPROVAL_REQUIRED:
            return Decision.APPROVAL_REQUIRED, code
    return decisions[0]


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
    """Evaluate a pre-tool hook event deterministically against policy and approval store."""
    norm_harness = normalize_harness_name(harness)
    raw_native_tool, unpacked_args, detected_ws = _unpack_harness_envelope(payload)
    base = (workspace_dir or detected_ws or Path.cwd()).resolve()

    p_path = Path(policy_path)
    if not p_path.is_absolute():
        p_path = (base / p_path).resolve()
    if not p_path.exists():
        # Fall back to dedicated per-harness policy file if default policy.json was not created
        harness_p = get_harness_policy_path(base, norm_harness)
        if harness_p.exists():
            p_path = harness_p

    policy = Policy.from_file(p_path)
    tool, action, resource, arguments = normalize_harness_payload(
        payload,
        policy=policy,
        workspace_dir=base,
    )

    # Multi-resource / batch & compound shell command inspection (prevents smuggling a denied file/command)
    candidate_resources: list[str | NoResource] = [resource]
    full_shell_lines: list[str] = []
    if tool == "shell":
        raw_cmds = _extract_all_commands_from_args(unpacked_args, payload)
        if not raw_cmds and isinstance(resource, str) and resource:
            raw_cmds = [resource]
        expanded_cmds: list[str | NoResource] = []
        for rc in raw_cmds:
            full_shell_lines.append(rc)
            sub_segs = _split_compound_shell_commands(rc)
            for seg in sub_segs:
                if seg not in expanded_cmds:
                    expanded_cmds.append(seg)
        if expanded_cmds:
            candidate_resources = expanded_cmds
    elif tool == "filesystem" and action in ("read_file", "write_file", "delete_file"):
        all_paths = _extract_all_paths_from_args(unpacked_args, base)
        if len(all_paths) > 1:
            candidate_resources = list(all_paths)

    effective_agent = (
        agent_id
        or str(payload.get("agent_id") or f"{norm_harness}-agent").strip()
    )

    chosen_req: ToolRequest | None = None
    decision = Decision.ALLOW
    code = "DMT_ALLOWED"

    # First check full unsplit shell lines against explicit DENY rules (e.g. "* | sh", "* | bash", "* *.env*")
    for full_line in full_shell_lines:
        full_req = ToolRequest(
            request_id=new_request_id(),
            agent_id=effective_agent,
            tool=tool,
            action=action,
            resource=full_line,
            arguments=thaw_json(arguments),
            context=TrustedContext({}),
        )
        f_dec, f_code = _evaluate_dual_policy(
            policy,
            norm_req=full_req,
            native_tool_name=raw_native_tool,
        )
        if f_dec is Decision.DENY and f_code == "DMT_POLICY_DENIED":
            chosen_req = full_req
            decision, code = f_dec, f_code
            break

    if chosen_req is None:
        for res_item in candidate_resources:
            req_item = ToolRequest(
                request_id=new_request_id(),
                agent_id=effective_agent,
                tool=tool,
                action=action,
                resource=res_item,
                arguments=thaw_json(arguments),
                context=TrustedContext({}),
            )
            item_dec, item_code = _evaluate_dual_policy(
                policy,
                norm_req=req_item,
                native_tool_name=raw_native_tool,
            )
            if chosen_req is None:
                chosen_req = req_item
                decision, code = item_dec, item_code
            elif item_dec is Decision.DENY:
                chosen_req = req_item
                decision, code = item_dec, item_code
                break
            elif item_dec is Decision.APPROVAL_REQUIRED and decision is Decision.ALLOW:
                chosen_req = req_item
                decision, code = item_dec, item_code

    assert chosen_req is not None
    # Preserve the full original resource string on APPROVAL_REQUIRED so retry fingerprints match 1:1
    if decision is Decision.APPROVAL_REQUIRED and isinstance(resource, str) and chosen_req.resource != resource:
        req = ToolRequest(
            request_id=chosen_req.request_id,
            agent_id=effective_agent,
            tool=tool,
            action=action,
            resource=resource,
            arguments=thaw_json(arguments),
            context=TrustedContext({}),
        )
    else:
        req = chosen_req
        resource = req.resource
    res_display = resource if isinstance(resource, str) else "(none)"
    capability_id = f"{tool}.{action}"
    hook_event_name = str(payload.get("hook_event_name") or payload.get("agent_action_name") or "PreToolUse")

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
            hook_event_name=hook_event_name,
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
            hook_event_name=hook_event_name,
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
                    arguments=thaw_json(arguments),
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
                    hook_event_name=hook_event_name,
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
            hook_event_name=hook_event_name,
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
    hook_event_name: str = "PreToolUse",
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
    elif harness == "codex":
        # OpenAI Codex CLI PreToolUse only enforces "allow" or "deny" (not "ask")
        codex_perm = "allow" if decision is Decision.ALLOW else "deny"
        harness_output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": codex_perm,
                "permissionDecisionReason": reason,
            },
            "decision": "allow" if decision is Decision.ALLOW else (
                "approval_required" if decision is Decision.APPROVAL_REQUIRED else "deny"
            ),
            "allow": decision is Decision.ALLOW,
            "permission": codex_perm,
            "permissionDecision": codex_perm,
            "permissionDecisionReason": reason,
            "code": code,
            "tool": tool,
            "action": action,
            "resource": resource,
            "reason": reason,
            "dmint": dmint_meta,
        }
        if approval_id:
            harness_output["approval_id"] = approval_id
    elif harness == "cursor":
        # Cursor preToolUse/beforeReadFile/subagentStart enforce "allow" | "deny";
        # beforeShellExecution/beforeMCPExecution also accept "ask", but fail-closed "deny"
        # ensures Dmint's cryptographic approval store (`dmint approve <id>`) is required.
        cursor_perm = "allow" if decision is Decision.ALLOW else "deny"
        harness_output = {
            "permission": cursor_perm,
            "user_message": reason,
            "agent_message": reason,
            "decision": perm_map[decision] if decision is not Decision.APPROVAL_REQUIRED else "approval_required",
            "allow": decision is Decision.ALLOW,
            "code": code,
            "tool": tool,
            "action": action,
            "resource": resource,
            "reason": reason,
            "dmint": dmint_meta,
        }
        if approval_id:
            harness_output["approval_id"] = approval_id
    elif harness == "cline":
        # Cline extension (.clinerules/hooks/PreToolUse) & CLI (.cline/hooks/PreToolUse.sh)
        # expect {"cancel": false} on allow and {"cancel": true, "errorMessage": "..."} on block.
        is_blocked = decision is not Decision.ALLOW
        harness_output = {
            "cancel": is_blocked,
            "decision": perm_map[decision] if decision is not Decision.APPROVAL_REQUIRED else "approval_required",
            "allow": not is_blocked,
            "permission": "allow" if not is_blocked else "deny",
            "code": code,
            "tool": tool,
            "action": action,
            "resource": resource,
            "reason": reason,
            "dmint": dmint_meta,
        }
        if is_blocked:
            harness_output["errorMessage"] = reason
        if approval_id:
            harness_output["approval_id"] = approval_id
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
    per_harness_policy: bool = True,
) -> dict[str, Path]:
    """Install Dmint pre-tool hooks for one or more AI coding harnesses.

    By default (`per_harness_policy=True`), each harness gets its own dedicated policy file
    at `.dmint/policies/<harness>.policy.json` containing rules for all built-in tools
    shipped by that harness, and its hook configuration points directly to that dedicated policy.
    """
    base = (workspace_dir or Path.cwd()).resolve()
    norm_harnesses = [normalize_harness_name(h) for h in harnesses]
    env_paths = ensure_local_dmint_environment(
        base,
        policy_path=policy_path,
        templates=templates,
        harnesses=norm_harnesses,
    )
    resolved_shared_policy = env_paths["policy_path"]
    resolved_db = Path(db_path).resolve() if db_path else env_paths["db_path"]
    root_dir = Path.home() if global_install else base

    # Determine whether caller explicitly asked for a custom non-default single policy file
    default_policy_file = (base / "policy.json").resolve()
    explicit_custom_policy = (
        policy_path is not None and Path(policy_path).resolve() != default_policy_file
    )

    installed: dict[str, Path] = {}
    for norm in norm_harnesses:
        if per_harness_policy and not explicit_custom_policy and norm in HARNESS_TEMPLATES:
            harness_policy_file = ensure_harness_policy_file(
                base,
                norm,
                extra_templates=templates,
            )
        else:
            harness_policy_file = resolved_shared_policy

        hook_cmd = (
            f'dmint hook run --harness {norm} '
            f'--policy "{harness_policy_file}" '
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
            pre_tool_list = [
                entry
                for entry in pre_tool_list
                if not any("dmint hook run" in str(hk.get("command", "")) for hk in entry.get("hooks", []))
            ]
            pre_tool_list.append(
                {
                    "matcher": "*",
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
                    "PreToolUse": [
                        {
                            "matcher": "Bash|apply_patch|mcp__.*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": hook_cmd,
                                }
                            ],
                        }
                    ],
                    "pre_tool_use": {
                        "command": "dmint",
                        "args": [
                            "hook",
                            "run",
                            "--harness",
                            "codex",
                            "--policy",
                            str(harness_policy_file),
                            "--db-path",
                            str(resolved_db),
                        ],
                    },
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
            # OpenCode v2 uses .opencode/plugins/ (plural); v1 used .opencode/plugin/ (singular).
            # Write both so every OpenCode release loads the guard plugin automatically.
            plugins_plural_dir = (
                (Path.home() / ".config" / "opencode" / "plugins")
                if global_install
                else (root_dir / ".opencode" / "plugins")
            )
            plugin_singular_dir = (
                (Path.home() / ".config" / "opencode" / "plugin")
                if global_install
                else (root_dir / ".opencode" / "plugin")
            )
            plugins_plural_dir.mkdir(parents=True, exist_ok=True)
            plugin_singular_dir.mkdir(parents=True, exist_ok=True)

            plugin_code = f"""// Dmint Deterministic Security Guard Plugin for OpenCode
// Automatically generated by `dmint hook install --harness opencode`
import {{ spawnSync }} from "node:child_process";

export const DmintGuardPlugin = async (ctx: any) => {{
  return {{
    "tool.execute.before": async (input: any, output: any) => {{
      const payload = JSON.stringify({{
        tool_name: input?.tool ?? "",
        session_id: input?.sessionID ?? "opencode-session",
        call_id: input?.callID ?? "",
        workspace_roots: ctx?.directory ? [ctx.directory] : [],
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
          {json.dumps(str(harness_policy_file))},
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
            plural_file = plugins_plural_dir / "dmint-guard.ts"
            singular_file = plugin_singular_dir / "dmint-guard.ts"
            plural_file.write_text(plugin_code, encoding="utf-8")
            singular_file.write_text(plugin_code, encoding="utf-8")
            installed["opencode"] = plural_file

        elif norm == "cursor":
            cursor_file = root_dir / ".cursor" / "hooks.json"
            cursor_file.parent.mkdir(parents=True, exist_ok=True)
            cursor_payload = {
                "version": 1,
                "hooks": {
                    "preToolUse": [
                        {
                            "command": hook_cmd,
                            "matcher": "*",
                            "failClosed": True,
                        }
                    ],
                    "beforeShellExecution": [
                        {
                            "command": hook_cmd,
                            "matcher": "*",
                            "failClosed": True,
                        }
                    ],
                    "beforeReadFile": [
                        {
                            "command": hook_cmd,
                            "failClosed": True,
                        }
                    ],
                    "beforeMCPExecution": [
                        {
                            "command": hook_cmd,
                            "failClosed": True,
                        }
                    ],
                    "subagentStart": [
                        {
                            "command": hook_cmd,
                            "matcher": "*",
                            "failClosed": True,
                        }
                    ],
                },
            }
            cursor_file.write_text(json.dumps(cursor_payload, indent=2) + "\n", encoding="utf-8")
            installed["cursor"] = cursor_file

        elif norm == "windsurf":
            ws_file = (
                (Path.home() / ".codeium" / "windsurf" / "hooks.json")
                if global_install
                else (root_dir / ".windsurf" / "hooks.json")
            )
            ws_file.parent.mkdir(parents=True, exist_ok=True)
            ws_entry = {
                "command": hook_cmd,
                "show_output": True,
            }
            ws_payload = {
                "hooks": {
                    "pre_run_command": [dict(ws_entry)],
                    "pre_read_code": [dict(ws_entry)],
                    "pre_write_code": [dict(ws_entry)],
                    "pre_mcp_tool_use": [dict(ws_entry)],
                }
            }
            ws_file.write_text(json.dumps(ws_payload, indent=2) + "\n", encoding="utf-8")
            installed["windsurf"] = ws_file

        elif norm == "cline":
            # 1. VS Code Extension executable hook: .clinerules/hooks/PreToolUse (no extension)
            ext_hook_dir = (
                (Path.home() / "Documents" / "Cline" / "Hooks")
                if global_install
                else (root_dir / ".clinerules" / "hooks")
            )
            ext_hook_dir.mkdir(parents=True, exist_ok=True)
            ext_script = ext_hook_dir / "PreToolUse"

            # 2. Cline CLI executable hook: .cline/hooks/PreToolUse.sh
            cli_hook_dir = (
                (Path.home() / ".cline" / "hooks")
                if global_install
                else (root_dir / ".cline" / "hooks")
            )
            cli_hook_dir.mkdir(parents=True, exist_ok=True)
            cli_script = cli_hook_dir / "PreToolUse.sh"

            script_body = (
                "#!/usr/bin/env sh\n"
                "# Dmint PreToolUse Hook for Cline (VS Code Extension & CLI)\n"
                f"exec {hook_cmd}\n"
            )
            for s_path in (ext_script, cli_script):
                s_path.write_text(script_body, encoding="utf-8")
                try:
                    s_path.chmod(s_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                except OSError:
                    pass

            # 3. Also write .clinerules/hooks.json for Roo Code / declarative inspection
            cline_json_file = root_dir / ".clinerules" / "hooks.json"
            cline_json_file.parent.mkdir(parents=True, exist_ok=True)
            cline_payload = {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "command": hook_cmd,
                        }
                    ],
                    "preToolUse": [
                        {
                            "matcher": "*",
                            "command": hook_cmd,
                        }
                    ],
                }
            }
            cline_json_file.write_text(json.dumps(cline_payload, indent=2) + "\n", encoding="utf-8")
            installed["cline"] = ext_script

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
        (
            "opencode",
            [
                Path(".opencode/plugins/dmint-guard.ts"),
                Path(".opencode/plugin/dmint-guard.ts"),
                Path(".config/opencode/plugins/dmint-guard.ts"),
                Path(".config/opencode/plugin/dmint-guard.ts"),
            ],
        ),
        ("cursor", [Path(".cursor/hooks.json")]),
        ("windsurf", [Path(".windsurf/hooks.json"), Path(".codeium/windsurf/hooks.json")]),
        (
            "cline",
            [
                Path(".clinerules/hooks/PreToolUse"),
                Path(".cline/hooks/PreToolUse.sh"),
                Path(".clinerules/hooks.json"),
                Path("Documents/Cline/Hooks/PreToolUse"),
                Path(".cline/hooks/PreToolUse"),
            ],
        ),
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
        "opencode": (
            (base / ".opencode" / "plugins" / "dmint-guard.ts").exists()
            or (base / ".opencode" / "plugin" / "dmint-guard.ts").exists()
        ),
        "cursor": (base / ".cursor" / "hooks.json").exists(),
        "windsurf": (base / ".windsurf" / "hooks.json").exists(),
        "cline": (
            (base / ".clinerules" / "hooks" / "PreToolUse").exists()
            or (base / ".cline" / "hooks" / "PreToolUse.sh").exists()
            or (base / ".clinerules" / "hooks.json").exists()
        ),
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
    p_install.add_argument("--policy", default="policy.json", help="Path to shared policy.json (default: policy.json)")
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
            ws_dir = Path(parsed.dir).resolve() if parsed.dir else Path.cwd().resolve()
            p_file = (ws_dir / parsed.policy) if not Path(parsed.policy).is_absolute() else Path(parsed.policy)
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
            h_pol = get_harness_policy_path(ws_dir, h_name)
            print(f"  - {h_name:<12} -> {h_path} (policy: {h_pol})")
        return 0

    if parsed.subcommand == "status":
        ws_dir = Path(parsed.dir).resolve() if parsed.dir else Path.cwd().resolve()
        st = get_harness_hook_status(ws_dir)
        payload_out = {
            "workspace": str(ws_dir),
            "harnesses": {
                h_name: {
                    "installed": active,
                    "policy_path": str(get_harness_policy_path(ws_dir, h_name)),
                    "policy_exists": get_harness_policy_path(ws_dir, h_name).exists(),
                }
                for h_name, active in st.items()
            },
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
            print(json.dumps({"decision": "deny", "permission": "deny", "cancel": True, "errorMessage": err_msg, "reason": err_msg}))
            return 2

        print(json.dumps(result["harness_output"]))
        dec_str = result["decision"]
        norm_h = normalize_harness_name(parsed.harness)
        if dec_str == "ALLOW":
            return 0
        if dec_str == "APPROVAL_REQUIRED":
            print(result["reason"], file=sys.stderr)
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
        description="Initialize Dmint in the current project (keys, per-harness policies, starter policy.json, and agent harness hooks).",
    )
    parser.add_argument("--policy", "-o", default="policy.json", help="Output policy file (default: policy.json)")
    parser.add_argument(
        "--templates",
        "-t",
        default="shell,filesystem",
        help=f"Comma-separated starter templates ({', '.join(sorted(AVAILABLE_TEMPLATES.keys()))})",
    )
    parser.add_argument(
        "--harness",
        "--agent",
        default="all",
        help="Install pre-tool hooks for harnesses: claude-code, codex, opencode, cursor, windsurf, cline, all, or none",
    )
    parser.add_argument("--dir", default=None, help="Target workspace directory (default: current directory)")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing policy files")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    tpl_list = [t.strip() for t in parsed.templates.split(",") if t.strip()]
    raw_h = parsed.harness.strip().lower()
    target_harnesses: list[str] = []
    if raw_h != "none":
        target_harnesses = (
            ["claude-code", "codex", "opencode", "cursor", "windsurf", "cline"]
            if raw_h == "all"
            else [x.strip() for x in raw_h.split(",") if x.strip()]
        )

    try:
        ws_dir = Path(parsed.dir).resolve() if parsed.dir else Path.cwd().resolve()
        p_path = (ws_dir / parsed.policy) if not Path(parsed.policy).is_absolute() else Path(parsed.policy)
        env_paths = ensure_local_dmint_environment(
            workspace_dir=ws_dir,
            policy_path=p_path,
            templates=tpl_list,
            harnesses=target_harnesses,
            force_policy=parsed.force,
        )
        installed: dict[str, Path] = {}
        if target_harnesses:
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
    print(f"  - Shared policy : {env_paths['policy_path']} ({len(policy_obj.rules)} rules)")
    for h_name, h_pol_path in env_paths.get("harness_policies", {}).items():
        h_pol_obj = Policy.from_file(h_pol_path)
        print(f"  - {h_name:<13} : {h_pol_path} ({len(h_pol_obj.rules)} rules)")
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


def main_doctor(args: list[str] | None = None) -> int:
    """CLI entrypoint for `dmint doctor`: end-to-end workspace diagnostic and security self-test."""
    parser = argparse.ArgumentParser(
        prog="dmint doctor",
        description="Verify Dmint keys, SQLite approval store, per-harness policies, hooks, and run a live 4-vector security self-test.",
    )
    parser.add_argument("--dir", default=None, help="Target workspace directory (default: current directory)")
    parser.add_argument("--policy", default="policy.json", help="Path to policy.json (default: policy.json)")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output diagnostic report as JSON")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    ws_dir = Path(parsed.dir).resolve() if parsed.dir else Path.cwd().resolve()
    dmint_dir = ws_dir / ".dmint"
    signing_key = dmint_dir / "signing.key"
    integrity_key = dmint_dir / "integrity.key"
    db_path = dmint_dir / "approvals.sqlite3"
    policy_file = (ws_dir / parsed.policy) if not Path(parsed.policy).is_absolute() else Path(parsed.policy)

    checks: dict[str, dict[str, Any]] = {}
    all_ok = True

    # 1. Cryptographic engine & RFC 8785 self-test
    try:
        from dmint.core.canonicalize import canonicalize_bytes
        eph_priv = Ed25519PrivateKey.generate()
        msg = canonicalize_bytes({"b": 1, "a": [2, 3]})
        sig = eph_priv.sign(msg)
        eph_priv.public_key().verify(sig, msg)
        checks["crypto_engine"] = {"ok": True, "detail": "RFC 8785 (JCS) + Ed25519 sign/verify verified"}
    except Exception as exc:
        checks["crypto_engine"] = {"ok": False, "detail": str(exc)}
        all_ok = False

    # 2. Keys check
    if signing_key.exists() and integrity_key.exists():
        try:
            priv = load_private_key_from_file(signing_key)
            pub_hex = public_key_hex(priv.public_key())
            checks["keys"] = {
                "ok": True,
                "signing_key": str(signing_key),
                "integrity_key": str(integrity_key),
                "public_key_prefix": pub_hex[:16],
            }
        except Exception as exc:
            checks["keys"] = {"ok": False, "detail": str(exc)}
            all_ok = False
    else:
        checks["keys"] = {
            "ok": False,
            "detail": f"Missing keys in {dmint_dir} (run `dmint init` to generate)",
        }
        all_ok = False

    # 3. Policy & Per-Harness Policies check
    if policy_file.exists():
        try:
            pol = Policy.from_file(policy_file)
            harness_pol_counts: dict[str, int] = {}
            for h_name in ("claude-code", "codex", "opencode", "cursor", "windsurf", "cline"):
                hp = get_harness_policy_path(ws_dir, h_name)
                if hp.exists():
                    harness_pol_counts[h_name] = len(Policy.from_file(hp).rules)
            checks["policy"] = {
                "ok": True,
                "policy_path": str(policy_file),
                "rules": len(pol.rules),
                "digest": policy_digest(pol)[:16],
                "harness_policies": harness_pol_counts,
            }
        except Exception as exc:
            checks["policy"] = {"ok": False, "detail": str(exc)}
            all_ok = False
    else:
        checks["policy"] = {
            "ok": False,
            "detail": f"Missing policy file {policy_file} (run `dmint init` to generate)",
        }
        all_ok = False

    # 4. Harness Hooks status
    hook_st = get_harness_hook_status(ws_dir)
    checks["hooks"] = {
        "ok": any(hook_st.values()),
        "installed": hook_st,
    }

    # 5. Live 4-Vector Security Self-Test
    if checks["policy"].get("ok") and checks["keys"].get("ok"):
        try:
            r_allow = evaluate_hook_request(
                {"tool_name": "Bash", "tool_input": {"command": "git status"}},
                harness="claude-code",
                policy_path=policy_file,
                db_path=db_path,
                workspace_dir=ws_dir,
            )
            r_deny_cmd = evaluate_hook_request(
                {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
                harness="claude-code",
                policy_path=policy_file,
                db_path=db_path,
                workspace_dir=ws_dir,
            )
            r_deny_smuggle = evaluate_hook_request(
                {"tool_name": "Bash", "tool_input": {"command": "ls -la && rm -rf /"}},
                harness="claude-code",
                policy_path=policy_file,
                db_path=db_path,
                workspace_dir=ws_dir,
            )
            r_deny_env = evaluate_hook_request(
                {"tool_name": "Read", "tool_input": {"file_path": ".env"}},
                harness="claude-code",
                policy_path=policy_file,
                db_path=db_path,
                workspace_dir=ws_dir,
            )
            vectors_ok = (
                r_allow["decision"] == "ALLOW"
                and r_deny_cmd["decision"] == "DENY"
                and r_deny_smuggle["decision"] == "DENY"
                and r_deny_env["decision"] == "DENY"
            )
            checks["self_test"] = {
                "ok": vectors_ok,
                "vectors": {
                    "allow_git_status": r_allow["decision"],
                    "deny_rm_rf_root": r_deny_cmd["decision"],
                    "deny_chained_smuggle": r_deny_smuggle["decision"],
                    "deny_read_dotenv": r_deny_env["decision"],
                },
            }
            if not vectors_ok:
                all_ok = False
        except Exception as exc:
            checks["self_test"] = {"ok": False, "detail": str(exc)}
            all_ok = False
    else:
        checks["self_test"] = {"ok": False, "detail": "Skipped (keys or policy missing)"}

    report = {
        "ok": all_ok,
        "workspace": str(ws_dir),
        "checks": checks,
    }
    if parsed.output_json:
        print(json.dumps(report, indent=2))
    else:
        status_banner = "PASS" if all_ok else "FAIL"
        print(f"Dmint Doctor Diagnostic Report [{status_banner}] ({ws_dir})")
        for name, info in checks.items():
            mark = "✓" if info.get("ok") else "✗"
            print(f"  {mark} {name:<15}: {json.dumps(info)}")
    return 0 if all_ok else 1
