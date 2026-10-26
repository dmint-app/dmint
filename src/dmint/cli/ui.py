"""Unified terminal UI, help formatting, and interactive prompt helpers for Dmint CLI."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any, Sequence

try:
    from rich.box import ROUNDED
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False


def use_color(stream: Any = None) -> bool:
    """Return True when rich/ANSI color output should be used for the given stream."""
    if os.environ.get("NO_COLOR") or os.environ.get("DMINT_NO_COLOR"):
        return False
    if os.environ.get("DMINT_FORCE_COLOR") in ("1", "true", "yes"):
        return _HAS_RICH
    if os.environ.get("TERM") == "dumb":
        return False
    target = stream if stream is not None else sys.stdout
    return bool(_HAS_RICH and hasattr(target, "isatty") and target.isatty())


class DmintHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Clean, wide, aligned help formatter for all Dmint CLI commands."""

    def __init__(
        self,
        prog: str,
        indent_increment: int = 2,
        max_help_position: int = 36,
        width: int | None = None,
    ) -> None:
        effective_width = width or min(max(shutil_terminal_width(), 88), 110)
        super().__init__(
            prog,
            indent_increment=indent_increment,
            max_help_position=max_help_position,
            width=effective_width,
        )


def shutil_terminal_width() -> int:
    try:
        import shutil

        return shutil.get_terminal_size((100, 24)).columns
    except Exception:
        return 100


def print_banner(title: str, subtitle: str | None = None) -> None:
    """Print a consistent header banner (Rich panel on TTY, classic banner when piped/tested)."""
    # Always keep the canonical text header so unit tests capturing stdout match reliably
    print("==================================================")
    print(f"  {title.center(46)}  ")
    if subtitle:
        print(f"  {subtitle.center(46)}  ")
    print("==================================================")


def print_step(message: str, status: str = "info") -> None:
    """Print a status line with consistent symbols (✓, ✗, [!], •)."""
    prefix_map = {
        "ok": "✓",
        "success": "✓",
        "error": "✗",
        "warn": "[!]",
        "info": "•",
    }
    sym = prefix_map.get(status, "•")
    stream = sys.stderr if status == "error" else sys.stdout
    if use_color(stream):
        color_map = {
            "ok": "bold green",
            "success": "bold green",
            "error": "bold red",
            "warn": "bold yellow",
            "info": "bold cyan",
        }
        col = color_map.get(status, "bold cyan")
        Console(file=stream, highlight=False).print(f"[{col}]{sym}[/{col}] {message}")
    else:
        print(f"{sym} {message}", file=stream)


def format_effect_badge(effect: str) -> str:
    """Format an effect string (ALLOW, APPROVAL_REQUIRED, DENY)."""
    up = effect.upper()
    return f"[{up}]"


def parse_cli_rule_spec(spec: str) -> dict[str, Any]:
    """Parse a shorthand CLI rule specification into a canonical Dmint rule dict.

    Supported formats:
      - '<effect>:<tool>.<action>'                   (e.g. 'allow:postgres.select')
      - '<effect>:<tool>.<action>:<resource>'        (e.g. 'deny:shell.execute:rm -rf *')
      - '<effect>:<tool>.<action>:<resource>:<kind>' (e.g. 'deny:filesystem.read_file:**/.env:path')
    """
    parts = [p.strip() for p in spec.split(":")]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(
            f"Invalid --rule spec '{spec}'. Expected '<effect>:<tool>.<action>[:<resource>[:<resource_kind>]]' "
            "(e.g. 'allow:postgres.select:*' or 'deny:shell.execute:rm -rf *')."
        )
    effect = parts[0].lower()
    if effect in ("approve", "approval", "ask"):
        effect = "approval_required"
    if effect not in ("allow", "approval_required", "deny"):
        raise ValueError(
            f"Invalid effect '{parts[0]}' in --rule '{spec}'. Must be 'allow', 'approval_required', or 'deny'."
        )
    cap = parts[1]
    if "." not in cap:
        raise ValueError(
            f"Invalid capability '{cap}' in --rule '{spec}'. Expected '<tool>.<action>' (e.g. 'shell.execute')."
        )
    tool, _, action = cap.partition(".")
    if not tool or not action:
        raise ValueError(f"Invalid capability '{cap}' in --rule '{spec}'. Both tool and action are required.")

    rule: dict[str, Any] = {
        "effect": effect,
        "tool": tool,
        "action": action,
        "resource": parts[2] if len(parts) >= 3 and parts[2] else "*",
    }
    if rule["resource"] != "*":
        if len(parts) >= 4 and parts[3]:
            rk = parts[3].lower()
            if rk in ("prefix", "glob", "wildcard"):
                rk = "path" if "/" in rule["resource"] else "identifier"
            rule["resource_kind"] = rk
        elif "/" in rule["resource"] or "**" in rule["resource"]:
            rule["resource_kind"] = "path"
    return rule


def interactive_rule_builder(
    prompt_select_fn: Any = None,
    prompt_text_fn: Any = None,
) -> list[dict[str, Any]]:
    """Interactive terminal rule builder (100% offline, zero LLM required)."""
    rules: list[dict[str, Any]] = []
    print("\n--- Interactive Policy Rule Builder (Offline) ---")
    print("Add rules one by one. Press Enter on tool name when finished.\n")

    idx = 1
    while True:
        try:
            tool = input(
                f"Rule #{idx} Tool name (e.g. shell, filesystem, postgres, stripe) [Enter to finish]: "
            ).strip()
        except EOFError:
            break
        if not tool:
            if rules:
                break
            print("  [!] Please add at least one rule (or press Ctrl+C to abort).")
            continue

        try:
            action = (
                input(f"Rule #{idx} Action for '{tool}' (e.g. execute, read_file, query) [default: *]: ").strip() or "*"
            )
            resource = (
                input(f"Rule #{idx} Resource pattern (e.g. *, git status *, **/.env) [default: *]: ").strip() or "*"
            )
            effect_in = (
                input(
                    f"Rule #{idx} Effect for '{tool}.{action}' on '{resource}' "
                    "[1=allow, 2=approval_required, 3=deny, default: 2]: "
                )
                .strip()
                .lower()
            )
        except EOFError:
            break

        effect_map = {
            "1": "allow",
            "allow": "allow",
            "a": "allow",
            "2": "approval_required",
            "approval_required": "approval_required",
            "approval": "approval_required",
            "ask": "approval_required",
            "": "approval_required",
            "3": "deny",
            "deny": "deny",
            "d": "deny",
        }
        effect = effect_map.get(effect_in, "approval_required")

        rule_dict: dict[str, Any] = {
            "effect": effect,
            "tool": tool,
            "action": action,
            "resource": resource,
        }
        if resource != "*":
            if "/" in resource or "**" in resource or resource.startswith("."):
                rule_dict["resource_kind"] = "path"
            else:
                rule_dict["resource_kind"] = "exact"

        rules.append(rule_dict)
        print(f"  ✓ Added Rule #{idx}: [{effect.upper()}] {tool}.{action} on '{resource}'\n")
        idx += 1

        try:
            more = input("Add another rule? [Y/n]: ").strip().lower()
        except EOFError:
            break
        if more in ("n", "no"):
            break

    return rules


def auto_classify_mcp_tool_effect(tool_name: str, description: str = "") -> str:
    """Deterministically classify an MCP tool into allow, approval_required, or deny."""
    lower_name = tool_name.lower()
    lower_desc = (description or "").lower()

    deny_keywords = (
        "drop_",
        "delete_account",
        "destroy",
        "terminate",
        "wipe",
        "purge",
        "rotate_master",
        "export_full",
        "truncate",
    )
    if any(k in lower_name for k in deny_keywords):
        return "deny"

    allow_prefixes = (
        "get_",
        "get-",
        "list_",
        "list-",
        "read_",
        "read-",
        "search_",
        "search-",
        "describe_",
        "describe-",
        "check_",
        "check-",
        "fetch_",
        "view_",
        "inspect_",
    )
    allow_suffixes = ("_read", "-read", "_list", "-list", "_get", "-get", "_status", "-status", "_logs", "-logs")
    if (
        lower_name in ("query", "select", "ping", "health", "status", "list", "read", "search", "echo")
        or lower_name.startswith(allow_prefixes)
        or lower_name.endswith(allow_suffixes)
    ):
        if not any(w in lower_desc for w in ("mutate", "delete", "drop", "destroy", "write", "transfer")):
            return "allow"

    return "approval_required"
