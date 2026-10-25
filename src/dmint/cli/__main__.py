"""Entry point for the Dmint CLI command."""

from __future__ import annotations

import argparse
import os
import sys

from dmint.cli.ui import DmintHelpFormatter
from dmint.cli.version import __version__


def _run_create_mcp(args: list[str]) -> int:
    try:
        from dmint.cli.create_mcp_policy import main_create_mcp

        return main_create_mcp(args)
    except ImportError as exc:
        print(
            f"Error: MCP support requires additional dependencies ({exc}).\nInstall with: pip install 'dmint[mcp]'",
            file=sys.stderr,
        )
        return 1


def _normalize_cli_args(args: list[str]) -> list[str]:
    """Normalize multi-word subcommands and global flags while preserving subcommand arguments."""
    cleaned: list[str] = []
    idx = 0
    while idx < len(args):
        a = args[idx]
        if a == "--no-color":
            os.environ["NO_COLOR"] = "1"
            idx += 1
            continue
        if a.startswith("--log-level="):
            os.environ["DMINT_LOG_LEVEL"] = a.split("=", 1)[1].strip().upper()
            idx += 1
            continue
        cleaned.append(a)
        idx += 1

    if not cleaned:
        return []

    # Only normalize the top-level subcommand at position 0 (never rewrite subcommand args like 'dmint hook install')
    first = cleaned[0]
    rest = cleaned[1:]

    if first == "create" and len(rest) >= 2 and rest[0] == "mcp" and rest[1] == "policy":
        return ["create-mcp-policy", *rest[2:]]
    if first == "create" and len(rest) >= 1 and rest[0] == "policy":
        return ["create-policy", *rest[1:]]
    if first == "create" and len(rest) >= 1 and rest[0] == "mcp-policy":
        return ["create-mcp-policy", *rest[1:]]
    if first == "protect-mcp":
        return ["create-mcp-policy", *rest]
    if first == "deny":
        return ["reject", *rest]
    if first == "audit":
        return ["logs", *rest]
    if first in ("redteam", "attack-sim"):
        return ["demo", *rest]
    if first == "verify" and len(rest) >= 1 and rest[0] == "policy":
        return ["verify-policy", *rest[1:]]
    if first == "compile" and len(rest) >= 1 and rest[0] == "policy":
        return ["compile-policy", *rest[1:]]
    if first == "install" and len(rest) >= 1 and rest[0] in ("skill", "skills"):
        return ["install-skill", *rest[1:]]
    if first in ("install-skills", "install"):
        return ["install-skill", *rest]
    if first in ("test-policy", "check-policy"):
        return ["check", *rest]
    if first == "hooks":
        return ["hook", *rest]
    if first == "self-test":
        return ["doctor", *rest]
    return cleaned


_TOP_LEVEL_EPILOG = """Available Commands:

Primary Commands (Quickstart & Runtime Protection):
  init                1-command zero-config project setup (keys, starter policy.json, and agent harness hooks)
  doctor              Verify keys, SQLite store, per-harness policies, hooks, and run a 4-vector security self-test
  status              Show installed agent harness hooks, policy paths, and key status
  logs                Inspect, filter, tail, export, and verify the tamper-evident SHA-256 audit log (alias: audit)
  demo                Run a live 7-scenario red-team attack & cryptographic simulation (alias: redteam)
  check               Simulate and test tool calls against policy.json directly from the terminal
  hook                Install, inspect, and run PreToolUse hooks for Claude Code, Codex, OpenCode, Cursor, Windsurf & Cline

Policy Authoring & Verification Commands:
  create-policy       Create a verified policy.json (via templates, inline rules, audit logs, interactive builder, or AI wizard)
  learn-policy        Auto-learn a verified least-privilege policy.json from observed .dmint/audit.jsonl activity
  create-mcp-policy   Discover tools from live MCP servers, pin SHA-256 schemas, and generate policy.json + mcp_protection.json
  verify-policy       Deterministic offline validation of policy.json against Dmint schema and invariants (LLM-free)
  policy-digest       Compute the canonical SHA-256 hex digest of exact policy file bytes

Approval & Dashboard Commands (Human-in-the-Loop):
  pending             List all tool execution requests currently awaiting approval in PENDING state
  approve             Approve a pending tool execution request with an Ed25519 single-use assertion
  reject              Reject a pending tool execution request with an optional audit note
  dashboard           Launch the local authenticated web approval dashboard (http://127.0.0.1:8080)

Key Management & Agent Skill Commands:
  init-keys           Generate and persist an Ed25519 signing key and HMAC integrity key (0600, atomic)
  export-public-key   Print the public key (hex + PEM + JSON) and issuer ID for gateway trusted_issuers
  install-skill       Install the Dmint AI coding agent skill into workspace (.agents/skills/) or global config

Compatibility Commands:
  compile-policy      [Compatibility] Legacy batch compilation of policy requirements (prefer 'create-policy')
  protect-mcp         [Compatibility alias] Alias for 'create-mcp-policy'

Examples:
  dmint init --harness all --templates shell,filesystem,postgres
  dmint doctor
  dmint check -t shell.execute -r "git status"
  dmint create-policy --template shell,filesystem -o policy.json
  dmint create-policy --rule "allow:postgres.select:*" --rule "deny:shell.execute:rm -rf *" -o policy.json
  dmint create-mcp-policy --command npx --args -y @modelcontextprotocol/server-postgres --offline -y
  dmint pending
  dmint approve <approval_id> --by alice@company.com
"""


def _build_top_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dmint",
        formatter_class=DmintHelpFormatter,
        usage="dmint [-h] [-V] [--no-color] <command> [options]",
        description="""Dmint — Deterministic Authorization & Cryptographic Enforcement for AI Agents.

Recommended Workflow:
  1. Quickstart Setup:
     - Coding agent hooks & keys: dmint init --harness all
     - Verify local setup:        dmint doctor
  2. Author Policy:
     - For external MCP servers:  dmint create-mcp-policy
     - For custom/local tools:    dmint create-policy
  3. Verify & Simulate Policy:
     - Deterministic offline:     dmint verify-policy policy.json
     - Test a tool call:          dmint check -t shell.execute -r "git status" """,
        epilog=_TOP_LEVEL_EPILOG,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )
    return parser


def main(args: list[str] | None = None) -> int:
    if args is None:
        args = sys.argv[1:]

    normalized_args = _normalize_cli_args(list(args))
    parser = _build_top_parser()

    if not normalized_args or normalized_args[0] in ("-h", "--help", "help"):
        if len(normalized_args) >= 2 and normalized_args[0] == "help":
            # Support 'dmint help <subcommand>'
            return main([normalized_args[1], "--help", *normalized_args[2:]])
        parser.print_help()
        return 0

    if normalized_args[0] in ("-v", "--version", "-V", "version"):
        print(f"dmint {__version__}")
        return 0

    cmd = normalized_args[0]
    cmd_args = normalized_args[1:]

    if cmd == "init":
        from dmint.cli.hooks import main_init

        return main_init(cmd_args)
    elif cmd == "check":
        from dmint.cli.hooks import main_check

        return main_check(cmd_args)
    elif cmd == "doctor":
        from dmint.cli.hooks import main_doctor

        return main_doctor(cmd_args)
    elif cmd == "hook":
        from dmint.cli.hooks import main_hook

        return main_hook(cmd_args)
    elif cmd == "create-policy":
        from dmint.cli.create_policy import main_create

        return main_create(cmd_args)
    elif cmd == "create-mcp-policy":
        return _run_create_mcp(cmd_args)
    elif cmd == "verify-policy":
        from dmint.cli.verify_policy import main_verify

        return main_verify(cmd_args)
    elif cmd == "policy-digest":
        from dmint.cli.policy_digest import main_policy_digest

        return main_policy_digest(cmd_args)
    elif cmd == "compile-policy":
        from dmint.cli.compile_policy import main_compile

        return main_compile(cmd_args)
    elif cmd == "install-skill":
        from dmint.cli.install_skill import main_install_skill

        return main_install_skill(cmd_args)
    elif cmd == "dashboard":
        from dmint.cli.dashboard import main_dashboard

        return main_dashboard(cmd_args)
    elif cmd == "init-keys":
        from dmint.cli.keys import main_init_keys

        return main_init_keys(cmd_args)
    elif cmd == "export-public-key":
        from dmint.cli.keys import main_export_public_key

        return main_export_public_key(cmd_args)
    elif cmd == "pending":
        from dmint.cli.approvals import main_pending

        return main_pending(cmd_args)
    elif cmd == "approve":
        from dmint.cli.approvals import main_approve

        return main_approve(cmd_args)
    elif cmd == "reject":
        from dmint.cli.approvals import main_reject

        return main_reject(cmd_args)
    elif cmd == "status":
        from dmint.cli.hooks import main_hook as _main_hook_status

        return _main_hook_status(["status", *cmd_args])
    elif cmd == "logs":
        from dmint.cli.logs import main_logs

        return main_logs(cmd_args)
    elif cmd == "demo":
        from dmint.cli.demo import main_demo

        return main_demo(cmd_args)
    elif cmd == "learn-policy":
        from dmint.cli.logs import main_learn_policy

        return main_learn_policy(cmd_args)
    else:
        print(f"dmint: error: unknown command '{cmd}'. See 'dmint --help' for Available Commands.\n", file=sys.stderr)
        parser.print_help(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
