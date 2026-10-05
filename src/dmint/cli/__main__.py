"""Entry point for dmint CLI command."""

from __future__ import annotations

import argparse
import sys

from dmint.cli.approvals import main_approve, main_pending, main_reject
from dmint.cli.compile_policy import main_compile
from dmint.cli.create_policy import main_create
from dmint.cli.dashboard import main_dashboard
from dmint.cli.install_skill import main_install_skill
from dmint.cli.verify_policy import main_verify
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


def main(args: list[str] | None = None) -> int:
    if args is None:
        args = sys.argv[1:]

    # Normalize subcommands: "create policy" -> "create-policy", "create mcp policy" / "create-mcp-policy" / "protect-mcp" -> "create-mcp-policy"
    normalized_args: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "create" and i + 2 < len(args) and args[i + 1] == "mcp" and args[i + 2] == "policy":
            normalized_args.append("create-mcp-policy")
            i += 3
            continue
        if arg == "create" and i + 1 < len(args) and args[i + 1] == "policy":
            normalized_args.append("create-policy")
            i += 2
            continue
        if arg == "create" and i + 1 < len(args) and args[i + 1] == "mcp-policy":
            normalized_args.append("create-mcp-policy")
            i += 2
            continue
        if arg == "protect-mcp":
            normalized_args.append("create-mcp-policy")
            i += 1
            continue
        if arg == "verify" and i + 1 < len(args) and args[i + 1] == "policy":
            normalized_args.append("verify-policy")
            i += 2
            continue
        if arg == "compile" and i + 1 < len(args) and args[i + 1] == "policy":
            normalized_args.append("compile-policy")
            i += 2
            continue
        if arg == "install" and i + 1 < len(args) and args[i + 1] in ("skill", "skills"):
            normalized_args.append("install-skill")
            i += 2
            continue
        if arg in ("install-skills", "install"):
            normalized_args.append("install-skill")
            i += 1
            continue
        normalized_args.append(arg)
        i += 1

    parser = argparse.ArgumentParser(
        prog="dmint",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""Dmint — Deterministic Security Enforcement & Policy Tooling.

Recommended Workflow:
  1. Author Policy:
     - For external MCP servers:  dmint create-mcp-policy
     - For custom/local tools:    dmint create-policy
  2. Verify Policy:
     - Deterministic offline:     dmint verify-policy <policy.json>""",
        epilog="""Primary Commands:
  create-policy       General policy authoring wizard (converts natural language requirements into verified policy.json)
  create-mcp-policy   Specialized MCP workflow: live tool discovery + policy authoring + mcp_protection.json generation
  verify-policy       Deterministic offline validation of policy.json against Dmint schema and invariants (LLM-free)
  install-skill       Install Dmint AI coding agent skill into workspace (.agents/skills/) or global config
  dashboard           Launch the local human approval dashboard (connects to Core SQLite)

Approval Commands (Terminal Management):
  pending             List all approvals currently in PENDING state
  approve             Approve a pending tool execution request with optional audit note
  reject              Reject a pending tool execution request with optional audit note

Compatibility Commands:
  compile-policy      [Compatibility] Legacy batch compilation of policy requirements (prefer 'create-policy')
  protect-mcp         [Compatibility alias] Alias for 'create-mcp-policy'
""",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit",
    )
    subparsers = parser.add_subparsers(dest="command", title="Available Commands", help="Command to run")

    subparsers.add_parser(
        "create-policy",
        help="General policy authoring wizard (converts requirements into verified policy.json)",
        add_help=False,
    )
    subparsers.add_parser(
        "create-mcp-policy",
        help="Specialized MCP workflow: live tool discovery + policy authoring + mcp_protection.json generation",
        add_help=False,
    )
    subparsers.add_parser(
        "verify-policy",
        help="Deterministic offline validation of policy.json against Dmint schema and invariants (LLM-free)",
        add_help=False,
    )
    subparsers.add_parser(
        "install-skill",
        help="Install Dmint AI coding agent skill into workspace (.agents/skills/) or global config",
        add_help=False,
    )
    subparsers.add_parser(
        "dashboard",
        help="Launch the local human approval dashboard (connects to Core SQLite)",
        add_help=False,
    )
    subparsers.add_parser(
        "pending",
        help="List all approvals currently in PENDING state",
        add_help=False,
    )
    subparsers.add_parser(
        "approve",
        help="Approve a pending tool execution request with optional audit note",
        add_help=False,
    )
    subparsers.add_parser(
        "reject",
        help="Reject a pending tool execution request with optional audit note",
        add_help=False,
    )
    subparsers.add_parser(
        "compile-policy",
        help="[Compatibility] Legacy batch compilation of policy requirements (prefer 'create-policy')",
        add_help=False,
    )
    subparsers.add_parser(
        "protect-mcp",
        help="[Compatibility alias] Alias for 'create-mcp-policy'",
        add_help=False,
    )

    if not normalized_args or normalized_args[0] in ("-h", "--help"):
        parser.print_help()
        return 0

    if normalized_args[0] in ("-v", "--version", "-V", "version"):
        print(f"dmint {__version__}")
        return 0

    cmd = normalized_args[0]
    cmd_args = normalized_args[1:]

    if cmd == "create-policy":
        return main_create(cmd_args)
    elif cmd == "create-mcp-policy":
        return _run_create_mcp(cmd_args)
    elif cmd == "verify-policy":
        return main_verify(cmd_args)
    elif cmd == "compile-policy":
        return main_compile(cmd_args)
    elif cmd == "install-skill":
        return main_install_skill(cmd_args)
    elif cmd == "dashboard":
        return main_dashboard(cmd_args)
    elif cmd == "pending":
        return main_pending(cmd_args)
    elif cmd == "approve":
        return main_approve(cmd_args)
    elif cmd == "reject":
        return main_reject(cmd_args)
    else:
        parser.print_help(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
