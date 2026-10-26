"""CLI command 'dmint logs' (alias: 'dmint audit') for viewing, filtering, tailing, exporting, and verifying tamper-evident audit logs."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import csv
import json
from pathlib import Path
import sys
import time
from typing import Any

from dmint.cli.ui import DmintHelpFormatter, use_color
from dmint.core.audit import (
    GENESIS_PREV_HASH,
    parse_log_level,
    read_audit_entries,
    resolve_default_audit_log_path,
    summarize_audit_entries,
    verify_audit_chain,
)


def _format_entry_line(entry: dict[str, Any]) -> str:
    seq = entry.get("seq", "?")
    ts = str(entry.get("timestamp", ""))[11:19]  # HH:MM:SS
    lvl = str(entry.get("level", "INFO")).ljust(8)
    dec = str(entry.get("decision", "")).ljust(17)
    har = str(entry.get("harness", "sdk")).ljust(11)
    cap = f"{entry.get('tool', '')}.{entry.get('action', '')}"
    res = str(entry.get("resource") if entry.get("resource") is not None else "-")
    if len(res) > 36:
        res = res[:33] + "..."
    mode = entry.get("mode", "enforce")
    mode_tag = " [SHADOW]" if entry.get("shadow_would_block") or mode == "shadow" else ""
    ehash = str(entry.get("entry_hash", ""))[:10]
    return f"#{seq:<4} {ts}  {lvl} {dec} {har} {cap:<24} {res:<36} {ehash}{mode_tag}"


def _render_entries_table(entries: list[dict[str, Any]], log_path: Path) -> None:
    if not entries:
        print(f"No matching audit log entries in {log_path}.")
        return

    if use_color():
        try:
            from rich.console import Console
            from rich.table import Table

            console = Console()
            table = Table(
                title=f"Dmint Tamper-Evident Audit Trail ({log_path})",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Seq", justify="right", style="dim")
            table.add_column("Time (UTC)", style="dim")
            table.add_column("Level")
            table.add_column("Decision")
            table.add_column("Harness", style="magenta")
            table.add_column("Capability", style="bold")
            table.add_column("Resource")
            table.add_column("Code", style="dim")
            table.add_column("SHA-256 Chain", style="dim")

            level_styles = {
                "DEBUG": "dim",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "bold red",
                "CRITICAL": "bold white on red",
            }
            dec_styles = {
                "ALLOW": "green",
                "APPROVED": "bold green",
                "CONSUMED": "cyan",
                "APPROVAL_REQUIRED": "yellow",
                "REJECTED": "red",
                "DENY": "bold red",
            }

            for e in entries:
                lvl = str(e.get("level", "INFO")).upper()
                dec = str(e.get("decision", "")).upper()
                if e.get("shadow_would_block"):
                    dec_disp = f"{dec} (SHADOW)"
                else:
                    dec_disp = dec
                res = str(e.get("resource") if e.get("resource") is not None else "-")
                if len(res) > 42:
                    res = res[:39] + "..."
                table.add_row(
                    f"#{e.get('seq', '?')}",
                    str(e.get("timestamp", ""))[11:19],
                    f"[{level_styles.get(lvl, 'white')}]{lvl}[/]",
                    f"[{dec_styles.get(dec, 'white')}]{dec_disp}[/]",
                    str(e.get("harness", "sdk")),
                    f"{e.get('tool', '')}.{e.get('action', '')}",
                    res,
                    str(e.get("code", "")),
                    str(e.get("entry_hash", ""))[:10],
                )
            console.print(table)
            return
        except Exception:
            pass

    header = f"{'SEQ':<5} {'TIME':<8}  {'LEVEL':<8} {'DECISION':<17} {'HARNESS':<11} {'CAPABILITY':<24} {'RESOURCE':<36} {'CHAIN_HASH'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(_format_entry_line(e))


def main_logs(argv: Sequence[str] | None = None) -> int:
    """Entry point for 'dmint logs' / 'dmint audit'."""
    parser = argparse.ArgumentParser(
        prog="dmint logs",
        formatter_class=DmintHelpFormatter,
        description="Inspect, filter, tail, export, and cryptographically verify the tamper-evident Dmint audit trail (.dmint/audit.jsonl).",
        epilog="""Examples:
  dmint logs                                   # Show the last 50 audit entries
  dmint logs --level WARNING                   # Show only WARNING, ERROR, and CRITICAL events
  dmint logs --denied                          # Show only blocked (DENY) tool calls
  dmint logs --harness claude-code --tool bash # Filter by coding harness and tool
  dmint logs --verify                          # Cryptographically verify the SHA-256 hash chain
  dmint logs --stats                           # Show decision, level, and top-blocked breakdown
  dmint logs --follow                          # Live tail new agent tool calls in real time
  dmint logs --export audit_report.csv         # Export filtered audit trail to CSV or JSON
""",
    )
    parser.add_argument(
        "--file", "--log-file", dest="log_file", help="Path to audit.jsonl file (default: .dmint/audit.jsonl)"
    )
    parser.add_argument("--dir", "-C", default=".", help="Workspace directory containing .dmint/audit.jsonl")
    parser.add_argument(
        "-l",
        "--level",
        "--log-level",
        dest="level",
        help="Minimum log level filter: DEBUG, INFO, WARNING, ERROR, CRITICAL",
    )
    parser.add_argument(
        "-d",
        "--decision",
        help="Filter by decision: ALLOW, APPROVAL_REQUIRED, DENY, APPROVED, REJECTED, CONSUMED",
    )
    parser.add_argument("--denied", action="store_true", help="Shorthand for --decision DENY")
    parser.add_argument("-t", "--tool", help="Filter by tool name or <tool.action> substring")
    parser.add_argument("--harness", help="Filter by harness (e.g. claude-code, codex, opencode, cursor, sdk, mcp)")
    parser.add_argument("--agent", help="Filter by agent_id")
    parser.add_argument("--mode", choices=["enforce", "shadow"], help="Filter by enforcement mode (enforce or shadow)")
    parser.add_argument(
        "-s", "--search", help="Case-insensitive substring search across resource, tool, code, or details"
    )
    parser.add_argument(
        "-n", "--limit", type=int, default=50, help="Maximum number of recent entries to show (0 for all, default: 50)"
    )
    parser.add_argument(
        "--verify", action="store_true", help="Verify the cryptographic SHA-256 hash chain from genesis to head"
    )
    parser.add_argument("--stats", action="store_true", help="Display summary statistics across matching audit events")
    parser.add_argument(
        "-f", "--follow", action="store_true", help="Live-tail new audit log entries as they are recorded"
    )
    parser.add_argument("--export", metavar="PATH", help="Export matching entries to a .json or .csv file")
    parser.add_argument("--clear", action="store_true", help="Clear the current audit.jsonl file")
    parser.add_argument("--json", action="store_true", help="Emit output as JSON")

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    if args.level:
        try:
            parse_log_level(args.level)
        except ValueError as exc:
            print(f"✗ {exc}", file=sys.stderr)
            return 2

    log_path = Path(args.log_file).resolve() if args.log_file else resolve_default_audit_log_path(args.dir)

    if args.clear:
        if log_path.exists():
            log_path.unlink()
        if args.json:
            print(json.dumps({"cleared": True, "file": str(log_path)}, indent=2))
        else:
            print(f"✓ Cleared audit log: {log_path}")
        return 0

    if args.verify:
        res = verify_audit_chain(log_path)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            if res.valid:
                print(
                    f"✓ Audit hash chain verified ({log_path}): "
                    f"{res.total_entries} entry(s) intact | head={res.head_hash[:16]}..."
                )
            else:
                print(f"✗ Audit hash chain TAMPERED ({log_path}): {res.error}", file=sys.stderr)
        return 0 if res.valid else 1

    decision_filter = "DENY" if args.denied else args.decision

    entries = read_audit_entries(
        log_path,
        min_level=args.level,
        decision=decision_filter,
        tool=args.tool,
        harness=args.harness,
        agent_id=args.agent,
        mode=args.mode,
        search=args.search,
        limit=args.limit if not (args.stats or args.export) else (args.limit if args.limit != 50 else 0),
    )

    if args.export:
        export_path = Path(args.export).resolve()
        export_path.parent.mkdir(parents=True, exist_ok=True)
        if export_path.suffix.lower() == ".csv":
            fieldnames = [
                "seq",
                "timestamp",
                "level",
                "event_type",
                "decision",
                "code",
                "harness",
                "agent_id",
                "tool",
                "action",
                "resource",
                "mode",
                "shadow_would_block",
                "approval_id",
                "latency_ms",
                "prev_hash",
                "entry_hash",
            ]
            with export_path.open("w", newline="", encoding="utf-8") as cf:
                writer = csv.DictWriter(cf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for e in entries:
                    writer.writerow(e)
        else:
            export_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps({"exported": len(entries), "path": str(export_path)}, indent=2))
        else:
            print(f"✓ Exported {len(entries)} audit entry(s) to {export_path}")
        return 0

    if args.stats:
        summary = summarize_audit_entries(entries)
        chain_check = verify_audit_chain(log_path)
        summary["chain_valid"] = chain_check.valid
        summary["head_hash"] = chain_check.head_hash
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"\n=== Dmint Audit Trail Statistics ({log_path}) ===")
            print(f"  Total Matching Events : {summary['total_events']}")
            print(
                f"  Chain Integrity       : {'✓ VALID' if chain_check.valid else '✗ BROKEN'} (head: {chain_check.head_hash[:12]}...)"
            )
            print(f"  Decisions             : {summary['by_decision']}")
            print(f"  Log Levels            : {summary['by_level']}")
            print(f"  Harnesses             : {summary['by_harness']}")
            if summary["shadow_would_block_count"]:
                print(f"  Shadow Mode Blocks    : {summary['shadow_would_block_count']}")
            if summary["top_capabilities"]:
                print("  Top Capabilities      :")
                for cap, cnt in summary["top_capabilities"].items():
                    print(f"    - {cap}: {cnt}")
            if summary["top_blocked_resources"]:
                print("  Top Blocked Resources :")
                for res, cnt in summary["top_blocked_resources"].items():
                    print(f"    - {res}: {cnt}")
            print()
        return 0

    if args.json and not args.follow:
        print(json.dumps(entries, indent=2))
        return 0

    _render_entries_table(entries, log_path)

    if args.follow:
        seen_seq = entries[-1]["seq"] if entries else 0
        print(f"\n--- Following live audit events from {log_path} (Ctrl+C to stop) ---")
        try:
            while True:
                new_entries = [
                    e
                    for e in read_audit_entries(
                        log_path,
                        min_level=args.level,
                        decision=decision_filter,
                        tool=args.tool,
                        harness=args.harness,
                        agent_id=args.agent,
                        mode=args.mode,
                        search=args.search,
                        limit=0,
                    )
                    if int(e.get("seq", 0)) > seen_seq
                ]
                for e in new_entries:
                    seen_seq = int(e.get("seq", seen_seq))
                    if args.json:
                        print(json.dumps(e), flush=True)
                    else:
                        print(_format_entry_line(e), flush=True)
                time.sleep(0.25)
        except KeyboardInterrupt:
            return 0

    return 0


def main_learn_policy(argv: Sequence[str] | None = None) -> int:
    """Entry point for 'dmint learn-policy' — synthesize a verified policy.json from .dmint/audit.jsonl."""
    from dmint.cli.verify_policy import verify_policy_file
    from dmint.core.audit import learn_policy_from_audit_logs
    from dmint.cli.create_policy import atomic_write_policy_json
    from dmint.core.policy import Policy
    from dmint.templates import deduplicate_policy_dict

    parser = argparse.ArgumentParser(
        prog="dmint learn-policy",
        formatter_class=DmintHelpFormatter,
        description="Auto-learn a least-privilege, verified policy.json from observed agent activity in .dmint/audit.jsonl (Shadow or Enforce mode).",
        epilog="""Examples:
  dmint learn-policy                                      # Learn from .dmint/audit.jsonl -> policy.json
  dmint learn-policy --from-logs .dmint/audit.jsonl -o learned_policy.json
""",
    )
    parser.add_argument(
        "--from-logs",
        "-f",
        "--file",
        dest="log_file",
        default=None,
        help="Path to audit.jsonl file (default: .dmint/audit.jsonl)",
    )
    parser.add_argument("--dir", "-C", default=".", help="Workspace directory containing .dmint/audit.jsonl")
    parser.add_argument(
        "-o", "--output", default="policy.json", help="Destination policy JSON file (default: policy.json)"
    )
    parser.add_argument("--json", action="store_true", help="Output summary as JSON")

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    log_path = Path(args.log_file).resolve() if args.log_file else resolve_default_audit_log_path(args.dir)
    if not log_path.exists():
        print(f"✗ Audit log not found: {log_path}. Run your agent in shadow or enforce mode first.", file=sys.stderr)
        return 1

    learned_rules = learn_policy_from_audit_logs(log_path)
    merged = deduplicate_policy_dict({"rules": learned_rules, "strict_arguments": False})
    verified_policy = Policy.from_mapping({"rules": merged["rules"]})
    out_path = Path(args.output).resolve()
    atomic_write_policy_json(out_path, verified_policy)
    verify_policy_file(out_path)

    counts = {"allow": 0, "approval_required": 0, "deny": 0}
    for r in verified_policy.rules:
        counts[r.effect.value] = counts.get(r.effect.value, 0) + 1

    if args.json:
        print(
            json.dumps(
                {
                    "source_log": str(log_path),
                    "output_policy": str(out_path),
                    "total_rules": len(verified_policy.rules),
                    "counts": counts,
                },
                indent=2,
            )
        )
    else:
        print(
            f"✓ Learned & verified policy from {log_path} -> {out_path} "
            f"({len(verified_policy.rules)} rule(s): {counts['allow']} allow, "
            f"{counts['approval_required']} approval_required, {counts['deny']} deny)"
        )
    return 0
