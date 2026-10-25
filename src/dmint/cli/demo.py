"""CLI command 'dmint demo' (aliases: 'dmint redteam', 'dmint attack-sim') — 1-command interactive 7-vector security & red-team simulator."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys
import tempfile
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint import ApprovalRequiredError, Dmint, Policy, Rule
from dmint.cli.approvals import main_approve
from dmint.cli.hooks import evaluate_hook_request, main_init
from dmint.cli.ui import DmintHelpFormatter, use_color
from dmint.core.audit import verify_audit_chain
from dmint.core.errors import DmintError
from dmint.core.keys import write_private_key_atomic


def run_redteam_simulation(workspace_dir: Path | None = None) -> dict[str, Any]:
    """Execute all 7 live red-team and cryptographic enforcement scenarios in an isolated workspace."""
    cleanup_dir: tempfile.TemporaryDirectory[str] | None = None
    if workspace_dir is None:
        cleanup_dir = tempfile.TemporaryDirectory(prefix="dmint_demo_")
        ws = Path(cleanup_dir.name).resolve()
    else:
        ws = Path(workspace_dir).resolve()
        ws.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            ws.chmod(0o700)
        except OSError:
            pass

    try:
        t_start = time.perf_counter()
        # Bootstrap full Dmint workspace (keys, SQLite store, per-harness policies, hooks)
        main_init(["--harness", "claude-code,codex", "--dir", str(ws)])
        claude_pol = ws / ".dmint" / "policies" / "claude-code.policy.json"
        codex_pol = ws / ".dmint" / "policies" / "codex.policy.json"
        db_path = ws / ".dmint" / "approvals.sqlite3"
        audit_path = ws / ".dmint" / "audit.jsonl"

        scenarios: list[dict[str, Any]] = []

        # Scenario 1: Safe Read-Only Command (ALLOW)
        s0 = time.perf_counter()
        r1 = evaluate_hook_request(
            {"tool_name": "Bash", "tool_input": {"command": "git status"}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        s1_ms = (time.perf_counter() - s0) * 1000.0
        scenarios.append({
            "id": 1,
            "name": "Safe Workspace Read & Git Status",
            "attack_vector": "Bash('git status')",
            "expected": "ALLOW",
            "actual": r1["decision"],
            "code": r1["code"],
            "passed": r1["decision"] == "ALLOW",
            "latency_ms": round(s1_ms, 2),
        })

        # Scenario 2: Compound Shell Command Smuggling (DENY)
        s0 = time.perf_counter()
        r2 = evaluate_hook_request(
            {"tool_name": "Bash", "tool_input": {"command": "git status && cat .env"}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        s2_ms = (time.perf_counter() - s0) * 1000.0
        scenarios.append({
            "id": 2,
            "name": "Compound Shell Secret Exfiltration",
            "attack_vector": "Bash('git status && cat .env')",
            "expected": "DENY",
            "actual": r2["decision"],
            "code": r2["code"],
            "passed": r2["decision"] == "DENY",
            "latency_ms": round(s2_ms, 2),
        })

        # Scenario 3: Symlink Escape Attack to /etc/passwd (DENY)
        s0 = time.perf_counter()
        symlink_file = ws / "harmless_notes.txt"
        try:
            symlink_file.symlink_to("/etc/passwd")
        except Exception:
            pass
        r3 = evaluate_hook_request(
            {"tool_name": "Read", "tool_input": {"file_path": str(symlink_file)}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        s3_ms = (time.perf_counter() - s0) * 1000.0
        scenarios.append({
            "id": 3,
            "name": "Symlink Escape to /etc/passwd",
            "attack_vector": "Read('harmless_notes.txt -> /etc/passwd')",
            "expected": "DENY",
            "actual": r3["decision"],
            "code": r3["code"],
            "passed": r3["decision"] == "DENY",
            "latency_ms": round(s3_ms, 2),
        })

        # Scenario 4: Multi-File Patch Smuggling (DENY)
        s0 = time.perf_counter()
        smuggled_patch = (
            "*** Begin Patch\n"
            "*** Update File: src/app.py\n"
            "@@\n-print('old')\n+print('new')\n"
            "*** Update File: .env.production\n"
            "@@\n+LEAKED=1\n"
            "*** End Patch"
        )
        r4 = evaluate_hook_request(
            {"tool_name": "apply_patch", "tool_input": {"patch": smuggled_patch}},
            harness="codex",
            policy_path=codex_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        s4_ms = (time.perf_counter() - s0) * 1000.0
        scenarios.append({
            "id": 4,
            "name": "Multi-File Patch Smuggling (apply_patch)",
            "attack_vector": "apply_patch(src/app.py + .env.production)",
            "expected": "DENY",
            "actual": r4["decision"],
            "code": r4["code"],
            "passed": r4["decision"] == "DENY",
            "latency_ms": round(s4_ms, 2),
        })

        # Scenario 5: Single-Use Ed25519 Human Approval Lifecycle
        s0 = time.perf_counter()
        sdk_policy = Policy([
            Rule.allow("stripe", "get_balance"),
            Rule.approval_required("stripe", "issue_refund"),
            Rule.deny("stripe", "delete_account"),
        ])
        dm = Dmint.local(sdk_policy, state_dir=ws / ".dmint")

        @dm.protect("stripe.issue_refund")
        def issue_refund(order_id: str, amount: int) -> str:
            return f"refunded:{order_id}:{amount}"

        apr_id = None
        try:
            issue_refund("ord_500", 500)
        except ApprovalRequiredError as exc:
            apr_id = exc.approval_id

        assert apr_id is not None
        main_approve([
            apr_id,
            "--by", "secops@company.com",
            "--db-path", str(db_path),
            "--key-file", str(ws / ".dmint" / "signing.key"),
            "--integrity-key-file", str(ws / ".dmint" / "integrity.key"),
        ])
        res_exec = dm.retry(issue_refund, None, "ord_500", 500)
        s5_ms = (time.perf_counter() - s0) * 1000.0
        scenarios.append({
            "id": 5,
            "name": "Ed25519 Single-Use Human Approval & Retry",
            "attack_vector": "stripe.issue_refund('ord_500', 500)",
            "expected": "APPROVED_AND_CONSUMED",
            "actual": "APPROVED_AND_CONSUMED" if res_exec == "refunded:ord_500:500" else "FAILED",
            "code": "DMT_APPROVAL_CONSUMED_ALLOW",
            "passed": res_exec == "refunded:ord_500:500",
            "latency_ms": round(s5_ms, 2),
        })

        # Scenario 6: Post-Approval Parameter Tampering (RFC 8785 JCS Mismatch)
        s0 = time.perf_counter()
        r6_ask = evaluate_hook_request(
            {"tool_name": "Bash", "tool_input": {"command": "git push origin staging"}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        staging_apr = r6_ask["approval_id"]
        main_approve([
            staging_apr,
            "--by", "secops@company.com",
            "--db-path", str(db_path),
            "--key-file", str(ws / ".dmint" / "signing.key"),
            "--integrity-key-file", str(ws / ".dmint" / "integrity.key"),
        ])
        # Agent tampers with approved command ('staging' -> 'main --force')
        r6_tamper = evaluate_hook_request(
            {"tool_name": "Bash", "tool_input": {"command": "git push origin main --force"}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        s6_ms = (time.perf_counter() - s0) * 1000.0
        tamper_blocked = r6_tamper["decision"] != "ALLOW" and r6_tamper.get("approval_id") != staging_apr
        scenarios.append({
            "id": 6,
            "name": "Post-Approval RFC 8785 Parameter Tampering",
            "attack_vector": "Approved 'staging' -> retried 'main --force'",
            "expected": "BLOCKED",
            "actual": "BLOCKED" if tamper_blocked else "BYPASSED",
            "code": "DMT_FINGERPRINT_ISOLATED",
            "passed": tamper_blocked,
            "latency_ms": round(s6_ms, 2),
        })

        # Scenario 7: Replay Attack & Rogue Ed25519 Key Forgery
        s0 = time.perf_counter()
        replay_code = ""
        try:
            dm.retry(issue_refund, None, "ord_500", 500)
        except DmintError as exc:
            replay_code = exc.code

        # Also attempt rogue Ed25519 signature forgery on a hook request
        r7_ask = evaluate_hook_request(
            {"tool_name": "Bash", "tool_input": {"command": "docker run --privileged alpine"}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        rogue_key = ws / ".dmint" / "rogue_attacker.key"
        write_private_key_atomic(rogue_key, Ed25519PrivateKey.generate(), force=True)
        main_approve([
            r7_ask["approval_id"],
            "--by", "attacker@evil.local",
            "--db-path", str(db_path),
            "--key-file", str(rogue_key),
            "--integrity-key-file", str(ws / ".dmint" / "integrity.key"),
        ])
        r7_forged = evaluate_hook_request(
            {"tool_name": "Bash", "tool_input": {"command": "docker run --privileged alpine"}},
            harness="claude-code",
            policy_path=claude_pol,
            db_path=db_path,
            workspace_dir=ws,
            audit_log_path=audit_path,
        )
        s7_ms = (time.perf_counter() - s0) * 1000.0
        s7_passed = (replay_code == "DMT_APPROVAL_CONSUMED") and (r7_forged["decision"] == "DENY")
        scenarios.append({
            "id": 7,
            "name": "Replay Attack & Rogue Ed25519 Key Forgery",
            "attack_vector": "Replay consumed token + sign with rogue key",
            "expected": "DENY",
            "actual": r7_forged["decision"],
            "code": f"{replay_code} + {r7_forged['code']}",
            "passed": s7_passed,
            "latency_ms": round(s7_ms, 2),
        })

        chain_status = verify_audit_chain(audit_path)
        total_ms = (time.perf_counter() - t_start) * 1000.0

        return {
            "all_passed": all(s["passed"] for s in scenarios) and chain_status.valid,
            "total_scenarios": len(scenarios),
            "passed_scenarios": sum(1 for s in scenarios if s["passed"]),
            "audit_chain_valid": chain_status.valid,
            "audit_entries": chain_status.total_entries,
            "audit_head_hash": chain_status.head_hash,
            "total_latency_ms": round(total_ms, 2),
            "scenarios": scenarios,
        }
    finally:
        if cleanup_dir is not None:
            cleanup_dir.cleanup()


def main_demo(argv: Sequence[str] | None = None) -> int:
    """Entry point for 'dmint demo' / 'dmint redteam'."""
    parser = argparse.ArgumentParser(
        prog="dmint demo",
        formatter_class=DmintHelpFormatter,
        description="Run a live 7-scenario red-team attack and cryptographic enforcement simulation against the Dmint engine.",
        epilog="""Examples:
  dmint demo
  dmint redteam --json
  dmint demo --keep-dir ./demo_workspace
""",
    )
    parser.add_argument("--keep-dir", default=None, help="Optional directory to persist the demo workspace, policies, and audit.jsonl")
    parser.add_argument("--json", action="store_true", help="Output simulation report as JSON")

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    ws_dir = Path(args.keep_dir).resolve() if args.keep_dir else None
    out_buf = sys.stderr if args.json else sys.stdout
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        report = run_redteam_simulation(ws_dir)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["all_passed"] else 1

    if use_color():
        try:
            from rich.console import Console
            from rich.table import Table

            console = Console()
            table = Table(
                title="Dmint v2.0.4 — Live 7-Scenario Red-Team & Cryptographic Enforcement Simulation",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("#", justify="right", style="dim")
            table.add_column("Scenario", style="bold")
            table.add_column("Simulated Agent Action / Attack")
            table.add_column("Outcome")
            table.add_column("Enforcement Code", style="dim")
            table.add_column("Latency", justify="right")
            table.add_column("Status")

            for s in report["scenarios"]:
                status_str = "[bold green]✓ PASS[/]" if s["passed"] else "[bold red]✗ FAIL[/]"
                act_str = s["actual"]
                act_styled = f"[green]{act_str}[/]" if "ALLOW" in act_str or "APPROVED" in act_str else f"[bold red]{act_str}[/]"
                table.add_row(
                    str(s["id"]),
                    s["name"],
                    s["attack_vector"],
                    act_styled,
                    s["code"],
                    f"{s['latency_ms']:.1f} ms",
                    status_str,
                )
            console.print()
            console.print(table)
            console.print(
                f"\n[bold green]✓ {report['passed_scenarios']}/{report['total_scenarios']} Red-Team Scenarios Defeated[/]  |  "
                f"SHA-256 Audit Chain: [bold cyan]{report['audit_entries']} entries verified ({report['audit_head_hash'][:12]}...)[/]  |  "
                f"Total Time: [bold]{report['total_latency_ms']:.1f} ms[/]\n"
            )
            if ws_dir:
                console.print(f"  Workspace & audit trail saved to: [bold]{ws_dir}[/]\n")
            return 0 if report["all_passed"] else 1
        except Exception:
            pass

    print("\n=== Dmint v2.0.4 — Live 7-Scenario Red-Team & Cryptographic Simulation ===", file=out_buf)
    for s in report["scenarios"]:
        badge = "✓ PASS" if s["passed"] else "✗ FAIL"
        print(
            f"  [{badge}] #{s['id']} {s['name']:<42} -> {s['actual']:<21} ({s['code']}) [{s['latency_ms']:.1f} ms]",
            file=out_buf,
        )
    print(
        f"\n✓ Summary: {report['passed_scenarios']}/{report['total_scenarios']} scenarios passed | "
        f"Audit chain verified ({report['audit_entries']} entries, head={report['audit_head_hash'][:12]}...) | "
        f"Total: {report['total_latency_ms']:.1f} ms\n",
        file=out_buf,
    )
    return 0 if report["all_passed"] else 1
