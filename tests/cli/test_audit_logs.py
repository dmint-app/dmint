"""Comprehensive unit and security tests for Features #1, #2, and #3:
- Feature #1: Tamper-Evident Audit & Level-Based Logging (dmint.core.audit & dmint logs / dmint audit)
- Feature #2: 1-Command Interactive 7-Vector Red-Team Simulator (dmint demo / dmint redteam)
- Feature #3: Shadow / Dry-Run Mode (--mode shadow) & Policy Auto-Learner (dmint learn-policy / create-policy --from-logs)
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from dmint.cli.__main__ import main as cli_main
from dmint.core.audit import (
    AuditLogger,
    read_audit_entries,
    verify_audit_chain,
)


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli_main(args)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 0
    return rc, out.getvalue(), err.getvalue()


class TestAuditLoggingEngine(unittest.TestCase):
    """Test suite for Features #1, #2, and #3."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self._orig_cwd = os.getcwd()
        self._orig_lvl = os.environ.get("DMINT_LOG_LEVEL")
        os.chdir(self.tmp_path)

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)
        if self._orig_lvl is None:
            os.environ.pop("DMINT_LOG_LEVEL", None)
        else:
            os.environ["DMINT_LOG_LEVEL"] = self._orig_lvl
        self._tmpdir.cleanup()

    def test_log_level_collection_filtering(self) -> None:
        """Verify that min_level / DMINT_LOG_LEVEL controls which events are collected."""
        log_file = self.tmp_path / ".dmint" / "audit.jsonl"

        logger_warn = AuditLogger(log_path=log_file, min_level="WARNING")
        self.assertIsNone(
            logger_warn.log_event(decision="ALLOW", tool="shell", action="execute", resource="git status")
        )
        e1 = logger_warn.log_event(
            decision="APPROVAL_REQUIRED", tool="shell", action="execute", resource="git push origin main"
        )
        e2 = logger_warn.log_event(decision="DENY", tool="shell", action="execute", resource="rm -rf /")
        e3 = logger_warn.log_event(
            decision="DENY",
            tool="stripe",
            action="refund",
            resource="ord_1",
            code="DMT_APPROVAL_SIGNATURE_INVALID",
        )
        self.assertIsNotNone(e1)
        self.assertEqual(e1["level"], "WARNING")
        self.assertEqual(e2["level"], "ERROR")
        self.assertEqual(e3["level"], "CRITICAL")

        entries = read_audit_entries(log_file)
        self.assertEqual(len(entries), 3)
        self.assertEqual([e["seq"] for e in entries], [1, 2, 3])

        logger_debug = AuditLogger(log_path=log_file, min_level="DEBUG")
        e4 = logger_debug.log_event(
            decision="ALLOW",
            tool="postgres",
            action="select",
            resource="users",
            arguments={"sql": "SELECT * FROM users", "api_key": "sk-secret1234567890abcdef"},
        )
        self.assertIsNotNone(e4)
        self.assertEqual(e4["seq"], 4)
        self.assertEqual(e4["details"]["arguments"]["api_key"], "[REDACTED]")

    def test_secret_and_dsn_redaction_in_audit_log(self) -> None:
        """Verify that database passwords, API keys, and tokens are automatically scrubbed from audit.jsonl."""
        log_file = self.tmp_path / ".dmint" / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, min_level="DEBUG")
        logger.log_event(
            decision="DENY",
            tool="postgres",
            action="connect",
            resource="postgresql://admin:SuperSecretPass123@db.internal:5432/prod",
            arguments={
                "password": "my_raw_password",
                "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "note": "Using key sk-proj1234567890abcdefghijklmnop",
            },
        )
        raw_content = log_file.read_text(encoding="utf-8")
        self.assertNotIn("SuperSecretPass123", raw_content)
        self.assertNotIn("my_raw_password", raw_content)
        self.assertNotIn("sk-proj1234567890abcdefghijklmnop", raw_content)
        self.assertIn("[REDACTED]", raw_content)

    def test_tamper_evident_hash_chain_and_detection(self) -> None:
        """Verify SHA-256 hash chaining detects payload edits and deleted lines via 'dmint logs --verify'."""
        log_file = self.tmp_path / ".dmint" / "audit.jsonl"
        logger = AuditLogger(log_path=log_file, min_level="INFO")
        for i in range(5):
            logger.log_event(
                decision="ALLOW" if i % 2 == 0 else "DENY",
                tool="shell",
                action="execute",
                resource=f"cmd_{i}",
            )

        res_ok = verify_audit_chain(log_file)
        self.assertTrue(res_ok.valid)
        self.assertEqual(res_ok.total_entries, 5)

        rc_cli, out_cli, _ = _run_cli(["logs", "--verify", "--file", str(log_file), "--json"])
        self.assertEqual(rc_cli, 0)
        self.assertTrue(json.loads(out_cli)["valid"])

        lines = log_file.read_text(encoding="utf-8").splitlines()
        original_lines = list(lines)
        tampered_obj = json.loads(lines[1])
        tampered_obj["decision"] = "ALLOW"
        lines[1] = json.dumps(tampered_obj)
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        rc_tamp, out_tamp, _ = _run_cli(["logs", "--verify", "--file", str(log_file), "--json"])
        self.assertEqual(rc_tamp, 1)
        tamp_data = json.loads(out_tamp)
        self.assertFalse(tamp_data["valid"])
        self.assertEqual(tamp_data["broken_at_seq"], 2)

        deleted_lines = [original_lines[0], original_lines[2], original_lines[3], original_lines[4]]
        log_file.write_text("\n".join(deleted_lines) + "\n", encoding="utf-8")
        res_del = verify_audit_chain(log_file)
        self.assertFalse(res_del.valid)
        self.assertEqual(res_del.broken_at_line, 2)

    def test_end_to_end_hook_run_and_cli_logs_commands(self) -> None:
        """Verify that dmint hook run, dmint approve, dmint logs, --stats, --denied, and --export work end-to-end."""
        _run_cli(["init", "--harness", "claude-code", "--dir", str(self.tmp_path)])
        pol_path = str(self.tmp_path / ".dmint" / "policies" / "claude-code.policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}}),
        ])
        _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}),
        ])
        _, out_apr, _ = _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}),
        ])
        apr_id = json.loads(out_apr)["dmint"]["approval_id"]
        _run_cli(["approve", apr_id, "--by", "secops@company.com", "--db-path", db_path])
        _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}),
        ])

        rc_v, out_v, _ = _run_cli(["logs", "--verify", "--json"])
        self.assertEqual(rc_v, 0)
        v_data = json.loads(out_v)
        self.assertTrue(v_data["valid"])
        self.assertEqual(v_data["total_entries"], 5)

        rc_d, out_d, _ = _run_cli(["logs", "--denied", "--json"])
        self.assertEqual(rc_d, 0)
        denied_list = json.loads(out_d)
        self.assertEqual(len(denied_list), 1)
        self.assertEqual(denied_list[0]["resource"], "rm -rf /")

        rc_s, out_s, _ = _run_cli(["audit", "--stats", "--json"])
        self.assertEqual(rc_s, 0)
        stats = json.loads(out_s)
        self.assertEqual(stats["total_events"], 5)
        self.assertTrue(stats["chain_valid"])
        self.assertEqual(stats["by_decision"]["DENY"], 1)
        self.assertEqual(stats["by_decision"]["APPROVED"], 1)
        self.assertEqual(stats["by_decision"]["CONSUMED"], 1)

        csv_path = self.tmp_path / "audit_export.csv"
        rc_e, _, _ = _run_cli(["logs", "--export", str(csv_path)])
        self.assertEqual(rc_e, 0)
        self.assertTrue(csv_path.exists())
        self.assertIn("entry_hash", csv_path.read_text(encoding="utf-8"))

    def test_feature_2_dmint_demo_and_redteam_simulator(self) -> None:
        """Verify Feature #2: dmint demo and dmint redteam --json run all 7 attack scenarios and verify the audit chain."""
        keep_ws = self.tmp_path / "demo_ws"
        rc, out, err = _run_cli(["redteam", "--json", "--keep-dir", str(keep_ws)])
        self.assertEqual(rc, 0, f"dmint redteam failed: {out}\n{err}")
        report = json.loads(out)
        self.assertTrue(report["all_passed"])
        self.assertEqual(report["total_scenarios"], 7)
        self.assertEqual(report["passed_scenarios"], 7)
        self.assertTrue(report["audit_chain_valid"])
        self.assertGreaterEqual(report["audit_entries"], 7)
        self.assertTrue((keep_ws / ".dmint" / "audit.jsonl").exists())

    def test_feature_3_shadow_mode_and_policy_auto_learner(self) -> None:
        """Verify Feature #3: --mode shadow allows tool calls while logging would-be blocks, and dmint learn-policy synthesizes a safe policy."""
        _run_cli(["init", "--harness", "claude-code", "--dir", str(self.tmp_path)])
        pol_path = str(self.tmp_path / ".dmint" / "policies" / "claude-code.policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")
        audit_path = self.tmp_path / ".dmint" / "audit.jsonl"

        rc1, out1, _ = _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--mode", "shadow",
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}}),
        ])
        self.assertEqual(rc1, 0)
        res1 = json.loads(out1)
        self.assertEqual(res1["hookSpecificOutput"]["permissionDecision"], "allow")
        self.assertFalse(res1["dmint"]["shadow_would_block"])

        rc2, out2, _ = _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--mode", "shadow",
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}),
        ])
        self.assertEqual(rc2, 0)
        res2 = json.loads(out2)
        self.assertEqual(res2["hookSpecificOutput"]["permissionDecision"], "allow")
        self.assertTrue(res2["dmint"]["shadow_would_block"])

        rc3, out3, _ = _run_cli([
            "hook", "run", "--harness", "claude-code", "--policy", pol_path, "--db-path", db_path,
            "--mode", "shadow",
            "--input", json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}),
        ])
        self.assertEqual(rc3, 0)
        res3 = json.loads(out3)
        self.assertEqual(res3["hookSpecificOutput"]["permissionDecision"], "allow")
        self.assertTrue(res3["dmint"]["shadow_would_block"])

        learned_out = self.tmp_path / "learned_policy.json"
        rc_lp, out_lp, err_lp = _run_cli([
            "learn-policy", "--from-logs", str(audit_path), "-o", str(learned_out), "--json"
        ])
        self.assertEqual(rc_lp, 0, f"learn-policy failed: {out_lp}\n{err_lp}")
        lp_summary = json.loads(out_lp)
        self.assertGreaterEqual(lp_summary["total_rules"], 5)

        learned_data = json.loads(learned_out.read_text(encoding="utf-8"))
        rule_map = {(r["tool"], r["action"], r["resource"]): r["effect"] for r in learned_data["rules"]}
        self.assertEqual(rule_map[("shell", "execute", "git status")], "allow")
        self.assertEqual(rule_map[("shell", "execute", "git push origin main")], "approval_required")
        self.assertEqual(rule_map[("shell", "execute", "rm -rf /")], "deny")

        learned_out2 = self.tmp_path / "learned_via_create.json"
        rc_cp, _, err_cp = _run_cli([
            "create-policy", "--from-logs", str(audit_path), "-o", str(learned_out2)
        ])
        self.assertEqual(rc_cp, 0, f"create-policy --from-logs failed: {err_cp}")
        self.assertTrue(learned_out2.exists())


if __name__ == "__main__":
    unittest.main()
