"""Tests for multi-harness PreToolUse hooks, dmint init, dmint check, and Dmint.local() DX."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from pathlib import Path
from typing import Any

from dmint import Dmint, Policy, Rule
from dmint.cli.__main__ import main as cli_main
from dmint.core.errors import AuthorizationError, DmintError


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli_main(args)
    return rc, out.getvalue(), err.getvalue()


class TestHooksAndDX(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_cwd = os.getcwd()
        self._orig_env = dict(os.environ)
        for k in list(os.environ.keys()):
            if k.startswith("DMINT_"):
                os.environ.pop(k, None)
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        os.chdir(self.tmp_path)

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)
        os.environ.clear()
        os.environ.update(self._orig_env)
        self._tmp_dir.cleanup()

    def test_dmint_init_and_check_roundtrip(self) -> None:
        """dmint init should generate keys, policy.json, and harness hooks in one command."""
        rc, out, err = _run_cli(["init", "--harness", "all", "--dir", str(self.tmp_path)])
        self.assertEqual(rc, 0, f"init failed: {out}\n{err}")

        self.assertTrue((self.tmp_path / "policy.json").exists())
        self.assertTrue((self.tmp_path / ".dmint" / "signing.key").exists())
        self.assertTrue((self.tmp_path / ".dmint" / "integrity.key").exists())
        self.assertTrue((self.tmp_path / ".claude" / "settings.json").exists())
        self.assertTrue((self.tmp_path / ".codex" / "hooks.json").exists())
        self.assertTrue((self.tmp_path / ".codex" / "dmint-hook.sh").exists())
        self.assertTrue((self.tmp_path / ".opencode" / "plugin" / "dmint-guard.ts").exists())
        self.assertTrue((self.tmp_path / ".cursor" / "hooks.json").exists())
        self.assertTrue((self.tmp_path / ".windsurf" / "hooks.json").exists())
        self.assertTrue((self.tmp_path / ".clinerules" / "hooks.json").exists())

        # Check status command
        rc_status, out_status, _ = _run_cli(["hook", "status", "--dir", str(self.tmp_path)])
        self.assertEqual(rc_status, 0)
        status_payload = json.loads(out_status)
        for harness in ("claude-code", "codex", "opencode", "cursor", "windsurf", "cline"):
            self.assertTrue(status_payload["harnesses"][harness]["installed"])

        # Test dmint check (ALLOW, DENY, APPROVAL_REQUIRED)
        rc_allow, out_allow, _ = _run_cli(
            [
                "check",
                "--policy",
                str(self.tmp_path / "policy.json"),
                "--tool",
                "shell.execute",
                "--resource",
                "git status",
            ]
        )
        self.assertEqual(rc_allow, 0)
        self.assertEqual(json.loads(out_allow)["verdict"], "ALLOW")

        rc_deny, out_deny, _ = _run_cli(
            [
                "check",
                "--policy",
                str(self.tmp_path / "policy.json"),
                "--tool",
                "shell.execute",
                "--resource",
                "rm -rf /",
            ]
        )
        self.assertEqual(rc_deny, 2)
        self.assertEqual(json.loads(out_deny)["verdict"], "DENY")

        rc_apr, out_apr, _ = _run_cli(
            [
                "check",
                "--policy",
                str(self.tmp_path / "policy.json"),
                "--tool",
                "shell.execute",
                "--resource",
                "git push origin main",
            ]
        )
        self.assertEqual(rc_apr, 1)
        self.assertEqual(json.loads(out_apr)["verdict"], "APPROVAL_REQUIRED")

    def test_hook_run_allow_deny_and_single_use_approval_lifecycle(self) -> None:
        """dmint hook run should enforce ALLOW, DENY, and single-use Ed25519 approval for PreToolUse hooks."""
        rc, _, _ = _run_cli(["init", "--harness", "claude-code", "--dir", str(self.tmp_path)])
        self.assertEqual(rc, 0)

        policy_path = str(self.tmp_path / "policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        # 1. Allowed Bash tool call (git status)
        allow_payload = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
            }
        )
        rc1, out1, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "claude-code",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                allow_payload,
            ]
        )
        self.assertEqual(rc1, 0)
        resp1 = json.loads(out1)
        self.assertEqual(resp1["hookSpecificOutput"]["permissionDecision"], "allow")

        # 2. Denied Bash tool call (rm -rf /)
        deny_payload = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"},
            }
        )
        rc2, out2, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "claude-code",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                deny_payload,
            ]
        )
        self.assertEqual(rc2, 2)
        resp2 = json.loads(out2)
        self.assertEqual(resp2["hookSpecificOutput"]["permissionDecision"], "deny")

        # 3. Approval-required Bash tool call (git push origin main)
        apr_payload = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git push origin main"},
            }
        )
        rc3, out3, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "claude-code",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                apr_payload,
            ]
        )
        self.assertEqual(rc3, 0)
        resp3 = json.loads(out3)
        self.assertEqual(resp3["hookSpecificOutput"]["permissionDecision"], "ask")
        approval_id = resp3["dmint"]["approval_id"]
        self.assertTrue(approval_id.startswith("apr_"))

        # 4. Approve via dmint approve (using auto-discovered .dmint store and keys!)
        rc_approve, out_approve, err_approve = _run_cli(["approve", approval_id, "--by", "alice@company.com"])
        self.assertEqual(rc_approve, 0, f"approve failed: {out_approve}\n{err_approve}")

        # 5. Re-run exact same tool call -> auto-consumes the single-use Ed25519 credential and returns allow!
        rc4, out4, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "claude-code",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                apr_payload,
            ]
        )
        self.assertEqual(rc4, 0)
        resp4 = json.loads(out4)
        self.assertEqual(resp4["hookSpecificOutput"]["permissionDecision"], "allow")

        # 6. Replay exact same tool call again -> credential was already consumed, so it creates a new pending request!
        rc5, out5, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "claude-code",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                apr_payload,
            ]
        )
        self.assertEqual(rc5, 0)
        resp5 = json.loads(out5)
        self.assertEqual(resp5["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertNotEqual(resp5["dmint"]["approval_id"], approval_id)

    def test_hook_run_across_codex_opencode_cursor_and_mcp_tools(self) -> None:
        """Verify tool normalization and output format across Codex, OpenCode, Cursor, and MCP tools."""
        _run_cli(["init", "--harness", "all", "--dir", str(self.tmp_path)])
        policy_path = str(self.tmp_path / "policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        # Codex exec_command
        codex_payload = json.dumps({"tool": "exec_command", "arguments": {"cmd": "ls -la"}})
        rc_codex, out_codex, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "codex",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                codex_payload,
            ]
        )
        self.assertEqual(rc_codex, 0)
        self.assertEqual(json.loads(out_codex)["decision"], "allow")

        # OpenCode read_file on .env (denied by filesystem template)
        opencode_payload = json.dumps({"tool": "read_file", "args": {"filePath": "/app/.env"}})
        rc_oc, out_oc, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "opencode",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                opencode_payload,
            ]
        )
        self.assertEqual(rc_oc, 2)
        self.assertFalse(json.loads(out_oc)["allow"])

        # Cursor read_file on src/app.py (allowed by filesystem template)
        cursor_payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "src/app.py"}})
        rc_cur, out_cur, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "cursor",
                "--policy",
                policy_path,
                "--db-path",
                db_path,
                "--input",
                cursor_payload,
            ]
        )
        self.assertEqual(rc_cur, 0)
        self.assertEqual(json.loads(out_cur)["permission"], "allow")

        # Uninstall hooks cleanly
        rc_un, _, _ = _run_cli(["hook", "uninstall", "--harness", "all", "--dir", str(self.tmp_path)])
        self.assertEqual(rc_un, 0)

    def test_dmint_local_and_credential_free_retry(self) -> None:
        """Dmint.local() should provide a zero-config engine and support retry() without passing credential manually."""
        policy = Policy(
            default="deny",
            rules=[
                Rule.allow("payments", "issue_small_refund"),
                Rule.require_approval("payments", "issue_large_refund"),
            ],
        )
        dmint = Dmint.local(policy, state_dir=self.tmp_path / ".dmint", approval_ttl=timedelta(minutes=5))

        @dmint.protected("payments.issue_small_refund")
        def small_refund(order_id: str, amount: int) -> dict[str, Any]:
            return {"order_id": order_id, "refunded": amount}

        @dmint.protected("payments.issue_large_refund")
        def large_refund(order_id: str, amount: int) -> dict[str, Any]:
            return {"order_id": order_id, "refunded": amount}

        # Small refund executes immediately
        self.assertEqual(small_refund("ord_1", 50), {"order_id": "ord_1", "refunded": 50})

        # Large refund pauses with DMT_APPROVAL_REQUIRED
        with self.assertRaises(AuthorizationError) as ctx:
            large_refund("ord_2", 250)
        err = ctx.exception
        self.assertEqual(err.code, "DMT_APPROVAL_REQUIRED")
        self.assertIsNotNone(err.request_id)

        # Approve via CLI using the same state_dir (works with either approval_id or request_id!)
        rc, out, err_text = _run_cli(
            [
                "approve",
                str(err.request_id),
                "--by",
                "finance@company.com",
                "--db-path",
                str(self.tmp_path / ".dmint" / "approvals.sqlite3"),
                "--key-path",
                str(self.tmp_path / ".dmint" / "signing.key"),
                "--integrity-key-path",
                str(self.tmp_path / ".dmint" / "integrity.key"),
            ]
        )
        self.assertEqual(rc, 0, f"approve failed: {out}\n{err_text}")

        # Retry WITHOUT passing approval_credential explicitly — Dmint auto-discovers and consumes it once!
        result = dmint.retry(large_refund, None, "ord_2", 250)
        self.assertEqual(result, {"order_id": "ord_2", "refunded": 250})

        # Second retry fails closed since the single-use credential is now CONSUMED
        with self.assertRaises(DmintError) as replay_ctx:
            dmint.retry(large_refund, None, "ord_2", 250)
        self.assertEqual(replay_ctx.exception.code, "DMT_APPROVAL_CONSUMED")



    def test_hook_run_blocks_tampered_arguments_and_supports_mcp_tools(self) -> None:
        """Verify that modifying command arguments after approval does not consume the approval, and mcp__ tools work."""
        _run_cli(["init", "--harness", "claude-code", "--templates", "shell,filesystem,postgres", "--dir", str(self.tmp_path)])
        policy_path = str(self.tmp_path / "policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        # 1. Request approval for "docker ps"
        req_docker_ps = json.dumps({"tool_name": "Bash", "tool_input": {"command": "docker ps"}})
        rc1, out1, _ = _run_cli(["hook", "run", "--harness", "claude-code", "--policy", policy_path, "--db-path", db_path, "--input", req_docker_ps])
        self.assertEqual(rc1, 0)
        apr_id = json.loads(out1)["dmint"]["approval_id"]

        # 2. Approve "docker ps"
        rc_app, _, _ = _run_cli(["approve", apr_id, "--by", "secops@company.com"])
        self.assertEqual(rc_app, 0)

        # 3. Agent tampers with command ("docker run --privileged alpine") -> MUST NOT consume apr_id!
        req_tampered = json.dumps({"tool_name": "Bash", "tool_input": {"command": "docker run --privileged alpine"}})
        rc_tamp, out_tamp, _ = _run_cli(["hook", "run", "--harness", "claude-code", "--policy", policy_path, "--db-path", db_path, "--input", req_tampered])
        self.assertEqual(rc_tamp, 0)
        resp_tamp = json.loads(out_tamp)
        self.assertEqual(resp_tamp["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertNotEqual(resp_tamp["dmint"]["approval_id"], apr_id)

        # 4. Original "docker ps" approval is still intact and succeeds once
        rc_orig, out_orig, _ = _run_cli(["hook", "run", "--harness", "claude-code", "--policy", policy_path, "--db-path", db_path, "--input", req_docker_ps])
        self.assertEqual(rc_orig, 0)
        self.assertEqual(json.loads(out_orig)["hookSpecificOutput"]["permissionDecision"], "allow")

        # 5. MCP tool call via Claude Code (mcp__postgres__select -> postgres.select)
        mcp_allow = json.dumps({"tool_name": "mcp__postgres__select", "tool_input": {"resource": "users"}})
        rc_mcp1, out_mcp1, _ = _run_cli(["hook", "run", "--harness", "claude-code", "--policy", policy_path, "--db-path", db_path, "--input", mcp_allow])
        self.assertEqual(rc_mcp1, 0)
        self.assertEqual(json.loads(out_mcp1)["hookSpecificOutput"]["permissionDecision"], "allow")

        mcp_deny = json.dumps({"tool_name": "mcp__postgres__drop_table", "tool_input": {"resource": "users"}})
        rc_mcp2, out_mcp2, _ = _run_cli(["hook", "run", "--harness", "claude-code", "--policy", policy_path, "--db-path", db_path, "--input", mcp_deny])
        self.assertEqual(rc_mcp2, 2)
        self.assertEqual(json.loads(out_mcp2)["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
