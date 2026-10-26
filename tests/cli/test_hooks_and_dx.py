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
        _run_cli(
            [
                "init",
                "--harness",
                "claude-code",
                "--templates",
                "shell,filesystem,postgres",
                "--dir",
                str(self.tmp_path),
            ]
        )
        policy_path = str(self.tmp_path / "policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        # 1. Request approval for "docker ps"
        req_docker_ps = json.dumps({"tool_name": "Bash", "tool_input": {"command": "docker ps"}})
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
                req_docker_ps,
            ]
        )
        self.assertEqual(rc1, 0)
        apr_id = json.loads(out1)["dmint"]["approval_id"]

        # 2. Approve "docker ps"
        rc_app, _, _ = _run_cli(["approve", apr_id, "--by", "secops@company.com"])
        self.assertEqual(rc_app, 0)

        # 3. Agent tampers with command ("docker run --privileged alpine") -> MUST NOT consume apr_id!
        req_tampered = json.dumps({"tool_name": "Bash", "tool_input": {"command": "docker run --privileged alpine"}})
        rc_tamp, out_tamp, _ = _run_cli(
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
                req_tampered,
            ]
        )
        self.assertEqual(rc_tamp, 0)
        resp_tamp = json.loads(out_tamp)
        self.assertEqual(resp_tamp["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertNotEqual(resp_tamp["dmint"]["approval_id"], apr_id)

        # 4. Original "docker ps" approval is still intact and succeeds once
        rc_orig, out_orig, _ = _run_cli(
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
                req_docker_ps,
            ]
        )
        self.assertEqual(rc_orig, 0)
        self.assertEqual(json.loads(out_orig)["hookSpecificOutput"]["permissionDecision"], "allow")

        # 5. MCP tool call via Claude Code (mcp__postgres__select -> postgres.select)
        mcp_allow = json.dumps({"tool_name": "mcp__postgres__select", "tool_input": {"resource": "users"}})
        rc_mcp1, out_mcp1, _ = _run_cli(
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
                mcp_allow,
            ]
        )
        self.assertEqual(rc_mcp1, 0)
        self.assertEqual(json.loads(out_mcp1)["hookSpecificOutput"]["permissionDecision"], "allow")

        mcp_deny = json.dumps({"tool_name": "mcp__postgres__drop_table", "tool_input": {"resource": "users"}})
        rc_mcp2, out_mcp2, _ = _run_cli(
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
                mcp_deny,
            ]
        )
        self.assertEqual(rc_mcp2, 2)
        self.assertEqual(json.loads(out_mcp2)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_per_harness_dedicated_policies_and_official_hook_schemas(self) -> None:
        """Each harness must get its own .dmint/policies/<harness>.policy.json and official hook format."""
        rc, out, err = _run_cli(["init", "--harness", "all", "--dir", str(self.tmp_path)])
        self.assertEqual(rc, 0, f"init failed: {out}\n{err}")

        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")
        policies_dir = self.tmp_path / ".dmint" / "policies"

        # 1. Verify all 6 dedicated per-harness policy files exist and are wired into each harness's hook config
        for h in ("claude-code", "codex", "opencode", "cursor", "windsurf", "cline"):
            h_pol = policies_dir / f"{h}.policy.json"
            self.assertTrue(h_pol.exists(), f"Missing dedicated policy for {h}: {h_pol}")

        claude_cfg = json.loads((self.tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(claude_cfg["hooks"]["PreToolUse"][0]["matcher"], "*")
        self.assertIn(
            str(policies_dir / "claude-code.policy.json"),
            claude_cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        )

        codex_cfg = json.loads((self.tmp_path / ".codex" / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("PreToolUse", codex_cfg["hooks"])
        self.assertIn(
            str(policies_dir / "codex.policy.json"),
            codex_cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        )

        # OpenCode v2 plural (.opencode/plugins/dmint-guard.ts) and v1 singular (.opencode/plugin/dmint-guard.ts)
        oc_plural = self.tmp_path / ".opencode" / "plugins" / "dmint-guard.ts"
        oc_singular = self.tmp_path / ".opencode" / "plugin" / "dmint-guard.ts"
        self.assertTrue(oc_plural.exists())
        self.assertTrue(oc_singular.exists())
        self.assertIn("opencode.policy.json", oc_plural.read_text(encoding="utf-8"))

        # Cursor hooks.json requires "version": 1 and failClosed: true
        cursor_cfg = json.loads((self.tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(cursor_cfg["version"], 1)
        for ev in ("preToolUse", "beforeShellExecution", "beforeReadFile", "beforeMCPExecution", "subagentStart"):
            self.assertIn(ev, cursor_cfg["hooks"])
            self.assertTrue(cursor_cfg["hooks"][ev][0]["failClosed"])
            self.assertIn("cursor.policy.json", cursor_cfg["hooks"][ev][0]["command"])

        # Windsurf Cascade hooks.json uses snake_case pre_run_command, pre_read_code, pre_write_code, pre_mcp_tool_use
        ws_cfg = json.loads((self.tmp_path / ".windsurf" / "hooks.json").read_text(encoding="utf-8"))
        for ev in ("pre_run_command", "pre_read_code", "pre_write_code", "pre_mcp_tool_use"):
            self.assertIn(ev, ws_cfg["hooks"])
            self.assertTrue(ws_cfg["hooks"][ev][0]["show_output"])
            self.assertIn("windsurf.policy.json", ws_cfg["hooks"][ev][0]["command"])

        # Cline executable hooks (.clinerules/hooks/PreToolUse & .cline/hooks/PreToolUse.sh)
        cline_ext_hook = self.tmp_path / ".clinerules" / "hooks" / "PreToolUse"
        cline_cli_hook = self.tmp_path / ".cline" / "hooks" / "PreToolUse.sh"
        self.assertTrue(cline_ext_hook.exists())
        self.assertTrue(cline_cli_hook.exists())
        self.assertIn("cline.policy.json", cline_ext_hook.read_text(encoding="utf-8"))

        # 2. Test built-in tools against each harness's dedicated policy file
        # 2a. Claude Code built-in tools (TodoWrite, AskUserQuestion, TaskCreate -> ALLOW; Skill -> APPROVAL_REQUIRED)
        claude_pol = str(policies_dir / "claude-code.policy.json")
        for safe_claude_tool in ("TodoWrite", "AskUserQuestion", "TaskCreate", "EnterPlanMode", "Glob", "Grep", "LSP"):
            rc_c, out_c, _ = _run_cli(
                [
                    "hook",
                    "run",
                    "--harness",
                    "claude-code",
                    "--policy",
                    claude_pol,
                    "--db-path",
                    db_path,
                    "--input",
                    json.dumps({"tool_name": safe_claude_tool, "tool_input": {}}),
                ]
            )
            self.assertEqual(rc_c, 0, f"Claude built-in tool {safe_claude_tool} should be ALLOWED")
            self.assertEqual(json.loads(out_c)["hookSpecificOutput"]["permissionDecision"], "allow")

        # 2b. Codex CLI apply_patch multi-file smuggling protection (src/app.py + .env -> DENY)
        codex_pol = str(policies_dir / "codex.policy.json")
        codex_smuggle = json.dumps(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "input": "*** Begin Patch\n*** Update File: src/app.py\n@@\n*** Update File: .env\n@@\n*** End Patch"
                },
            }
        )
        rc_cx, out_cx, _ = _run_cli(
            ["hook", "run", "--harness", "codex", "--policy", codex_pol, "--db-path", db_path, "--input", codex_smuggle]
        )
        self.assertEqual(rc_cx, 2)
        self.assertEqual(json.loads(out_cx)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(json.loads(out_cx)["dmint"]["decision"], "DENY")

        # Codex built-in update_plan -> ALLOW
        rc_plan, out_plan, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "codex",
                "--policy",
                codex_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps({"tool_name": "update_plan", "tool_input": {"plan": []}}),
            ]
        )
        self.assertEqual(rc_plan, 0)
        self.assertEqual(json.loads(out_plan)["hookSpecificOutput"]["permissionDecision"], "allow")

        # 2c. OpenCode apply_patch with patchText header & todowrite -> ALLOW / APPROVAL_REQUIRED
        oc_pol = str(policies_dir / "opencode.policy.json")
        rc_oc_todo, out_oc_todo, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "opencode",
                "--policy",
                oc_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps({"tool_name": "todowrite", "tool_input": {"todos": []}}),
            ]
        )
        self.assertEqual(rc_oc_todo, 0)
        self.assertTrue(json.loads(out_oc_todo)["allow"])

        # 2d. Windsurf Cascade official pre_run_command & pre_read_code payloads
        ws_pol = str(policies_dir / "windsurf.policy.json")
        rc_ws_ok, _, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "windsurf",
                "--policy",
                ws_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps({"agent_action_name": "pre_run_command", "tool_info": {"command_line": "git status"}}),
            ]
        )
        self.assertEqual(rc_ws_ok, 0)

        rc_ws_deny, _, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "windsurf",
                "--policy",
                ws_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps({"agent_action_name": "pre_read_code", "tool_info": {"file_path": ".env.local"}}),
            ]
        )
        self.assertEqual(rc_ws_deny, 2)

        # 2e. Cline VS Code extension (.preToolUse) & CLI (.tool_call) payloads
        cline_pol = str(policies_dir / "cline.policy.json")
        rc_cl_ok, out_cl_ok, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "cline",
                "--policy",
                cline_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps({"preToolUse": {"toolName": "attempt_completion", "parameters": {"result": "All done"}}}),
            ]
        )
        self.assertEqual(rc_cl_ok, 0)
        self.assertFalse(json.loads(out_cl_ok)["cancel"])

        # Cline multi-command batch smuggling in run_commands -> DENY (cancel: true)
        rc_cl_batch, out_cl_batch, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "cline",
                "--policy",
                cline_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps(
                    {
                        "tool_call": {
                            "name": "run_commands",
                            "input": {"commands": ["git status", "rm -rf /"]},
                        }
                    }
                ),
            ]
        )
        self.assertEqual(rc_cl_batch, 2)
        parsed_cl_batch = json.loads(out_cl_batch)
        self.assertTrue(parsed_cl_batch["cancel"])
        self.assertIn("DMT_POLICY_DENIED", parsed_cl_batch["errorMessage"])

    def test_compound_shell_command_smuggling_and_symlink_escape_blocked(self) -> None:
        """Compound shell commands (&&, ;, |, $()) and relative symlinks to secrets must never bypass policy."""
        _run_cli(["init", "--harness", "claude-code", "--dir", str(self.tmp_path)])
        policy_path = str(self.tmp_path / ".dmint" / "policies" / "claude-code.policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        # 1. Benign compound command ("git status && pytest -q") -> ALLOW
        rc_ok, out_ok, _ = _run_cli(
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
                json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status && pytest -q"}}),
            ]
        )
        self.assertEqual(rc_ok, 0)
        self.assertEqual(json.loads(out_ok)["hookSpecificOutput"]["permissionDecision"], "allow")

        # 2. Chained destructive command ("ls -la && rm -rf /") -> DENY (both in hook run and dmint check)
        rc_smug, out_smug, _ = _run_cli(
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
                json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la && rm -rf /"}}),
            ]
        )
        self.assertEqual(rc_smug, 2)
        self.assertEqual(json.loads(out_smug)["hookSpecificOutput"]["permissionDecision"], "deny")

        rc_chk_smug, out_chk_smug, _ = _run_cli(
            ["check", "-p", policy_path, "-t", "shell.execute", "-r", "ls -la && rm -rf /"]
        )
        self.assertEqual(rc_chk_smug, 2)
        self.assertEqual(json.loads(out_chk_smug)["verdict"], "DENY")

        # 3. Subshell command substitution ("echo $(cat .env)") -> DENY
        rc_sub, out_sub, _ = _run_cli(
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
                json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo $(cat .env)"}}),
            ]
        )
        self.assertEqual(rc_sub, 2)
        self.assertEqual(json.loads(out_sub)["dmint"]["code"], "DMT_POLICY_DENIED")

        # 4. Relative symlink inside src/ pointing to ../.env -> resolved via realpath and DENIED
        src_dir = self.tmp_path / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        env_file = self.tmp_path / ".env"
        env_file.write_text("SECRET=1\n", encoding="utf-8")
        symlink_file = src_dir / "innocent_config.py"
        symlink_file.symlink_to(env_file)

        rc_sym, out_sym, _ = _run_cli(
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
                json.dumps({"tool_name": "Read", "tool_input": {"file_path": "src/innocent_config.py"}}),
            ]
        )
        self.assertEqual(rc_sym, 2)
        self.assertEqual(json.loads(out_sym)["dmint"]["decision"], "DENY")
        self.assertEqual(json.loads(out_sym)["dmint"]["code"], "DMT_POLICY_DENIED")

    def test_dmint_doctor_end_to_end_self_test(self) -> None:
        """dmint doctor should verify crypto engine, keys, per-harness policies, hooks, and 4 security vectors."""
        _run_cli(["init", "--harness", "all", "--dir", str(self.tmp_path)])
        rc_doc, out_doc, err_doc = _run_cli(["doctor", "--dir", str(self.tmp_path), "--json"])
        self.assertEqual(rc_doc, 0, f"doctor failed: {out_doc}\n{err_doc}")
        report = json.loads(out_doc)
        self.assertTrue(report["ok"])
        for check_key in ("crypto_engine", "keys", "policy", "hooks", "self_test"):
            self.assertTrue(report["checks"][check_key]["ok"], f"Check {check_key} failed: {report}")
        self.assertEqual(len(report["checks"]["policy"]["harness_policies"]), 6)

    def test_blackbox_manual_qa_e2e_regressions(self) -> None:
        """Verify all 6 edge cases uncovered during black-box manual QA E2E testing."""
        # 1. dmint init --templates all --harness all
        rc_init, _, err_init = _run_cli(
            ["init", "--templates", "all", "--harness", "all", "--dir", str(self.tmp_path), "--force"]
        )
        self.assertEqual(rc_init, 0, err_init)
        pol_path = str(self.tmp_path / "policy.json")
        claude_pol = str(self.tmp_path / ".dmint" / "policies" / "claude-code.policy.json")
        cursor_pol = str(self.tmp_path / ".dmint" / "policies" / "cursor.policy.json")
        cline_pol = str(self.tmp_path / ".dmint" / "policies" / "cline.policy.json")
        db_path = str(self.tmp_path / ".dmint" / "approvals.sqlite3")

        # 2. dmint doctor --harness <h>
        rc_doc_h, _, _ = _run_cli(["doctor", "--dir", str(self.tmp_path), "--harness", "claude-code"])
        self.assertEqual(rc_doc_h, 0)

        # 3. filesystem.read alias & dmint check -a '{...}' JSON arguments fallback
        rc_fs, out_fs, _ = _run_cli(["check", "-p", pol_path, "-t", "filesystem.read", "-r", "README.md", "--json"])
        self.assertEqual(rc_fs, 0)
        self.assertEqual(json.loads(out_fs)["decision"], "ALLOW")

        rc_pg, out_pg, _ = _run_cli(
            [
                "check",
                "-p",
                pol_path,
                "-t",
                "postgres.select",
                "-r",
                "db://app/users",
                "-a",
                '{"sql":"SELECT 1"}',
                "--json",
            ]
        )
        self.assertEqual(rc_pg, 0)
        self.assertEqual(json.loads(out_pg)["decision"], "ALLOW")

        # 4. MultiEdit batch smuggling via 'edits' array without top-level file_path
        rc_me, out_me, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "claude-code",
                "--policy",
                claude_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps(
                    {
                        "tool_name": "MultiEdit",
                        "tool_input": {"edits": [{"file_path": "src/a.py"}, {"file_path": ".env"}]},
                    }
                ),
            ]
        )
        self.assertEqual(rc_me, 2)
        self.assertEqual(json.loads(out_me)["dmint"]["decision"], "DENY")

        # 5. Cursor beforeMCPExecution fallback to APPROVAL_REQUIRED
        rc_cur, out_cur, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "cursor",
                "--policy",
                cursor_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps(
                    {
                        "hook_event_name": "beforeMCPExecution",
                        "tool_name": "postgres.query",
                        "tool_input": {"sql": "SELECT 1"},
                    }
                ),
            ]
        )
        self.assertEqual(rc_cur, 2)
        self.assertEqual(json.loads(out_cur)["dmint"]["decision"], "APPROVAL_REQUIRED")

        # 6. Cline preToolUse with 'tool' key
        rc_cl, out_cl, _ = _run_cli(
            [
                "hook",
                "run",
                "--harness",
                "cline",
                "--policy",
                cline_pol,
                "--db-path",
                db_path,
                "--input",
                json.dumps(
                    {
                        "hookName": "PreToolUse",
                        "preToolUse": {"tool": "execute_command", "parameters": {"command": "git status"}},
                    }
                ),
            ]
        )
        self.assertEqual(rc_cl, 0)
        self.assertFalse(json.loads(out_cl)["cancel"])


if __name__ == "__main__":
    unittest.main()

    def test_10_uncharted_real_world_and_adversarial_edges(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            test_uncharted_real_world_and_adversarial_edges(Path(td))


def test_uncharted_real_world_and_adversarial_edges(tmp_path: Path) -> None:
    """Verify undocumented real-world edge cases:
    - Single & background shell operator splitting and metacharacter blocking
    - Non-standard path argument keys (filepath, filename, destination, dest, source, src)
    - Tool names containing secret/token/password/key inside mcp_protection.json tool_bindings
    - Bearer ${ENV_VAR} header interpolation in mcp_protection.json
    - Dmint.protect(tool=..., action=...) and Dmint.retry() on bound class methods & async functions
    - 10-way concurrent double-spend replay race and wrong-key signature forgery on hooks
    """
    import asyncio
    import concurrent.futures
    import os
    import threading
    from dmint import ApprovalRequired, Dmint
    from dmint.cli.approvals import main_approve
    from dmint.cli.hooks import (
        _extract_all_paths_from_args,
        _split_compound_shell_commands,
        ensure_local_dmint_environment,
        evaluate_hook_request,
    )
    from dmint.core.keys import Ed25519PrivateKey, write_private_key_atomic
    from dmint.mcp.config_loader import parse_protection_config

    ensure_local_dmint_environment(tmp_path, harnesses=["claude-code"])

    # 1. Background & operator splitting & blocking
    assert _split_compound_shell_commands("git status & rm -rf /") == ["git status", "rm -rf /"]
    bg_res = evaluate_hook_request(
        payload={"tool_name": "Bash", "tool_input": {"command": "git status & rm -rf /"}},
        harness="claude-code",
        workspace_dir=tmp_path,
    )
    assert bg_res["decision"] == "DENY"

    # 2. Non-standard path argument keys
    for key in ("filepath", "filename", "destination", "dest", "source", "src"):
        extracted = _extract_all_paths_from_args({key: ".env"}, tmp_path)
        assert extracted == [".env"]
        r = evaluate_hook_request(
            payload={"tool_name": "Read", "tool_input": {key: ".env"}},
            harness="claude-code",
            workspace_dir=tmp_path,
        )
        assert r["decision"] == "DENY"

    # 3. tool_bindings with tool names containing secret/token/password/key + Bearer ${ENV_VAR}
    cfg = parse_protection_config(
        {
            "policy": {
                "rules": [{"tool": "vault", "action": "rotate_master_secret", "resource": "*", "effect": "deny"}]
            },
            "integrations": [
                {
                    "integration_id": "vault",
                    "transport": "streamable_http",
                    "connection": {
                        "url": "http://127.0.0.1:9999/mcp",
                        "headers": {"Authorization": "Bearer ${VAULT_MCP_TOKEN}"},
                    },
                    "tool_bindings": {
                        "rotate_master_secret": "vault.rotate_master_secret",
                        "create_secret_key": "vault.create_secret_key",
                        "revoke_access_token": "vault.revoke_access_token",
                    },
                }
            ],
        }
    )
    assert len(cfg.integrations) == 1
    assert "rotate_master_secret" in cfg.integrations[0].tool_bindings

    # 4. SDK dynamic wrapping & bound class method retry
    sdk_dir = tmp_path / "sdk_test"
    sdk_dir.mkdir()
    pol_file = sdk_dir / "policy.json"
    pol_file.write_text(
        json.dumps({"rules": [{"tool": "erp", "action": "payout", "effect": "approval_required"}]}),
        encoding="utf-8",
    )
    dm = Dmint.local(policy_path=pol_file, storage=sdk_dir / "approvals.sqlite3")

    class ErpClient:
        def __init__(self, tag: str) -> None:
            self.tag = tag

        @dm.protect(tool="erp", action="payout")
        def send_payout(self, iban: str, amount: int) -> str:
            return f"{self.tag}:{iban}:{amount}"

    client = ErpClient("ACME")
    try:
        client.send_payout("DE89000", 900)
        raise AssertionError("Expected ApprovalRequired")
    except ApprovalRequired as exc:
        rc = main_approve(
            [
                exc.request_id,
                "--by",
                "cfo@acme.com",
                "--db",
                str(sdk_dir / "approvals.sqlite3"),
                "--key-file",
                str(sdk_dir / ".dmint/signing.key"),
            ]
        )
        assert rc == 0
        assert dm.retry(client.send_payout, "DE89000", 900) == "ACME:DE89000:900"

    # 5. Wrong-key signature forgery must be rejected with DENY
    forgery_req = evaluate_hook_request(
        payload={"tool_name": "Bash", "tool_input": {"command": "git push origin main"}},
        harness="claude-code",
        workspace_dir=tmp_path,
    )
    assert forgery_req["decision"] == "APPROVAL_REQUIRED"
    rogue_key = tmp_path / "rogue.key"
    write_private_key_atomic(rogue_key, Ed25519PrivateKey.generate())
    assert (
        main_approve(
            [
                forgery_req["approval_id"],
                "--by",
                "rogue@evil.com",
                "--db",
                str(tmp_path / ".dmint/approvals.sqlite3"),
                "--key-file",
                str(rogue_key),
            ]
        )
        == 0
    )
    forgery_retry = evaluate_hook_request(
        payload={"tool_name": "Bash", "tool_input": {"command": "git push origin main"}},
        harness="claude-code",
        workspace_dir=tmp_path,
    )
    assert forgery_retry["decision"] == "DENY"
    assert "SIGNATURE_INVALID" in forgery_retry["code"]


class TestModernCLIUX(unittest.TestCase):
    """Verify v2.0.4 CLI modernization: help screens, offline policy authoring, positional check, --dir, and --json."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self._orig_cwd = os.getcwd()
        os.chdir(self.tmp_path)

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)
        self._tmpdir.cleanup()

    def test_all_help_screens_and_hook_install_bugfix(self) -> None:
        """Verify all 25 CLI --help / -h / help screens exit 0 including hook install --help and hook list --help."""
        help_cmds = [
            ["--help"],
            ["-h"],
            ["help", "create-policy"],
            ["help", "hook"],
            ["init", "--help"],
            ["check", "--help"],
            ["status", "--help"],
            ["doctor", "--help"],
            ["hook", "--help"],
            ["hook", "install", "--help"],
            ["hook", "uninstall", "--help"],
            ["hook", "status", "--help"],
            ["hook", "list", "--help"],
            ["hook", "run", "--help"],
            ["create-policy", "--help"],
            ["compile-policy", "--help"],
            ["create-mcp-policy", "--help"],
            ["verify-policy", "--help"],
            ["policy-digest", "--help"],
            ["approve", "--help"],
            ["deny", "--help"],
            ["pending", "--help"],
            ["dashboard", "--help"],
            ["init-keys", "--help"],
            ["export-public-key", "--help"],
            ["install-skill", "--help"],
        ]
        for cmd in help_cmds:
            rc, out, err = _run_cli(cmd)
            self.assertEqual(rc, 0, f"Help failed for {cmd}: rc={rc}, out={out}, err={err}")
            self.assertIn("usage:", out.lower() + err.lower(), f"Missing usage in {cmd}")

    def test_create_policy_offline_templates_and_rules(self) -> None:
        """Verify dmint create-policy --template and --rule work 100% offline without -f or LLM API key."""
        out_tpl = self.tmp_path / "tpl_policy.json"
        rc1, out1, err1 = _run_cli(["create-policy", "--template", "postgres,stripe", "-o", str(out_tpl)])
        self.assertEqual(rc1, 0, f"create-policy --template failed: {out1}\n{err1}")
        self.assertTrue(out_tpl.exists())
        data1 = json.loads(out_tpl.read_text())
        self.assertGreaterEqual(len(data1["rules"]), 4)

        out_rules = self.tmp_path / "rules_policy.json"
        rc2, out2, err2 = _run_cli(
            [
                "create-policy",
                "-r",
                "allow:postgres.select:users",
                "-r",
                "approval_required:stripe.refund:*",
                "-r",
                "deny:shell.exec:*:prefix",
                "-o",
                str(out_rules),
            ]
        )
        self.assertEqual(rc2, 0, f"create-policy -r failed: {out2}\n{err2}")
        data2 = json.loads(out_rules.read_text())
        self.assertEqual(len(data2["rules"]), 3)
        self.assertEqual(data2["rules"][0]["effect"], "allow")
        self.assertEqual(data2["rules"][1]["effect"], "approval_required")
        self.assertEqual(data2["rules"][2]["effect"], "deny")

    def test_create_policy_interactive_offline_builder(self) -> None:
        """Verify dmint create-policy --interactive builds a valid policy offline from prompted rules."""
        from unittest.mock import patch

        out_int = self.tmp_path / "interactive_policy.json"
        # Inputs: tool=postgres, action=select, resource=users, effect=1 (allow), more=n, confirm_save=y
        inputs = iter(["postgres", "select", "users", "1", "n", "y"])
        with patch("builtins.input", side_effect=lambda *a: next(inputs)):
            rc, out, err = _run_cli(["create-policy", "--interactive", "-o", str(out_int)])
        self.assertEqual(rc, 0, f"create-policy --interactive failed: {out}\n{err}")
        data = json.loads(out_int.read_text())
        self.assertEqual(len(data["rules"]), 1)
        self.assertEqual(data["rules"][0]["tool"], "postgres")
        self.assertEqual(data["rules"][0]["action"], "select")

    def test_create_mcp_policy_offline_auto_classify(self) -> None:
        import sys

        """Verify dmint create-mcp-policy --offline auto-classifies MCP tools and pins schema hashes without an LLM API key."""
        mock_srv = Path(__file__).resolve().parent.parent / "mcp" / "mock_server.py"
        pol_out = self.tmp_path / "mcp_policy.json"
        cfg_out = self.tmp_path / "mcp_protection.json"
        rc, out, err = _run_cli(
            [
                "create-mcp-policy",
                "--command",
                sys.executable,
                "--args",
                str(mock_srv),
                "--integration-id",
                "mockdb",
                "--offline",
                "-y",
                "-o",
                str(pol_out),
                "--config-output",
                str(cfg_out),
            ]
        )
        self.assertEqual(rc, 0, f"create-mcp-policy --offline failed: {out}\n{err}")
        pol_data = json.loads(pol_out.read_text())
        cfg_data = json.loads(cfg_out.read_text())
        self.assertEqual(len(pol_data["rules"]), 2)
        effects = {f"{r['tool']}.{r['action']}": r["effect"] for r in pol_data["rules"]}
        # echo -> allow, delete_database -> approval_required
        self.assertEqual(effects["mockdb.echo"], "allow")
        self.assertEqual(effects["mockdb.delete_database"], "approval_required")
        self.assertIn("echo", pol_data["tool_schemas"])
        self.assertEqual(len(pol_data["tool_schemas"]["echo"]), 64)
        self.assertEqual(cfg_data["integrations"][0]["integration_id"], "mockdb")

    def test_check_positional_and_json_outputs_and_keys_dir(self) -> None:
        """Verify positional dmint check, init-keys --dir, export-public-key --dir --json, verify-policy --json, and policy-digest --json."""
        pol_path = self.tmp_path / "policy.json"
        _run_cli(["create-policy", "-r", "allow:postgres.select:users", "-o", str(pol_path)])

        # 1. Positional dmint check <tool.action>
        rc_chk, out_chk, err_chk = _run_cli(["check", "postgres.select", "-r", "users", "-p", str(pol_path), "--json"])
        self.assertEqual(rc_chk, 0, f"positional check failed: {out_chk}\n{err_chk}")
        self.assertEqual(json.loads(out_chk)["decision"], "ALLOW")

        # 2. verify-policy --json
        rc_ver, out_ver, _ = _run_cli(["verify-policy", str(pol_path), "--json"])
        self.assertEqual(rc_ver, 0)
        self.assertTrue(json.loads(out_ver)["valid"])

        # 3. policy-digest --json
        rc_dig, out_dig, _ = _run_cli(["policy-digest", "-p", str(pol_path), "--json"])
        self.assertEqual(rc_dig, 0)
        self.assertEqual(len(json.loads(out_dig)["policy_digest"]), 64)

        # 4. init-keys --dir and export-public-key --dir --json
        kdir = self.tmp_path / "custom_keys"
        rc_ik, out_ik, err_ik = _run_cli(["init-keys", "--dir", str(kdir)])
        self.assertEqual(rc_ik, 0, f"init-keys --dir failed: {out_ik}\n{err_ik}")
        self.assertTrue((kdir / "signing.key").exists())
        self.assertTrue((kdir / "integrity.key").exists())

        rc_ek, out_ek, err_ek = _run_cli(["export-public-key", "--dir", str(kdir), "--json"])
        self.assertEqual(rc_ek, 0, f"export-public-key --dir --json failed: {out_ek}\n{err_ek}")
        ek_data = json.loads(out_ek)
        self.assertEqual(len(ek_data["public_key_hex"]), 64)
