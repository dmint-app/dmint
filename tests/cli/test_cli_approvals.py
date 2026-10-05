"""Tests for CLI approvals management: dmint pending, dmint approve, dmint reject."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from dmint.approvals import ApprovalRecord, ApprovalState, PolicyProvenance, new_request_id
from dmint.authority import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalVerifier,
    LocalApprovalAuthority,
)
from dmint.cli.__main__ import main
from dmint.models import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.storage.sqlite import SQLiteApprovalStore


class TestCLIApprovals(unittest.TestCase):
    """Test suite for 'dmint pending', 'dmint approve', and 'dmint reject' commands."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "approvals.sqlite"
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="default")
        self.store.__enter__()

    def tearDown(self) -> None:
        self.store.__exit__(None, None, None)
        self.tempdir.cleanup()

    def _make_record(
        self,
        *,
        tool: str = "postgres",
        action: str = "drop_table",
        resource: str | None = "prod_users",
        agent_id: str = "claude-code",
        arguments: dict | None = None,
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ApprovalRecord:
        now = created_at or datetime.now(timezone.utc)
        exp = expires_at or (now + timedelta(minutes=15))
        req = ToolRequest(
            request_id=new_request_id(),
            agent_id=agent_id,
            tool=tool,
            action=action,
            resource=resource if resource is not None else NO_RESOURCE,
            arguments=arguments if arguments is not None else ({"table": resource} if resource else {}),
            context=TrustedContext({}),
        )
        return ApprovalRecord.create(
            request=req,
            integration_id=f"mcp.{tool}",
            capability_id=f"{tool}.{action}",
            policy_provenance=PolicyProvenance(
                version_id="policy-v1",
                policy_digest=hashlib.sha256(b"dummy-policy").hexdigest(),
                evaluated_at=now,
            ),
            created_at=now,
            expires_at=exp,
        )

    def test_pending_empty(self) -> None:
        """'dmint pending' on empty store reports no pending approvals and exits 0."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["pending", "--db-path", str(self.db_path)])
        self.assertEqual(code, 0)
        self.assertIn("No pending approvals found.", buf.getvalue())

    def test_pending_table_formatting(self) -> None:
        """'dmint pending' outputs aligned table with required columns."""
        r1 = self._make_record(tool="postgres", action="drop_table", resource="prod_users", agent_id="agent-007")
        r2 = self._make_record(tool="aws", action="terminate_instance", resource="i-12345", agent_id="cursor-agent")
        self.store.save_pending(r1)
        self.store.save_pending(r2)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["pending", "--db-path", str(self.db_path)])
        self.assertEqual(code, 0)
        output = buf.getvalue()

        # Check headers
        self.assertIn("APPROVAL ID", output)
        self.assertIn("TOOL/ACTION", output)
        self.assertIn("RESOURCE/TARGET", output)
        self.assertIn("PRINCIPAL", output)
        self.assertIn("REQUESTED", output)

        # Check records
        self.assertIn(r1.approval_id, output)
        self.assertIn("postgres.drop_table", output)
        self.assertIn("prod_users", output)
        self.assertIn("agent-007", output)

        self.assertIn(r2.approval_id, output)
        self.assertIn("aws.terminate_instance", output)
        self.assertIn("i-12345", output)
        self.assertIn("cursor-agent", output)

    def test_pending_filters_non_pending(self) -> None:
        """'dmint pending' only lists PENDING records, not approved or rejected."""
        r1 = self._make_record(tool="t1", action="a1")
        r2 = self._make_record(tool="t2", action="a2")
        r3 = self._make_record(tool="t3", action="a3")
        self.store.save_pending(r1)
        self.store.save_pending(r2)
        self.store.save_pending(r3)

        auth = LocalApprovalAuthority(issuer_id="test-authority", audience="dmint/cli/v1")
        # Approve r2
        self.store.approve_pending(r2.approval_id, authority=auth, approved_by="admin")

        # Reject r3
        self.store.reject_pending(r3.approval_id, authority=auth, rejected_by="admin", reason="Disallowed")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["pending", "--db-path", str(self.db_path)])
        self.assertEqual(code, 0)
        output = buf.getvalue()

        self.assertIn(r1.approval_id, output)
        self.assertNotIn(r2.approval_id, output)
        self.assertNotIn(r3.approval_id, output)

    def test_pending_via_database_url_flag(self) -> None:
        """'dmint pending' works with --database-url SQLite URL."""
        record = self._make_record(tool="github", action="create_pr", resource="main")
        self.store.save_pending(record)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["pending", "--database-url", f"sqlite:///{self.db_path}"])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(record.approval_id, output)
        self.assertIn("github.create_pr", output)

    def test_approve_happy_path(self) -> None:
        """'dmint approve <id> --reason' signs approval, updates store, and exits 0."""
        record = self._make_record(tool="postgres", action="truncate_table", resource="audit_logs")
        self.store.save_pending(record)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                [
                    "approve",
                    record.approval_id,
                    "--db-path",
                    str(self.db_path),
                    "--reason",
                    "Reviewed and permitted for cleanup",
                    "--approver-id",
                    "alice@example.com",
                ]
            )
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(record.approval_id, output)
        self.assertIn("postgres.truncate_table", output)

        # Verify record in store
        updated = self.store.get(record.approval_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.state, ApprovalState.APPROVED)
        self.assertEqual(updated.state_reason, "Reviewed and permitted for cleanup")
        self.assertIsNotNone(updated.decision_authority)
        self.assertEqual(updated.decision_authority.subject_id, "alice@example.com")

    def test_approve_without_reason(self) -> None:
        """'dmint approve <id>' succeeds when --reason is omitted."""
        record = self._make_record(tool="shell", action="exec", resource="df -h")
        self.store.save_pending(record)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                [
                    "approve",
                    record.approval_id,
                    "--db-path",
                    str(self.db_path),
                ]
            )
        self.assertEqual(code, 0)
        updated = self.store.get(record.approval_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.state, ApprovalState.APPROVED)
        self.assertIsNone(updated.state_reason)

    def test_approve_nonexistent_id(self) -> None:
        """'dmint approve' with nonexistent ID fails with non-zero exit code."""
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(
                [
                    "approve",
                    "apr_0123456789012345678901234567890123456789012",
                    "--db-path",
                    str(self.db_path),
                ]
            )
        self.assertNotEqual(code, 0)
        self.assertIn("not found", err_buf.getvalue().lower())

    def test_approve_already_terminal_state(self) -> None:
        """'dmint approve' on already approved/rejected record fails closed with clear error."""
        record = self._make_record()
        self.store.save_pending(record)

        # First approve succeeds
        main(["approve", record.approval_id, "--db-path", str(self.db_path)])

        # Second approve fails
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(["approve", record.approval_id, "--db-path", str(self.db_path)])
        self.assertNotEqual(code, 0)
        self.assertIn("APPROVED", err_buf.getvalue())

    def test_approve_already_rejected_record(self) -> None:
        """'dmint approve' on a rejected record fails closed."""
        record = self._make_record()
        self.store.save_pending(record)
        auth = LocalApprovalAuthority(issuer_id="test-authority", audience="dmint/cli/v1")
        self.store.reject_pending(record.approval_id, authority=auth, rejected_by="security-lead", reason="Denied")

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(["approve", record.approval_id, "--db-path", str(self.db_path)])
        self.assertNotEqual(code, 0)
        self.assertIn("REJECTED", err_buf.getvalue())

    def test_approve_already_consumed_record(self) -> None:
        """'dmint approve' on an already CONSUMED record fails closed with clear error."""
        record = self._make_record()
        self.store.save_pending(record)
        auth = LocalApprovalAuthority(issuer_id="test-authority", audience="dmint/cli/v1")
        approver = ApprovalAuthority._from_trusted_boundary("cli", "admin", ApprovalAuthorityKind.HUMAN)
        assertion = auth.issue(record, approver)
        approved = record.approve(approver, now=datetime.now(timezone.utc))
        self.store.save_approved(approved)

        verifier = ApprovalVerifier(
            trusted_issuers={auth.issuer_id: auth.public_key},
            audience=auth.audience,
        )
        consumed = self.store.consume_approved(
            approval_id=record.approval_id,
            credential=assertion,
            expected_request=record.request,
            verifier=verifier,
        )
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(["approve", record.approval_id, "--db-path", str(self.db_path)])
        self.assertNotEqual(code, 0)
        self.assertIn("CONSUMED", err_buf.getvalue())

    def test_approve_expired_record(self) -> None:
        """'dmint approve' on an expired record fails with clear expiration error."""
        now = datetime.now(timezone.utc) - timedelta(minutes=30)
        exp = now + timedelta(minutes=5)  # Expired 25 mins ago
        record = self._make_record(created_at=now, expires_at=exp)
        self.store.save_pending(record)

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(["approve", record.approval_id, "--db-path", str(self.db_path)])
        self.assertNotEqual(code, 0)
        self.assertIn("expired", err_buf.getvalue().lower())

    def test_approve_policy_changed_denies(self) -> None:
        """If policy has changed to DENY the capability, dmint approve refuses to sign."""
        record = self._make_record(tool="cloud", action="delete_bucket", resource="backup-bucket")
        self.store.save_pending(record)

        # Create an updated policy file that explicitly denies this action
        policy_file = Path(self.tempdir.name) / "new_policy.json"
        policy_data = {
            "rules": [
                {
                    "effect": "deny",
                    "tool": "cloud",
                    "action": "delete_bucket",
                    "resource": "*",
                }
            ]
        }
        policy_file.write_text(json.dumps(policy_data), encoding="utf-8")

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(
                [
                    "approve",
                    record.approval_id,
                    "--db-path",
                    str(self.db_path),
                    "--policy",
                    str(policy_file),
                ]
            )
        self.assertNotEqual(code, 0)
        self.assertIn("current policy denies", err_buf.getvalue().lower())
        self.assertIn("cloud.delete_bucket", err_buf.getvalue())

        # Verify status in store remains PENDING (not approved)
        unapproved = self.store.get(record.approval_id)
        self.assertIsNotNone(unapproved)
        self.assertEqual(unapproved.state, ApprovalState.PENDING)

    def test_reject_happy_path(self) -> None:
        """'dmint reject <id> --reason' marks request REJECTED and exits 0."""
        record = self._make_record(tool="file", action="rmdir", resource="/etc")
        self.store.save_pending(record)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                [
                    "reject",
                    record.approval_id,
                    "--db-path",
                    str(self.db_path),
                    "--reason",
                    "Destructive operation blocked by admin",
                    "--approver-id",
                    "bob@example.com",
                ]
            )
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(record.approval_id, output)

        # Verify record in store
        rejected = self.store.get(record.approval_id)
        self.assertIsNotNone(rejected)
        self.assertEqual(rejected.state, ApprovalState.REJECTED)
        self.assertEqual(rejected.state_reason, "Destructive operation blocked by admin")

    def test_reject_nonexistent_id(self) -> None:
        """'dmint reject' with nonexistent ID fails with non-zero exit code."""
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(
                [
                    "reject",
                    "apr_0123456789012345678901234567890123456789012",
                    "--db-path",
                    str(self.db_path),
                ]
            )
        self.assertNotEqual(code, 0)
        self.assertIn("not found", err_buf.getvalue().lower())

    def test_reject_already_terminal_state(self) -> None:
        """'dmint reject' on already rejected record fails closed."""
        record = self._make_record()
        self.store.save_pending(record)

        main(["reject", record.approval_id, "--db-path", str(self.db_path)])

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            code = main(["reject", record.approval_id, "--db-path", str(self.db_path)])
        self.assertNotEqual(code, 0)
        self.assertIn("REJECTED", err_buf.getvalue())

    def test_help_flags_for_all_commands(self) -> None:
        """'dmint pending --help', 'approve --help', 'reject --help' exit 0 and show usage."""
        for cmd in ["pending", "approve", "reject"]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main([cmd, "--help"])
            self.assertEqual(code, 0)
            output = buf.getvalue().lower()
            self.assertIn(f"usage: dmint {cmd}", output)
            self.assertIn("--db-path", output)

    def test_malicious_approval_id_rejected_cleanly(self) -> None:
        """'dmint approve' and 'dmint reject' reject SQL injection and path traversal cleanly."""
        malicious_ids = [
            "' OR '1'='1",
            "'; DROP TABLE approval_records; --",
            "apr_'; DROP TABLE approval_records; --",
            "../../../../etc/passwd",
            "apr_../../../etc/shadow",
            "apr_UNION SELECT * FROM approval_records--",
            "apr_<script>alert('xss')</script>",
            "apr_12345; DELETE FROM approval_records;",
        ]
        valid_rec = self._make_record()
        self.store.save_pending(valid_rec)

        for mal_id in malicious_ids:
            for cmd in ["approve", "reject"]:
                err_buf = io.StringIO()
                with contextlib.redirect_stderr(err_buf):
                    code = main([cmd, mal_id, "--db-path", str(self.db_path)])
                self.assertNotEqual(code, 0, f"{cmd} should fail for malicious id: {mal_id}")
                err_text = err_buf.getvalue().lower()
                self.assertTrue(
                    "not found" in err_text or "invalid approval_id" in err_text or "failed" in err_text,
                    f"Unexpected error output for {mal_id}: {err_text}",
                )

        # Confirm the database and pending records remain completely unharmed
        self.assertIsNotNone(self.store.get(valid_rec.approval_id))


if __name__ == "__main__":
    unittest.main()
