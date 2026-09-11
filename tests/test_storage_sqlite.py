import hashlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dmint import (
    ANY_RESOURCE,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalVerifier,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    SQLiteApprovalStore,
    TrustedContext,
)
from dmint.approvals import ApprovalRecord, ApprovalState
from dmint.errors import (
    ApprovalRequiredError,
    ApprovalStoreError,
    AuthorizationError,
    CorruptApprovalRecordError,
    MalformedApprovalError,
    RequestValidationError,
)


class SQLiteApprovalStoreTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 2, 1, tzinfo=timezone.utc)
        self.expires = self.now + timedelta(minutes=10)
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Path(self.tempdir.name) / "approvals.sqlite"
        self.dmint = Dmint(
            Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),)),
            agent_id="agent-a",
            context=TrustedContext({"environment": "production"}),
        )

        def delete_user(user_id):
            return user_id

        self.dmint.register(
            delete_user,
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.delete_user = delete_user

    def tearDown(self):
        self.tempdir.cleanup()

    def make_record(self, *, user_id=123):
        authorized = self.dmint.authorize(
            self.delete_user,
            user_id,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        return ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=PolicyProvenance(
                "policy-v1",
                hashlib.sha256(b"policy-v1").hexdigest(),
                self.now,
            ),
            created_at=self.now,
            expires_at=self.expires,
        )

    def open_store(self, epoch="epoch-1"):
        return SQLiteApprovalStore(self.database, deployment_epoch=epoch, clock=lambda: self.now)

    def test_pending_round_trip_preserves_exact_request_and_metadata(self):
        record = self.make_record()
        with self.open_store() as store:
            store.save_pending(record)
            loaded = store.require_pending(record.approval_id)

        self.assertEqual(loaded.state, ApprovalState.PENDING)
        self.assertEqual(loaded.approval_id, record.approval_id)
        self.assertEqual(loaded.request_id, record.request_id)
        self.assertEqual(loaded.request_fingerprint, record.request_fingerprint)
        self.assertEqual(loaded.request, record.request)
        self.assertEqual(loaded.binding_version, record.binding_version)
        self.assertEqual(loaded.canonicalization_profile, record.canonicalization_profile)
        self.assertEqual(loaded.integration_id, record.integration_id)
        self.assertEqual(loaded.capability_id, record.capability_id)
        self.assertEqual(loaded.policy_provenance, record.policy_provenance)
        self.assertEqual(loaded.created_at, record.created_at)
        self.assertEqual(loaded.expires_at, record.expires_at)

    def test_loaded_request_is_immutable_and_original_mutation_does_not_change_storage(self):
        options = {"nested": {"enabled": True}}
        policy = Policy((Rule.allow("database", "read"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        def read_user(user_id, options):
            return user_id, options

        dmint.register(read_user, "database.read")
        authorized = dmint.authorize(read_user, 123, options, capability="database.read")
        record = ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.read",
            policy_provenance=PolicyProvenance(
                "policy-v1", hashlib.sha256(b"policy-v1").hexdigest(), self.now
            ),
            created_at=self.now,
            expires_at=self.expires,
        )
        with self.open_store() as store:
            store.save_pending(record)
        options["nested"]["enabled"] = False

        with self.open_store() as store:
            loaded = store.require_pending(record.approval_id)
        self.assertTrue(loaded.request.arguments["options"]["nested"]["enabled"])
        with self.assertRaises(AttributeError):
            loaded._request = None

    def test_store_rejects_non_pending_records_and_has_no_consume_api(self):
        record = self.make_record()
        with self.open_store() as store:
            with self.assertRaises(MalformedApprovalError):
                store.save_pending(record.approve(
                    ApprovalAuthority._from_trusted_boundary(
                        "approval-ui", "human-1", ApprovalAuthorityKind.HUMAN
                    ),
                    now=self.now + timedelta(minutes=1),
                ))
            self.assertFalse(hasattr(store, "consume"))

    def tamper_and_assert_corrupt(self, field, value, idx=1):
        record = self.make_record(user_id=1000 + idx)
        with self.open_store() as store:
            store.save_pending(record)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                f"UPDATE approval_records SET {field} = ? WHERE approval_id = ?",
                (value, record.approval_id),
            )
        with self.open_store() as store:
            with self.assertRaises(CorruptApprovalRecordError):
                store.require_pending(record.approval_id)

    def test_security_relevant_database_tampering_fails_closed(self):
        tampering = {
            "request_fingerprint": hashlib.sha256(b"tampered").hexdigest(),
            "tool": "filesystem",
            "action": "read",
            "resource_value": "users/999",
            "principal_id": "agent-b",
            "integration_id": "other-runtime",
            "capability_id": "filesystem.read",
            "binding_version": "dmint/request-binding/v999",
            "canonicalization_profile": "dmint/jcs-v999",
            "policy_version_id": "policy-v999",
            "policy_digest": hashlib.sha256(b"tampered").hexdigest(),
            "policy_evaluated_at": "2099-01-01T00:00:00+00:00",
            "state": "APPROVED",
            "expires_at": (self.now + timedelta(days=1)).isoformat(),
        }
        for idx, (field, value) in enumerate(tampering.items()):
            with self.subTest(field=field):
                self.tamper_and_assert_corrupt(field, value, idx=idx)
        self.tamper_and_assert_corrupt("arguments_json", "not-json", idx=99)

    def test_malformed_json_duplicate_keys_and_missing_fields_fail_closed(self):
        self.tamper_and_assert_corrupt("arguments_json", '{"user_id":123,"user_id":999}', idx=201)
        self.tamper_and_assert_corrupt("arguments_json", "not-json", idx=202)
        self.tamper_and_assert_corrupt("trusted_context_json", "[]", idx=203)
        self.tamper_and_assert_corrupt("request_id", "request-1", idx=204)

        record = self.make_record()
        with self.open_store() as store:
            store.save_pending(record)
        with sqlite3.connect(self.database) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE approval_records SET policy_version_id = NULL WHERE approval_id = ?",
                    (record.approval_id,),
                )

    def test_invalid_lookup_and_missing_record_fail_closed(self):
        with self.open_store() as store:
            self.assertIsNone(store.get_pending("apr_" + "a" * 43))
            with self.assertRaises(CorruptApprovalRecordError):
                store.get_pending("not-an-approval-id")
            with self.assertRaises(ApprovalStoreError):
                store.require_pending("apr_" + "b" * 43)

    def test_old_deployment_epoch_is_not_loaded_as_current(self):
        record = self.make_record()
        with self.open_store(epoch="epoch-old") as store:
            store.save_pending(record)
        with self.open_store(epoch="epoch-new") as store:
            with self.assertRaises(CorruptApprovalRecordError):
                store.require_pending(record.approval_id)

    def test_duplicate_workflow_ids_are_rejected(self):
        record = self.make_record()
        with self.open_store() as store:
            store.save_pending(record)
            with self.assertRaises(ApprovalStoreError):
                store.save_pending(record)

    def test_database_rollback_replay_is_detected_and_rejected(self):
        authority = LocalApprovalAuthority(issuer_id="authority-1", audience="dmint/local-runtime", clock=lambda: self.now)
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-1", ApprovalAuthorityKind.HUMAN)
        verifier = ApprovalVerifier(trusted_issuers={"authority-1": authority.public_key}, audience="dmint/local-runtime", clock=lambda: self.now + timedelta(seconds=2))

        record = self.make_record()
        assertion = authority.issue(record, approver)
        approved = record.approve(approver, now=self.now + timedelta(seconds=1))

        # Save approved record to DB
        with self.open_store() as store:
            store.save_approved(approved)

        # Snapshot DB before consumption
        snapshot_bytes = self.database.read_bytes()

        # Consume the approval
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1", clock=lambda: self.now + timedelta(seconds=2)) as store:
            store.consume_approved(approval_id=approved.approval_id, credential=assertion, expected_request=approved.request, verifier=verifier)

        # Restore DB snapshot taken before consumption
        self.database.write_bytes(snapshot_bytes)

        # Opening or accessing restored snapshot under same deployment epoch fails closed due to rollback detection
        with self.assertRaises(ApprovalStoreError) as raised:
            with self.open_store() as store:
                store.get(approved.approval_id)
        self.assertIn("rollback", str(raised.exception))

    def test_storage_confidentiality_permissions_and_redaction(self):
        import stat
        db_file = Path(self.tempdir.name) / "secret_store.sqlite"
        store = SQLiteApprovalStore(
            db_file,
            deployment_epoch="epoch-1",
            redact_keys={"password", "secret"},
        )
        # Verify strict file mode 0600 (user read/write only)
        mode = stat.S_IMODE(db_file.stat().st_mode)
        self.assertEqual(mode, 0o600)

        # Create record with secret arguments
        auth_policy = Policy((Rule.allow("auth", "login"),))
        auth_dmint = Dmint(auth_policy, agent_id="agent-a", context=TrustedContext({}))

        def login(user_id, password, secret_token):
            return user_id

        auth_dmint.register(login, "auth.login")
        auth_req = auth_dmint.authorize(login, 123, "my_super_secret_password", "top_secret_token", capability="auth.login").request
        record = ApprovalRecord.create(
            request=auth_req,
            integration_id="local-runtime",
            capability_id="auth.login",
            policy_provenance=PolicyProvenance("p1", hashlib.sha256(b"p1").hexdigest(), self.now),
            created_at=self.now,
            expires_at=self.expires,
        )
        store.save_pending(record)

        # Inspect raw SQLite database row
        row = store._connection.execute("SELECT arguments_json FROM approval_records WHERE approval_id = ?", (record.approval_id,)).fetchone()
        self.assertNotIn("my_super_secret_password", row["arguments_json"])
        self.assertIn("[REDACTED]", row["arguments_json"])
        store.close()

    def test_oversized_request_fails_closed(self):
        huge_payload = "x" * (70 * 1024)
        policy = Policy((Rule.allow("database", "write"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        def write_data(data):
            return data

        dmint.register(write_data, "database.write")
        with self.assertRaises(AuthorizationError):
            dmint.authorize(write_data, huge_payload, capability="database.write")

    def test_pending_request_deduplication_and_quota_limits(self):
        store = SQLiteApprovalStore(
            Path(self.tempdir.name) / "quota_store.sqlite",
            deployment_epoch="epoch-1",
            max_pending_per_principal=3,
            clock=lambda: self.now,
        )
        policy = Policy((Rule.approval_required("database", "delete"),))
        dmint = Dmint(
            policy,
            agent_id="agent-a",
            context=TrustedContext({}),
            approval_store=store,
            policy_provenance=PolicyProvenance("p1", hashlib.sha256(b"p1").hexdigest(), self.now),
            approval_ttl=timedelta(minutes=5),
            clock=lambda: self.now,
        )

        @dmint.protected("database.delete")
        def delete_user(user_id):
            return user_id

        # 1. Repeated identical approval-required call deduplicates to same approval_id
        with self.assertRaises(ApprovalRequiredError) as exc1:
            delete_user(1)
        with self.assertRaises(ApprovalRequiredError) as exc2:
            delete_user(1)

        self.assertEqual(exc1.exception.approval_id, exc2.exception.approval_id)
        row_count = store._connection.execute("SELECT COUNT(*) AS count FROM approval_records WHERE state = 'PENDING'").fetchone()["count"]
        self.assertEqual(row_count, 1)

        # 2. Distinct requests fill quota up to max_pending_per_principal (3)
        with self.assertRaises(ApprovalRequiredError):
            delete_user(2)
        with self.assertRaises(ApprovalRequiredError):
            delete_user(3)

        row_count = store._connection.execute("SELECT COUNT(*) AS count FROM approval_records WHERE state = 'PENDING'").fetchone()["count"]
        self.assertEqual(row_count, 3)

        # 3. 4th distinct request exceeds quota (3) and fails closed
        with self.assertRaises(Exception) as exc_quota:
            delete_user(4)
        cause_str = str(getattr(exc_quota.exception, "__cause__", exc_quota.exception)).lower()
        self.assertIn("quota", cause_str)
        store.close()

    def test_expired_record_cleanup(self):
        current_time = self.now
        store = SQLiteApprovalStore(
            Path(self.tempdir.name) / "cleanup_store.sqlite",
            deployment_epoch="epoch-1",
            clock=lambda: current_time,
        )
        record = self.make_record(user_id=123)
        store.save_pending(record)
        self.assertIsNotNone(store.get(record.approval_id))

        # Advance time past record expiration
        store._clock = lambda: self.now + timedelta(minutes=20)
        cleaned = store.cleanup_expired()
        self.assertEqual(cleaned, 1)
        self.assertIsNone(store.get(record.approval_id))
        store.close()
