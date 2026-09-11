import hashlib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalConsumedError,
    ApprovalMalformedError,
    ApprovalVerifier,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    SQLiteApprovalStore,
    ToolRequest,
    TrustedContext,
)
from dmint.approvals import ApprovalRecord, ApprovalState
from dmint.errors import (
    ApprovalDeploymentInvalidError,
    ApprovalExpiredError,
    ApprovalInvalidError,
    ApprovalNotApprovedError,
    ApprovalNotFoundError,
    ApprovalRequestMismatchError,
    ApprovalSignatureInvalidError,
    ApprovalStoreError,
    CorruptApprovalRecordError,
    MalformedApprovalError,
)


class AtomicConsumptionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 4, 1, tzinfo=timezone.utc)
        self.expires = self.now + timedelta(minutes=5)
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Path(self.tempdir.name) / "approvals.sqlite"
        self.private_key = Ed25519PrivateKey.generate()
        self.authority = LocalApprovalAuthority(
            issuer_id="authority-1",
            audience="dmint/runtime-1",
            private_key=self.private_key,
        )
        self.approver = ApprovalAuthority._from_trusted_boundary(
            "approval-ui", "human-1", ApprovalAuthorityKind.HUMAN
        )
        self.dmint = Dmint(
            Policy((Rule.allow("database", "delete", resource="users/123"),)),
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
        self.verifier = ApprovalVerifier(
            trusted_issuers={self.authority.issuer_id: self.authority.public_key},
            audience=self.authority.audience,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def make_approved(self, *, expires_at=None):
        if expires_at is None:
            expires_at = self.expires
        authorized = self.dmint.authorize(
            self.delete_user,
            123,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        pending = ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=PolicyProvenance(
                "policy-v1", hashlib.sha256(b"policy-v1").hexdigest(), self.now
            ),
            created_at=self.now,
            expires_at=expires_at,
        )
        assertion = self.authority.issue(pending, self.approver, now=self.now)
        approved = pending.approve(self.approver, now=self.now + timedelta(seconds=1))
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            store.save_approved(approved)
        return approved, assertion

    def consume(self, record, assertion, *, expected_request=None, epoch="epoch-1", now=None):
        if expected_request is None:
            expected_request = record.request
        current_time = now or (self.now + timedelta(seconds=2))
        with SQLiteApprovalStore(
            self.database,
            deployment_epoch=epoch,
            clock=lambda: current_time,
        ) as store:
            return store.consume_approved(
                approval_id=record.approval_id,
                credential=assertion,
                expected_request=expected_request,
                verifier=ApprovalVerifier(
                    trusted_issuers={self.authority.issuer_id: self.authority.public_key},
                    audience=self.authority.audience,
                    clock=lambda: current_time,
                ),
            )

    def test_single_consumption_succeeds_and_returns_consumed_record(self):
        approved, assertion = self.make_approved()

        consumed = self.consume(approved, assertion)

        self.assertEqual(consumed.state, ApprovalState.CONSUMED)
        self.assertEqual(consumed.approval_id, approved.approval_id)
        self.assertEqual(consumed.request_fingerprint, approved.request_fingerprint)
        with self.assertRaises(AttributeError):
            consumed._state = ApprovalState.APPROVED

    def test_second_consumption_fails(self):
        approved, assertion = self.make_approved()
        self.consume(approved, assertion)

        with self.assertRaises(ApprovalConsumedError):
            self.consume(approved, assertion)

    def test_wrong_request_fails_without_consuming(self):
        approved, assertion = self.make_approved()
        wrong = ToolRequest(
            request_id=approved.request_id,
            agent_id=approved.request.agent_id,
            tool=approved.request.tool,
            action=approved.request.action,
            resource="users/999",
            arguments={"user_id": 999},
            context=approved.request.context,
        )
        with self.assertRaises(ApprovalRequestMismatchError):
            self.consume(approved, assertion, expected_request=wrong)
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get_approved(approved.approval_id).state, ApprovalState.APPROVED)

    def test_wrong_principal_and_integration_fail(self):
        approved, assertion = self.make_approved()
        wrong_principal = self.dmint.authorize(
            self.delete_user,
            123,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        ).request
        object.__setattr__(wrong_principal, "agent_id", "agent-b")
        with self.assertRaises((ApprovalRequestMismatchError, CorruptApprovalRecordError)):
            self.consume(approved, assertion, expected_request=wrong_principal)

        other_authority = LocalApprovalAuthority(
            issuer_id="authority-1",
            audience="dmint/runtime-1",
        )
        other_assertion = other_authority.issue(approved, self.approver, now=self.now)
        with self.assertRaises(ApprovalSignatureInvalidError):
            self.consume(approved, other_assertion)

    def test_expired_approval_fails(self):
        approved, assertion = self.make_approved(expires_at=self.now + timedelta(seconds=2))
        with self.assertRaises(ApprovalExpiredError):
            self.consume(approved, assertion, now=self.now + timedelta(seconds=3))
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get_approved(approved.approval_id).state, ApprovalState.APPROVED)

    def test_pending_and_missing_approvals_fail(self):
        authorized = self.dmint.authorize(
            self.delete_user,
            123,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        pending = ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=PolicyProvenance(
                "policy-v1", hashlib.sha256(b"policy-v1").hexdigest(), self.now
            ),
            created_at=self.now,
            expires_at=self.expires,
        )
        assertion = self.authority.issue(pending, self.approver, now=self.now)
        with SQLiteApprovalStore(
            self.database,
            deployment_epoch="epoch-1",
            clock=lambda: self.now + timedelta(seconds=1),
        ) as store:
            store.save_pending(pending)
            verifier = ApprovalVerifier(
                trusted_issuers={self.authority.issuer_id: self.authority.public_key},
                audience=self.authority.audience,
                clock=lambda: self.now + timedelta(seconds=1),
            )
            with self.assertRaises(ApprovalNotApprovedError):
                store.consume_approved(
                    approval_id=pending.approval_id,
                    credential=assertion,
                    expected_request=pending.request,
                    verifier=verifier,
                )
            with self.assertRaises(ApprovalNotFoundError):
                store.consume_approved(
                    approval_id="apr_" + "z" * 43,
                    credential=assertion,
                    expected_request=pending.request,
                    verifier=verifier,
                )

    def test_wrong_epoch_and_malformed_credential_fail(self):
        approved, assertion = self.make_approved()
        with self.assertRaises(ApprovalDeploymentInvalidError):
            self.consume(approved, assertion, epoch="epoch-old")
        with self.assertRaises(ApprovalMalformedError):
            self.consume(approved, b"not-an-assertion")

    def test_policy_invalidated_approval_cannot_be_consumed(self):
        approved, assertion = self.make_approved()
        invalidated = approved.invalidate_policy(
            now=self.now + timedelta(seconds=2),
            reason="current policy changed",
        )
        from dmint.storage.sqlite import _STORED_COLUMNS

        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            serialized = store._serialize(invalidated)
            columns = (*_STORED_COLUMNS, "record_checksum")
            assignments = ", ".join(f"{column} = ?" for column in columns)
            with store._connection:
                store._connection.execute(
                    f"UPDATE approval_records SET {assignments} WHERE approval_id = ?",
                    serialized + (approved.approval_id,),
                )
            verifier = ApprovalVerifier(
                trusted_issuers={self.authority.issuer_id: self.authority.public_key},
                audience=self.authority.audience,
                clock=lambda: self.now + timedelta(seconds=3),
            )
            with self.assertRaises(Exception) as raised:
                store.consume_approved(
                    approval_id=approved.approval_id,
                    credential=assertion,
                    expected_request=approved.request,
                    verifier=verifier,
                )
        self.assertEqual(getattr(raised.exception, "code", None), "DMT_APPROVAL_POLICY_INVALID")

    def test_approval_id_alone_is_not_a_consumption_api(self):
        approved, _ = self.make_approved()
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            with self.assertRaises(TypeError):
                store.consume_approved(approval_id=approved.approval_id)

    def test_storage_failure_fails_closed(self):
        approved, assertion = self.make_approved()
        store = SQLiteApprovalStore(self.database, deployment_epoch="epoch-1")
        store.close()
        with self.assertRaises(ApprovalStoreError):
            store.consume_approved(
                approval_id=approved.approval_id,
                credential=assertion,
                expected_request=approved.request,
                verifier=self.verifier,
            )

    def test_concurrent_consumption_allows_exactly_one_winner(self):
        approved, assertion = self.make_approved()
        barrier = threading.Barrier(8)

        def attempt(_index):
            barrier.wait()
            try:
                with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
                    store.consume_approved(
                        approval_id=approved.approval_id,
                        credential=assertion,
                        expected_request=approved.request,
                        verifier=self.verifier,
                        now=self.now + timedelta(seconds=2),
                    )
                return "success"
            except (ApprovalConsumedError, ApprovalStoreError) as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(attempt, range(8)))
        self.assertEqual(results.count("success"), 1)
        self.assertEqual(sum(result != "success" for result in results), 7)
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get(approved.approval_id).state, ApprovalState.CONSUMED)
