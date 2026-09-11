import hashlib
import re
import unittest
from datetime import datetime, timedelta, timezone

from dmint import (
    APPROVAL_RECORD_SCHEMA_VERSION,
    CANONICALIZATION_PROFILE,
    Dmint,
    Policy,
    PolicyProvenance,
    REQUEST_BINDING_VERSION,
    Rule,
    TrustedContext,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    parse_approval_state,
)
from dmint.errors import (
    ApprovalExpiredError,
    AuthorizationError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
    UnknownApprovalStateError,
    UnknownApprovalVersionError,
)
from dmint.approvals import _AUTHORITY_TOKEN


REQUEST_ID_PATTERN = re.compile(r"^req_[A-Za-z0-9_-]{43}$")
APPROVAL_ID_PATTERN = re.compile(r"^apr_[A-Za-z0-9_-]{43}$")


class ApprovalDomainTests(unittest.TestCase):
    def setUp(self):
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.expires_at = self.created_at + timedelta(minutes=10)
        self.approver = ApprovalAuthority._from_trusted_boundary(
            "approval-ui",
            "human-123",
            ApprovalAuthorityKind.HUMAN,
        )
        self.policy_provenance = PolicyProvenance(
            "policy-v1",
            hashlib.sha256(b"policy-v1").hexdigest(),
            self.created_at,
        )
        dmint = Dmint(
            Policy((Rule.allow("database", "delete", resource="users/123"),)),
            agent_id="agent-a",
            context=TrustedContext({"environment": "production"}),
        )

        def delete_user(user_id):
            return user_id

        dmint.register(
            delete_user,
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.delete_user = delete_user
        self.authorized = dmint.authorize(
            delete_user,
            123,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.dmint = dmint

    def make_record(self, **changes):
        values = {
            "request": self.authorized.request,
            "integration_id": "local-runtime",
            "capability_id": "database.delete",
            "policy_provenance": self.policy_provenance,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        values.update(changes)
        return ApprovalRecord.create(**values)

    def test_valid_state_transitions_return_new_immutable_records(self):
        pending = self.make_record()
        approved = pending.approve(self.approver, now=self.created_at + timedelta(minutes=1))
        consumed = approved.consume(now=self.created_at + timedelta(minutes=2))
        rejected = self.make_record().reject(self.approver, now=self.created_at + timedelta(minutes=1))
        cancelled = self.make_record().cancel(now=self.created_at + timedelta(minutes=1))
        expired = self.make_record().expire(now=self.expires_at)
        invalidated = self.make_record().invalidate_policy(now=self.created_at + timedelta(minutes=1))

        self.assertEqual(pending.state, ApprovalState.PENDING)
        self.assertEqual(approved.state, ApprovalState.APPROVED)
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)
        self.assertEqual(rejected.state, ApprovalState.REJECTED)
        self.assertEqual(cancelled.state, ApprovalState.CANCELLED)
        self.assertEqual(expired.state, ApprovalState.EXPIRED)
        self.assertEqual(invalidated.state, ApprovalState.POLICY_INVALIDATED)
        self.assertEqual(pending.request_id, approved.request_id)
        self.assertEqual(approved.approval_id, consumed.approval_id)
        self.assertIsNot(pending, approved)

    def test_illegal_transitions_fail(self):
        pending = self.make_record()
        approved = pending.approve(self.approver, now=self.created_at + timedelta(minutes=1))
        rejected = self.make_record().reject(self.approver, now=self.created_at + timedelta(minutes=1))
        cancelled = self.make_record().cancel(now=self.created_at + timedelta(minutes=1))
        invalidated = self.make_record().invalidate_policy(now=self.created_at + timedelta(minutes=1))
        consumed = approved.consume(now=self.created_at + timedelta(minutes=2))

        with self.assertRaises(IllegalApprovalTransitionError):
            pending.consume(now=self.created_at + timedelta(minutes=1))
        with self.assertRaises(IllegalApprovalTransitionError):
            approved.approve(self.approver, now=self.created_at + timedelta(minutes=2))
        with self.assertRaises(IllegalApprovalTransitionError):
            rejected.approve(self.approver, now=self.created_at + timedelta(minutes=2))
        with self.assertRaises(IllegalApprovalTransitionError):
            cancelled.approve(self.approver, now=self.created_at + timedelta(minutes=2))
        with self.assertRaises(IllegalApprovalTransitionError):
            invalidated.consume(now=self.created_at + timedelta(minutes=2))
        with self.assertRaises(IllegalApprovalTransitionError):
            consumed.consume(now=self.created_at + timedelta(minutes=3))

    def test_expiration_prevents_approval_and_consumption(self):
        pending = self.make_record()
        after_expiration = self.expires_at + timedelta(seconds=1)

        with self.assertRaises(ApprovalExpiredError):
            pending.approve(self.approver, now=after_expiration)

        expired = pending.expire(now=self.expires_at)
        with self.assertRaises(IllegalApprovalTransitionError):
            expired.approve(self.approver, now=after_expiration)

        approved = self.make_record().approve(self.approver, now=self.created_at + timedelta(minutes=1))
        with self.assertRaises(ApprovalExpiredError):
            approved.consume(now=after_expiration)

    def test_workflow_and_approval_identities_are_separate(self):
        first = self.make_record()
        second_authorized = self.dmint.authorize(
            self.delete_user,
            123,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        second = self.make_record(request=second_authorized.request)

        self.assertNotEqual(first.request_id, second.request_id)
        self.assertNotEqual(first.approval_id, second.approval_id)
        self.assertNotEqual(first.request_id, first.approval_id)
        self.assertTrue(REQUEST_ID_PATTERN.fullmatch(first.request_id))
        self.assertTrue(APPROVAL_ID_PATTERN.fullmatch(first.approval_id))
        self.assertEqual(first.request_fingerprint, second.request_fingerprint)
        self.assertNotEqual(first.request_id, first.request_fingerprint)
        self.assertNotEqual(first.approval_id, first.request_fingerprint)

    def test_ids_are_stable_across_transitions(self):
        pending = self.make_record()
        approved = pending.approve(self.approver, now=self.created_at + timedelta(minutes=1))
        consumed = approved.consume(now=self.created_at + timedelta(minutes=2))

        self.assertEqual(pending.request_id, approved.request_id)
        self.assertEqual(approved.request_id, consumed.request_id)
        self.assertEqual(pending.approval_id, approved.approval_id)
        self.assertEqual(approved.approval_id, consumed.approval_id)

    def test_caller_mutation_cannot_mutate_record(self):
        options = {"notify": {"email": True}}
        dmint = Dmint(
            Policy((Rule.allow("database", "read"),)),
            agent_id="agent-a",
            context=TrustedContext({}),
        )

        def read_user(user_id, options):
            return user_id, options

        dmint.register(read_user, "database.read")
        authorized = dmint.authorize(read_user, 123, options, capability="database.read")
        record = ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.read",
            policy_provenance=self.policy_provenance,
            created_at=self.created_at,
            expires_at=self.expires_at,
        )
        options["notify"]["email"] = False

        self.assertTrue(record.request.arguments["options"]["notify"]["email"])
        with self.assertRaises(AttributeError):
            record._state = ApprovalState.CONSUMED

    def test_unknown_states_versions_and_malformed_records_fail_closed(self):
        with self.assertRaises(UnknownApprovalStateError):
            parse_approval_state("UNKNOWN")

        for field, value in (
            ("schema_version", "dmint/approval-record/v999"),
            ("binding_version", "dmint/request-binding/v999"),
            ("canonicalization_profile", "dmint/unknown-json-v1"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(UnknownApprovalVersionError):
                    self.make_record(**{field: value})

        with self.assertRaises(MalformedApprovalError):
            self.make_record(expires_at=self.created_at)
        with self.assertRaises(MalformedApprovalError):
            self.make_record(created_at=datetime(2026, 1, 1))

    def test_agent_or_llm_cannot_be_approval_authority_value(self):
        with self.assertRaises(ValueError):
            ApprovalAuthorityKind("LLM")
        with self.assertRaises(ValueError):
            ApprovalAuthorityKind("AGENT")
        with self.assertRaises(MalformedApprovalError):
            self.make_record().approve("agent-a", now=self.created_at + timedelta(minutes=1))
        with self.assertRaises(TypeError):
            ApprovalAuthority("not-the-private-token", "approval-ui", "human-123", ApprovalAuthorityKind.HUMAN)
        with self.assertRaises(MalformedApprovalError):
            ApprovalAuthority(_AUTHORITY_TOKEN, "approval-ui", "agent-a", "HUMAN")

    def test_approval_is_not_itself_permission(self):
        record = self.make_record().approve(self.approver, now=self.created_at + timedelta(minutes=1))

        self.assertFalse(hasattr(record, "execute"))
        with self.assertRaises(AuthorizationError):
            self.dmint.execute(record)
        with self.assertRaises(AuthorizationError):
            self.dmint.execute(record.approval_id)

    def test_profile_and_policy_provenance_are_explicit_and_separate(self):
        record = self.make_record()

        self.assertEqual(record.schema_version, APPROVAL_RECORD_SCHEMA_VERSION)
        self.assertEqual(record.binding_version, REQUEST_BINDING_VERSION)
        self.assertEqual(record.canonicalization_profile, CANONICALIZATION_PROFILE)
        self.assertEqual(record.policy_provenance, self.policy_provenance)
        self.assertNotEqual(record.request_fingerprint, record.policy_provenance.policy_digest)

    def test_create_default_expires_at_succeeds_with_five_minute_ttl(self):
        record = ApprovalRecord.create(
            request=self.authorized.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=self.policy_provenance,
            created_at=self.created_at,
        )
        self.assertEqual(record.expires_at, self.created_at + timedelta(minutes=5))

