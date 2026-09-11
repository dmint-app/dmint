import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint import (
    ApprovalAssertion,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalVerifier,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    TrustedContext,
)
from dmint.errors import (
    ApprovalAlgorithmUnsupportedError,
    ApprovalAudienceInvalidError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalIntegrationMismatchError,
    ApprovalInvalidError,
    ApprovalIssuerInvalidError,
    ApprovalMalformedError,
    ApprovalPrincipalMismatchError,
    ApprovalSignatureInvalidError,
    ApprovalVersionUnsupportedError,
)


class ApprovalAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 3, 1, tzinfo=timezone.utc)
        self.expires = self.now + timedelta(minutes=5)
        self.private_key = Ed25519PrivateKey.generate()
        self.authority = LocalApprovalAuthority(
            issuer_id="approval-authority-1",
            audience="dmint/local-runtime",
            private_key=self.private_key,
            clock=lambda: self.now,
        )
        self.approver = ApprovalAuthority._from_trusted_boundary(
            "approval-ui",
            "human-1",
            ApprovalAuthorityKind.HUMAN,
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
        authorized = dmint.authorize(
            delete_user,
            123,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.record = __import__("dmint").ApprovalRecord.create(
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
        self.assertion = self.authority.issue(self.record, self.approver)
        self.verifier = ApprovalVerifier(
            trusted_issuers={self.authority.issuer_id: self.authority.public_key},
            audience=self.authority.audience,
            clock=lambda: self.now + timedelta(seconds=1),
        )

    def _values(self, assertion=None):
        assertion = assertion or self.assertion
        return {
            "credential_version": assertion.credential_version,
            "algorithm": assertion.algorithm,
            "approval_id": assertion.approval_id,
            "request_id": assertion.request_id,
            "request_fingerprint": assertion.request_fingerprint,
            "principal_id": assertion.principal_id,
            "integration_id": assertion.integration_id,
            "audience": assertion.audience,
            "issuer": assertion.issuer,
            "issued_at": assertion.issued_at,
            "expires_at": assertion.expires_at,
            "policy_version_id": assertion.policy_version_id,
            "policy_digest": assertion.policy_digest,
            "policy_evaluated_at": assertion.policy_evaluated_at,
            "decision": assertion.decision,
            "nonce": assertion.nonce,
            "approver_authority_id": assertion.approver_authority_id,
            "approver_subject_id": assertion.approver_subject_id,
            "approver_kind": assertion.approver_kind,
        }

    def resign(self, **changes):
        values = self._values()
        values.update(changes)
        signing_envelope = ApprovalAssertion._unsigned_values(values)
        signature = self.private_key.sign(rfc8785.dumps(signing_envelope))
        return ApprovalAssertion._signed(values, signature)

    def test_valid_signed_assertion_round_trip(self):
        serialized = self.assertion.to_bytes()
        parsed = ApprovalAssertion.from_bytes(serialized)
        verified = self.verifier.verify(parsed, self.record)

        self.assertEqual(verified.assertion.approval_id, self.record.approval_id)
        self.assertEqual(verified.assertion.request_fingerprint, self.record.request_fingerprint)
        self.assertFalse(hasattr(verified, "execute"))

    def test_approval_assertion_is_not_an_execution_permission(self):
        dmint = Dmint(Policy((Rule.allow("database", "delete", resource="users/123"),)), agent_id="agent-a", context=TrustedContext({"environment": "production"}))
        with self.assertRaises(Exception):
            dmint.execute(self.assertion)

    def test_payload_changes_with_old_signature_fail(self):
        document = json.loads(self.assertion.to_bytes().decode("utf-8"))
        mutations = {
            "request_fingerprint": hashlib.sha256(b"other-request").hexdigest(),
            "request_id": "req_" + "a" * 43,
            "principal_id": "agent-b",
            "integration_id": "other-runtime",
            "audience": "other-audience",
            "approval_id": "apr_" + "b" * 43,
            "expires_at": (self.expires + timedelta(days=1)).isoformat(),
            "issuer": "other-authority",
            "policy_version_id": "policy-v2",
            "policy_digest": hashlib.sha256(b"policy-v2").hexdigest(),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                mutated = dict(document)
                payload = dict(document["payload"])
                payload[field] = value
                mutated["payload"] = payload
                serialized = rfc8785.dumps(mutated)
                with self.assertRaises((ApprovalSignatureInvalidError, ApprovalError)):
                    self.verifier.verify(serialized, self.record)

    def test_resigned_request_mutations_fail_exact_binding(self):
        cases = (
            ("request_fingerprint", hashlib.sha256(b"other-request").hexdigest(), ApprovalInvalidError),
            ("request_id", "req_" + "a" * 43, ApprovalInvalidError),
            ("principal_id", "agent-b", ApprovalPrincipalMismatchError),
            ("integration_id", "other-runtime", ApprovalIntegrationMismatchError),
            ("audience", "other-audience", ApprovalAudienceInvalidError),
            ("approval_id", "apr_" + "b" * 43, ApprovalInvalidError),
            ("expires_at", (self.expires + timedelta(days=1)), ApprovalInvalidError),
            ("issuer", "other-authority", ApprovalIssuerInvalidError),
            ("policy_version_id", "policy-v2", ApprovalInvalidError),
        )
        for field, value, error_type in cases:
            with self.subTest(field=field):
                with self.assertRaises(error_type):
                    self.verifier.verify(
                        self.resign(**{field: value}),
                        self.record,
                    )

    def test_wrong_signer_fails(self):
        wrong_authority = LocalApprovalAuthority(
            issuer_id=self.authority.issuer_id,
            audience=self.authority.audience,
            clock=lambda: self.now,
        )
        wrong_assertion = wrong_authority.issue(self.record, self.approver)
        with self.assertRaises(ApprovalSignatureInvalidError):
            self.verifier.verify(wrong_assertion, self.record)

    def test_expired_assertion_fails(self):
        expired_verifier = ApprovalVerifier(
            trusted_issuers={self.authority.issuer_id: self.authority.public_key},
            audience=self.authority.audience,
            clock=lambda: self.expires,
        )
        with self.assertRaises(ApprovalExpiredError):
            expired_verifier.verify(self.assertion, self.record)

    def test_signature_mutation_fails(self):
        document = json.loads(self.assertion.to_bytes().decode("utf-8"))
        signature = bytearray(base64.urlsafe_b64decode(document["signature"] + "=="))
        signature[0] ^= 1
        document["signature"] = base64.urlsafe_b64encode(bytes(signature)).decode("ascii").rstrip("=")
        with self.assertRaises(ApprovalSignatureInvalidError):
            self.verifier.verify(rfc8785.dumps(document), self.record)

    def test_algorithm_version_and_unsigned_assertions_fail(self):
        document = json.loads(self.assertion.to_bytes().decode("utf-8"))
        document["algorithm"] = "none"
        with self.assertRaises(ApprovalAlgorithmUnsupportedError):
            ApprovalAssertion.from_bytes(rfc8785.dumps(document))

        document = json.loads(self.assertion.to_bytes().decode("utf-8"))
        document["credential_version"] = "dmint/approval-assertion/v999"
        with self.assertRaises(ApprovalVersionUnsupportedError):
            ApprovalAssertion.from_bytes(rfc8785.dumps(document))

        document = json.loads(self.assertion.to_bytes().decode("utf-8"))
        document.pop("signature")
        with self.assertRaises(ApprovalMalformedError):
            ApprovalAssertion.from_bytes(rfc8785.dumps(document))

    def test_malformed_and_duplicate_serialization_fails(self):
        with self.assertRaises(ApprovalMalformedError):
            ApprovalAssertion.from_bytes(b"not-json")
        with self.assertRaises(ApprovalMalformedError):
            ApprovalAssertion.from_bytes(b'{"algorithm":"Ed25519","algorithm":"none"}')
        with self.assertRaises(ApprovalMalformedError):
            ApprovalAssertion.from_bytes(b" {\"algorithm\":\"Ed25519\"} ")

    def test_replay_before_consumption_is_verification_only(self):
        first = self.verifier.verify(self.assertion, self.record, now=self.now + timedelta(seconds=1))
        second = self.verifier.verify(self.assertion, self.record, now=self.now + timedelta(seconds=2))
        self.assertEqual(first.assertion.nonce, second.assertion.nonce)
        self.assertEqual(self.record.state.value, "PENDING")

    def test_untrusted_caller_cannot_issue_without_authority_value(self):
        with self.assertRaises(ApprovalMalformedError):
            self.authority.issue(self.record, "agent-says-approved", now=self.now)
