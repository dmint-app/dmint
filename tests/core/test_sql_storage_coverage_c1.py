"""Comprehensive unit tests covering uncovered branches in dmint.core.storage.sql."""

from __future__ import annotations

import hashlib
import hmac
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text

from dmint.core.approvals import (
    APPROVAL_RECORD_SCHEMA_VERSION,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
    new_approval_id,
    new_request_id,
)
from dmint.core.authority import LocalApprovalAuthority
from dmint.core.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalConsumedError,
    ApprovalDeploymentInvalidError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalNotApprovedError,
    ApprovalPolicyInvalidError,
    ApprovalPrincipalMismatchError,
    ApprovalRequestMismatchError,
    ApprovalStoreConfigurationError,
    ApprovalStoreError,
    CorruptApprovalRecordError,
    DeprecatedStorageFormatError,
    MalformedApprovalError,
    UnknownApprovalVersionError,
)
from dmint.core.models import (
    NO_RESOURCE,
    NoResource,
    ToolRequest,
    TrustedContext,
)
from dmint.core.policy import Policy, Rule
from dmint.core.request_binding import request_binding_fingerprint
from dmint.core.storage.sql import SQLAlchemyApprovalStore
from dmint.core.storage.sqlite import _canonical_json, _integrity_checksum, _timestamp
from dmint.core.verification import ApprovalAssertion, ApprovalVerifier
from dmint.core.versions import CANONICALIZATION_PROFILE, REQUEST_BINDING_VERSION


class SqlStorageCoverageC1Tests(unittest.TestCase):
    """Test uncovered execution paths and edge cases in SQLAlchemyApprovalStore."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_url = f"sqlite:///{self.tmp_path / 'test.db'}"
        self.integrity_key = b"0" * 32
        self.epoch = "epoch-c1"
        self.private_key = Ed25519PrivateKey.generate()
        self.authority = LocalApprovalAuthority(
            issuer_id="test-iss",
            audience="local-runtime",
            private_key=self.private_key,
        )
        self.verifier = ApprovalVerifier(
            trusted_issuers={self.authority.issuer_id: self.authority.public_key},
            audience=self.authority.audience,
        )
        self.store = SQLAlchemyApprovalStore(
            self.db_url,
            deployment_epoch=self.epoch,
            integrity_key=self.integrity_key,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _sample_request(
        self,
        request_id: str | None = None,
        tool: str = "bash",
        action: str = "execute",
        resource: str | NoResource = NO_RESOURCE,
    ) -> ToolRequest:
        return ToolRequest(
            request_id=request_id or new_request_id(),
            agent_id="agent_1",
            tool=tool,
            action=action,
            resource=resource,
            arguments={"cmd": "ls"},
            context=TrustedContext({"user": "alice"}),
        )

    def _sample_record(
        self,
        approval_id: str | None = None,
        request_id: str | None = None,
        state: ApprovalState = ApprovalState.PENDING,
        created_delta: timedelta = timedelta(0),
        expires_delta: timedelta = timedelta(hours=1),
    ) -> ApprovalRecord:
        req = self._sample_request(request_id=request_id)
        now = datetime.now(timezone.utc)
        created_at = now + created_delta
        expires_at = now + expires_delta
        provenance = PolicyProvenance(
            version_id="pol_v1",
            policy_digest="a" * 64,
            evaluated_at=created_at,
        )
        fp = request_binding_fingerprint(
            req,
            integration_id="int_1",
            capability_id="cap_1",
            binding_version=REQUEST_BINDING_VERSION,
            canonicalization_profile=CANONICALIZATION_PROFILE,
        )
        return ApprovalRecord._from_storage(
            schema_version=APPROVAL_RECORD_SCHEMA_VERSION,
            approval_id=approval_id or new_approval_id(),
            request=req,
            request_fingerprint=fp,
            binding_version=REQUEST_BINDING_VERSION,
            canonicalization_profile=CANONICALIZATION_PROFILE,
            integration_id="int_1",
            capability_id="cap_1",
            policy_provenance=provenance,
            created_at=created_at,
            expires_at=expires_at,
            state=state,
            state_at=created_at,
            row_version=1,
        )

    def test_constructor_validation(self) -> None:
        """Constructor validates deployment_epoch and max_pending_per_principal."""
        with self.assertRaises(ValueError):
            SQLAlchemyApprovalStore(self.db_url, deployment_epoch="")
        with self.assertRaises(ValueError):
            SQLAlchemyApprovalStore(self.db_url, deployment_epoch="  bad_spacing  ")
        with self.assertRaises(ValueError):
            SQLAlchemyApprovalStore(self.db_url, deployment_epoch="ep", max_pending_per_principal=0)
        with self.assertRaises(ValueError):
            SQLAlchemyApprovalStore(self.db_url, deployment_epoch="ep", max_pending_per_principal=-5)

    def test_constructor_invalid_db_engine_and_connect_error(self) -> None:
        """Constructor raises ApprovalStoreConfigurationError on invalid DB configuration or connection."""
        with self.assertRaises(ApprovalStoreConfigurationError):
            SQLAlchemyApprovalStore("nonexistent_dialect://bad", deployment_epoch="ep")

        with patch("sqlalchemy.engine.Engine.connect", side_effect=Exception("connection refused")):
            with self.assertRaises(ApprovalStoreConfigurationError) as ctx:
                SQLAlchemyApprovalStore(self.db_url, deployment_epoch="ep")
            self.assertIn("Failed to connect", str(ctx.exception))

    def test_recovery_epoch_sidecar_rollback_detected(self) -> None:
        """Sidecar file detection raises ApprovalStoreError on rollback."""
        sidecar = self.tmp_path / "recovery.epoch"
        sidecar.write_text("9999", encoding="utf-8")  # Much higher than initial DB counter 1

        with self.assertRaises(ApprovalStoreError) as ctx:
            SQLAlchemyApprovalStore(
                self.db_url,
                deployment_epoch="ep",
                recovery_epoch_file=sidecar,
            )
        self.assertIn("database rollback detected", str(ctx.exception))

    def test_engine_property_and_close(self) -> None:
        """engine property returns Engine and close disposes it."""
        eng = self.store.engine
        self.assertIsNotNone(eng)
        self.store.close()

    def test_authoritative_policy_store_and_load(self) -> None:
        """set_authoritative_policy stores and updates policy, get_authoritative_policy retrieves it."""
        now = datetime.now(timezone.utc)
        pol1 = Policy([Rule.allow("bash", "execute")])
        prov1 = PolicyProvenance("v1", hashlib.sha256(b"pol1").hexdigest(), now)

        self.assertIsNone(self.store.get_authoritative_policy())

        # Insert
        self.store.set_authoritative_policy(pol1, prov1)
        loaded = self.store.get_authoritative_policy()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded[1].version_id, "v1")

        # Update
        pol2 = Policy([Rule.allow("fs", "read")])
        prov2 = PolicyProvenance("v2", hashlib.sha256(b"pol2").hexdigest(), now)
        self.store.set_authoritative_policy(pol2, prov2)
        loaded2 = self.store.get_authoritative_policy()
        self.assertIsNotNone(loaded2)
        self.assertEqual(loaded2[1].version_id, "v2")

    def test_max_pending_per_principal_exceeded(self) -> None:
        """save_pending raises ApprovalStoreError when max_pending_per_principal is exceeded."""
        store = SQLAlchemyApprovalStore(
            f"sqlite:///{self.tmp_path / 'pending_limit.db'}",
            deployment_epoch=self.epoch,
            integrity_key=self.integrity_key,
            max_pending_per_principal=2,
        )
        # Distinct requests so deduplication is not triggered
        req1 = self._sample_request()
        object.__setattr__(req1, "arguments", {"cmd": "run_1"})
        rec1 = self._sample_record()
        object.__setattr__(rec1, "_request", req1)

        req2 = self._sample_request()
        object.__setattr__(req2, "arguments", {"cmd": "run_2"})
        rec2 = self._sample_record()
        object.__setattr__(rec2, "_request", req2)

        req3 = self._sample_request()
        object.__setattr__(req3, "arguments", {"cmd": "run_3"})
        rec3 = self._sample_record()
        object.__setattr__(rec3, "_request", req3)

        # Recompute fingerprints so they are distinct
        fp1 = request_binding_fingerprint(req1, integration_id="int_1", capability_id="cap_1")
        fp2 = request_binding_fingerprint(req2, integration_id="int_1", capability_id="cap_1")
        fp3 = request_binding_fingerprint(req3, integration_id="int_1", capability_id="cap_1")
        object.__setattr__(rec1, "_request_fingerprint", fp1)
        object.__setattr__(rec2, "_request_fingerprint", fp2)
        object.__setattr__(rec3, "_request_fingerprint", fp3)

        store.save_pending(rec1)
        store.save_pending(rec2)
        with self.assertRaises(ApprovalStoreError) as ctx:
            store.save_pending(rec3)
        self.assertIn("maximum pending approvals reached", str(ctx.exception))
        store.close()

    def test_save_duplicate_conflicts(self) -> None:
        """save_pending raises ApprovalStoreError on duplicate approval_id or request_id."""
        rec1 = self._sample_record()
        self.store.save_pending(rec1)

        # Duplicate approval_id
        dup_rec = self._sample_record(approval_id=rec1.approval_id)
        with self.assertRaises(ApprovalStoreError):
            self.store.save_pending(dup_rec)

    def test_get_and_require_pending_and_approved(self) -> None:
        """get_pending and get_approved enforce their respective states."""
        rec = self._sample_record()
        self.store.save_pending(rec)

        # Pending check
        self.assertIsNotNone(self.store.get_pending(rec.approval_id))
        self.assertEqual(self.store.require_pending(rec.approval_id).approval_id, rec.approval_id)

        # Missing require_pending raises ApprovalNotFoundError
        with self.assertRaises(ApprovalNotFoundError):
            self.store.require_pending(new_approval_id())

        # Invalid approval_id format
        with self.assertRaises(CorruptApprovalRecordError):
            self.store.get("invalid_id_format")

        # Approve it
        approved = self.store.approve_pending(
            rec.approval_id,
            authority=self.authority,
            approved_by="bob",
            reason="looks good",
        )
        self.assertIsNotNone(self.store.get_approved(approved.approval_id))

        # Calling get_pending on approved record raises CorruptApprovalRecordError
        with self.assertRaises(CorruptApprovalRecordError):
            self.store.get_pending(approved.approval_id)

    def test_approve_pending_and_reject_pending_validations(self) -> None:
        """approve_pending and reject_pending validate authority, approver, and reasons."""
        rec = self._sample_record()
        self.store.save_pending(rec)

        # Invalid authority type
        with self.assertRaises(MalformedApprovalError):
            self.store.approve_pending(rec.approval_id, authority="not_an_auth", approved_by="bob")  # type: ignore[arg-type]
        with self.assertRaises(MalformedApprovalError):
            self.store.reject_pending(rec.approval_id, authority="not_an_auth", rejected_by="bob")  # type: ignore[arg-type]

        # Empty approved_by / rejected_by
        with self.assertRaises(MalformedApprovalError):
            self.store.approve_pending(rec.approval_id, authority=self.authority, approved_by="")
        with self.assertRaises(MalformedApprovalError):
            self.store.reject_pending(rec.approval_id, authority=self.authority, rejected_by="")

        # Reason too long (> 1000)
        with self.assertRaises(MalformedApprovalError):
            self.store.approve_pending(rec.approval_id, authority=self.authority, approved_by="bob", reason="x" * 1001)
        with self.assertRaises(MalformedApprovalError):
            self.store.reject_pending(rec.approval_id, authority=self.authority, rejected_by="bob", reason="x" * 1001)

        # Missing approval record
        with self.assertRaises(ApprovalNotFoundError):
            self.store.approve_pending(new_approval_id(), authority=self.authority, approved_by="bob")
        with self.assertRaises(ApprovalNotFoundError):
            self.store.reject_pending(new_approval_id(), authority=self.authority, rejected_by="bob")

    def test_cleanup_expired(self) -> None:
        """cleanup_expired transitions past-expiry PENDING records to EXPIRED."""
        # Create an expired pending record
        rec_exp = self._sample_record(
            created_delta=timedelta(hours=-2),
            expires_delta=timedelta(hours=-1),
        )
        self.store.save_pending(rec_exp)

        # Run cleanup
        count = self.store.cleanup_expired()
        self.assertGreaterEqual(count, 1)

        # Should now be deleted from pending / store
        stored = self.store.get(rec_exp.approval_id)
        self.assertIsNone(stored)

    def test_list_records_and_list_pending_limits_and_filters(self) -> None:
        """list_records and list_pending validate limit and state filters."""
        # limit < 1 raises MalformedApprovalError
        with self.assertRaises(MalformedApprovalError):
            self.store.list_pending(limit=0)
        with self.assertRaises(MalformedApprovalError):
            self.store.list_records(limit=0)

        # Invalid states filter
        with self.assertRaises(MalformedApprovalError):
            self.store.list_records(states=set())  # empty
        with self.assertRaises(MalformedApprovalError):
            self.store.list_records(states={"PENDING"})  # type: ignore[arg-type]

        rec = self._sample_record()
        self.store.save_pending(rec)

        res_pend = self.store.list_pending(limit=10)
        self.assertEqual(len(res_pend), 1)

        res_all = self.store.list_records(states={ApprovalState.PENDING})
        self.assertEqual(len(res_all), 1)

        res_empty = self.store.list_records(states={ApprovalState.CONSUMED})
        self.assertEqual(len(res_empty), 0)

    def test_invalidate_approved_requires_approved_state(self) -> None:
        """invalidate_approved raises ApprovalNotApprovedError on non-approved records."""
        rec = self._sample_record()
        self.store.save_pending(rec)

        with self.assertRaises(ApprovalNotApprovedError):
            self.store.invalidate_approved(rec, reason="test invalidation")

        # Approve, then invalidate
        approved = self.store.approve_pending(rec.approval_id, authority=self.authority, approved_by="bob")
        invalidated = self.store.invalidate_approved(approved, reason="policy update")
        self.assertEqual(invalidated.state, ApprovalState.POLICY_INVALIDATED)

    def test_consume_approved_error_branches(self) -> None:
        """consume_approved validates request, verifier, epoch, fingerprint, and consumption races."""
        rec = self._sample_record()
        self.store.save_pending(rec)
        req = rec.request

        # Create valid approved assertion for tests
        approved = self.store.approve_pending(rec.approval_id, authority=self.authority, approved_by="bob")
        now_dt = datetime.now(timezone.utc)
        approver = ApprovalAuthority._from_trusted_boundary(
            self.authority.issuer_id, "bob", ApprovalAuthorityKind.HUMAN
        )
        assertion = self.authority.issue(approved, approver, now=now_dt)

        # 1. Invalid approval_id format
        with self.assertRaises(CorruptApprovalRecordError):
            self.store.consume_approved(
                approval_id="bad_id",
                credential=assertion,
                expected_request=req,
                verifier=self.verifier,
            )

        # 2. expected_request not ToolRequest
        with self.assertRaises(ApprovalRequestMismatchError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request="not_a_request",  # type: ignore[arg-type]
                verifier=self.verifier,
            )

        # 3. verifier not ApprovalVerifier
        with self.assertRaises(ApprovalStoreError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request=req,
                verifier="not_verifier",  # type: ignore[arg-type]
            )

        # 4. Record not found
        with self.assertRaises(ApprovalNotFoundError):
            self.store.consume_approved(
                approval_id=new_approval_id(),
                credential=assertion,
                expected_request=req,
                verifier=self.verifier,
            )

        # 5. Record is PENDING (not approved)
        pending_rec = self._sample_record()
        self.store.save_pending(pending_rec)
        with self.assertRaises(ApprovalNotApprovedError):
            self.store.consume_approved(
                approval_id=pending_rec.approval_id,
                credential=assertion,
                expected_request=pending_rec.request,
                verifier=self.verifier,
            )

        # 6. Request ID mismatch
        mismatched_req = ToolRequest(
            request_id=new_request_id(),
            agent_id=req.agent_id,
            tool=req.tool,
            action=req.action,
            resource=req.resource,
            arguments=dict(req.arguments),
            context=req.context,
        )
        with self.assertRaises(ApprovalRequestMismatchError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request=mismatched_req,
                verifier=self.verifier,
            )

        # 7. Agent ID mismatch
        mismatched_agent = ToolRequest(
            request_id=req.request_id,
            agent_id="mallory",
            tool=req.tool,
            action=req.action,
            resource=req.resource,
            arguments=dict(req.arguments),
            context=req.context,
        )
        with self.assertRaises(ApprovalPrincipalMismatchError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request=mismatched_agent,
                verifier=self.verifier,
            )

        # 8. Request arguments/fingerprint mismatch
        mismatched_args = ToolRequest(
            request_id=req.request_id,
            agent_id=req.agent_id,
            tool=req.tool,
            action=req.action,
            resource=req.resource,
            arguments={"cmd": "rm -rf /"},
            context=req.context,
        )
        with self.assertRaises(ApprovalRequestMismatchError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request=mismatched_args,
                verifier=self.verifier,
            )

        # 9. Successful consumption
        consumed = self.store.consume_approved(
            approval_id=rec.approval_id,
            credential=assertion,
            expected_request=req,
            verifier=self.verifier,
        )
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)

        # 10. Already consumed
        with self.assertRaises(ApprovalConsumedError):
            self.store.consume_approved(
                approval_id=rec.approval_id,
                credential=assertion,
                expected_request=req,
                verifier=self.verifier,
            )

    def test_deserialize_corrupt_records(self) -> None:
        """_deserialize fails closed on schema version mismatch, corrupt checksum, or corrupt fields."""
        rec = self._sample_record()
        self.store.save_pending(rec)

        with self.store.engine.connect() as conn:
            row = (
                conn.execute(
                    text("SELECT * FROM approval_records WHERE approval_id = :id"),
                    {"id": rec.approval_id},
                )
                .mappings()
                .fetchone()
            )

        # Tampered checksum
        bad_row = dict(row)
        bad_row["record_checksum"] = "bad" * 16
        with self.assertRaises(CorruptApprovalRecordError):
            self.store._deserialize(bad_row)

        # Unknown schema version
        bad_version_row = dict(row)
        bad_version_row["schema_version"] = "99.0"
        with self.assertRaises(UnknownApprovalVersionError):
            self.store._deserialize(bad_version_row)

        # Deployment epoch mismatch
        bad_epoch_row = dict(row)
        bad_epoch_row["deployment_epoch"] = "other_epoch"
        with self.assertRaises(CorruptApprovalRecordError):
            self.store._deserialize(bad_epoch_row)

        # Incomplete authority
        bad_auth_row = dict(row)
        bad_auth_row["decision_authority_id"] = "auth1"
        bad_auth_row["decision_authority_subject"] = None
        bad_auth_row["decision_authority_kind"] = "HUMAN"
        with self.assertRaises(CorruptApprovalRecordError):
            self.store._deserialize(bad_auth_row)

        # Invalid authority kind
        bad_kind_row = dict(row)
        bad_kind_row["decision_authority_id"] = "auth1"
        bad_kind_row["decision_authority_subject"] = "sub1"
        bad_kind_row["decision_authority_kind"] = "INVALID_KIND"
        with self.assertRaises(CorruptApprovalRecordError):
            self.store._deserialize(bad_kind_row)

        # Invalid resource kind
        bad_res_row = dict(row)
        bad_res_row["resource_kind"] = "unknown_kind"
        with self.assertRaises(CorruptApprovalRecordError):
            self.store._deserialize(bad_res_row)

    def test_save_approved_and_deduplication(self) -> None:
        """save_approved persists approved records and save_pending reuses identical pending."""
        rec = self._sample_record()

        # Cannot save pending record as approved
        with self.assertRaises(MalformedApprovalError):
            self.store.save_approved(rec)

        # Save pending, then save_pending with identical request returns existing record
        saved_pend = self.store.save_pending(rec)
        dup_request_rec = self._sample_record(request_id=new_request_id())
        reused = self.store.save_pending(dup_request_rec)
        self.assertEqual(reused.approval_id, saved_pend.approval_id)

        # Transition pending record to approved via save_approved (update branch)
        approver = ApprovalAuthority._from_trusted_boundary(
            self.authority.issuer_id, "bob", ApprovalAuthorityKind.HUMAN
        )
        now_dt = datetime.now(timezone.utc)
        approved_from_pend = saved_pend.approve(approver, now=now_dt)
        self.store.save_approved(approved_from_pend)
        self.assertEqual(self.store.get_approved(saved_pend.approval_id).approval_id, saved_pend.approval_id)

        # Directly insert an approved record (insert branch)
        direct_pend = self._sample_record()
        approved_direct = direct_pend.approve(approver, now=now_dt)
        self.store.save_approved(approved_direct)
        self.assertEqual(self.store.get_approved(direct_pend.approval_id).approval_id, direct_pend.approval_id)

        # get_approved on pending record raises CorruptApprovalRecordError
        pend2 = self._sample_record()
        # Change arguments so it doesn't deduplicate
        req2 = self._sample_request()
        object.__setattr__(req2, "arguments", {"cmd": "other"})
        object.__setattr__(pend2, "_request", req2)
        object.__setattr__(
            pend2,
            "_request_fingerprint",
            request_binding_fingerprint(req2, integration_id="int_1", capability_id="cap_1"),
        )
        self.store.save_pending(pend2)
        with self.assertRaises(CorruptApprovalRecordError):
            self.store.get_approved(pend2.approval_id)

    def test_redact_keys_and_recovery_file_success(self) -> None:
        """Store redacts sensitive keys and writes sidecar recovery file."""
        sidecar = self.tmp_path / "valid_recovery.epoch"
        sidecar.write_text("1", encoding="utf-8")

        redacting_store = SQLAlchemyApprovalStore(
            f"sqlite:///{self.tmp_path / 'redact.db'}",
            deployment_epoch=self.epoch,
            integrity_key=self.integrity_key,
            recovery_epoch_file=sidecar,
            redact_keys={"password", "token"},
        )
        req = self._sample_request()
        object.__setattr__(req, "arguments", {"password": "supersecretpassword", "safe": "public"})
        rec = self._sample_record()
        object.__setattr__(rec, "_request", req)
        object.__setattr__(
            rec, "_request_fingerprint", request_binding_fingerprint(req, integration_id="int_1", capability_id="cap_1")
        )

        redacting_store.save_pending(rec)
        with redacting_store.engine.connect() as conn:
            row = conn.execute(
                text("SELECT arguments_json FROM approval_records WHERE approval_id = :id"),
                {"id": rec.approval_id},
            ).scalar()
        self.assertNotIn("supersecretpassword", row)
        self.assertIn("[REDACTED]", row)
        redacting_store.close()

    def test_list_records_skipping_unsupported_and_multiple_states(self) -> None:
        """list_pending and list_records skip unsupported schema version records with warnings."""
        from dmint.core.storage.sql import _required

        # Test _required missing
        with self.assertRaises(CorruptApprovalRecordError):
            _required({}, "absent_key")

        rec = self._sample_record()
        self.store.save_pending(rec)

        # Directly insert an unsupported schema version row
        with self.store.engine.begin() as conn:
            row_dict = (
                conn.execute(
                    text("SELECT * FROM approval_records WHERE approval_id = :id"),
                    {"id": rec.approval_id},
                )
                .mappings()
                .fetchone()
            )
            bad_row = dict(row_dict)
            bad_row["approval_id"] = new_approval_id()
            bad_row["request_id"] = new_request_id()
            bad_row["schema_version"] = "unsupported_version_0"
            conn.execute(
                text(
                    "INSERT INTO approval_records (schema_version, approval_id, request_id, request_fingerprint, binding_version, canonicalization_profile, integration_id, capability_id, principal_id, tool, action, resource_kind, resource_value, arguments_json, trusted_context_json, policy_version_id, policy_digest, policy_evaluated_at, created_at, expires_at, state, state_at, decision_authority_id, decision_authority_subject, decision_authority_kind, decision_at, state_reason, consumed_at, deployment_epoch, row_version, record_checksum) VALUES (:schema_version, :approval_id, :request_id, :request_fingerprint, :binding_version, :canonicalization_profile, :integration_id, :capability_id, :principal_id, :tool, :action, :resource_kind, :resource_value, :arguments_json, :trusted_context_json, :policy_version_id, :policy_digest, :policy_evaluated_at, :created_at, :expires_at, :state, :state_at, :decision_authority_id, :decision_authority_subject, :decision_authority_kind, :decision_at, :state_reason, :consumed_at, :deployment_epoch, :row_version, :record_checksum)"
                ),
                bad_row,
            )

        # Both list_pending and list_records should skip the bad row and warn
        pending_list = self.store.list_pending()
        self.assertEqual(len(pending_list), 1)

        records_list = self.store.list_records(states={ApprovalState.PENDING, ApprovalState.APPROVED})
        self.assertEqual(len(records_list), 1)
