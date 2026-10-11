"""Comprehensive regression tests killing mutation survivors from audit Phase 9."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.core.authority import LocalApprovalAuthority
from dmint.core.constraints import evaluate_constraints
from dmint.core.errors import (
    ApprovalDeploymentInvalidError,
    ApprovalInvalidError,
    KeyLoadError,
    KeyPermissionError,
)
from dmint.core.keys import (
    check_key_file_permissions,
    load_private_key_from_file,
    write_private_key_atomic,
)
from dmint import (
    ApprovalAssertion,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    Policy,
    PolicyProvenance,
    ToolRequest,
    TrustedContext,
    new_request_id,
    policy_digest,
)
from dmint.core.request_binding import (
    request_binding_envelope,
    request_binding_fingerprint,
)
from dmint.core.resources import ResourceMatchingError, validate_resource_syntax
from dmint.core.storage.sqlite import SQLiteApprovalStore
from dmint.core.verification import ApprovalVerifier
from dmint.mcp import DiscoveryMode, MCPIntegrationConfig, MCPToolBinding
from dmint.mcp.auth import CURRENT_AGENT_ID
from dmint.mcp.gateway import MCPGateway, MCPGatewayConfig
from mcp import types


class MutationRegressionTests(unittest.TestCase):
    """Regression test suite for all 13 mutation testing survivors."""

    def setUp(self):
        self.now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
        self.expires = self.now + timedelta(hours=1)

    def test_mut_11_resource_syntax_generic_rejects_nul_bytes(self):
        """MUT-11: validate_resource_syntax must reject NUL bytes in generic/exact resources."""
        with self.assertRaises(ResourceMatchingError) as ctx:
            validate_resource_syntax("resource\x00evil", kind="exact")
        self.assertIn("NUL byte", str(ctx.exception))

        with self.assertRaises(ResourceMatchingError) as ctx:
            validate_resource_syntax("resource\x00evil", kind="custom")
        self.assertIn("NUL byte", str(ctx.exception))

    def test_mut_16_numeric_minimum_constraint_enforced(self):
        """MUT-16: evaluate_constraints must fail-closed when integer or float is below minimum."""
        schema = {
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "amount": {"type": "number", "minimum": 0.01, "maximum": 500.0},
            }
        }
        # Violate integer minimum at boundary (0 < 1)
        ok, err = evaluate_constraints(schema, {"limit": 0, "amount": 10.0})
        self.assertFalse(ok)
        self.assertIn("must be >= 1", err or "")

        # Violate integer minimum well below boundary (-50 < 1)
        ok, err = evaluate_constraints(schema, {"limit": -50, "amount": 10.0})
        self.assertFalse(ok)
        self.assertIn("must be >= 1", err or "")

        # Violate number minimum at boundary (0.0099 < 0.01)
        ok, err = evaluate_constraints(schema, {"limit": 10, "amount": 0.0099})
        self.assertFalse(ok)
        self.assertIn("must be >= 0.01", err or "")

        # Violate number minimum well below boundary (-10.5 < 0.01)
        ok, err = evaluate_constraints(schema, {"limit": 10, "amount": -10.5})
        self.assertFalse(ok)
        self.assertIn("must be >= 0.01", err or "")

        # Exactly at minimum must pass
        ok, err = evaluate_constraints(schema, {"limit": 1, "amount": 0.01})
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_mut_18_through_25_request_binding_fields_and_keys(self):
        """MUT-18,19,20,22,24,25: Each field in envelope must affect fingerprint, and keyset must match exactly."""
        base_req = ToolRequest(
            request_id=new_request_id(),
            agent_id="agent-original",
            tool="tool_a",
            action="action_read",
            resource="res://original",
            arguments={"param_k": "param_v"},
            context=TrustedContext({"ctx_env": "production"}),
        )

        # 1. Exact expected keyset
        expected_keys = {
            "action",
            "arguments",
            "binding_version",
            "canonicalization_profile",
            "capability_id",
            "integration_id",
            "principal_id",
            "resource",
            "tool",
            "trusted_context",
        }
        env = request_binding_envelope(
            base_req,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertEqual(set(env.keys()), expected_keys)

        base_fp = request_binding_fingerprint(
            base_req,
            integration_id="integ-original",
            capability_id="cap-original",
        )

        def make_req(**overrides):
            fields = {
                "request_id": base_req.request_id,
                "agent_id": base_req.agent_id,
                "tool": base_req.tool,
                "action": base_req.action,
                "resource": base_req.resource,
                "arguments": dict(base_req.arguments),
                "context": base_req.context,
            }
            fields.update(overrides)
            return ToolRequest(**fields)

        # 2. MUT-18: action
        req_diff_action = make_req(action="action_write")
        fp_action = request_binding_fingerprint(
            req_diff_action,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_action)

        # 3. MUT-19: arguments
        req_diff_args = make_req(arguments={"param_k": "different_value"})
        fp_args = request_binding_fingerprint(
            req_diff_args,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_args)

        # 4. MUT-20: capability_id
        fp_cap = request_binding_fingerprint(
            base_req,
            integration_id="integ-original",
            capability_id="cap-altered",
        )
        self.assertNotEqual(base_fp, fp_cap)

        # 5. MUT-21 / integration_id
        fp_integ = request_binding_fingerprint(
            base_req,
            integration_id="integ-altered",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_integ)

        # 6. MUT-22: principal_id (agent_id)
        req_diff_principal = make_req(agent_id="agent-different")
        fp_principal = request_binding_fingerprint(
            req_diff_principal,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_principal)

        # 7. MUT-23 / resource
        req_diff_res = make_req(resource="res://different")
        fp_res = request_binding_fingerprint(
            req_diff_res,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_res)

        # 8. MUT-24: tool
        req_diff_tool = make_req(tool="tool_b")
        fp_tool = request_binding_fingerprint(
            req_diff_tool,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_tool)

        # 9. MUT-25: trusted_context
        req_diff_ctx = make_req(context=TrustedContext({"ctx_env": "staging"}))
        fp_ctx = request_binding_fingerprint(
            req_diff_ctx,
            integration_id="integ-original",
            capability_id="cap-original",
        )
        self.assertNotEqual(base_fp, fp_ctx)

    def test_mut_32_verification_rejects_mismatched_policy_digest(self):
        """MUT-32: ApprovalVerifier must reject assertions where policy_digest does not match policy_provenance."""
        key = Ed25519PrivateKey.generate()
        authority = LocalApprovalAuthority(
            issuer_id="auth-authority",
            audience="local-runtime",
            private_key=key,
            clock=lambda: self.now,
        )
        verifier = ApprovalVerifier(
            trusted_issuers={authority.issuer_id: authority.public_key},
            audience="local-runtime",
            clock=lambda: self.now,
        )
        req = ToolRequest(
            request_id=new_request_id(),
            agent_id="test-agent",
            tool="db",
            action="query",
            resource="sql://users",
            arguments={"q": "select 1"},
            context=TrustedContext({}),
        )
        record = ApprovalRecord.create(
            request=req,
            integration_id="local-runtime",
            capability_id="db.query",
            policy_provenance=PolicyProvenance(
                "policy-v1",
                hashlib.sha256(b"original-policy").hexdigest(),
                self.now,
            ),
            created_at=self.now,
            expires_at=self.expires,
        )
        approver = ApprovalAuthority._from_trusted_boundary("ui", "human-1", ApprovalAuthorityKind.HUMAN)
        approved_record = record.approve(approver, now=self.now)
        valid_assertion = authority.issue(record, approver)

        # Resign with a tampered policy digest
        values = {
            "credential_version": valid_assertion.credential_version,
            "algorithm": valid_assertion.algorithm,
            "approval_id": valid_assertion.approval_id,
            "request_id": valid_assertion.request_id,
            "request_fingerprint": valid_assertion.request_fingerprint,
            "principal_id": valid_assertion.principal_id,
            "integration_id": valid_assertion.integration_id,
            "audience": valid_assertion.audience,
            "issuer": valid_assertion.issuer,
            "issued_at": valid_assertion.issued_at,
            "expires_at": valid_assertion.expires_at,
            "policy_version_id": valid_assertion.policy_version_id,
            "policy_digest": hashlib.sha256(b"tampered-policy").hexdigest(),
            "policy_evaluated_at": valid_assertion.policy_evaluated_at,
            "decision": valid_assertion.decision,
            "nonce": valid_assertion.nonce,
            "approver_authority_id": valid_assertion.approver_authority_id,
            "approver_subject_id": valid_assertion.approver_subject_id,
            "approver_kind": valid_assertion.approver_kind,
        }
        from dmint.core.verification import _canonical_envelope
        unsigned = ApprovalAssertion._unsigned_values(values)
        signature = key.sign(_canonical_envelope(unsigned))
        tampered_assertion = ApprovalAssertion._signed(values, signature)

        with self.assertRaises(ApprovalInvalidError) as ctx:
            verifier.verify(tampered_assertion, approved_record)
        self.assertIn("policy provenance", str(ctx.exception))

    def test_mut_34_sqlite_consume_rejects_mismatched_deployment_epoch(self):
        """MUT-34: SQLiteApprovalStore.consume_approved must reject records from a different deployment epoch."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_approvals.db"

            key = Ed25519PrivateKey.generate()
            authority = LocalApprovalAuthority(
                issuer_id="auth-authority",
                audience="local-runtime",
                private_key=key,
                clock=lambda: self.now,
            )
            verifier = ApprovalVerifier(
                trusted_issuers={authority.issuer_id: authority.public_key},
                audience="local-runtime",
                clock=lambda: self.now,
            )
            req = ToolRequest(
                request_id=new_request_id(),
                agent_id="test-agent",
                tool="db",
                action="query",
                resource="sql://users",
                arguments={"q": "select 1"},
                context=TrustedContext({}),
            )
            record = ApprovalRecord.create(
                request=req,
                integration_id="local-runtime",
                capability_id="db.query",
                policy_provenance=PolicyProvenance(
                    "policy-v1",
                    hashlib.sha256(b"original-policy").hexdigest(),
                    self.now,
                ),
                created_at=self.now,
                expires_at=self.expires,
            )
            approver = ApprovalAuthority._from_trusted_boundary("ui", "human-1", ApprovalAuthorityKind.HUMAN)
            approved_record = record.approve(approver, now=self.now)
            assertion = authority.issue(record, approver)

            # Save and approve in epoch-1
            with SQLiteApprovalStore(db_path, deployment_epoch="epoch-1", clock=lambda: self.now) as store1:
                store1.save_approved(approved_record)

            # Consume in epoch-2 must fail closed
            with SQLiteApprovalStore(db_path, deployment_epoch="epoch-2", clock=lambda: self.now) as store2:
                with self.assertRaises(ApprovalDeploymentInvalidError) as ctx:
                    store2.consume_approved(
                        approval_id=record.approval_id,
                        credential=assertion,
                        expected_request=req,
                        verifier=verifier,
                    )
                self.assertIn("deployment epoch", str(ctx.exception))

    def test_mut_37_gateway_rejects_spoofed_client_agent_id(self):
        """MUT-37: Gateway must reject client-supplied agent_id argument differing from authenticated identity."""
        policy = Policy.from_mapping({"rules": [{"tool": "test", "action": "run", "effect": "allow"}]})
        provenance = PolicyProvenance("v1", policy_digest(policy), self.now)
        integ_cfg = MCPIntegrationConfig(
            integration_id="test_integ",
            command="echo",
            tool_bindings=[MCPToolBinding("any_tool", "test.run", discovery=DiscoveryMode.EXPOSED)],
        )
        config = MCPGatewayConfig(
            policy=policy,
            policy_provenance=provenance,
            integrations=[integ_cfg],
            agent_id="authenticated-agent",
        )
        gateway = MCPGateway(config)
        gateway._is_connected = True

        token = CURRENT_AGENT_ID.set("authenticated-agent")
        try:
            params = types.CallToolRequestParams(
                name="any_tool",
                arguments={"agent_id": "spoofed-admin", "data": 123},
            )
            res = asyncio.run(gateway._handle_call_tool(None, params))
            self.assertTrue(res.is_error)
            self.assertIn("DMT_AGENT_IDENTITY_MISMATCH", res.content[0].text)
            self.assertIn("spoofed-admin", res.content[0].text)
        finally:
            CURRENT_AGENT_ID.reset(token)

    def test_mut_47_check_key_file_permissions_rejects_unowned_key(self):
        """MUT-47: check_key_file_permissions must reject key files where st_uid != geteuid()."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            key_path = Path(tmp_dir) / "test.key"
            write_private_key_atomic(key_path, Ed25519PrivateKey.generate())

            real_uid = os.geteuid()
            calls = [0]
            def fake_geteuid():
                calls[0] += 1
                if calls[0] == 1:
                    return real_uid  # parent directory check passes
                return real_uid + 1000  # key file UID check triggers

            with patch("os.geteuid", side_effect=fake_geteuid):
                with self.assertRaises(KeyPermissionError) as ctx:
                    check_key_file_permissions(key_path)
                self.assertIn("key file owner UID", str(ctx.exception))
                self.assertIn("does not match current process UID", str(ctx.exception))

    def test_mut_48_symlinked_key_rejected_by_check_permissions_and_load(self):
        """MUT-48: Both check_key_file_permissions and load_private_key_from_file must reject symlinks via O_NOFOLLOW."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_key = Path(tmp_dir) / "real.key"
            sym_key = Path(tmp_dir) / "sym.key"
            write_private_key_atomic(real_key, Ed25519PrivateKey.generate())
            os.symlink(real_key, sym_key)

            # check_key_file_permissions without path.resolve() must catch symlink
            with self.assertRaises(KeyPermissionError) as ctx:
                check_key_file_permissions(sym_key)
            self.assertIn("symlink", str(ctx.exception))

            # load_private_key_from_file must catch symlink
            with self.assertRaises(KeyLoadError) as ctx:
                load_private_key_from_file(sym_key)
            self.assertIn("symlink", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
