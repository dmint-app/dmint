import hashlib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint import (
    ANY_RESOURCE,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRequiredError,
    ApprovalVerifier,
    Dmint,
    ExecutionError,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    SQLiteApprovalStore,
    TrustedContext,
)
from dmint.errors import (
    ApprovalConsumedError,
    ApprovalCredentialInvalidError,
    ApprovalInvalidError,
    ApprovalPolicyInvalidError,
    ApprovalRequestMismatchError,
    AuthorizationError,
)


class RetryFlowTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
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
        self.policy_provenance = PolicyProvenance(
            "policy-v1", hashlib.sha256(b"policy-v1").hexdigest(), self.now
        )
        self.counter_lock = threading.Lock()
        self.executions = []
        self.dmint = self.make_dmint(
            Policy(
                (
                    Rule.approval_required("database", "delete", resource=ANY_RESOURCE),
                    Rule.approval_required("database", "read", resource=ANY_RESOURCE),
                )
            )
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def make_dmint(self, policy, *, store=None, integration="local-runtime", clock=None):
        test_clock = clock or (lambda: self.now)
        return Dmint(
            policy,
            agent_id="agent-a",
            context=TrustedContext({"environment": "production"}),
            integration_id=integration,
            approval_store=store or SQLiteApprovalStore(self.database, deployment_epoch="epoch-1", clock=test_clock),
            approval_verifier=ApprovalVerifier(
                trusted_issuers={self.authority.issuer_id: self.authority.public_key},
                audience=self.authority.audience,
                clock=test_clock,
            ),
            policy_provenance=self.policy_provenance,
            approval_ttl=timedelta(minutes=5),
            clock=test_clock,
        )

    def protected_delete(self, dmint=None):
        dmint = dmint or self.dmint

        @dmint.protected(
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        def delete_user(user_id, options=None):
            with self.counter_lock:
                self.executions.append((user_id, options))
            return user_id

        return delete_user

    def approve_pending(self, record):
        approved = record.approve(self.approver, now=self.now + timedelta(seconds=1))
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            store.save_approved(approved)
        assertion = self.authority.issue(approved, self.approver, now=self.now)
        return approved, assertion

    def create_approved_retry(self, function=None, options=None):
        function = function or self.protected_delete()
        if options is None:
            options = {"source": "test"}
        with self.assertRaises(ApprovalRequiredError) as raised:
            function(123, options)
        pending = self.dmint._approval_store.require_pending(raised.exception.approval_id)
        approved, assertion = self.approve_pending(pending)
        return function, approved, assertion, options

    def test_initial_call_stops_and_exact_retry_executes(self):
        function, approved, assertion, options = self.create_approved_retry()
        self.assertEqual(self.executions, [])

        result = self.dmint.retry(
            function,
            123,
            options,
            approval_credential=assertion,
        )

        self.assertEqual(result, 123)
        self.assertEqual(self.executions, [(123, {"source": "test"})])
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get(approved.approval_id).state.value, "CONSUMED")

    def test_numeric_ambiguity_in_retry_is_rejected(self):
        function, approved, assertion, options = self.create_approved_retry()
        # Retry with float 123.0 instead of int 123 is rejected
        with self.assertRaises(Exception):
            self.dmint.retry(
                function,
                123.0,
                options,
                approval_credential=assertion,
            )
        self.assertEqual(self.executions, [])

    def test_modified_arguments_resource_and_other_protected_callable_fail(self):
        function, approved, assertion, options = self.create_approved_retry()
        with self.assertRaises(ApprovalRequestMismatchError):
            self.dmint.retry(
                function,
                999,
                options,
                approval_credential=assertion,
            )
        self.assertEqual(self.executions, [])

        other = self.dmint.protected(
            "database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )(lambda user_id, options=None: self.executions.append(("other", user_id)))
        with self.assertRaises(ApprovalRequestMismatchError):
            self.dmint.retry(
                other,
                123,
                options,
                approval_credential=assertion,
            )

    def test_mutation_after_initial_request_does_not_change_approved_snapshot(self):
        options = {"nested": {"enabled": True}}
        function, approved, assertion, _ = self.create_approved_retry(options=options)
        options["nested"]["enabled"] = False
        with self.assertRaises(ApprovalRequestMismatchError):
            self.dmint.retry(
                function,
                123,
                options,
                approval_credential=assertion,
            )
        self.assertEqual(self.executions, [])

    def test_replay_fails_and_does_not_execute_twice(self):
        function, approved, assertion, options = self.create_approved_retry()
        self.dmint.retry(function, 123, options, approval_credential=assertion)
        with self.assertRaises(ApprovalConsumedError):
            self.dmint.retry(function, 123, options, approval_credential=assertion)
        self.assertEqual(len(self.executions), 1)

    def test_current_deny_invalidates_retry_without_consuming(self):
        function, approved, assertion, options = self.create_approved_retry()
        object.__setattr__(self.dmint, "_policy", Policy((Rule.deny("database", "delete", resource=ANY_RESOURCE),)))
        with self.assertRaises(ApprovalPolicyInvalidError):
            self.dmint.retry(function, 123, options, approval_credential=assertion)
        self.assertEqual(self.executions, [])
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get(approved.approval_id).state.value, "POLICY_INVALIDATED")

    def test_current_allow_still_requires_the_approval_retry_credential(self):
        function, approved, assertion, options = self.create_approved_retry()
        object.__setattr__(self.dmint, "_policy", Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),)))
        self.dmint.retry(function, 123, options, approval_credential=assertion)
        self.assertEqual(len(self.executions), 1)
        with self.assertRaises(ApprovalConsumedError):
            self.dmint.retry(function, 123, options, approval_credential=assertion)

    def test_policy_provenance_change_fails_before_consumption(self):
        function, approved, assertion, options = self.create_approved_retry()
        object.__setattr__(
            self.dmint,
            "_policy_provenance",
            PolicyProvenance("policy-v2", hashlib.sha256(b"policy-v2").hexdigest(), self.now),
        )
        with self.assertRaises(ApprovalPolicyInvalidError):
            self.dmint.retry(function, 123, options, approval_credential=assertion)
        self.assertEqual(self.executions, [])

    def test_expired_and_forged_credentials_fail(self):
        function, approved, assertion, options = self.create_approved_retry()
        with self.assertRaises(ApprovalCredentialInvalidError):
            self.dmint.retry(function, 123, options, approval_credential=b"forged")

        # Test expiration with clock advance via injected test clock
        expired_clock = lambda: self.now + timedelta(minutes=10)
        expired_dmint = self.make_dmint(self.dmint._policy, clock=expired_clock)
        expired_function = self.protected_delete(expired_dmint)
        with self.assertRaises(Exception):
            expired_dmint.retry(expired_function, 123, options, approval_credential=assertion)

    def test_caller_cannot_pass_now_parameter_to_retry(self):
        function, approved, assertion, options = self.create_approved_retry()
        with self.assertRaises(TypeError):
            self.dmint.retry(
                function,
                123,
                options,
                approval_credential=assertion,
                now=self.now,
            )

    def test_tool_failure_after_consume_does_not_restore_approval(self):
        calls = []

        @self.dmint.protected(
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        def failing(user_id):
            calls.append(user_id)
            raise RuntimeError("tool failed")

        with self.assertRaises(ApprovalRequiredError) as raised:
            failing(123)
        pending = self.dmint._approval_store.require_pending(raised.exception.approval_id)
        approved, assertion = self.approve_pending(pending)
        with self.assertRaises(ExecutionError):
            self.dmint.retry(failing, 123, approval_credential=assertion)
        self.assertEqual(calls, [123])
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get(approved.approval_id).state.value, "CONSUMED")

    def test_concurrent_retries_execute_at_most_once(self):
        function, approved, assertion, options = self.create_approved_retry()
        def attempt(_index):
            worker_dmint = self.make_dmint(
                Policy(
                    (
                        Rule.approval_required("database", "delete", resource=ANY_RESOURCE),
                        Rule.approval_required("database", "read", resource=ANY_RESOURCE),
                    )
                )
            )
            protected = self.protected_delete(worker_dmint)
            try:
                worker_dmint.retry(
                    protected,
                    123,
                    options,
                    approval_credential=assertion,
                )
                return "success"
            except Exception as exc:
                return getattr(exc, "code", type(exc).__name__)
            except Exception as exc:
                return getattr(exc, "code", type(exc).__name__)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(attempt, range(8)))
        self.assertEqual(results.count("success"), 1, results)
        self.assertEqual(len(self.executions), 1)

    def test_shared_store_policy_update_invalidates_stale_runtime_retry(self):
        function, approved, assertion, options = self.create_approved_retry()
        # Runtime B updates authoritative policy in shared store to DENY
        deny_policy = Policy((Rule.deny("database", "delete", resource=ANY_RESOURCE),))
        deny_provenance = PolicyProvenance("policy-v2-deny", hashlib.sha256(b"policy-v2-deny").hexdigest(), self.now)
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            store.set_authoritative_policy(deny_policy, deny_provenance)

        # Runtime A (self.dmint) retries with stale policy-v1 in memory
        with self.assertRaises(ApprovalPolicyInvalidError):
            self.dmint.retry(function, 123, options, approval_credential=assertion)

        self.assertEqual(self.executions, [])
        with SQLiteApprovalStore(self.database, deployment_epoch="epoch-1") as store:
            self.assertEqual(store.get(approved.approval_id).state.value, "POLICY_INVALIDATED")
