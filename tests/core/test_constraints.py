"""Comprehensive test suite for Phase 6 argument constraints engine.

Tests cover:
- Pure evaluator constraint evaluation
- Numeric constraints (bool, NaN, Inf, safe int/float comparison, safe range)
- String patterns (anchoring, length limits, timing bound ReDoS defense)
- Required fields & no additional properties
- Schema validation & rejection of unknown constraint types at load time
- Immutability against argument mutation post-evaluation
- 10 real-world example policies with allow and deny tests
"""

from __future__ import annotations

import math
import time
import unittest

from dmint.core.constraints import (
    MAX_PATTERN_LENGTH,
    MAX_SAFE_INTEGER,
    MAX_STRING_INPUT_LENGTH,
    evaluate_constraints,
    safe_compare,
    validate_constraints_schema,
)
from dmint.core.enforcement import Dmint
from dmint.core.errors import AuthorizationError, PolicyError
from dmint.core.models import Decision, ToolRequest, TrustedContext
from dmint.core.policy import Policy, Rule


def make_test_request(
    tool: str = "test",
    action: str = "run",
    resource: str = "*",
    arguments: dict | None = None,
) -> ToolRequest:
    return ToolRequest(
        request_id="req_0123456789abcdef0123456789abcdef01234567890",
        agent_id="test-agent",
        tool=tool,
        action=action,
        resource=resource,
        arguments=arguments or {},
        context=TrustedContext.from_mapping({}),
    )


class TestArgumentConstraints(unittest.TestCase):
    """Core unit tests for argument constraints evaluation and schema validation."""

    def test_numeric_constraints_reject_bool_nan_inf(self) -> None:
        """Numeric constraints must strictly reject bool, NaN, Infinity, and non-numbers."""
        constraints = {
            "properties": {
                "amount": {"type": "number", "minimum": 0, "maximum": 100},
                "count": {"type": "integer", "minimum": 1},
            }
        }
        # Booleans must be rejected as numbers and integers
        ok, reason = evaluate_constraints(constraints, {"amount": True, "count": 1})
        self.assertFalse(ok)
        self.assertIn("must be a valid number", reason or "")

        ok, reason = evaluate_constraints(constraints, {"amount": 50, "count": False})
        self.assertFalse(ok)
        self.assertIn("must be an integer", reason or "")

        # NaN and Inf must be rejected
        ok, reason = evaluate_constraints(constraints, {"amount": float("nan"), "count": 1})
        self.assertFalse(ok)
        ok, reason = evaluate_constraints(constraints, {"amount": float("inf"), "count": 1})
        self.assertFalse(ok)
        ok, reason = evaluate_constraints(constraints, {"amount": float("-inf"), "count": 1})
        self.assertFalse(ok)

        # Strings where numbers are expected must be rejected
        ok, reason = evaluate_constraints(constraints, {"amount": "50", "count": 1})
        self.assertFalse(ok)

        # Valid numbers and integers succeed
        ok, _ = evaluate_constraints(constraints, {"amount": 50.5, "count": 5})
        self.assertTrue(ok)

    def test_safe_compare_ints_and_floats(self) -> None:
        """Safe comparison accurately compares ints, floats, and decimals without precision loss."""
        self.assertEqual(safe_compare(10, 10.5), -1)
        self.assertEqual(safe_compare(10.5, 10), 1)
        self.assertEqual(safe_compare(10, 10), 0)
        self.assertEqual(safe_compare(0.01, 0.02), -1)

    def test_safe_integer_range_enforced(self) -> None:
        """Integers outside safe 53-bit range are rejected."""
        constraints = {"properties": {"id": {"type": "integer"}}}
        ok, _ = evaluate_constraints(constraints, {"id": MAX_SAFE_INTEGER})
        self.assertTrue(ok)
        ok, reason = evaluate_constraints(constraints, {"id": MAX_SAFE_INTEGER + 1})
        self.assertFalse(ok)
        self.assertIn("safe integer range", reason or "")

    def test_string_patterns_anchored_only(self) -> None:
        """Regex patterns match the entire string (anchored), never a partial substring."""
        constraints = {"properties": {"code": {"type": "string", "pattern": "[A-Z]{3}"}}}
        # Exact match
        ok, _ = evaluate_constraints(constraints, {"code": "ABC"})
        self.assertTrue(ok)
        # Substring prefix/suffix must fail
        ok, _ = evaluate_constraints(constraints, {"code": "1ABC2"})
        self.assertFalse(ok)
        ok, _ = evaluate_constraints(constraints, {"code": "ABCD"})
        self.assertFalse(ok)

    def test_string_length_limits_and_timing_bound(self) -> None:
        """String input exceeding MAX_STRING_INPUT_LENGTH fails closed; ReDoS pattern is rejected; timing is bounded."""
        # Nested quantifiers with catastrophic backtracking risk are rejected at policy load/validation time
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": "^(a+)+$"}}})
        self.assertIn("nested quantifiers", str(ctx.exception))

        safe_constraints = {
            "properties": {"text": {"type": "string", "pattern": r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"}}
        }
        # Input exceeding max length
        long_str = "a" * (MAX_STRING_INPUT_LENGTH + 1)
        ok, reason = evaluate_constraints(safe_constraints, {"text": long_str})
        self.assertFalse(ok)
        self.assertIn("maximum allowed length", reason or "")

        # Long input matching pattern up to edge evaluated within strict timing bound (< 50ms)
        adversarial_input = ("a" * 2000) + "@" + ("b" * 2000) + ".com"
        start = time.perf_counter()
        ok, _ = evaluate_constraints(safe_constraints, {"text": adversarial_input})
        elapsed = time.perf_counter() - start
        self.assertTrue(ok)
        self.assertLess(elapsed, 0.05, f"Pattern evaluation took too long: {elapsed:.4f}s")

    def test_required_fields_and_no_additional_properties(self) -> None:
        """Support for 'required' fields and 'additionalProperties': False."""
        constraints = {
            "required": ["user_id", "email"],
            "additionalProperties": False,
            "properties": {
                "user_id": {"type": "integer"},
                "email": {"type": "string"},
            },
        }
        # Missing required field
        ok, reason = evaluate_constraints(constraints, {"user_id": 1})
        self.assertFalse(ok)
        self.assertIn("missing required argument 'email'", reason or "")

        # Disallowed additional property
        ok, reason = evaluate_constraints(constraints, {"user_id": 1, "email": "a@b.com", "role": "admin"})
        self.assertFalse(ok)
        self.assertIn("additional argument 'role' is not allowed", reason or "")

        # Valid payload
        ok, _ = evaluate_constraints(constraints, {"user_id": 1, "email": "a@b.com"})
        self.assertTrue(ok)

    def test_unknown_constraint_types_rejected_at_load_time(self) -> None:
        """Unknown constraint keys and unknown types in policy.json must be rejected with PolicyError."""
        # Unknown top-level key
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"unknownField": True})

        # Unknown property constraint
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"properties": {"field": {"unknownConstraint": 123}}})

        # Unknown type
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"properties": {"field": {"type": "custom_type"}}})

        # Excessive pattern length
        long_pattern = "a" * (MAX_PATTERN_LENGTH + 1)
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"properties": {"field": {"pattern": long_pattern}}})

        # Invalid bounds (minimum > maximum)
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"properties": {"field": {"minimum": 100, "maximum": 50}}})

    def test_argument_mutation_post_evaluation_fails_or_is_ignored(self) -> None:
        """Mutating arguments after evaluation cannot change what was approved or executed."""
        policy = Policy(
            [
                Rule.allow(
                    "finance",
                    "transfer",
                    constraints={"properties": {"amount": {"type": "number", "maximum": 100}}},
                )
            ]
        )
        engine = Dmint(policy, agent_id="test-agent", context=TrustedContext({}))

        captured = []

        @engine.protected("finance.transfer")
        def transfer(amount: float, recipient: str) -> None:
            captured.append((amount, recipient))

        # Initial call authorizes amount=50
        transfer(50.0, "alice")
        self.assertEqual(captured, [(50.0, "alice")])

        # Attempt to authorize through authorize() artifact
        authorized = engine.authorize(transfer, 50.0, "alice", capability="finance.transfer")
        # Attempting to mutate request.arguments directly raises TypeError (immutable MappingProxyType)
        with self.assertRaises(TypeError):
            authorized.request.arguments["amount"] = 999999.0  # type: ignore[index]

        # Executing the authorized artifact safely runs the captured snapshot (50.0, 'alice')
        engine.execute(authorized)
        self.assertEqual(captured, [(50.0, "alice"), (50.0, "alice")])


class TestTenExamplePolicies(unittest.TestCase):
    """Test suite executing 10 real-world example policies with argument constraints."""

    def test_policy_1_refund_limit(self) -> None:
        """Example 1: Refund limit (amount <= 500, allowed currency, reason length)."""
        policy = Policy(
            [
                Rule.allow(
                    "payments",
                    "refund",
                    resource="*",
                    constraints={
                        "required": ["amount", "currency", "reason"],
                        "additionalProperties": False,
                        "properties": {
                            "amount": {"type": "number", "minimum": 0.01, "maximum": 500.0},
                            "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
                            "reason": {"type": "string", "minLength": 5},
                        },
                    },
                )
            ]
        )
        # Valid refund
        req_ok = make_test_request(
            "payments", "refund", "*", {"amount": 150.0, "currency": "USD", "reason": "Defective item"}
        )
        dec, code = policy.evaluate_detailed(req_ok)
        self.assertEqual(dec, Decision.ALLOW)
        self.assertIsNone(code)

        # Violation: amount > 500
        req_bad_amt = make_test_request(
            "payments", "refund", "*", {"amount": 750.0, "currency": "USD", "reason": "Defective item"}
        )
        dec, code = policy.evaluate_detailed(req_bad_amt)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # Violation: disallowed currency
        req_bad_curr = make_test_request(
            "payments", "refund", "*", {"amount": 100.0, "currency": "BTC", "reason": "Defective item"}
        )
        dec, code = policy.evaluate_detailed(req_bad_curr)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_2_readonly_sql_guard(self) -> None:
        """Example 2: Read-only SQL guard (strictly SELECT queries, rejecting DDL/DML)."""
        policy = Policy(
            [
                Rule.allow(
                    "database",
                    "query",
                    resource="*",
                    constraints={
                        "required": ["sql"],
                        "properties": {
                            "sql": {"type": "string", "pattern": r"(?i)^\s*SELECT\s+[\s\S]+$"},
                        },
                    },
                )
            ]
        )
        # Valid SELECT
        req_ok = make_test_request("database", "query", "*", {"sql": "SELECT id, name FROM users"})
        dec, code = policy.evaluate_detailed(req_ok)
        self.assertEqual(dec, Decision.ALLOW)
        self.assertIsNone(code)

        # Violation: DROP TABLE
        req_drop = make_test_request("database", "query", "*", {"sql": "DROP TABLE users"})
        dec, code = policy.evaluate_detailed(req_drop)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # Violation: UPDATE
        req_update = make_test_request("database", "query", "*", {"sql": "UPDATE users SET role = 'admin'"})
        dec, code = policy.evaluate_detailed(req_update)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_3_user_role_provisioning_enum(self) -> None:
        """Example 3: Allowed-values enum for role assignment."""
        policy = Policy(
            [
                Rule.allow(
                    "iam",
                    "assign_role",
                    resource="*",
                    constraints={
                        "required": ["role", "user_id"],
                        "properties": {
                            "role": {"type": "string", "enum": ["viewer", "editor", "auditor"]},
                            "user_id": {"type": "string", "pattern": r"^usr_[0-9a-f]{8}$"},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request("iam", "assign_role", "*", {"role": "editor", "user_id": "usr_0123abcd"})
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: unauthorized 'admin' role
        req_admin = make_test_request("iam", "assign_role", "*", {"role": "superadmin", "user_id": "usr_0123abcd"})
        dec, code = policy.evaluate_detailed(req_admin)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_4_filesystem_write_guard(self) -> None:
        """Example 4: Filesystem write guard with mode, size bound, and boolean flag."""
        policy = Policy(
            [
                Rule.allow(
                    "fs",
                    "write",
                    resource="/workspace/**",
                    resource_kind="path",
                    constraints={
                        "required": ["mode", "content", "create_backup"],
                        "properties": {
                            "mode": {"type": "string", "enum": ["w", "a"]},
                            "content": {"type": "string", "maxLength": 1000},
                            "create_backup": {"type": "boolean"},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request(
            "fs", "write", "/workspace/main.py", {"mode": "w", "content": "print('ok')", "create_backup": True}
        )
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: content too large
        req_large = make_test_request(
            "fs", "write", "/workspace/main.py", {"mode": "w", "content": "x" * 1001, "create_backup": True}
        )
        dec, code = policy.evaluate_detailed(req_large)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_5_pagination_and_query_limits(self) -> None:
        """Example 5: API search limits on limit (1-100) and offset (>= 0)."""
        policy = Policy(
            [
                Rule.allow(
                    "api",
                    "search",
                    resource="*",
                    constraints={
                        "required": ["limit", "offset", "query"],
                        "properties": {
                            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                            "offset": {"type": "integer", "minimum": 0},
                            "query": {"type": "string", "minLength": 1, "maxLength": 100},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request("api", "search", "*", {"limit": 50, "offset": 0, "query": "audit log"})
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: excessive limit
        req_excess = make_test_request("api", "search", "*", {"limit": 1000, "offset": 0, "query": "audit log"})
        dec, code = policy.evaluate_detailed(req_excess)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_6_strict_token_rotation(self) -> None:
        """Example 6: Strict token rotation with no extra properties allowed."""
        policy = Policy(
            [
                Rule.allow(
                    "auth",
                    "rotate_token",
                    resource="*",
                    constraints={
                        "required": ["token_id", "scope"],
                        "additionalProperties": False,
                        "properties": {
                            "token_id": {"type": "string", "pattern": r"^tok_[a-z0-9]{12}$"},
                            "scope": {"type": "string", "enum": ["read_only", "limited_write"]},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request("auth", "rotate_token", "*", {"token_id": "tok_123456abcdef", "scope": "read_only"})
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: prompt injection trying to sneak elevated privileges
        req_injected = make_test_request(
            "auth",
            "rotate_token",
            "*",
            {"token_id": "tok_123456abcdef", "scope": "read_only", "is_admin": True},
        )
        dec, code = policy.evaluate_detailed(req_injected)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_7_cloud_deployment_tier_bounds(self) -> None:
        """Example 7: Deployment replica bounds and allowed environments."""
        policy = Policy(
            [
                Rule.allow(
                    "cloud",
                    "deploy",
                    resource="*",
                    constraints={
                        "required": ["replicas", "environment"],
                        "properties": {
                            "replicas": {"type": "integer", "minimum": 1, "maximum": 5},
                            "environment": {"type": "string", "enum": ["staging", "development"]},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request("cloud", "deploy", "*", {"replicas": 3, "environment": "staging"})
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: production deploy denied by constraint
        req_prod = make_test_request("cloud", "deploy", "*", {"replicas": 3, "environment": "production"})
        dec, code = policy.evaluate_detailed(req_prod)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_8_email_notification_guard(self) -> None:
        """Example 8: Email recipient syntax pattern and priority bounds."""
        policy = Policy(
            [
                Rule.allow(
                    "notification",
                    "send_email",
                    resource="*",
                    constraints={
                        "required": ["to", "subject", "priority"],
                        "properties": {
                            "to": {"type": "string", "pattern": r"^[a-zA-Z0-9._%+-]+@company\.com$"},
                            "subject": {"type": "string", "maxLength": 100},
                            "priority": {"type": "string", "enum": ["low", "normal"]},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request(
            "notification", "send_email", "*", {"to": "alice@company.com", "subject": "Update", "priority": "normal"}
        )
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: email outside allowed internal domain
        req_ext = make_test_request(
            "notification", "send_email", "*", {"to": "attacker@evil.com", "subject": "Update", "priority": "normal"}
        )
        dec, code = policy.evaluate_detailed(req_ext)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_9_discount_percent_bounds(self) -> None:
        """Example 9: Discount percentage bounds (0 < pct <= 30.0)."""
        policy = Policy(
            [
                Rule.allow(
                    "billing",
                    "apply_discount",
                    resource="*",
                    constraints={
                        "required": ["discount_pct"],
                        "properties": {
                            "discount_pct": {"type": "number", "exclusiveMinimum": 0.0, "maximum": 30.0},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request("billing", "apply_discount", "*", {"discount_pct": 15.5})
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: 0.0 is not allowed by exclusiveMinimum
        req_zero = make_test_request("billing", "apply_discount", "*", {"discount_pct": 0.0})
        dec, code = policy.evaluate_detailed(req_zero)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # Violation: 50% discount exceeds maximum of 30%
        req_high = make_test_request("billing", "apply_discount", "*", {"discount_pct": 50.0})
        dec, code = policy.evaluate_detailed(req_high)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_policy_10_webhook_dispatcher_url_guard(self) -> None:
        """Example 10: Webhook dispatcher HTTPS URL and timeout bounds."""
        policy = Policy(
            [
                Rule.allow(
                    "webhooks",
                    "dispatch",
                    resource="*",
                    constraints={
                        "required": ["target_url", "timeout_sec"],
                        "properties": {
                            "target_url": {"type": "string", "pattern": r"^https://api\.trusted\.com/hooks/[a-z0-9]+$"},
                            "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 10},
                        },
                    },
                )
            ]
        )
        req_ok = make_test_request(
            "webhooks",
            "dispatch",
            "*",
            {"target_url": "https://api.trusted.com/hooks/event123", "timeout_sec": 5},
        )
        self.assertEqual(policy.evaluate(req_ok), Decision.ALLOW)

        # Violation: HTTP insecure scheme
        req_insecure = make_test_request(
            "webhooks",
            "dispatch",
            "*",
            {"target_url": "http://api.trusted.com/hooks/event123", "timeout_sec": 5},
        )
        dec, code = policy.evaluate_detailed(req_insecure)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # Violation: timeout exceeds 10s
        req_timeout = make_test_request(
            "webhooks",
            "dispatch",
            "*",
            {"target_url": "https://api.trusted.com/hooks/event123", "timeout_sec": 60},
        )
        dec, code = policy.evaluate_detailed(req_timeout)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")


if __name__ == "__main__":
    unittest.main()
