"""Tests for Phase 6 deterministic argument constraints and schema validation."""

from __future__ import annotations

import time
import unittest
from typing import Any

from dmint.core.canonicalize import MAX_SAFE_INTEGER
from dmint.core.constraints import (
    MAX_CONTAINER_SIZE,
    MAX_PATTERN_LENGTH,
    MAX_STRING_INPUT_LENGTH,
    evaluate_constraints,
    safe_compare,
    validate_constraints_schema,
)
from dmint.core.enforcement import Dmint
from dmint.core.errors import AuthorizationError, PolicyError
from dmint.core.hashing import request_fingerprint
from dmint.core.models import Decision, ToolRequest, TrustedContext
from dmint.core.policy import Policy, Rule
from dmint.core.storage import SQLiteApprovalStore


def make_test_request(tool: str, action: str, resource: str, args: dict[str, Any]) -> ToolRequest:
    return ToolRequest(
        request_id="req-test-123",
        agent_id="test-agent",
        tool=tool,
        action=action,
        resource=resource,
        arguments=args,
        context=TrustedContext({}),
    )


class TestConstraintsEvaluation(unittest.TestCase):
    """Test suite for argument constraints evaluation."""

    def test_numeric_safe_compare_and_bounds(self) -> None:
        """Safe numeric comparisons without floating point rounding errors."""
        self.assertEqual(safe_compare(10, 20), -1)
        self.assertEqual(safe_compare(20, 10), 1)
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

    def test_whole_float_rejected_for_integer_field(self) -> None:
        """Whole floats like 1.0 or 100.0 are strictly rejected for integer fields."""
        constraints = {"properties": {"count": {"type": "integer"}}}
        ok, _ = evaluate_constraints(constraints, {"count": 1})
        self.assertTrue(ok)

        ok, reason = evaluate_constraints(constraints, {"count": 1.0})
        self.assertFalse(ok)
        self.assertIn("must be an integer", reason or "")

        ok, reason = evaluate_constraints(constraints, {"count": 100.0})
        self.assertFalse(ok)
        self.assertIn("must be an integer", reason or "")

    def test_inferred_type_requirements_when_type_omitted(self) -> None:
        """If 'type' is omitted, constraints like maximum or minLength require matching type."""
        # maximum without type: string value must DENY
        num_constraints = {"properties": {"amount": {"maximum": 500}}}
        ok, reason = evaluate_constraints(num_constraints, {"amount": "999"})
        self.assertFalse(ok)
        self.assertIn("must be a valid number", reason or "")

        ok, _ = evaluate_constraints(num_constraints, {"amount": 250})
        self.assertTrue(ok)

        # minLength without type: int value must DENY
        str_constraints = {"properties": {"code": {"minLength": 3}}}
        ok, reason = evaluate_constraints(str_constraints, {"code": 12345})
        self.assertFalse(ok)
        self.assertIn("must be a string", reason or "")

        # minItems without type: dict value must DENY
        arr_constraints = {"properties": {"items": {"minItems": 1}}}
        ok, reason = evaluate_constraints(arr_constraints, {"items": {"a": 1}})
        self.assertFalse(ok)
        self.assertIn("must be an array", reason or "")

    def test_enum_strict_type_and_value_equality(self) -> None:
        """Enum compares with strict type-and-value equality (True must not match 1)."""
        constraints = {"properties": {"val": {"enum": [1, 2, 3]}}}
        ok, _ = evaluate_constraints(constraints, {"val": 1})
        self.assertTrue(ok)

        ok, reason = evaluate_constraints(constraints, {"val": True})
        self.assertFalse(ok)
        self.assertIn("must be one of", reason or "")

        bool_constraints = {"properties": {"flag": {"enum": [True]}}}
        ok, _ = evaluate_constraints(bool_constraints, {"flag": True})
        self.assertTrue(ok)

        ok, reason = evaluate_constraints(bool_constraints, {"flag": 1})
        self.assertFalse(ok)
        self.assertIn("must be one of", reason or "")

    def test_tuples_rejected_in_constraints_schema(self) -> None:
        """Tuples in enum candidates or schema definitions are strictly rejected (consistent with canonicalization)."""
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"role": {"enum": ("a", "b")}}})
        self.assertIn("cannot be a tuple", str(ctx.exception))

        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"role": {"enum": [("admin", "root")]}}})
        self.assertIn("cannot be a tuple", str(ctx.exception))

    def test_container_depth_and_size_caps(self) -> None:
        """Arrays and objects exceeding container size or depth caps are rejected."""
        # Size cap
        oversized_list = [1] * (MAX_CONTAINER_SIZE + 1)
        constraints = {"properties": {"items": {"type": "array"}}}
        ok, reason = evaluate_constraints(constraints, {"items": oversized_list})
        self.assertFalse(ok)
        self.assertIn("maximum container size", reason or "")

        # Nested depth cap
        deep_schema: dict[str, Any] = {"type": "object", "properties": {}}
        curr = deep_schema
        for i in range(35):
            curr["properties"] = {"next": {"type": "object", "properties": {}}}
            curr = curr["properties"]["next"]
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema(deep_schema)
        self.assertIn("maximum allowed nesting depth", str(ctx.exception))

    def test_empty_enum_rejected_at_schema_validation(self) -> None:
        """Empty enum is rejected at policy schema validation time."""
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"role": {"enum": []}}})
        self.assertIn("non-empty array", str(ctx.exception))

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

    def test_regex_safety_hostile_patterns_rejected_or_bounded(self) -> None:
        """Hostile ReDoS patterns are rejected at schema validation time or bounded under time limit."""
        hostile_patterns = [
            r"^(a|a)+$",
            r"^(a*)*$",
            r"^(a+){2,}$",
            r"^a*a*a*a*b$",
        ]
        for hostile_pat in hostile_patterns:
            with self.assertRaises(PolicyError) as ctx:
                validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": hostile_pat}}})
            # Must reject with clear ReDoS risk message
            self.assertTrue(
                any(
                    keyword in str(ctx.exception).lower()
                    for keyword in ["backtracking", "repeat", "alternation", "redos"]
                ),
                f"Unexpected exception message: {ctx.exception}",
            )

        # Safe pattern evaluated against 4096-char input terminates well under time bound (< 50ms)
        safe_constraints = {
            "properties": {"text": {"type": "string", "pattern": r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"}}
        }
        long_input = "a" * 4096
        start = time.perf_counter()
        ok, _ = evaluate_constraints(safe_constraints, {"text": long_input})
        elapsed = time.perf_counter() - start
        self.assertFalse(ok)
        self.assertLess(elapsed, 0.05, f"Evaluation of safe pattern against 4096 chars took {elapsed:.4f}s")

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

    def test_toctou_mutation_of_original_arguments_has_no_effect(self) -> None:
        """TOCTOU test: mutating original arguments after evaluation does not change fingerprint or execution."""
        policy = Policy(
            [
                Rule.allow(
                    "shop",
                    "checkout",
                    constraints={
                        "properties": {
                            "user_id": {"type": "integer"},
                            "items": {"type": "array"},
                        }
                    },
                )
            ]
        )
        engine = Dmint(policy, agent_id="agent-1", context=TrustedContext({"env": "prod"}))

        executed_calls = []

        @engine.protect("shop.checkout")
        def checkout(user_id: int, items: list[dict[str, Any]], tags: list[str]) -> str:
            executed_calls.append({"user_id": user_id, "items": items, "tags": tags})
            return "ok"

        orig_args = {
            "user_id": 100,
            "items": [{"sku": "A1", "qty": 2}],
            "tags": ["urgent", "billing"],
        }

        # 1. Authorize call
        authorized = engine.authorize(checkout, capability="shop.checkout", **orig_args)

        # Compute fingerprint before mutation
        fp_before = request_fingerprint(authorized.request)

        # 2. Mutate original dictionary and nested structures
        orig_args["user_id"] = 999
        orig_args["items"][0]["qty"] = 99  # type: ignore[index]
        orig_args["tags"].append("injected")

        # Compute fingerprint after mutation of orig_args
        fp_after = request_fingerprint(authorized.request)

        # Fingerprints must be strictly identical
        self.assertEqual(fp_before, fp_after)

        # 3. Execute the authorized request
        res = engine.execute(authorized)
        self.assertEqual(res, "ok")

        # 4. Assert executed call received original pre-mutation values
        self.assertEqual(
            executed_calls[-1],
            {
                "user_id": 100,
                "items": [{"sku": "A1", "qty": 2}],
                "tags": ["urgent", "billing"],
            },
        )

    def test_ordering_constraint_violation_denies_before_approval_record_created(self) -> None:
        """Constraint violation returns DENY before any approval record is created."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_approvals.db"
            store = SQLiteApprovalStore(db_path, deployment_epoch="test-epoch")
            policy = Policy(
                [
                    Rule.approval_required(
                        "payments",
                        "wire_transfer",
                        resource="*",
                        constraints={
                            "required": ["amount", "iban"],
                            "properties": {
                                "amount": {"type": "number", "maximum": 5000.0},
                                "iban": {"type": "string"},
                            },
                        },
                    )
                ]
            )
            engine = Dmint(
                policy,
                agent_id="test-agent",
                context=TrustedContext({}),
                approval_store=store,
                policy_provenance=Policy.from_dict(policy.to_dict()).provenance
                if hasattr(policy, "provenance")
                else None,
            )

            # 1. Request violating constraint (amount > 5000.0)
            req_violating = make_test_request(
                "payments",
                "wire_transfer",
                "*",
                {"amount": 99999.0, "iban": "DE123456789"},
            )
            decision, code = policy.evaluate_detailed(req_violating)

            # Must return DENY with DMT_CONSTRAINT_VIOLATION, NOT APPROVAL_REQUIRED
            self.assertEqual(decision, Decision.DENY)
            self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

            # Ensure no pending approval record was ever saved in the store
            pending_records = store.list_pending()
            self.assertEqual(len(pending_records), 0)


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
                            "reason": {"type": "string", "minLength": 5, "maxLength": 200},
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

    def test_policy_2_sql_weak_input_filter(self) -> None:
        """Example 2: SQL weak input filter (proves regex ACCEPTS 'SELECT 1; DROP TABLE users')."""
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

        # Proves documentation warning: regex ACCEPTS multi-statement injection!
        req_injected = make_test_request("database", "query", "*", {"sql": "SELECT 1; DROP TABLE users"})
        dec, code = policy.evaluate_detailed(req_injected)
        self.assertEqual(
            dec,
            Decision.ALLOW,
            "Proves the documentation warning: regex pattern alone cannot prevent SQL injection",
        )

        # Rejects direct non-SELECT statements
        req_drop = make_test_request("database", "query", "*", {"sql": "DROP TABLE users"})
        dec, code = policy.evaluate_detailed(req_drop)
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
