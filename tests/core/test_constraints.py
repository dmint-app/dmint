from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import tempfile
import time
from typing import Any
import unittest

import mcp.types as types

from dmint.core.approvals import PolicyProvenance
from dmint.core.canonicalize import MAX_SAFE_INTEGER
from dmint.core.constraints import (
    MAX_CONTAINER_SIZE,
    MAX_PATTERN_LENGTH,
    MAX_STRING_INPUT_LENGTH,
    _compile_anchored_pattern,
    evaluate_constraints,
    safe_compare,
    validate_constraints_schema,
    validate_pattern_safety,
)
from dmint.core.enforcement import Dmint
from dmint.core.errors import ApprovalRequiredError, AuthorizationError, PolicyError
from dmint.core.hashing import request_fingerprint
from dmint.core.models import Decision, ToolRequest, TrustedContext
from dmint.core.policy import Policy, Rule, policy_digest
from dmint.core.storage import SQLiteApprovalStore
from dmint.mcp import (
    DisclosureMode,
    DiscoveryMode,
    DownstreamMCPClient,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPToolBinding,
)


class MockDownstreamClient(DownstreamMCPClient):
    """Mock downstream client simulating an MCP server for test_constraints."""

    def __init__(self, config: MCPIntegrationConfig, tools: list[types.Tool] | None = None) -> None:
        super().__init__(config)
        self._connected = False
        self._tools = tools or []
        self.call_log: list[tuple[str, dict]] = []

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_tools(self) -> list[types.Tool]:
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        self.call_log.append((name, arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"executed {self.config.integration_id}:{name}")]
        )


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
            # Hostile patterns specified in Phase 6b requirements:
            r"^.*a.*a.*a.*a.*b$",
            r"^[a-z]*x[a-z]*x[a-z]*x[a-z]*x[a-z]*y$",
            r"^.+a.+a.+a.+b$",
            r"^.*@.*@.*@.*@.*\.com$",
        ]
        for hostile_pat in hostile_patterns:
            try:
                validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": hostile_pat}}})
                # If loaded (e.g. when linear-time google-re2 is available), verify evaluation is under 50 ms
                start = time.perf_counter()
                evaluate_constraints(
                    {"properties": {"text": {"type": "string", "pattern": hostile_pat}}},
                    {"text": "a" * 4096},
                )
                elapsed = time.perf_counter() - start
                self.assertLess(
                    elapsed,
                    0.05,
                    f"Pattern '{hostile_pat}' took {elapsed * 1000:.2f} ms on 4096 'a' chars",
                )
            except PolicyError as ctx:
                self.assertTrue(
                    any(
                        keyword in str(ctx).lower()
                        for keyword in ["backtracking", "repeat", "alternation", "redos", "quantifier"]
                    ),
                    f"Unexpected exception message for {hostile_pat}: {ctx}",
                )

        # Safe pattern evaluated against 4096-char input terminates well under time bound (< 50ms)
        safe_constraints = {
            "properties": {
                "text": {
                    "type": "string",
                    "pattern": r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}$",
                }
            }
        }
        long_input = "a" * 4096
        start = time.perf_counter()
        ok, _ = evaluate_constraints(safe_constraints, {"text": long_input})
        elapsed = time.perf_counter() - start
        self.assertFalse(ok)
        self.assertLess(elapsed, 0.05, f"Evaluation of safe pattern against 4096 chars took {elapsed:.4f}s")

    def test_redos_fuzz_allowed_grammar_timing(self) -> None:
        """Fuzz test generating patterns from allowed grammar and timing each against 4096-char adversarial input."""
        rng = random.Random(42)

        def generate_pattern() -> str:
            atoms = ["a", "b", "[a-z]", "[0-9]", r"\w", r"\d"]
            delims = ["-", "_", ".", ":", "/", "@"]
            bounded_quants = ["{1,3}", "{2}", "?"]
            unbounded_quants = ["*", "+"]

            parts = ["^"]
            num_segments = rng.randint(2, 3)
            quants_left = 3
            unbounded_left = 1
            for i in range(num_segments):
                atom = rng.choice(atoms)
                roll = rng.random()
                if roll < 0.4 and quants_left > 0 and unbounded_left > 0:
                    q = rng.choice(unbounded_quants)
                    parts.append(atom + q)
                    quants_left -= 1
                    unbounded_left -= 1
                elif roll < 0.7 and quants_left > 0:
                    q = rng.choice(bounded_quants)
                    parts.append(atom + q)
                    quants_left -= 1
                else:
                    parts.append(atom)
                if i < num_segments - 1 and rng.random() < 0.6:
                    parts.append(rng.choice(delims))
            parts.append("$")
            return "".join(parts)

        patterns = [generate_pattern() for _ in range(30)]
        adversarial_inputs = [
            "a" * 4096,
            "a" * 4095 + "b",
            "b" + "a" * 4095,
            "a" * 2048 + "@" + "a" * 2047,
        ]

        timings: list[float] = []
        for pat in patterns:
            validate_constraints_schema({"properties": {"data": {"pattern": pat}}})
            for adv_input in adversarial_inputs:
                start = time.perf_counter()
                evaluate_constraints({"properties": {"data": {"pattern": pat}}}, {"data": adv_input})
                elapsed = time.perf_counter() - start
                timings.append(elapsed)
                self.assertLess(
                    elapsed,
                    0.05,
                    f"Pattern '{pat}' took {elapsed * 1000:.2f} ms on 4096-char input (exceeds 50 ms bound)",
                )

        max_ms = max(timings) * 1000
        avg_ms = (sum(timings) / len(timings)) * 1000
        min_ms = min(timings) * 1000
        print(
            f"\n[ReDoS Fuzz Timing Output] Tested {len(patterns)} patterns against 4096 chars ({len(timings)} evaluations): "
            f"min={min_ms:.4f}ms, avg={avg_ms:.4f}ms, max={max_ms:.4f}ms (all strictly < 50ms)"
        )

    def test_bounded_repeats_and_repetition_budget_caps(self) -> None:
        """Test bounded repeats caps (max 64 per quantifier, total budget <= 10^6, at most 3 quantifiers in total)."""
        # 1. {0, 50} x 4: exceeds max 3 quantifiers -> must be rejected at load time
        pat_50_x4 = r"^[a-z]{0,50}[a-z]{0,50}[a-z]{0,50}[a-z]{0,50}b$"
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_50_x4}}})
        self.assertIn("quantifier", str(ctx.exception).lower())

        # 2. {0, 500} x 4: exceeds bound 64 and exceeds max 3 quantifiers -> must be rejected at load time
        pat_500_x4 = r"^[a-z]{0,500}[a-z]{0,500}[a-z]{0,500}[a-z]{0,500}b$"
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_500_x4}}})
        self.assertIn("quantifier", str(ctx.exception).lower())

        # 3. Single quantifier exceeding bound 64: {0, 500} -> rejected at load time
        pat_500_single = r"^[a-z]{0,500}$"
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_500_single}}})
        self.assertIn("exceeds maximum limit of 64", str(ctx.exception))

        # 4. Mixed combinations:
        # 4a. 4 quantifiers mixed (2 unbounded + 2 bounded) -> rejected at load time
        pat_mixed_4 = r"^[a-z]*[a-z]{0,50}[a-z]*[a-z]{0,50}b$"
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_mixed_4}}})

        # 4b. 2 unbounded + 1 bounded -> rejected at load time
        pat_mixed_2unb_1bnd = r"^[a-z]*[a-z]{0,32}[a-z]+b$"
        with self.assertRaises(PolicyError):
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_mixed_2unb_1bnd}}})

        # 4c. Valid bounded combination: 3 bounded repeats with bounds <= 64
        # Accepted at load time, and must match in under 50 ms on 4096 'a' characters
        pat_valid_3bnd = r"^[a-z]{0,32}[a-z]{0,32}[a-z]{0,32}b$"
        validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_valid_3bnd}}})
        t0 = time.perf_counter()
        evaluate_constraints(
            {"properties": {"text": {"type": "string", "pattern": pat_valid_3bnd}}},
            {"text": "a" * 4096},
        )
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.05, f"Valid 3-bounded pattern took {elapsed * 1000:.2f} ms (bound 50 ms)")

        # 4d. Valid mixed combination: 1 unbounded + 2 bounded repeats with bounds <= 50
        # Accepted at load time, and must match in under 50 ms on 4096 'a' characters
        pat_valid_mixed = r"^[a-z]*[a-z]{0,50}[a-z]{0,50}b$"
        validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_valid_mixed}}})
        times_mixed = []
        for _ in range(3):
            t0 = time.perf_counter()
            evaluate_constraints(
                {"properties": {"text": {"type": "string", "pattern": pat_valid_mixed}}},
                {"text": "a" * 4096},
            )
            times_mixed.append(time.perf_counter() - t0)
        elapsed = min(times_mixed)
        self.assertLess(elapsed, 0.05, f"Valid mixed pattern took {elapsed * 1000:.2f} ms (bound 50 ms)")

        # 4e. Valid mixed combination: 1 unbounded + 1 bounded
        pat_valid_unb_bnd = r"^[a-z]+[0-9]{1,32}b$"
        validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_valid_unb_bnd}}})
        t0 = time.perf_counter()
        evaluate_constraints(
            {"properties": {"text": {"type": "string", "pattern": pat_valid_unb_bnd}}},
            {"text": "a" * 4096},
        )
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.05, f"Valid unb+bnd pattern took {elapsed * 1000:.2f} ms (bound 50 ms)")

    def test_pattern_ascii_and_cost_budget(self) -> None:
        """Test re.ASCII enforcement, load-time cost budget rejection, and hostile 4096-char input benchmarks."""
        # 1. ASCII enforcement: ^\d{3}$ must reject Arabic/eastern digits "١٢٣"
        passed, err = evaluate_constraints(
            {"properties": {"code": {"type": "string", "pattern": r"^\d{3}$"}}},
            {"code": "١٢٣"},
        )
        self.assertFalse(passed)
        self.assertIn("does not match pattern", str(err))

        passed, err = evaluate_constraints(
            {"properties": {"code": {"type": "string", "pattern": r"^\d{3}$"}}},
            {"code": "123"},
        )
        self.assertTrue(passed)

        # 2. Hostile patterns with 2 unbounded repeats + bound 64 must be rejected at load time
        # without maxLength because n^2 * 64 = 4096^2 * 64 = 1,073,741,824 exceeds budget 25,000,000
        pat_hostile_1 = r"^.*a.*a[a-z]{0,64}b$"
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_hostile_1}}})
        self.assertIn("budget", str(ctx.exception).lower())

        pat_hostile_2 = r"^\w*a\w*a\w{0,64}b$"
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat_hostile_2}}})
        self.assertIn("budget", str(ctx.exception).lower())

        # 3. When bounded by maxLength <= 512, pattern is accepted and finishes under 50 ms
        validate_constraints_schema(
            {"properties": {"text": {"type": "string", "pattern": pat_hostile_1, "maxLength": 512}}}
        )
        t0 = time.perf_counter()
        evaluate_constraints(
            {"properties": {"text": {"type": "string", "pattern": pat_hostile_1, "maxLength": 512}}},
            {"text": "a" * 512},
        )
        elapsed_512 = time.perf_counter() - t0
        self.assertLess(elapsed_512, 0.05, f"512-char bounded hostile pattern took {elapsed_512 * 1000:.2f} ms")

        # 4. Corpus of accepted patterns on hostile inputs of exactly 4096 characters (< 50 ms each)
        test_patterns = [
            (r"^[a-z]{0,32}[a-z]{0,32}[a-z]{0,32}b$", "valid_3bnd"),
            (r"^[a-z]*[a-z]{0,50}[a-z]{0,50}b$", "valid_mixed"),
            (r"^[a-z]+[0-9]{1,32}b$", "valid_unb_bnd"),
            (r"^.*a.*b$", "valid_2unb_delim"),
        ]
        hostile_4096 = "a" * 4096
        for pat, name in test_patterns:
            validate_constraints_schema({"properties": {"text": {"type": "string", "pattern": pat}}})
            times = []
            for _ in range(3):
                t0 = time.perf_counter()
                evaluate_constraints(
                    {"properties": {"text": {"type": "string", "pattern": pat}}},
                    {"text": hostile_4096},
                )
                times.append(time.perf_counter() - t0)
            elapsed = min(times)
            self.assertLess(
                elapsed,
                0.05,
                f"Pattern '{name}' took {elapsed * 1000:.2f} ms on 4096 chars (exceeded 50 ms bound)",
            )

    def test_engine_determinism_corpus_200_pairs(self) -> None:
        """Assert deterministic identical decisions on a corpus of >= 200 pattern/input pairs.

        Covers \\d, \\w, \\s, unicode classes, and case flags (?i).
        """
        corpus: list[tuple[str, str, bool]] = []

        # 1. Digits \d and [0-9] (40 pairs)
        digit_patterns = [
            r"^\d+$",
            r"^\d{3,5}$",
            r"^[0-9]{2}$",
            r"^\d{1,4}[a-z]$",
        ]
        digit_cases = [
            (digit_patterns[0], "123", True),
            (digit_patterns[0], "0", True),
            (digit_patterns[0], "1234567890", True),
            (digit_patterns[0], "12a3", False),
            (digit_patterns[0], "", False),
            (digit_patterns[0], "abc", False),
            (digit_patterns[0], " 123 ", False),
            (digit_patterns[0], "12.3", False),
            (digit_patterns[0], "-5", False),
            (digit_patterns[0], "+5", False),
            (digit_patterns[1], "123", True),
            (digit_patterns[1], "1234", True),
            (digit_patterns[1], "12345", True),
            (digit_patterns[1], "12", False),
            (digit_patterns[1], "123456", False),
            (digit_patterns[1], "12a4", False),
            (digit_patterns[1], "", False),
            (digit_patterns[1], " 123", False),
            (digit_patterns[1], "123 ", False),
            (digit_patterns[1], "9999", True),
            (digit_patterns[2], "00", True),
            (digit_patterns[2], "99", True),
            (digit_patterns[2], "42", True),
            (digit_patterns[2], "1", False),
            (digit_patterns[2], "123", False),
            (digit_patterns[2], "ab", False),
            (digit_patterns[2], "0a", False),
            (digit_patterns[2], "", False),
            (digit_patterns[2], " 99", False),
            (digit_patterns[2], "99 ", False),
            (digit_patterns[3], "1a", True),
            (digit_patterns[3], "12b", True),
            (digit_patterns[3], "123c", True),
            (digit_patterns[3], "1234d", True),
            (digit_patterns[3], "12345e", False),
            (digit_patterns[3], "a", False),
            (digit_patterns[3], "12", False),
            (digit_patterns[3], "12A", False),
            (digit_patterns[3], "1234", False),
            (digit_patterns[3], "", False),
        ]
        corpus.extend(digit_cases)

        # 2. Word chars \w and [a-zA-Z0-9_] (40 pairs)
        word_patterns = [
            r"^\w+$",
            r"^\w{1,8}$",
            r"^[a-zA-Z0-9_]{3,6}$",
            r"^prefix_\w{1,4}$",
        ]
        word_cases = [
            (word_patterns[0], "hello", True),
            (word_patterns[0], "hello_world", True),
            (word_patterns[0], "var_123", True),
            (word_patterns[0], "12345", True),
            (word_patterns[0], "_private", True),
            (word_patterns[0], "hello world", False),
            (word_patterns[0], "user@domain", False),
            (word_patterns[0], "foo-bar", False),
            (word_patterns[0], "", False),
            (word_patterns[0], "hello!", False),
            (word_patterns[1], "a", True),
            (word_patterns[1], "abcdefgh", True),
            (word_patterns[1], "test_1", True),
            (word_patterns[1], "abcdefghi", False),
            (word_patterns[1], "", False),
            (word_patterns[1], "ab cd", False),
            (word_patterns[1], "a-b", False),
            (word_patterns[1], "12345678", True),
            (word_patterns[1], "_", True),
            (word_patterns[1], "special$", False),
            (word_patterns[2], "abc", True),
            (word_patterns[2], "abc123", True),
            (word_patterns[2], "user_1", True),
            (word_patterns[2], "ab", False),
            (word_patterns[2], "abcdefg", False),
            (word_patterns[2], "abc-de", False),
            (word_patterns[2], "abc def", False),
            (word_patterns[2], "", False),
            (word_patterns[2], "ABC_9", True),
            (word_patterns[2], "XYZ123", True),
            (word_patterns[3], "prefix_a", True),
            (word_patterns[3], "prefix_1234", True),
            (word_patterns[3], "prefix_ok", True),
            (word_patterns[3], "prefix_", False),
            (word_patterns[3], "prefix_12345", False),
            (word_patterns[3], "pre_fix_a", False),
            (word_patterns[3], "prefix a", False),
            (word_patterns[3], "", False),
            (word_patterns[3], "other_a", False),
            (word_patterns[3], "PREFIX_a", False),
        ]
        corpus.extend(word_cases)

        # 3. Whitespace \s and non-whitespace \S (36 pairs)
        ws_patterns = [
            r"^hello\s+world$",
            r"^\s{0,4}[a-z]+\s{0,4}$",
            r"^[a-z]+ [a-z]+$",
        ]
        ws_cases = [
            (ws_patterns[0], "hello world", True),
            (ws_patterns[0], "hello\tworld", True),
            (ws_patterns[0], "hello   world", True),
            (ws_patterns[0], "hello\nworld", True),
            (ws_patterns[0], "hello\r\nworld", True),
            (ws_patterns[0], "helloworld", False),
            (ws_patterns[0], "hello world!", False),
            (ws_patterns[0], " hello world", False),
            (ws_patterns[0], "hello world ", False),
            (ws_patterns[0], "HELLO WORLD", False),
            (ws_patterns[0], "", False),
            (ws_patterns[0], "hello-world", False),
            (ws_patterns[1], "word", True),
            (ws_patterns[1], "  word", True),
            (ws_patterns[1], "word  ", True),
            (ws_patterns[1], "  word  ", True),
            (ws_patterns[1], "\tword\t", True),
            (ws_patterns[1], "  two words  ", False),
            (ws_patterns[1], "  123  ", False),
            (ws_patterns[1], "   ", False),
            (ws_patterns[1], "", False),
            (ws_patterns[1], "WORD", False),
            (ws_patterns[1], "a", True),
            (ws_patterns[1], "     word", False),
            (ws_patterns[2], "hello world", True),
            (ws_patterns[2], "foo bar", True),
            (ws_patterns[2], "a b", True),
            (ws_patterns[2], "first second", True),
            (ws_patterns[2], "hello", False),
            (ws_patterns[2], "hello  world", False),
            (ws_patterns[2], " hello world", False),
            (ws_patterns[2], "hello world ", False),
            (ws_patterns[2], "one two three", False),
            (ws_patterns[2], "123 456", False),
            (ws_patterns[2], "", False),
            (ws_patterns[2], "foo\tbar", False),
        ]
        corpus.extend(ws_cases)

        # 4. Unicode classes and multilingual text (40 pairs)
        unicode_patterns = [
            r"^[\u00c0-\u017fa-z]+$",
            r"^[α-ω]+$",
            r"^[а-яА-Я0-9_]+$",
            r"^caf[\u00e9e]$",
        ]
        unicode_cases = [
            (unicode_patterns[0], "café", True),
            (unicode_patterns[0], "naïve", True),
            (unicode_patterns[0], "über", True),
            (unicode_patterns[0], "crème", True),
            (unicode_patterns[0], "normal", True),
            (unicode_patterns[0], "café123", False),
            (unicode_patterns[0], "café bar", False),
            (unicode_patterns[0], "", False),
            (unicode_patterns[0], "CAFÉ", False),
            (unicode_patterns[0], "français", True),
            (unicode_patterns[1], "αβγ", True),
            (unicode_patterns[1], "ω", True),
            (unicode_patterns[1], "α", True),
            (unicode_patterns[1], "abc", False),
            (unicode_patterns[1], "αβγ1", False),
            (unicode_patterns[1], "", False),
            (unicode_patterns[1], "ΑΒΓ", False),
            (unicode_patterns[1], "α β", False),
            (unicode_patterns[1], "δεζηθ", True),
            (unicode_patterns[1], "ικλμν", True),
            (unicode_patterns[2], "тест", True),
            (unicode_patterns[2], "Тест123", True),
            (unicode_patterns[2], "юзер_1", True),
            (unicode_patterns[2], "русский_язык", True),
            (unicode_patterns[2], "тест!", False),
            (unicode_patterns[2], "тест тест", False),
            (unicode_patterns[2], "", False),
            (unicode_patterns[2], "english", False),
            (unicode_patterns[2], "12345", True),
            (unicode_patterns[2], "_", True),
            (unicode_patterns[3], "café", True),
            (unicode_patterns[3], "cafe", True),
            (unicode_patterns[3], "caff", False),
            (unicode_patterns[3], "caf", False),
            (unicode_patterns[3], "cafeé", False),
            (unicode_patterns[3], "CAFÉ", False),
            (unicode_patterns[3], "", False),
            (unicode_patterns[3], "cafée", False),
            (unicode_patterns[3], "caf1", False),
            (unicode_patterns[3], "other", False),
        ]
        corpus.extend(unicode_cases)

        # 5. Case flags (?i) (35 pairs)
        case_patterns = [
            r"(?i)^[a-z]+$",
            r"(?i)^admin_[0-9]{1,3}$",
            r"(?i)^[a-z]{2,4}_[a-z]{2,4}$",
        ]
        case_cases = [
            (case_patterns[0], "hello", True),
            (case_patterns[0], "HELLO", True),
            (case_patterns[0], "HeLLo", True),
            (case_patterns[0], "hElLo", True),
            (case_patterns[0], "a", True),
            (case_patterns[0], "Z", True),
            (case_patterns[0], "hello123", False),
            (case_patterns[0], "hello world", False),
            (case_patterns[0], "hello_world", False),
            (case_patterns[0], "", False),
            (case_patterns[0], "123", False),
            (case_patterns[0], "!@#", False),
            (case_patterns[1], "admin_1", True),
            (case_patterns[1], "ADMIN_1", True),
            (case_patterns[1], "Admin_99", True),
            (case_patterns[1], "aDmIn_123", True),
            (case_patterns[1], "admin_0", True),
            (case_patterns[1], "ADMIN_1234", False),
            (case_patterns[1], "admin_", False),
            (case_patterns[1], "user_1", False),
            (case_patterns[1], "admin-1", False),
            (case_patterns[1], "admin_abc", False),
            (case_patterns[1], "", False),
            (case_patterns[1], "ADMIN_000", True),
            (case_patterns[2], "us_east", True),
            (case_patterns[2], "US_EAST", True),
            (case_patterns[2], "Us_East", True),
            (case_patterns[2], "eu_west", True),
            (case_patterns[2], "ap_east", True),
            (case_patterns[2], "u_east", False),
            (case_patterns[2], "us_easting", False),
            (case_patterns[2], "us-east", False),
            (case_patterns[2], "us east", False),
            (case_patterns[2], "", False),
            (case_patterns[2], "US_WEST", True),
        ]
        corpus.extend(case_cases)

        # 6. Additional edge cases & complex combinations (30 pairs)
        edge_patterns = [
            r"^[a-z]?$",
            r"^(?:read|write|delete)$",
            r"^https?://[a-z.]+$",
        ]
        edge_cases = [
            (edge_patterns[0], "", True),
            (edge_patterns[0], "a", True),
            (edge_patterns[0], "z", True),
            (edge_patterns[0], "ab", False),
            (edge_patterns[0], "1", False),
            (edge_patterns[0], " ", False),
            (edge_patterns[0], "A", False),
            (edge_patterns[0], "\n", False),
            (edge_patterns[0], "-", False),
            (edge_patterns[0], "abc", False),
            (edge_patterns[1], "read", True),
            (edge_patterns[1], "write", True),
            (edge_patterns[1], "delete", True),
            (edge_patterns[1], "update", False),
            (edge_patterns[1], "READ", False),
            (edge_patterns[1], "read ", False),
            (edge_patterns[1], " read", False),
            (edge_patterns[1], "", False),
            (edge_patterns[1], "delete_all", False),
            (edge_patterns[1], "read_write", False),
            (edge_patterns[2], "http://example.com", True),
            (edge_patterns[2], "https://example.com", True),
            (edge_patterns[2], "https://api.github.com", True),
            (edge_patterns[2], "ftp://example.com", False),
            (edge_patterns[2], "https://", False),
            (edge_patterns[2], "http://", False),
            (edge_patterns[2], "https://example.com/path", False),
            (edge_patterns[2], "https://example.com:8080", False),
            (edge_patterns[2], "", False),
            (edge_patterns[2], "http://localhost", True),
        ]
        corpus.extend(edge_cases)

        self.assertGreaterEqual(len(corpus), 200, f"Expected >= 200 pairs, found {len(corpus)}")

        for pat, inp, expected in corpus:
            # 1. Grammar validation check
            validate_pattern_safety(pat)

            # 2. Engine compilation
            compiled = _compile_anchored_pattern(pat)

            # 3. Match execution
            match_res = bool(compiled.fullmatch(inp))
            self.assertEqual(
                match_res,
                expected,
                f"Mismatch for pattern {pat!r} on input {inp!r}: expected {expected}, got {match_res}",
            )

            # 4. evaluate_constraints integration check
            rule_schema = {"properties": {"val": {"type": "string", "pattern": pat}}}
            ok, _ = evaluate_constraints(rule_schema, {"val": inp})
            self.assertEqual(
                ok,
                expected,
                f"evaluate_constraints mismatch for pattern {pat!r} on input {inp!r}: expected {expected}, got {ok}",
            )

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

    def test_ordering_constraint_violation_via_dmint_authorize_and_gateway(self) -> None:
        """Constraint violation returns DENY before pending record is created across Dmint.authorize and MCP gateway."""
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
            provenance = PolicyProvenance("p1", policy_digest(policy), datetime.now(timezone.utc))
            engine = Dmint(
                policy,
                agent_id="test-agent",
                context=TrustedContext({}),
                approval_store=store,
                policy_provenance=provenance,
                approval_ttl=timedelta(minutes=30),
            )

            @engine.protect("payments.wire_transfer")
            def dummy_wire_transfer(amount: float, iban: str) -> str:
                return f"transferred {amount} to {iban}"

            # --- Test Path 1: Dmint.authorize ---
            # 1a. Violating request: amount > 5000.0
            with self.assertRaises(AuthorizationError) as ctx:
                engine.authorize(
                    dummy_wire_transfer,
                    capability="payments.wire_transfer",
                    amount=99999.0,
                    iban="DE123456789",
                )
            self.assertEqual(ctx.exception.code, "DMT_CONSTRAINT_VIOLATION")
            # list_pending() MUST stay empty
            self.assertEqual(len(store.list_pending()), 0)

            # 1b. Valid request: amount <= 5000.0
            with self.assertRaises(ApprovalRequiredError):
                engine.authorize(
                    dummy_wire_transfer,
                    capability="payments.wire_transfer",
                    amount=100.0,
                    iban="DE123456789",
                )
            # list_pending() MUST have exactly 1 pending record
            pending = store.list_pending()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].request.arguments["amount"], 100.0)

            # --- Test Path 2: MCPGateway with real SQLite store ---
            integ_cfg = MCPIntegrationConfig(
                integration_id="payments",
                command="dummy",
                tool_bindings=[
                    MCPToolBinding("wire_transfer", "payments.wire_transfer", discovery=DiscoveryMode.EXPOSED)
                ],
            )
            gateway_db = Path(tmp_dir) / "gateway_approvals.db"
            gw_cfg = MCPGatewayConfig(
                policy=policy,
                policy_provenance=provenance,
                integrations=[integ_cfg],
                approval_store_path=gateway_db,
                approval_ttl=timedelta(minutes=30),
                disclosure_mode=DisclosureMode.DOG,
                agent_id="test-agent",
            )
            client = MockDownstreamClient(integ_cfg)
            gateway = MCPGateway(gw_cfg, client_factory=lambda _: client)

            async def run_gateway_checks() -> None:
                await gateway.connect()
                # 2a. Violating request
                res_bad = await gateway._handle_call_tool(
                    None,  # type: ignore[arg-type]
                    types.CallToolRequestParams(
                        name="payments.wire_transfer",
                        arguments={"amount": 99999.0, "iban": "DE123456789"},
                    ),
                )
                self.assertTrue(res_bad.is_error)
                self.assertIn("DMT_CONSTRAINT_VIOLATION", res_bad.content[0].text)  # type: ignore[union-attr]
                # Gateway's approval store MUST stay empty
                self.assertIsNotNone(gateway.approval_store)
                assert gateway.approval_store is not None
                self.assertEqual(len(gateway.approval_store.list_pending()), 0)

                # 2b. Valid request
                res_ok = await gateway._handle_call_tool(
                    None,  # type: ignore[arg-type]
                    types.CallToolRequestParams(
                        name="payments.wire_transfer",
                        arguments={"amount": 250.0, "iban": "DE123456789"},
                    ),
                )
                self.assertTrue(res_ok.is_error)
                self.assertIn("DMT_APPROVAL_REQUIRED", res_ok.content[0].text)  # type: ignore[union-attr]
                # Gateway's approval store MUST have exactly 1 record
                gw_pending = gateway.approval_store.list_pending()
                self.assertEqual(len(gw_pending), 1)
                self.assertEqual(gw_pending[0].request.arguments["amount"], 250.0)

            asyncio.run(run_gateway_checks())

    def test_multi_rule_constraint_evaluation_precedence(self) -> None:
        """Test multi-rule evaluation precedence with argument constraints."""
        # Scenario A: ALLOW rule with failing constraints plus broader unconstrained ALLOW
        # Expected: whole request DENIED with DMT_CONSTRAINT_VIOLATION
        policy_a = Policy(
            [
                Rule.allow(
                    "fs",
                    "read",
                    resource="*",
                    constraints={
                        "required": ["path"],
                        "properties": {"path": {"type": "string", "minLength": 1}},
                    },
                ),
                Rule.allow("fs", "read", resource="*"),  # Broader unconstrained ALLOW
            ]
        )
        req_missing = make_test_request("fs", "read", "*", {})
        dec, code = policy_a.evaluate_detailed(req_missing)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # When path is provided, ALLOW is granted
        req_valid = make_test_request("fs", "read", "*", {"path": "/etc/hosts"})
        dec, code = policy_a.evaluate_detailed(req_valid)
        self.assertEqual(dec, Decision.ALLOW)
        self.assertIsNone(code)

        # Scenario B: DENY rule with constraints is rejected at load time
        with self.assertRaises(PolicyError) as ctx:
            Policy(
                [
                    Rule.deny(
                        "db",
                        "query",
                        resource="*",
                        constraints={"properties": {"limit": {"type": "integer", "maximum": 100}}},
                    ),
                    Rule.allow("db", "query", resource="*"),
                ]
            )
        self.assertIn("DENY rules cannot have constraints", str(ctx.exception))

        # Scenario C: APPROVAL_REQUIRED rule with constraints
        policy_c = Policy(
            [
                Rule.approval_required(
                    "auth",
                    "reset_password",
                    resource="*",
                    constraints={
                        "required": ["email"],
                        "properties": {"email": {"type": "string", "minLength": 5}},
                    },
                )
            ]
        )
        # C.1: Failing constraints -> DMT_CONSTRAINT_VIOLATION
        req_bad_email = make_test_request("auth", "reset_password", "*", {"email": "a"})
        dec, code = policy_c.evaluate_detailed(req_bad_email)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # C.2: Satisfying constraints -> DMT_APPROVAL_REQUIRED
        req_ok_email = make_test_request("auth", "reset_password", "*", {"email": "user@example.com"})
        dec, code = policy_c.evaluate_detailed(req_ok_email)
        self.assertEqual(dec, Decision.APPROVAL_REQUIRED)
        self.assertEqual(code, "DMT_APPROVAL_REQUIRED")

        # Scenario D: Two ALLOW rules with different constraints
        policy_d = Policy(
            [
                Rule.allow(
                    "finance",
                    "transfer",
                    resource="*",
                    constraints={"properties": {"amount": {"type": "number", "maximum": 500.0}}},
                ),
                Rule.allow(
                    "finance",
                    "transfer",
                    resource="*",
                    constraints={"properties": {"currency": {"type": "string", "enum": ["USD", "EUR"]}}},
                ),
            ]
        )
        # Both constraints satisfied -> ALLOW
        req_both_ok = make_test_request("finance", "transfer", "*", {"amount": 200.0, "currency": "USD"})
        dec, code = policy_d.evaluate_detailed(req_both_ok)
        self.assertEqual(dec, Decision.ALLOW)
        self.assertIsNone(code)

        # Rule 1 violated (amount > 500) -> DMT_CONSTRAINT_VIOLATION
        req_amount_bad = make_test_request("finance", "transfer", "*", {"amount": 999.0, "currency": "USD"})
        dec, code = policy_d.evaluate_detailed(req_amount_bad)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

        # Rule 2 violated (unsupported currency) -> DMT_CONSTRAINT_VIOLATION
        req_curr_bad = make_test_request("finance", "transfer", "*", {"amount": 200.0, "currency": "JPY"})
        dec, code = policy_d.evaluate_detailed(req_curr_bad)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_CONSTRAINT_VIOLATION")

    def test_strict_arguments_policy_setting(self) -> None:
        """Test optional policy-level 'strict_arguments': true."""
        # By default (strict_arguments=False), additional properties default to true
        policy_default = Policy(
            [
                Rule.allow(
                    "svc",
                    "act",
                    resource="*",
                    constraints={"properties": {"param": {"type": "string"}}},
                )
            ]
        )
        req_extra = make_test_request("svc", "act", "*", {"param": "ok", "extra_field": 123})
        dec, code = policy_default.evaluate_detailed(req_extra)
        self.assertEqual(dec, Decision.ALLOW)

        # With strict_arguments=True, additional properties default to false
        policy_strict = Policy(
            [
                Rule.allow(
                    "svc",
                    "act",
                    resource="*",
                    constraints={"properties": {"param": {"type": "string"}}},
                )
            ],
            strict_arguments=True,
        )
        dec_strict, code_strict = policy_strict.evaluate_detailed(req_extra)
        self.assertEqual(dec_strict, Decision.DENY)
        self.assertEqual(code_strict, "DMT_CONSTRAINT_VIOLATION")

        # Rule with explicit additionalProperties: True can opt out of policy strictness
        policy_opt_out = Policy(
            [
                Rule.allow(
                    "svc",
                    "act",
                    resource="*",
                    constraints={
                        "additionalProperties": True,
                        "properties": {"param": {"type": "string"}},
                    },
                )
            ],
            strict_arguments=True,
        )
        dec_opt, code_opt = policy_opt_out.evaluate_detailed(req_extra)
        self.assertEqual(dec_opt, Decision.ALLOW)

        # Roundtrip JSON and dict serialization
        p_dict = policy_strict.to_dict()
        self.assertTrue(p_dict.get("strict_arguments"))
        p_loaded = Policy.from_dict(p_dict)
        self.assertTrue(p_loaded.strict_arguments)
        p_json = policy_strict.to_json()
        p_from_json = Policy.from_json(p_json)
        self.assertTrue(p_from_json.strict_arguments)

    def test_reject_tuples_in_constraints(self) -> None:
        """Tuples specified as arrays in constraints are strictly rejected with PolicyError."""
        # 1. Tuple in required
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"required": ("user_id", "email")})
        self.assertIn("tuple", str(ctx.exception).lower())

        # 2. Tuple in enum
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"role": {"enum": ("admin", "user")}}})
        self.assertIn("tuple", str(ctx.exception).lower())

        # 3. Tuple in schema items
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema({"properties": {"tags": ({"type": "string"},)}})
        self.assertIn("tuple", str(ctx.exception).lower())

        # 4. Constructing rule with tuple in constraints
        with self.assertRaises(PolicyError):
            Rule.allow(
                "box",
                "pack",
                resource="*",
                constraints={"required": ("item",)},
            )

    def test_reject_conflicting_property_constraints_without_type(self) -> None:
        """Reject property constraints with conflicting type keys when 'type' is omitted."""
        with self.assertRaises(PolicyError) as ctx:
            validate_constraints_schema(
                {
                    "properties": {
                        "bad_field": {
                            "minimum": 10,
                            "pattern": r"^[a-z]+$",
                        }
                    }
                }
            )
        self.assertIn("conflicting constraint types", str(ctx.exception))

    def test_mcp_gateway_toctou_prevention(self) -> None:
        """Mutating original argument dict after calling gateway does not affect downstream call or recorded approval."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "toctou_approvals.db"
            store = SQLiteApprovalStore(db_path, deployment_epoch="test-epoch")
            policy = Policy(
                [
                    Rule.allow("files", "write", resource="*"),
                    Rule.approval_required("admin", "grant", resource="*"),
                ]
            )
            provenance = PolicyProvenance("p1", policy_digest(policy), datetime.now(timezone.utc))
            integ_cfg = MCPIntegrationConfig(
                integration_id="infra",
                command="dummy",
                tool_bindings=[
                    MCPToolBinding("write", "files.write", discovery=DiscoveryMode.EXPOSED),
                    MCPToolBinding("grant", "admin.grant", discovery=DiscoveryMode.EXPOSED),
                ],
            )
            gw_cfg = MCPGatewayConfig(
                policy=policy,
                policy_provenance=provenance,
                integrations=[integ_cfg],
                approval_store_path=db_path,
                approval_ttl=timedelta(minutes=30),
                disclosure_mode=DisclosureMode.DOG,
                agent_id="test-agent",
            )
            client = MockDownstreamClient(integ_cfg)
            gateway = MCPGateway(gw_cfg, client_factory=lambda _: client)

            async def run_toctou_checks() -> None:
                await gateway.connect()

                # Case 1: ALLOW call
                orig_write_args = {
                    "path": "/safe/file.txt",
                    "meta": {"owner": "alice"},
                    "tags": ["prod"],
                }
                res = await gateway._handle_call_tool(
                    None,  # type: ignore[arg-type]
                    types.CallToolRequestParams(name="infra.write", arguments=orig_write_args),
                )
                self.assertFalse(res.is_error)

                # Mutate original dict immediately
                orig_write_args["path"] = "/etc/shadow"
                orig_write_args["meta"]["owner"] = "attacker"
                orig_write_args["tags"].append("hacked")

                # Verify downstream call log has pre-mutation values
                self.assertEqual(len(client.call_log), 1)
                tool_called, actual_args = client.call_log[0]
                self.assertEqual(tool_called, "write")
                self.assertEqual(actual_args["path"], "/safe/file.txt")
                self.assertEqual(actual_args["meta"], {"owner": "alice"})
                self.assertEqual(actual_args["tags"], ["prod"])

                # Case 2: APPROVAL_REQUIRED call
                orig_grant_args = {
                    "user": "bob",
                    "roles": ["viewer"],
                    "details": {"reason": "auditing"},
                }
                res_app = await gateway._handle_call_tool(
                    None,  # type: ignore[arg-type]
                    types.CallToolRequestParams(name="infra.grant", arguments=orig_grant_args),
                )
                self.assertTrue(res_app.is_error)

                # Mutate original dict immediately
                orig_grant_args["user"] = "root"
                orig_grant_args["roles"].append("superadmin")
                orig_grant_args["details"]["reason"] = "pwned"

                # Verify pending record stored in SQLite has pre-mutation values
                self.assertIsNotNone(gateway.approval_store)
                assert gateway.approval_store is not None
                pending = gateway.approval_store.list_pending()
                self.assertEqual(len(pending), 1)
                stored_args = pending[0].request.arguments
                self.assertEqual(stored_args["user"], "bob")
                self.assertEqual(stored_args["roles"], ("viewer",))
                self.assertEqual(stored_args["details"], {"reason": "auditing"})

            asyncio.run(run_toctou_checks())


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
                            "sql": {"type": "string", "pattern": r"(?i)^\s*SELECT\s{1,10}[\s\S]+$"},
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
