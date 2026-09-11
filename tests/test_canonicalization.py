import math
import unittest

from dmint import ToolRequest, TrustedContext, canonicalize, canonicalize_request, request_fingerprint
from dmint.errors import CanonicalizationError


def request(arguments):
    return ToolRequest(
        request_id="request-1",
        agent_id="agent-a",
        tool="database",
        action="read",
        resource="users/123",
        arguments=arguments,
        context=TrustedContext.from_mapping({"environment": "development"}),
    )


class CanonicalizationTests(unittest.TestCase):
    def test_key_order_does_not_change_canonical_request(self):
        first = request({"user_id": 123, "reason": "test"})
        second = request({"reason": "test", "user_id": 123})

        self.assertEqual(canonicalize_request(first), canonicalize_request(second))
        self.assertEqual(request_fingerprint(first), request_fingerprint(second))

    def test_security_relevant_argument_types_are_distinct(self):
        self.assertNotEqual(request_fingerprint(request({"value": 1})), request_fingerprint(request({"value": "1"})))
        self.assertNotEqual(request_fingerprint(request({"value": True})), request_fingerprint(request({"value": 1})))
        self.assertNotEqual(request_fingerprint(request({"value": None})), request_fingerprint(request({})))

    def test_non_json_values_are_rejected(self):
        with self.assertRaises(CanonicalizationError):
            request({"value": object()})

        with self.assertRaises(CanonicalizationError):
            request({"value": (1, 2)})

    def test_non_finite_and_unsafe_numbers_are_rejected(self):
        with self.assertRaises(CanonicalizationError):
            request({"value": math.nan})
        with self.assertRaises(CanonicalizationError):
            request({"value": math.inf})
        with self.assertRaises(CanonicalizationError):
            request({"value": 2**53})
        # max safe integer boundary is 2**53 - 1
        valid = request({"value": 2**53 - 1})
        self.assertEqual(valid.arguments["value"], 9007199254740991)

    def test_negative_zero_and_whole_floats_are_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize(-0.0)
        with self.assertRaises(CanonicalizationError):
            canonicalize(1.0)
        with self.assertRaises(CanonicalizationError):
            canonicalize(0.0)
        # Non-integer finite float is allowed
        self.assertEqual(canonicalize(1.5), "1.5")
        self.assertNotEqual(canonicalize("\u00e9"), canonicalize("e\u0301"))

    def test_request_snapshot_is_immutable(self):
        original = {"nested": {"value": 1}}
        frozen = request(original)
        original["nested"]["value"] = 2

        self.assertEqual(frozen.arguments["nested"]["value"], 1)
        with self.assertRaises(TypeError):
            frozen.arguments["nested"]["value"] = 3
