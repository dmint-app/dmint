from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import subprocess
import unittest

from dmint import (
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
    ToolRequest,
    TrustedContext,
    canonicalize,
    canonicalize_bytes,
    canonicalize_request,
    request_fingerprint,
)
from dmint.core.canonicalize import utf16_sort_key
from dmint.authority import ApprovalAssertion
from dmint.errors import (
    ApprovalVersionUnsupportedError,
    CanonicalizationError,
    UnknownApprovalVersionError,
)


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

    def test_rfc8785_number_serialization(self):
        """RFC 8785 requires -0.0 and 0.0 -> '0', whole floats -> integer format without .0."""
        self.assertEqual(canonicalize(-0.0), "0")
        self.assertEqual(canonicalize(0.0), "0")
        self.assertEqual(canonicalize(1.0), "1")
        self.assertEqual(canonicalize(-1.0), "-1")
        self.assertEqual(canonicalize(1.5), "1.5")
        self.assertEqual(canonicalize(-2.5), "-2.5")
        self.assertEqual(canonicalize(1e-6), "0.000001")
        self.assertEqual(canonicalize(1e20), "100000000000000000000")

    def test_utf16_sort_order(self):
        """RFC 8785 Section 3.2.3 requires sorting keys by UTF-16 code units, not Unicode codepoints."""
        # Supplementary character U+10000 (surrogate pair \uD800\uDC00) must sort BEFORE
        # BMP character U+E000 (\uE000) because 0xD800 < 0xE000 in UTF-16.
        bmp = "\ue000"
        astral = "\U00010000"
        self.assertLess(utf16_sort_key(astral), utf16_sort_key(bmp))

        payload = {bmp: "bmp", astral: "supplementary"}
        canon = canonicalize(payload)
        expected = f'{{"{astral}":"supplementary","{bmp}":"bmp"}}'
        self.assertEqual(canon, expected)

    def test_unicode_normalization_preserved(self):
        """JCS does NOT normalize Unicode strings; distinct encodings remain distinct."""
        self.assertNotEqual(canonicalize("\u00e9"), canonicalize("e\u0301"))

    def test_canonicalize_vectors_file(self):
        """All test vectors in tests/fixtures/canonicalize_vectors.json must match exactly."""
        vector_path = Path(__file__).parents[1] / "fixtures" / "canonicalize_vectors.json"
        self.assertTrue(vector_path.exists(), f"Vector file not found at {vector_path}")
        with open(vector_path, "r", encoding="utf-8") as f:
            vectors = json.load(f)

        self.assertGreaterEqual(len(vectors), 25, "Must have comprehensive vector suite")
        for v in vectors:
            inp = v["input"]
            if "float" in v["name"]:
                inp = float(inp)
            actual = canonicalize(inp)
            expected = v["expected_canonical"]
            self.assertEqual(
                actual,
                expected,
                f"Vector mismatch on {v['name']}: actual={actual} != expected={expected}",
            )

    def test_cross_check_npm_canonicalize(self):
        """Cross-check live output directly against npm 'canonicalize' package."""
        node_script = """
        const canonicalize = require('./tests/fixtures/node_modules/canonicalize').default;
        const fs = require('fs');
        const data = JSON.parse(fs.readFileSync(0, 'utf8'));
        console.log(canonicalize(data));
        """
        test_data = {
            "unicode": "café 🚀 漢字",
            "nested": {"z": 1, "a": [3, 2, 1], "m": True, "nil": None},
            "astral_key": {"\ue000": 1, "\U00010000": 2},
            "floats": [0.0, -0.0, 1.0, 1.5, 0.00001],
        }
        py_output = canonicalize(test_data)
        proc = subprocess.run(
            ["node", "-e", node_script],
            input=json.dumps(test_data),
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parents[2]),
        )
        self.assertEqual(proc.returncode, 0, f"Node error: {proc.stderr}")
        js_output = proc.stdout.strip()
        self.assertEqual(py_output, js_output)

    def test_old_record_version_v1_fails_closed(self):
        """Records from v1 must fail closed with UnknownApprovalVersionError (DMT_APPROVAL_UNKNOWN_VERSION)."""
        now = datetime.now(timezone.utc)
        provenance = PolicyProvenance("policy-1", "0" * 64, now)
        req = request({"action": "test"})
        with self.assertRaises(UnknownApprovalVersionError) as ctx:
            ApprovalRecord._from_storage(
                schema_version="dmint/approval-record/v1",
                approval_id="apr_0123456789abcdef0123456789abcdef0123456789a",
                request=req,
                request_fingerprint="0" * 64,
                binding_version="dmint/request-binding/v1",
                canonicalization_profile="dmint/jcs-v1",
                integration_id="local",
                capability_id="database.read",
                policy_provenance=provenance,
                created_at=now,
                expires_at=now + timedelta(hours=1),
                state=ApprovalState.PENDING,
                state_at=now,
            )
        self.assertEqual(ctx.exception.code, "DMT_APPROVAL_UNKNOWN_VERSION")

    def test_old_assertion_version_v1_fails_closed(self):
        """Assertions from v1 must fail closed with ApprovalVersionUnsupportedError (DMT_APPROVAL_VERSION_UNSUPPORTED)."""
        raw_v1_envelope = {
            "algorithm": "Ed25519",
            "credential_version": "dmint/approval-assertion/v1",
            "payload": {
                "approval_id": "apr_0123456789abcdef0123456789abcdef0123456789a",
                "request_id": "req_0123456789abcdef0123456789abcdef0123456789a",
                "request_fingerprint": "0" * 64,
                "principal_id": "agent-1",
                "integration_id": "local",
                "audience": "dmint/dashboard/v1",
                "issuer": "ops-authority",
                "issued_at": "2026-10-07T12:00:00Z",
                "expires_at": "2026-10-07T13:00:00Z",
                "policy_version_id": "pol-1",
                "policy_digest": "0" * 64,
                "policy_evaluated_at": "2026-10-07T12:00:00Z",
                "decision": "APPROVED",
                "nonce": "nonce_0123456789abcdef0123456789abcdef01234567",
                "approver_authority_id": "ops-authority",
                "approver_subject_id": "admin",
                "approver_kind": "HUMAN",
            },
            "signature": "A" * 86 + "==",
        }
        raw_bytes = json.dumps(raw_v1_envelope).encode("utf-8")
        with self.assertRaises(ApprovalVersionUnsupportedError) as ctx:
            ApprovalAssertion.from_bytes(raw_bytes)
        self.assertEqual(ctx.exception.code, "DMT_APPROVAL_VERSION_UNSUPPORTED")

    def test_request_snapshot_is_immutable(self):
        original = {"nested": {"value": 1}}
        frozen = request(original)
        original["nested"]["value"] = 2

        self.assertEqual(frozen.arguments["nested"]["value"], 1)
        with self.assertRaises(TypeError):
            frozen.arguments["nested"]["value"] = 3
