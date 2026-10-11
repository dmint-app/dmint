from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import subprocess
from typing import Any
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

    def test_lone_surrogates_raise_canonicalization_error(self):
        """Lone surrogates must raise CanonicalizationError, not UnicodeEncodeError."""
        for s in ["\ud800", "\udfff", "before\ud800after"]:
            with self.assertRaises(CanonicalizationError) as ctx:
                canonicalize(s)
            self.assertIn("lone surrogates", str(ctx.exception))
            self.assertNotIsInstance(ctx.exception, UnicodeEncodeError)

    def test_serialize_str_edge_cases_and_node_parity(self):
        """Test DEL unescaped, U+2028/2029 unescaped, control chars lowercase \\u00xx,

        short forms, quotes/backslash, non-ASCII raw, emoji (surrogate pair),
        and keys sorting differently in UTF-16 vs code point order. Compare against Node.
        """
        # DEL (0x7f) unescaped: \x7f
        del_char = "\x7f"
        self.assertEqual(canonicalize(del_char), f'"{del_char}"')

        # U+2028 / U+2029 unescaped
        u2028 = "\u2028"
        u2029 = "\u2029"
        self.assertEqual(canonicalize(u2028), f'"{u2028}"')
        self.assertEqual(canonicalize(u2029), f'"{u2029}"')

        # Control chars as lowercase \u00xx
        self.assertEqual(canonicalize("\x00"), '"\\u0000"')
        self.assertEqual(canonicalize("\x01"), '"\\u0001"')
        self.assertEqual(canonicalize("\x1f"), '"\\u001f"')

        # Short forms \b, \t, \n, \f, \r
        self.assertEqual(canonicalize("\b\t\n\f\r"), '"\\b\\t\\n\\f\\r"')

        # Quotes and backslash
        self.assertEqual(canonicalize('"\\'), '"\\"\\\\"')

        # Non-ASCII raw (e.g. accented Latin, Asian characters)
        raw_non_ascii = "café 漢字"
        self.assertEqual(canonicalize(raw_non_ascii), f'"{raw_non_ascii}"')

        # Emoji (surrogate pair in UTF-16)
        emoji = "🚀"  # U+1F680 -> UTF-16 \uD83D\uDE80
        self.assertEqual(canonicalize(emoji), f'"{emoji}"')

        # Keys that sort differently in UTF-16 vs code point order
        # In Unicode code points: \U00010000 (0x10000) > \uE000 (0xE000)
        # In UTF-16 code units: \U00010000 is \uD800\uDC00, and 0xD800 < 0xE000
        obj = {"\ue000": 1, "\U00010000": 2}
        expected = '{"\\ud800\\udc00":2,"\\ue000":1}' if False else f'{{"\U00010000":2,"\ue000":1}}'
        self.assertEqual(canonicalize(obj), expected)

        # Cross-check each against Node JSON.stringify
        test_strings = [
            del_char,
            u2028,
            u2029,
            "\x00\x01\x1f",
            "\b\t\n\f\r",
            '"\\',
            raw_non_ascii,
            emoji,
        ]
        node_script = """
        const fs = require('fs');
        const items = JSON.parse(fs.readFileSync(0, 'utf8'));
        console.log(JSON.stringify(items.map(s => JSON.stringify(s))));
        """
        proc = subprocess.run(
            ["node", "-e", node_script],
            input=json.dumps(test_strings),
            capture_output=True,
            text=True,
            check=True,
        )
        node_results = json.loads(proc.stdout.strip())
        for s, node_str in zip(test_strings, node_results):
            self.assertEqual(canonicalize(s), node_str)

    def test_tuples_and_mappings_rejected_as_originally_specified(self):
        """Tuples and non-dict mappings must be strictly rejected by canonicalize."""
        from types import MappingProxyType

        with self.assertRaises(CanonicalizationError):
            canonicalize((1, 2))
        with self.assertRaises(CanonicalizationError):
            canonicalize({"a": (1, 2)})
        with self.assertRaises(CanonicalizationError):
            canonicalize(MappingProxyType({"a": 1}))

    def test_v1_record_in_sqlite_store_skipped_without_crashing_list_pending_or_dashboard(self):
        """A v1 record sitting in the SQLite store does not crash list_pending or the dashboard."""
        import hashlib
        import rfc8785
        import tempfile
        import sqlite3
        from dmint.core.storage.sqlite import SQLiteApprovalStore
        from dmint.core.storage.sqlite import _integrity_checksum

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "store.db"
            epoch = "test-epoch"
            store = SQLiteApprovalStore(db_path, deployment_epoch=epoch)

            # Insert a valid v2 record
            req = ToolRequest(
                request_id="req_0123456789abcdef0123456789abcdef01234567892",
                agent_id="agent-a",
                tool="database",
                action="read",
                resource="users/123",
                arguments={"action": "allowed"},
                context=TrustedContext.from_mapping({"environment": "development"}),
            )
            rec2 = ApprovalRecord.create(
                request=req,
                integration_id="local",
                capability_id="database.read",
                policy_provenance=PolicyProvenance("pol-1", "0" * 64, datetime.now(timezone.utc)),
            )
            store.save_pending(rec2)

            # Manually inject a v1 record into SQLite
            conn = sqlite3.connect(str(db_path))
            v1_row = {
                "schema_version": "dmint/approval-record/v1",
                "approval_id": "apr_0123456789abcdef0123456789abcdef01234567891",
                "request_id": "req_0123456789abcdef0123456789abcdef01234567891",
                "request_fingerprint": "0" * 64,
                "binding_version": "dmint/request-binding/v1",
                "canonicalization_profile": "dmint/jcs-v1",
                "integration_id": "local",
                "capability_id": "database.read",
                "principal_id": "agent-a",
                "tool": "database",
                "action": "read",
                "resource_kind": "value",
                "resource_value": "users/123",
                "arguments_json": '{"action":"allowed"}',
                "trusted_context_json": '{"environment":"development"}',
                "policy_version_id": "pol-1",
                "policy_digest": "0" * 64,
                "policy_evaluated_at": "2026-10-07T12:00:00+00:00",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                "state": "PENDING",
                "decision_authority_id": None,
                "decision_authority_subject": None,
                "decision_authority_kind": None,
                "decision_at": None,
                "state_reason": None,
                "state_at": datetime.now(timezone.utc).isoformat(),
                "consumed_at": None,
                "deployment_epoch": epoch,
            }
            checksum = hashlib.sha256(
                b"dmint/approval-record-integrity/v1\x00" + rfc8785.dumps(dict(v1_row))
            ).hexdigest()
            cols = list(v1_row.keys()) + ["record_checksum"]
            vals = list(v1_row.values()) + [checksum]
            placeholders = ", ".join("?" * len(cols))
            conn.execute(
                f"INSERT INTO approval_records ({', '.join(cols)}) VALUES ({placeholders})",
                vals,
            )
            conn.commit()
            conn.close()

            # list_pending should succeed and return only the valid v2 record, logging warning
            with self.assertLogs("dmint.core.storage.sqlite", level="WARNING") as cm:
                pending = store.list_pending()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].approval_id, rec2.approval_id)
            self.assertTrue(
                any("Skipped 1 pending approval records with unsupported schema version" in msg for msg in cm.output)
            )

            # list_records should also succeed without crashing and log warning
            with self.assertLogs("dmint.core.storage.sqlite", level="WARNING") as cm_rec:
                records = store.list_records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].approval_id, rec2.approval_id)
            self.assertTrue(
                any("Skipped 1 approval records with unsupported schema version" in msg for msg in cm_rec.output)
            )

            # Approving the v1 record directly must raise UnknownApprovalVersionError
            from dmint.authority import LocalApprovalAuthority
            from dmint.core.errors import UnknownApprovalVersionError
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            authority = LocalApprovalAuthority(
                issuer_id="test-iss",
                audience=epoch,
                private_key=Ed25519PrivateKey.generate(),
            )
            v1_id = "apr_0123456789abcdef0123456789abcdef01234567891"
            with self.assertRaises(UnknownApprovalVersionError) as err_ctx:
                store.approve_pending(v1_id, authority=authority, approved_by="admin")
            self.assertEqual(err_ctx.exception.code, "DMT_APPROVAL_UNKNOWN_VERSION")

            # dmint approve <v1 approval id> CLI must return version error code
            import io
            from unittest.mock import patch
            from dmint.cli.approvals import main_approve

            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                exit_code = main_approve([v1_id, "--db-path", str(db_path), "--deployment-epoch", epoch])
            self.assertEqual(exit_code, 1)
            self.assertIn("DMT_APPROVAL_UNKNOWN_VERSION", stderr_buf.getvalue())
            store.close()

    def test_object_key_lone_surrogates_rejected_before_sorting(self):
        """Object keys containing lone surrogates must raise CanonicalizationError before sorting."""
        with self.assertRaises(CanonicalizationError) as ctx:
            canonicalize({"\ud800": 1})
        self.assertIn("lone surrogates", str(ctx.exception))

    def test_max_depth_exceeded_10000_levels(self):
        """Nesting 10,000 levels deep must raise CanonicalizationError without RecursionError."""
        cur: dict[str, Any] = {}
        for _ in range(10000):
            cur = {"a": cur}
        with self.assertRaises(CanonicalizationError) as ctx:
            canonicalize(cur)
        self.assertIn("maximum nesting depth", str(ctx.exception))

    def test_cycle_detection_self_referencing_dict_and_list(self):
        """Self-referencing dicts and lists must raise CanonicalizationError for circular references."""
        cyclic_dict: dict[str, Any] = {}
        cyclic_dict["self"] = cyclic_dict
        with self.assertRaises(CanonicalizationError) as ctx_d:
            canonicalize(cyclic_dict)
        self.assertIn("circular reference detected", str(ctx_d.exception))

        cyclic_list: list[Any] = []
        cyclic_list.append(cyclic_list)
        with self.assertRaises(CanonicalizationError) as ctx_l:
            canonicalize(cyclic_list)
        self.assertIn("circular reference detected", str(ctx_l.exception))

    def test_max_canonical_size_exceeded(self):
        """Payloads exceeding max_bytes limit must raise CanonicalizationError."""
        payload = {"data": "x" * 100}
        with self.assertRaises(CanonicalizationError) as ctx:
            canonicalize(payload, max_bytes=50)
        self.assertIn("maximum canonical size", str(ctx.exception))

    def test_200k_doubles_fuzz_against_node(self):
        """Fuzz test at least 200,000 doubles against Node JSON.stringify."""
        import random
        import shutil
        import struct

        node_bin = shutil.which("node")
        if node_bin is None:
            self.fail("Node.js is required for 200k doubles fuzz test but 'node' was not found in PATH")

        seed = 1337
        rng = random.Random(seed)
        doubles = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            1.5,
            -2.5,
            1e-7,
            1e-6,
            1e-5,
            9.999999999999997e-7,
            0.000001,
            1e15,
            1e16,
            float(2**53),
            float(2**53 - 1),
            float(-(2**53 - 1)),
            1e20,
            1e21,
            1e22,
            1e23,
            5e-324,
            -5e-324,
            1.7976931348623157e308,
            -1.7976931348623157e308,
            2.2250738585072014e-308,
        ]

        for center in [1e-7, 1e-6, 1e-5, 1e15, 1e16, float(2**53), 1e21, 1e22]:
            for delta in [-1e-12, -1e-15, 0.0, 1e-15, 1e-12]:
                doubles.append(center * (1.0 + delta))

        # Appendix B vectors
        hex_samples = [
            "0000000000000000",
            "8000000000000000",
            "0000000000000001",
            "8000000000000001",
            "7fefffffffffffff",
            "ffefffffffffffff",
            "4340000000000000",
            "c340000000000000",
            "4430000000000000",
            "44b52d02c7e14af5",
            "44b52d02c7e14af6",
            "44b52d02c7e14af7",
            "444b1ae4d6e2ef4e",
            "444b1ae4d6e2ef4f",
            "444b1ae4d6e2ef50",
            "3eb0c6f7a0b5ed8c",
            "3eb0c6f7a0b5ed8d",
            "41b3de4355555553",
            "41b3de4355555554",
            "41b3de4355555555",
            "41b3de4355555556",
            "41b3de4355555557",
            "becbf647612f3696",
            "43143ff3c1cb0959",
        ]
        for h in hex_samples:
            doubles.append(struct.unpack(">d", bytes.fromhex(h))[0])

        for _ in range(5000):
            mantissa = rng.getrandbits(52)
            sign = rng.choice([0, 1])
            raw = (sign << 63) | mantissa
            doubles.append(struct.unpack(">d", struct.pack(">Q", raw))[0])

        target_count = 200_000
        while len(doubles) < target_count:
            raw = rng.getrandbits(64)
            v = struct.unpack(">d", struct.pack(">Q", raw))[0]
            if not math.isnan(v) and not math.isinf(v):
                doubles.append(v)

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            doubles_file = Path(tmpdir) / "doubles.txt"
            node_out_file = Path(tmpdir) / "node_out.txt"
            script_file = Path(tmpdir) / "script.js"

            with open(doubles_file, "w") as f:
                for x in doubles:
                    f.write(repr(x) + "\n")

            with open(script_file, "w") as f:
                f.write("""const fs = require("fs");
const readline = require("readline");

const rl = readline.createInterface({
    input: fs.createReadStream(process.argv[2]),
    crlfDelay: Infinity
});

const out = fs.createWriteStream(process.argv[3]);
rl.on("line", (line) => {
    if (!line) return;
    const n = parseFloat(line);
    out.write(JSON.stringify(n) + "\\n");
});
rl.on("close", () => {
    out.end();
});
""")

            subprocess.run(["node", str(script_file), str(doubles_file), str(node_out_file)], check=True)
            import time

            time.sleep(0.5)

            with open(node_out_file, "r") as f_node:
                for idx, (x, node_line) in enumerate(zip(doubles, f_node)):
                    node_exp = node_line.strip()
                    py_act = canonicalize(x)
                    if py_act != node_exp:
                        self.fail(
                            f"200k doubles fuzz test failed with fixed seed {seed} at index {idx} "
                            f"for {x} (repr={repr(x)}): py={py_act} != node={node_exp}"
                        )
