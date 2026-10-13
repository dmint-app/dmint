"""Tests for Dmint deterministic resource matching engine (Phase 5)."""

from __future__ import annotations

import json
from pathlib import Path
import time
import unittest

from dmint.core.models import Decision, ToolRequest, TrustedContext
from dmint.core.policy import Policy, Rule
from dmint.core.resources import (
    ResourceKind,
    ResourceMatchingError,
    compile_path_pattern,
    match_host,
    match_identifier,
    match_path,
    match_resource,
    match_url,
    normalize_host,
    normalize_identifier,
    normalize_path,
    normalize_url,
    validate_resource_syntax,
)


class TestResourceMatching(unittest.TestCase):
    """Test suite for kind-specific resource normalization and matching."""

    def test_vectors_file(self) -> None:
        """Run all test vectors from tests/vectors/resource_matching.json."""
        vector_file = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "resource_matching.json"
        self.assertTrue(vector_file.exists(), f"Vector file {vector_file} does not exist")

        vectors = json.loads(vector_file.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(vectors), 50, "Vector file must have at least 50 test cases")

        for idx, vec in enumerate(vectors):
            name = vec.get("name", f"vector_{idx}")
            kind = vec["kind"]
            input_val = vec["input"]
            rule_val = vec["rule"]
            expected = vec["expected"]

            if expected == "invalid":
                # Must fail closed with ResourceMatchingError during syntax validation
                with self.assertRaises(
                    ResourceMatchingError,
                    msg=f"Vector '{name}' ({kind}) expected invalid syntax to raise ResourceMatchingError",
                ):
                    validate_resource_syntax(input_val, kind)
                # match_resource should also return False on invalid input
                self.assertFalse(
                    match_resource(rule_val, input_val, kind=kind),
                    f"Vector '{name}' ({kind}) match_resource must return False on invalid input",
                )
            else:
                result = match_resource(rule_val, input_val, kind=kind)
                self.assertEqual(
                    result,
                    expected,
                    f"Vector '{name}' ({kind}) failed: match_resource(rule={rule_val!r}, input={input_val!r}) "
                    f"expected {expected}, got {result}",
                )

    def test_path_posix_double_slash_quirk(self) -> None:
        """POSIX // quirk in posixpath.normpath must be handled securely."""
        self.assertEqual(normalize_path("//etc/passwd"), "/etc/passwd")
        self.assertEqual(normalize_path("///etc/passwd"), "/etc/passwd")
        self.assertEqual(normalize_path("////var//log///syslog/"), "/var/log/syslog")

    def test_path_normalization_resolves_dot_and_dot_dot(self) -> None:
        """Path normalization resolves '.' and '..' segments securely."""
        self.assertEqual(normalize_path("/var/log/../log/syslog"), "/var/log/syslog")
        self.assertEqual(normalize_path("/var/./log/./syslog"), "/var/log/syslog")
        self.assertEqual(normalize_path("/a/b/c/../../d"), "/a/d")

    def test_path_normalization_rejects_root_escape(self) -> None:
        """Paths that escape root must raise ResourceMatchingError."""
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/../etc/passwd")
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/../../etc/passwd")
        with self.assertRaises(ResourceMatchingError):
            normalize_path("../../escape")

    def test_path_normalization_rejects_nul_and_backslash(self) -> None:
        """NUL bytes and Windows backslashes must be strictly rejected."""
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/log/test\x00.log")
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var\\log\\test.log")

    def test_path_normalization_rejects_encoded_traversal(self) -> None:
        """Encoded path traversal tokens (%2f, %2e%2e) must be strictly rejected."""
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/%2f/log")
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/%2e%2e/etc/passwd")
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/%2E%2E/etc/passwd")

    def test_path_nfc_normalization(self) -> None:
        """Both sides of path matching must be NFC-normalized."""
        nfd_path = "/files/caf\u0065\u0301.txt"  # Decomposed 'e' + combining acute
        nfc_path = "/files/caf\u00e9.txt"  # Precomposed 'é'
        self.assertEqual(normalize_path(nfd_path), normalize_path(nfc_path))
        self.assertTrue(match_path(nfc_path, nfd_path))
        self.assertTrue(match_path(nfd_path, nfc_path))

    def test_path_case_insensitivity_option(self) -> None:
        """Explicit case-insensitive option allows case-folding for macOS/Windows filesystems."""
        # Default is strictly case-sensitive
        self.assertTrue(match_path("/var/log/App.log", "/var/log/App.log", case_sensitive=True))
        self.assertFalse(match_path("/var/log/App.log", "/var/log/app.log", case_sensitive=True))
        self.assertFalse(match_path("/etc/passwd", "/ETC/PASSWD", case_sensitive=True))

        # Explicit case-insensitive matching
        self.assertTrue(match_path("/etc/passwd", "/ETC/PASSWD", case_sensitive=False))
        self.assertTrue(match_path("/ETC/PASSWD", "/etc/passwd", case_sensitive=False))
        self.assertTrue(match_path("/var/log/*.log", "/VAR/LOG/APP.LOG", case_sensitive=False))

    def test_path_glob_single_star_does_not_cross_slash(self) -> None:
        """'*' matches within a single segment and never crosses slashes."""
        self.assertTrue(match_path("/var/log/*.log", "/var/log/app.log"))
        self.assertFalse(match_path("/var/log/*.log", "/var/log/nginx/access.log"))
        self.assertTrue(match_path("*.py", "main.py"))
        self.assertFalse(match_path("*.py", "src/main.py"))

    def test_path_glob_globstar_crosses_segments(self) -> None:
        """'**' matches zero or more segments across slashes."""
        self.assertTrue(match_path("/workspace/**", "/workspace"))
        self.assertTrue(match_path("/workspace/**", "/workspace/main.py"))
        self.assertTrue(match_path("/workspace/**", "/workspace/src/utils/helpers.py"))
        self.assertTrue(match_path("/workspace/**/*.py", "/workspace/main.py"))
        self.assertTrue(match_path("/workspace/**/*.py", "/workspace/src/test.py"))
        self.assertFalse(match_path("/workspace/**/*.py", "/workspace/main.txt"))
        self.assertTrue(match_path("/a/**/b", "/a/b"))
        self.assertTrue(match_path("/a/**/b", "/a/x/b"))
        self.assertTrue(match_path("/a/**/b", "/a/x/y/z/b"))
        self.assertFalse(match_path("/a/**/b", "/a/x/y/z/c"))

    def test_path_adversarial_timing_bound_5000_segments(self) -> None:
        """Adversarial pattern /a/**/b/**/c/**/d against 5000 segments must complete within 50ms."""
        pattern = "/a/**/b/**/c/**/d"
        # Construct an adversarial path with 5000 segments containing candidate segments
        middle_segments = ["segment"] * 4996
        adversarial_path = "/a/" + "/".join(middle_segments) + "/b/c/d"

        start_time = time.perf_counter()
        result = match_path(pattern, adversarial_path)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        self.assertTrue(result)
        self.assertLess(
            elapsed_ms,
            50.0,
            f"Adversarial path matching took {elapsed_ms:.2f}ms, exceeding 50ms bound",
        )

        # Mismatch path must also complete well under 50ms
        adversarial_mismatch = "/a/" + "/".join(middle_segments) + "/b/c/mismatch"
        start_time = time.perf_counter()
        result_mismatch = match_path(pattern, adversarial_mismatch)
        elapsed_mismatch_ms = (time.perf_counter() - start_time) * 1000.0

        self.assertFalse(result_mismatch)
        self.assertLess(
            elapsed_mismatch_ms,
            50.0,
            f"Adversarial mismatch path matching took {elapsed_mismatch_ms:.2f}ms, exceeding 50ms bound",
        )

    def test_url_userinfo_tricks_rejected(self) -> None:
        """URL userinfo tricks like @ and \\@ must fail closed."""
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://api.github.com@evil.com/")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://evil.com\\@github.com")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://user:pass@example.com/api")

    def test_url_non_http_schemes_fail_closed(self) -> None:
        """Non-http schemes must be rejected immediately."""
        with self.assertRaises(ResourceMatchingError):
            normalize_url("ftp://example.com/file")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("file:///etc/passwd")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("javascript:alert(1)")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("gopher://example.com/gopher")

    def test_url_trailing_dot_host_and_ipv6_and_punycode(self) -> None:
        """URL normalization handles trailing dot, IPv6 literals, and IDN punycode."""
        self.assertEqual(
            normalize_url("https://api.github.com./repos"),
            "https://api.github.com/repos",
        )
        self.assertEqual(
            normalize_url("http://[::1]:8080/api"),
            "http://[::1]:8080/api",
        )
        self.assertEqual(
            normalize_url("https://münchen.de/api"),
            "https://xn--mnchen-3ya.de/api",
        )

    def test_url_default_ports_and_case(self) -> None:
        """URL default ports 80/443 are stripped and schemes/hosts are case-insensitive."""
        self.assertEqual(
            normalize_url("HTTP://EXAMPLE.COM:80/path"),
            "http://example.com/path",
        )
        self.assertEqual(
            normalize_url("HTTPS://EXAMPLE.COM:443/path"),
            "https://example.com/path",
        )
        # Non-default port retained
        self.assertEqual(
            normalize_url("https://example.com:8443/path"),
            "https://example.com:8443/path",
        )

    def test_url_encoded_traversal_rejected(self) -> None:
        """URL paths with encoded traversal (%2f, %2e%2e) must be rejected."""
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://api.github.com/%2e%2e/admin")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://api.github.com/%2f/admin")

    def test_identifier_rejects_leading_and_trailing_whitespace(self) -> None:
        """Identifier normalization must reject leading/trailing whitespace rather than stripping."""
        with self.assertRaises(ResourceMatchingError):
            normalize_identifier("  user_123")
        with self.assertRaises(ResourceMatchingError):
            normalize_identifier("user_123  ")
        with self.assertRaises(ResourceMatchingError):
            normalize_identifier(" user_123 ")
        self.assertEqual(normalize_identifier("user_123"), "user_123")

    def test_identifier_wildcard_character_set(self) -> None:
        """Identifier wildcard '*' strictly matches alphanumeric plus '_', '-', '.'."""
        self.assertTrue(match_identifier("user_*", "user_123"))
        self.assertTrue(match_identifier("user_*", "user_abc-def.ghi"))
        self.assertFalse(match_identifier("user_*", "user_@evil"))
        self.assertFalse(match_identifier("user_*", "user_/evil"))
        self.assertFalse(match_identifier("user_*", "user_ evil"))

    def test_policy_evaluator_fails_closed_on_unnormalizable_resource_before_matching(self) -> None:
        """DENY /etc/passwd + ALLOW * must return DENY before rule matching for unnormalizable input."""
        policy = Policy(
            [
                Rule.deny("fs", "read", resource="/etc/passwd", resource_kind="path"),
                Rule.allow("fs", "read", resource="*"),
            ]
        )

        def make_req(res: str) -> ToolRequest:
            return ToolRequest(
                request_id="req_0123456789abcdef0123456789abcdef01234567890",
                agent_id="test-agent",
                tool="fs",
                action="read",
                resource=res,
                arguments={},
                context=TrustedContext.from_mapping({}),
            )

        # Normal valid input matching ALLOW *
        self.assertEqual(policy.evaluate(make_req("/workspace/main.py")), Decision.ALLOW)

        # Unnormalizable inputs: root escape, NUL byte, backslash
        # Each must evaluate to DENY immediately with DMT_RESOURCE_INVALID!
        for invalid_res in (
            "/../etc/passwd",
            "/etc/passwd\x00",
            "/etc\\passwd",
            "/var/%2f/passwd",
            "/var/%2e%2e/passwd",
            "/var/%2E%2E/passwd",
            "/var/%252e%252e/passwd",
        ):
            dec, code = policy.evaluate_detailed(make_req(invalid_res))
            self.assertEqual(dec, Decision.DENY)
            self.assertEqual(code, "DMT_RESOURCE_INVALID")

    def test_evaluator_never_calls_unchecked_matcher_with_unvalidated_input(self) -> None:
        """Prove that the evaluator fails closed on invalid input before calling unchecked helpers."""
        from unittest.mock import patch

        policy = Policy(
            [
                Rule.deny("fs", "read", resource="/etc/passwd", resource_kind="path"),
                Rule.allow("fs", "read", resource="*"),
            ]
        )
        req = ToolRequest(
            request_id="req_0123456789abcdef0123456789abcdef01234567890",
            agent_id="test-agent",
            tool="fs",
            action="read",
            resource="/../etc/passwd",
            arguments={},
            context=TrustedContext.from_mapping({}),
        )

        with patch("dmint.core.resources._match_path_unchecked") as mock_match:
            decision, code = policy.evaluate_detailed(req)
            self.assertEqual(decision, Decision.DENY)
            self.assertEqual(code, "DMT_RESOURCE_INVALID")
            mock_match.assert_not_called()

    def test_url_wildcard_against_evil_subdomains_and_hyphens(self) -> None:
        """Verify *.github.com does not match evil-github.com or github.com.evil.com."""
        self.assertFalse(match_url("https://*.github.com/repos", "https://evil-github.com/repos"))
        self.assertFalse(match_url("https://*.github.com/repos", "https://github.com.evil.com/repos"))
        self.assertFalse(match_host("*.github.com", "evil-github.com"))
        self.assertFalse(match_host("*.github.com", "github.com.evil.com"))
        self.assertTrue(match_url("https://*.github.com/repos", "https://api.github.com/repos"))
        self.assertTrue(match_host("*.github.com", "api.github.com"))

    def test_double_encoded_and_uppercase_traversal(self) -> None:
        """Verify double-encoded %252e%252e and uppercase %2E%2E raise ResourceMatchingError."""
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/%252e%252e/etc/passwd")
        with self.assertRaises(ResourceMatchingError):
            normalize_path("/var/%2E%2E/etc/passwd")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://api.github.com/%252e%252e/admin")
        with self.assertRaises(ResourceMatchingError):
            normalize_url("https://api.github.com/%2E%2E/admin")

    def test_ipv4_and_ipv6_zone_ids(self) -> None:
        """Verify IPv4 host matching and IPv6 zone ID handling."""
        self.assertTrue(match_host("192.168.1.1", "192.168.1.1"))
        self.assertFalse(match_host("192.168.1.1", "192.168.1.2"))
        self.assertFalse(match_host("192.168.1.1", "evil.192.168.1.1.com"))
        self.assertTrue(match_url("http://192.168.1.1/api", "http://192.168.1.1/api"))
        self.assertTrue(match_host("[fe80::1%eth0]", "[fe80::1%eth0]"))
        self.assertTrue(match_url("http://[fe80::1%eth0]/api", "http://[fe80::1%eth0]/api"))

    def test_empty_string_resource_fails_closed(self) -> None:
        """Verify empty string resources raise ResourceMatchingError and fail closed."""
        for kind in ("path", "url", "host", "identifier"):
            with self.assertRaises(ResourceMatchingError):
                validate_resource_syntax("", kind=kind)
            self.assertFalse(match_resource("dummy", "", kind=kind))

    def test_host_normalization_rejects_empty_labels_and_repeated_dots(self) -> None:
        """Reject empty labels and repeated trailing dots as ResourceMatchingError / DMT_RESOURCE_INVALID."""
        invalid_hosts = [
            "zt8ggjag8bj..",
            "api.github.com..",
            "example.com...",
            "api..github.com",
            ".api.github.com",
            ".",
            "..",
            "...",
            "foo..bar.com",
            "https://api.github.com../path",
            "https://api..github.com/path",
        ]
        for bad in invalid_hosts:
            if "://" in bad:
                with self.assertRaises(ResourceMatchingError):
                    normalize_url(bad)
            else:
                with self.assertRaises(ResourceMatchingError):
                    normalize_host(bad)

        # Policy evaluation fails closed with DMT_RESOURCE_INVALID
        policy = Policy([Rule.allow("api", "call", resource="*.github.com", resource_kind="host")])
        req_bad = ToolRequest(
            request_id="req-1",
            agent_id="test-agent",
            tool="api",
            action="call",
            resource="api.github.com..",
            arguments={},
            context=TrustedContext({}),
        )
        dec, code = policy.evaluate_detailed(req_bad)
        self.assertEqual(dec, Decision.DENY)
        self.assertEqual(code, "DMT_RESOURCE_INVALID")

    def test_host_normalization_idempotence(self) -> None:
        """normalize(normalize(x)) == normalize(x) for every accepted input."""
        accepted_hosts = [
            "api.github.com",
            "api.github.com.",  # single trailing dot (DNS canonicalization)
            "GITHUB.COM",
            "localhost",
            "127.0.0.1",
            "192.168.1.1:8080",
            "[::1]",
            "[::1]:8080",
            "sub.domain.co.uk",
            "sub.domain.co.uk.",
            "xn--bcher-kva.example",
            "bücher.example",
        ]
        for host in accepted_hosts:
            norm1 = normalize_host(host)
            norm2 = normalize_host(norm1)
            self.assertEqual(norm1, norm2, f"Idempotence violated for {host}: {norm1} != {norm2}")

    def test_resource_fuzz_classification_counts(self) -> None:
        """Fuzz test ensuring every iteration is classified as valid, rejected, or error and counts sum to total."""
        import random
        import string

        rng = random.Random(42)
        total_per_kind = 1000
        chars = string.ascii_letters + string.digits + "./:@_-%" + "\x00\r\n"

        for kind, norm_fn in [
            ("host", normalize_host),
            ("path", normalize_path),
            ("url", normalize_url),
            ("identifier", normalize_identifier),
        ]:
            valid_count = 0
            rejected_count = 0
            error_count = 0

            for i in range(total_per_kind):
                if i % 2 == 0:
                    if kind == "host":
                        base = f"sub{rng.randint(1, 100)}.domain{rng.randint(1, 50)}.org"
                    elif kind == "path":
                        base = f"/var/log/app_{rng.randint(1, 50)}.log"
                    elif kind == "url":
                        base = f"https://api{rng.randint(1, 50)}.service.io/v1/items"
                    else:
                        base = f"user_action_{rng.randint(1, 50)}"

                    if rng.random() < 0.3:
                        noise = "".join(rng.choice(chars) for _ in range(rng.randint(1, 5)))
                        raw = base + noise
                    else:
                        raw = base
                else:
                    length = rng.randint(0, 100)
                    raw = "".join(rng.choice(chars) for _ in range(length))
                    if rng.random() < 0.2:
                        raw += ".."

                try:
                    norm = norm_fn(raw)
                    self.assertEqual(norm_fn(norm), norm)
                    valid_count += 1
                except ResourceMatchingError:
                    rejected_count += 1
                except Exception:
                    error_count += 1

            self.assertEqual(
                valid_count + rejected_count + error_count,
                total_per_kind,
                f"Classification count mismatch for kind '{kind}'",
            )
            self.assertEqual(error_count, 0, f"Unexpected unhandled error for kind '{kind}'")
            self.assertGreater(valid_count, 0, f"Expected at least some valid inputs for kind '{kind}'")
            self.assertGreater(rejected_count, 0, f"Expected rejected inputs for kind '{kind}'")


if __name__ == "__main__":
    unittest.main()
