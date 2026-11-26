"""Deterministic generative and property tests for canonicalization and resource normalization.

The corpus is seeded so failures are reproducible.  ``hypothesis`` is used when
it is installed; the built-in PRNG corpus always runs and does not depend on it.
"""

from __future__ import annotations

import json
import math
import random
import struct
import unittest
from typing import Any, Callable

import rfc8785

from dmint.core.canonicalize import canonicalize
from dmint.core.errors import CanonicalizationError
from dmint.core.resources import (
    ResourceMatchingError,
    normalize_host,
    normalize_identifier,
    normalize_path,
    normalize_url,
)

try:  # pragma: no cover - exercised only when the optional dependency is present
    from hypothesis import given, settings
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover - default development environment
    HAS_HYPOTHESIS = False


SAFE_INT_MAX = 2**53 - 1
SAFE_INT_MIN = -(2**53 - 1)

_STRING_ALPHABET = "abcXYZ0123456789 _-./:@?&=#%\\\x00\x01\x1f\b\t\n\f\r\"'éñ漢字🚀\ue000\U00010000\U0001f680"
_KEY_ALPHABET = "abcXYZ0123456789_-./ \u0000é漢🚀\ue000\U00010000"

_FLOAT_POOL = [
    0.0,
    -0.0,
    1.0,
    -1.0,
    1.5,
    1e-7,
    1e-6,
    1e20,
    1e21,
    1e22,
    5e-324,
    2.2250738585072014e-308,
    1.7976931348623157e308,
    0.1 + 0.2,
]


def _random_string(rng: random.Random, *, alphabet: str = _STRING_ALPHABET, max_length: int = 12) -> str:
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_length)))


def _random_float(rng: random.Random) -> float:
    if rng.random() < 0.5:
        return rng.choice(_FLOAT_POOL)
    while True:
        value = struct.unpack(">d", struct.pack(">Q", rng.getrandbits(64)))[0]
        if math.isfinite(value):
            return value


def _random_json(rng: random.Random, depth: int = 0) -> Any:
    if depth >= 4:
        kind = rng.choice(["none", "bool", "int", "float", "str"])
    else:
        kind = rng.choice(["none", "bool", "int", "float", "str", "list", "dict"])

    if kind == "none":
        return None
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "int":
        return rng.randint(SAFE_INT_MIN, SAFE_INT_MAX)
    if kind == "float":
        return _random_float(rng)
    if kind == "str":
        return _random_string(rng)
    if kind == "list":
        return [_random_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]

    result: dict[str, Any] = {}
    for _ in range(rng.randint(0, 4)):
        result[_random_string(rng, alphabet=_KEY_ALPHABET, max_length=10)] = _random_json(rng, depth + 1)
    return result


def _reverse_dicts(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _reverse_dicts(item) for key, item in reversed(list(value.items()))}
    if isinstance(value, list):
        return [_reverse_dicts(item) for item in value]
    return value


def _build_corpus(seed: int = 20261124, count: int = 600) -> list[Any]:
    rng = random.Random(seed)
    corpus: list[Any] = []
    for _ in range(count):
        corpus.append(_random_json(rng))
    return corpus


def _mutate(rng: random.Random, base: str, *, max_mutations: int = 4) -> str:
    value = base
    for _ in range(rng.randint(1, max_mutations)):
        operation = rng.choice(["insert", "delete", "replace", "swap"])
        if operation == "insert" or not value:
            index = rng.randint(0, len(value))
            value = value[:index] + rng.choice(_STRING_ALPHABET) + value[index:]
        elif operation == "delete":
            index = rng.randrange(len(value))
            value = value[:index] + value[index + 1 :]
        elif operation == "replace":
            index = rng.randrange(len(value))
            value = value[:index] + rng.choice(_STRING_ALPHABET) + value[index + 1 :]
        else:
            if len(value) >= 2:
                index = rng.randrange(len(value) - 1)
                value = value[:index] + value[index + 1] + value[index] + value[index + 2 :]
    return value


class CanonicalizerPropertyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = _build_corpus()

    def test_seeded_corpus_is_key_order_independent(self):
        rng = random.Random(424242)
        for value in self.corpus:
            reordered = _reverse_dicts(value)
            if rng.random() < 0.5:
                reordered = _reverse_dicts(reordered)
            self.assertEqual(canonicalize(value), canonicalize(reordered))

    def test_seeded_corpus_is_idempotent_through_json_round_trip(self):
        for value in self.corpus:
            canonical = canonicalize(value)
            # JSON.parse treats every number as an IEEE 754 double.  Python's
            # json.loads would instead turn large integer tokens (e.g. 1e20)
            # into arbitrary-precision ints, which the safe-integer guard
            # intentionally rejects.  parse_int=float mirrors ECMAScript.
            reparsed = json.loads(canonical, parse_int=float)
            self.assertEqual(canonicalize(reparsed), canonical, repr(value))

        safe_payloads = [
            {"a": 1, "b": [True, None, "x"], "c": {"d": -(2**53 - 1)}},
            {"floats": [0.0, -0.0, 1.5, 1e-7, 1e-6]},
        ]
        for payload in safe_payloads:
            self.assertEqual(canonicalize(json.loads(canonicalize(payload))), canonicalize(payload))

    def test_seeded_corpus_matches_rfc8785_reference_implementation(self):
        for value in self.corpus:
            self.assertEqual(
                canonicalize(value).encode("utf-8"),
                rfc8785.dumps(value),
                repr(value),
            )

    def test_surrogate_pair_sorting_and_equal_prefix_keys(self):
        astral = "\U00010000"  # UTF-16 D800 DC00
        bmp = "\ue000"  # UTF-16 E000
        self.assertEqual(canonicalize({bmp: 1, astral: 2}), f'{{"{astral}":2,"{bmp}":1}}')

        equal_prefix = {"a": 1, "ab": 2, "a\x00": 3, "a\U00010000": 4}
        expected = '{"a":1,"a\\u0000":3,"ab":2,"a\U00010000":4}'
        self.assertEqual(canonicalize(equal_prefix), expected)
        self.assertEqual(rfc8785.dumps(equal_prefix).decode("utf-8"), expected)

    def test_host_rejects_control_characters_exposed_by_trailing_dot(self):
        with self.assertRaises(ResourceMatchingError):
            normalize_host("API.Exapm&e.COM\x1f.")
        with self.assertRaises(ResourceMatchingError):
            normalize_host("api.example.com\x1f")

    def test_lone_surrogates_are_rejected_with_canonicalization_error(self):
        for value in ["\ud800", "\udfff", "x\ud800y", {"\ud800": 1}, ["\udc00"]]:
            with self.assertRaises(CanonicalizationError):
                canonicalize(value)

    def test_depth_size_and_cycle_violations_fail_closed(self):
        deep: Any = {}
        cursor = deep
        for _ in range(120):
            child: dict[str, Any] = {}
            cursor["nested"] = child
            cursor = child
        with self.assertRaises(CanonicalizationError):
            canonicalize(deep)

        with self.assertRaises(CanonicalizationError):
            canonicalize({"payload": "x" * 512}, max_bytes=64)

        cyclic: list[Any] = []
        cyclic.append(cyclic)
        with self.assertRaises(CanonicalizationError):
            canonicalize(cyclic)


class ResourceNormalizerPropertyTests(unittest.TestCase):
    BASES: dict[str, list[str]] = {
        "path": [
            "/",
            "/a/b/c",
            "/a/./b/../c/",
            "a/b/c",
            ".",
            "./a//b/",
            "/var/log/app.log",
            "/tmp/100%_complete",
            "/data/éñ漢字",
            "a\\b",
            "/a/%2e%2e/b",
        ],
        "url": [
            "https://example.com/",
            "HTTP://Example.COM:80/a/../b?q=1#frag",
            "https://example.com:443/path/",
            "https://sub.example.com:8443/a//b/../c",
            "http://[::1]:8080/x",
            "https://例え.テスト/パス",
            "https://example.com/a?x=1&y=2",
            "ftp://example.com/file",
            "https://user:pass@example.com/",
            "https://example.com/%2e%2e/secret",
        ],
        "host": [
            "example.com",
            "API.Example.COM.",
            "api.example.com:443",
            "[::1]",
            "[::1]:8443",
            "例え.テスト",
            "bad host",
            "user@example.com",
            "example.com/path",
            "example..com",
        ],
        "identifier": [
            "user_123",
            "ns:service:action",
            " service:api",
            "service:api ",
            "a\x00b",
            "",
            "éñ漢字",
            "-" * 10,
            "a.b/c",
            "UPPER_lower-123",
        ],
    }

    def _assert_only_resource_errors(
        self,
        name: str,
        normalizer: Callable[[str], str],
        inputs: list[str],
    ) -> tuple[int, int]:
        normalized_count = 0
        rejected_count = 0
        for raw in inputs:
            try:
                first = normalizer(raw)
            except ResourceMatchingError:
                rejected_count += 1
                continue
            except Exception as exc:  # noqa: BLE001 - the assertion is the point
                self.fail(f"{name} raised {type(exc).__name__} for {raw!r}: {exc}")
            else:
                normalized_count += 1
                try:
                    second = normalizer(first)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"{name} was not idempotent for {raw!r}: second call raised {exc!r}")
                self.assertEqual(second, first, f"{name} is not idempotent for {raw!r}")
        return normalized_count, rejected_count

    def test_known_normalizations(self):
        self.assertEqual(normalize_path("/a/b/../c//d/"), "/a/c/d")
        self.assertEqual(normalize_path("a/./b"), "a/b")
        self.assertEqual(normalize_path("."), ".")
        self.assertEqual(normalize_url("HTTP://Example.COM:80/a/../b?q=1"), "http://example.com/b?q=1")
        self.assertEqual(normalize_url("https://example.com:443/"), "https://example.com/")
        self.assertEqual(normalize_host("API.Example.COM.:443"), "api.example.com:443")
        self.assertEqual(normalize_identifier("ns:service:action"), "ns:service:action")

    def test_mutated_paths_normalize_idempotently_or_fail_closed(self):
        rng = random.Random(1001)
        inputs = []
        for base in self.BASES["path"]:
            for _ in range(60):
                inputs.append(_mutate(rng, base))
        normalized, rejected = self._assert_only_resource_errors("normalize_path", normalize_path, inputs)
        self.assertGreater(normalized, 0)
        self.assertGreater(rejected, 0)

    def test_mutated_urls_normalize_idempotently_or_fail_closed(self):
        rng = random.Random(1002)
        inputs = []
        for base in self.BASES["url"]:
            for _ in range(60):
                inputs.append(_mutate(rng, base))
        normalized, rejected = self._assert_only_resource_errors("normalize_url", normalize_url, inputs)
        self.assertGreater(normalized, 0)
        self.assertGreater(rejected, 0)

    def test_mutated_hosts_normalize_idempotently_or_fail_closed(self):
        rng = random.Random(1003)
        inputs = []
        for base in self.BASES["host"]:
            for _ in range(60):
                inputs.append(_mutate(rng, base))
        normalized, rejected = self._assert_only_resource_errors("normalize_host", normalize_host, inputs)
        self.assertGreater(normalized, 0)
        self.assertGreater(rejected, 0)

    def test_mutated_identifiers_normalize_idempotently_or_fail_closed(self):
        rng = random.Random(1004)
        inputs = []
        for base in self.BASES["identifier"]:
            for _ in range(60):
                inputs.append(_mutate(rng, base))
        normalized, rejected = self._assert_only_resource_errors("normalize_identifier", normalize_identifier, inputs)
        self.assertGreater(normalized, 0)
        self.assertGreater(rejected, 0)


if HAS_HYPOTHESIS:  # pragma: no cover - only runs when hypothesis is installed

    class HypothesisParityTests(unittest.TestCase):
        @settings(max_examples=200, derandomize=True, deadline=None)
        @given(
            st.recursive(
                st.one_of(
                    st.none(),
                    st.booleans(),
                    st.integers(min_value=SAFE_INT_MIN, max_value=SAFE_INT_MAX),
                    st.floats(allow_nan=False, allow_infinity=False),
                    st.text(),
                ),
                lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4),
                max_leaves=25,
            )
        )
        def test_canonicalize_matches_rfc8785(self, value):
            self.assertEqual(canonicalize(value).encode("utf-8"), rfc8785.dumps(value))
