"""Canonical JSON handling for security-relevant request data per RFC 8785 (JCS)."""

from __future__ import annotations

import math
import re
from collections.abc import Collection, Mapping
from types import MappingProxyType
from typing import Any

from .errors import CanonicalizationError


MAX_SAFE_INTEGER: int = 2**53 - 1
MIN_SAFE_INTEGER: int = -(2**53 - 1)
MAX_CANONICAL_DEPTH: int = 100
MAX_CANONICAL_BYTES: int = 10 * 1024 * 1024  # 10 MB

# Escape table per RFC 8785 Section 3.2.2.2:
# Only characters U+0000 through U+001F, quote (\"), and backslash (\\) are escaped.
_ESCAPE = re.compile(r'[\x00-\x1f\\"\b\f\n\r\t]')
_ESCAPE_MAP = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}
for _i in range(0x20):
    _ESCAPE_MAP.setdefault(chr(_i), f"\\u{_i:04x}")


def utf16_sort_key(s: str) -> bytes:
    """Return the UTF-16 big-endian code unit sort key for RFC 8785 key ordering.

    RFC 8785 Section 3.2.3 requires sorting keys lexicographically by their
    UTF-16 code units (16-bit unsigned integers). In Python, big-endian UTF-16
    bytes comparison precisely matches 16-bit unsigned integer ordering.
    """
    return s.encode("utf-16be")


def _serialize_str(s: str) -> str:
    """Serialize a string per RFC 8785 Section 3.2.2.2."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("string contains invalid Unicode (lone surrogates)") from exc

    def _replace(match: re.Match[str]) -> str:
        return _ESCAPE_MAP[match.group(0)]

    return f'"{_ESCAPE.sub(_replace, s)}"'


import decimal


def _serialize_number(val: int | float) -> str:
    """Serialize an integer or float per RFC 8785 Section 3.2.2.3 and ECMAScript 7.1.12.1.

    Rules:
      - Integers must be within IEEE 754 safe integer range [-2^53 + 1, 2^53 - 1].
      - Floats must be finite (no NaN, +Infinity, -Infinity).
      - Zero and negative zero are serialized as '0'.
      - Direct ECMAScript Number::toString implementation: shortest round-trip
        digit string s from repr(val) (via decimal.Decimal(repr(val)).as_tuple(),
        no float formatting with fixed precision), k = len(s),
        n = decimal point position (value = 0.s * 10^n).
    """
    if type(val) is int:
        if val < MIN_SAFE_INTEGER or val > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer {val} exceeds safe integer domain [-2^53+1, 2^53-1]")
        return str(val)

    f = float(val)
    if math.isnan(f) or math.isinf(f):
        raise CanonicalizationError(f"non-finite number {f} cannot be canonicalized")
    if f == 0.0:
        return "0"

    prefix = ""
    if f < 0.0:
        prefix = "-"
        f = -f

    d = decimal.Decimal(repr(f)).normalize().as_tuple()
    s = "".join(str(digit) for digit in d.digits)
    k = len(s)
    exp = int(d.exponent) if isinstance(d.exponent, int) else 0
    n = exp + k

    if k <= n <= 21:
        res = s + "0" * (n - k)
    elif 0 < n <= 21:
        res = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        res = "0." + "0" * (-n) + s
    else:
        e = n - 1
        sign = "+" if e >= 0 else "-"
        if k == 1:
            res = s + "e" + sign + str(abs(e))
        else:
            res = s[0] + "." + s[1:] + "e" + sign + str(abs(e))

    return prefix + res


def canonicalize(
    value: Any,
    *,
    max_depth: int = MAX_CANONICAL_DEPTH,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> str:
    """Serialize JSON-compatible data deterministically per RFC 8785 (JCS).

    Guarantees:
      - Object keys sorted lexicographically by UTF-16 code units.
      - Numbers formatted per ECMAScript 7.1.12.1 ToString with safe integer validation.
      - Strings escaped strictly per RFC 8785 (no unnecessary non-ASCII escapes).
      - Whitespace completely eliminated.
      - Only JSON-native Python types accepted: dict, list, str, bool, int, float, None.
      - Tuples, custom Mappings, and other non-JSON types are strictly rejected.
      - Depth limit, total size limit, and cyclic references fail closed with CanonicalizationError.
    """
    seen_ids: set[int] = set()
    size_counter: list[int] = [0]
    return _canonicalize_value(
        value,
        depth=0,
        max_depth=max_depth,
        max_bytes=max_bytes,
        seen_ids=seen_ids,
        size_counter=size_counter,
    )


def canonicalize_bytes(
    value: Any,
    *,
    max_depth: int = MAX_CANONICAL_DEPTH,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> bytes:
    """Return RFC 8785 canonical bytes encoded as UTF-8."""
    return canonicalize(value, max_depth=max_depth, max_bytes=max_bytes).encode("utf-8")


def _canonicalize_value(
    value: Any,
    depth: int,
    max_depth: int,
    max_bytes: int,
    seen_ids: set[int],
    size_counter: list[int],
) -> str:
    if depth > max_depth:
        raise CanonicalizationError(f"maximum nesting depth of {max_depth} exceeded")

    if value is None:
        size_counter[0] += 4
        if size_counter[0] > max_bytes:
            raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")
        return "null"

    if type(value) is bool:
        s = "true" if value else "false"
        size_counter[0] += len(s)
        if size_counter[0] > max_bytes:
            raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")
        return s

    if type(value) in (int, float):
        s = _serialize_number(value)
        size_counter[0] += len(s)
        if size_counter[0] > max_bytes:
            raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")
        return s

    if type(value) is str:
        s = _serialize_str(value)
        size_counter[0] += len(s)
        if size_counter[0] > max_bytes:
            raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")
        return s

    if type(value) is list:
        val_id = id(value)
        if val_id in seen_ids:
            raise CanonicalizationError("circular reference detected in list structure")
        seen_ids.add(val_id)
        try:
            # '[' and ']' + commas
            structural = 2 + (len(value) - 1 if value else 0)
            size_counter[0] += structural
            if size_counter[0] > max_bytes:
                raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")
            items = [
                _canonicalize_value(
                    item,
                    depth + 1,
                    max_depth,
                    max_bytes,
                    seen_ids,
                    size_counter,
                )
                for item in value
            ]
            return "[" + ",".join(items) + "]"
        finally:
            seen_ids.remove(val_id)

    if type(value) is dict:
        val_id = id(value)
        if val_id in seen_ids:
            raise CanonicalizationError("circular reference detected in dict structure")
        seen_ids.add(val_id)
        try:
            sorted_pairs = []
            for k, v in value.items():
                if type(k) is not str:
                    raise CanonicalizationError("object keys must be strings")
                try:
                    k.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise CanonicalizationError("object key contains invalid Unicode (lone surrogates)") from exc
                sorted_pairs.append((k, v))
            sorted_pairs.sort(key=lambda pair: utf16_sort_key(pair[0]))

            # '{' and '}' + colons + commas
            structural = 2 + len(sorted_pairs) + (len(sorted_pairs) - 1 if sorted_pairs else 0)
            size_counter[0] += structural
            if size_counter[0] > max_bytes:
                raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")

            members = []
            for k, v in sorted_pairs:
                key_str = _serialize_str(k)
                size_counter[0] += len(key_str)
                if size_counter[0] > max_bytes:
                    raise CanonicalizationError(f"maximum canonical size of {max_bytes} bytes exceeded")
                val_str = _canonicalize_value(
                    v,
                    depth + 1,
                    max_depth,
                    max_bytes,
                    seen_ids,
                    size_counter,
                )
                members.append(f"{key_str}:{val_str}")
            return "{" + ",".join(members) + "}"
        finally:
            seen_ids.remove(val_id)

    raise CanonicalizationError(f"unsupported value type for canonicalization: {type(value).__name__}")


def freeze_json(value: Any, path: str = "value") -> Any:
    """Create an immutable snapshot of JSON-compatible data."""
    if type(value) is dict:
        return MappingProxyType({key: freeze_json(item, f"{path}.{key}") for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze_json(item, f"{path}[{index}]") for index, item in enumerate(value))
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise CanonicalizationError(f"unsupported value type at {path}")


def thaw_json(value: Any) -> Any:
    """Convert an immutable request snapshot into execution arguments."""
    if isinstance(value, (Mapping, MappingProxyType)):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def canonicalize_frozen(value: Any) -> str:
    """Canonicalize Dmint's internal immutable representation."""
    return canonicalize(thaw_json(value))


def canonicalize_request(request: Any) -> str:
    """Canonicalize every security-relevant field of a tool request."""
    from .models import ToolRequest

    if type(request) is not ToolRequest:
        raise CanonicalizationError("expected a ToolRequest")
    return canonicalize(
        {
            "action": request.action,
            "agent_id": request.agent_id,
            "arguments": thaw_json(request.arguments),
            "context": thaw_json(request.context.values),
            "request_id": request.request_id,
            "resource": request.resource,
            "tool": request.tool,
        }
    )


DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "private_key",
        "ssn",
    }
)


def redact_sensitive_data(
    value: Any,
    redact_keys: Collection[str] = DEFAULT_SENSITIVE_KEYS,
) -> Any:
    """Return a copy of data with sensitive keys recursively replaced by '[REDACTED]'."""

    if isinstance(value, (Mapping, MappingProxyType)):
        redacted = {}
        for k, v in value.items():
            if isinstance(k, str) and any(sk in k.lower() for sk in redact_keys):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_data(v, redact_keys)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_sensitive_data(item, redact_keys) for item in value]
    return value
