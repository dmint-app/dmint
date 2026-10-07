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


def _serialize_number(val: int | float) -> str:
    """Serialize an integer or float per RFC 8785 Section 3.2.2.3 and ECMAScript 7.1.12.1.

    Rules:
      - Integers must be within IEEE 754 safe integer range [-2^53 + 1, 2^53 - 1].
      - Floats must be finite (no NaN, +Infinity, -Infinity).
      - Zero and negative zero are serialized as '0'.
      - Floats follow ECMAScript ToString() rules.
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
    if f < 0.0:
        return "-" + _serialize_number(-f)

    stringified = str(f)
    exponent_str = ""
    exponent_value = 0
    q = stringified.find("e")
    if q > 0:
        exponent_str = stringified[q:]
        if exponent_str[2:3] == "0":
            exponent_str = exponent_str[:2] + exponent_str[3:]
        stringified = stringified[:q]
        exponent_value = int(exponent_str[1:])

    dot = ""
    last = ""
    q = stringified.find(".")
    if q > 0:
        dot = "."
        first = stringified[:q]
        last = stringified[q + 1 :]
    else:
        first = stringified

    if last == "0":
        dot = ""
        last = ""

    if 0 < exponent_value < 21:
        first += last
        last = ""
        dot = ""
        exponent_str = ""
        q = exponent_value - len(first)
        while q >= 0:
            q -= 1
            first += "0"
    elif -7 < exponent_value < 0:
        last = first + last
        first = "0"
        dot = "."
        exponent_str = ""
        q = exponent_value
        while q < -1:
            q += 1
            last = "0" + last

    return f"{first}{dot}{last}{exponent_str}"


def canonicalize(value: Any) -> str:
    """Serialize JSON-compatible data deterministically per RFC 8785 (JCS).

    Guarantees:
      - Object keys sorted lexicographically by UTF-16 code units.
      - Numbers formatted per ECMAScript 7.1.12.1 ToString with safe integer validation.
      - Strings escaped strictly per RFC 8785 (no unnecessary non-ASCII escapes).
      - Whitespace completely eliminated.
      - Rejects non-string object keys, non-finite floats, non-safe integers, and unhandled types.
    """
    return _canonicalize_value(value)


def canonicalize_bytes(value: Any) -> bytes:
    """Return RFC 8785 canonical bytes encoded as UTF-8."""
    return canonicalize(value).encode("utf-8")


def _canonicalize_value(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if type(value) is str:
        return _serialize_str(value)
    if isinstance(value, (list, tuple)):
        items = [_canonicalize_value(item) for item in value]
        return "[" + ",".join(items) + "]"
    if isinstance(value, (dict, Mapping, MappingProxyType)):
        sorted_pairs = []
        for k, v in value.items():
            if type(k) is not str:
                raise CanonicalizationError("object keys must be strings")
            sorted_pairs.append((k, v))
        sorted_pairs.sort(key=lambda pair: utf16_sort_key(pair[0]))
        members = [f"{_serialize_str(k)}:{_canonicalize_value(v)}" for k, v in sorted_pairs]
        return "{" + ",".join(members) + "}"
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
    return canonicalize(value)


def canonicalize_request(request: Any) -> str:
    """Canonicalize every security-relevant field of a tool request."""
    from .models import ToolRequest

    if type(request) is not ToolRequest:
        raise CanonicalizationError("expected a ToolRequest")
    return canonicalize(
        {
            "action": request.action,
            "agent_id": request.agent_id,
            "arguments": request.arguments,
            "context": request.context.values,
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
