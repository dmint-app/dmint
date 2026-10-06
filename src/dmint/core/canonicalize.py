"""Canonical JSON handling for security-relevant request data."""

from __future__ import annotations

import json
import math
from collections.abc import Collection, Mapping
from types import MappingProxyType
from typing import Any

from .errors import CanonicalizationError


MAX_SAFE_INTEGER = 2**53 - 1


def _normalise(value: Any, path: str = "value", *, allow_frozen: bool = False) -> Any:
    """Return a JSON-compatible value after strict type validation."""

    if allow_frozen and isinstance(value, MappingProxyType):
        return {key: _normalise(item, f"{path}.{key}", allow_frozen=True) for key, item in value.items()}
    if allow_frozen and type(value) is tuple:
        return [_normalise(item, f"{path}[{index}]", allow_frozen=True) for index, item in enumerate(value)]
    if value is None or type(value) is str or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer out of range at {path}")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise CanonicalizationError(f"non-finite number at {path}")
        if value.is_integer() or math.copysign(1.0, value) == -1.0:
            raise CanonicalizationError(
                f"ambiguous numeric representation at {path}: float with integer value or negative zero"
            )
        return value
    if type(value) is dict:
        normalised: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalizationError(f"non-string object key at {path}")
            normalised[key] = _normalise(item, f"{path}.{key}", allow_frozen=allow_frozen)
        return normalised
    if type(value) is list:
        return [_normalise(item, f"{path}[{index}]", allow_frozen=allow_frozen) for index, item in enumerate(value)]
    raise CanonicalizationError(f"unsupported value type at {path}")


def freeze_json(value: Any, path: str = "value") -> Any:
    """Create an immutable snapshot of JSON-compatible data."""

    normalised = _normalise(value, path)
    return _freeze_normalised(normalised, path)


def _freeze_normalised(value: Any, path: str) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_normalised(item, f"{path}.{key}") for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_normalised(item, f"{path}[{index}]") for index, item in enumerate(value))
    return value


def thaw_json(value: Any) -> Any:
    """Convert an immutable request snapshot into execution arguments."""

    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def canonicalize(value: Any) -> str:
    """Serialize JSON-compatible data deterministically.

    Object keys are sorted by Unicode code point, all non-ASCII characters are
    escaped, and non-finite numbers and non-string object keys are rejected.
    Only JSON-native Python values are accepted: ``dict``, ``list``, strings,
    booleans, safe-range integers, finite floats, and ``None``. Tuples and
    custom Python objects are rejected.
    """

    normalised = _normalise(value)
    return _dump(normalised)


def canonicalize_frozen(value: Any) -> str:
    """Canonicalize Dmint's internal immutable representation."""

    return _dump(_normalise(value, allow_frozen=True))


def _dump(normalised: Any) -> str:
    try:
        return json.dumps(
            normalised,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError("value cannot be canonicalized") from exc


def canonicalize_request(request: Any) -> str:
    """Canonicalize every security-relevant field of a tool request."""

    from .models import ToolRequest

    if type(request) is not ToolRequest:
        raise CanonicalizationError("expected a ToolRequest")
    return canonicalize_frozen(
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


def redact_database_url(url: str | None) -> str:
    """Safely redact embedded credentials in a database URL using urllib.parse."""
    if not url or not isinstance(url, str):
        return ""
    clean_url = url.strip()
    try:
        import urllib.parse

        parsed = urllib.parse.urlparse(clean_url)
        if parsed.password:
            # Reconstruct netloc with redacted password
            userinfo = parsed.username or ""
            userinfo += ":[REDACTED]"
            host_port = ""
            if parsed.hostname:
                if ":" in parsed.hostname:  # IPv6
                    host_port = f"[{parsed.hostname}]"
                else:
                    host_port = parsed.hostname
            if parsed.port:
                host_port += f":{parsed.port}"
            netloc = f"{userinfo}@{host_port}" if userinfo else host_port
            return urllib.parse.urlunparse(
                (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
            )
        elif parsed.username:
            # Reconstruct netloc with username only
            return clean_url
        return clean_url
    except Exception:
        # If parsing completely fails, avoid leaking potential credentials
        return "[REDACTED_URL]"
