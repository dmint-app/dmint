"""Redaction and credential sanitization utilities for safe logging and error reporting."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

SENSITIVE_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "key",
        "sslpassword",
        "sslkey",
        "api_key",
        "apikey",
        "auth",
        "authorization",
    }
)

_LIBPQ_KV_PATTERN = re.compile(
    r"(?i)\b(password|passwd|sslpassword|sslkey|secret|token)\s*=\s*('[^']*'|\"[^\"]*\"|[^\s&]+)"
)

# Pattern matching embedded or standalone URIs in text
_URI_PATTERN = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>)]+)")
_TRAILING_PUNCT = re.compile(r"([:;,.]+)$")
_RAW_URI_GREEDY_AT = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)(.*)@([^/@]+(?::\d+)?(?:/.*)?)$")


def _redact_query_params(url_part: str) -> str:
    """Sanitize sensitive credentials in query parameters."""
    if "?" not in url_part:
        return url_part
    base, query = url_part.split("?", 1)
    query_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    if not any(k.lower() in SENSITIVE_PARAM_NAMES for k, _ in query_pairs):
        return url_part
    redacted_pairs = [
        (k, "[REDACTED]" if k.lower() in SENSITIVE_PARAM_NAMES else v)
        for k, v in query_pairs
    ]
    return f"{base}?{urllib.parse.urlencode(redacted_pairs)}"


def _redact_single_uri(raw_uri: str) -> str:
    """Sanitize credentials in a single URI string, preserving trailing punctuation."""
    trailing = ""
    m_trail = _TRAILING_PUNCT.search(raw_uri)
    if m_trail:
        trailing = m_trail.group(1)
        raw_uri = raw_uri[: -len(trailing)]

    # Check unescaped raw password containing @ or /
    m_raw = _RAW_URI_GREEDY_AT.match(raw_uri)
    if m_raw and ("@" in m_raw.group(2) or "/" in m_raw.group(2)):
        scheme, userinfo, host_and_rest = m_raw.group(1), m_raw.group(2), m_raw.group(3)
        user = userinfo.split(":", 1)[0] if ":" in userinfo else userinfo
        redacted_userinfo = f"{user}:[REDACTED]" if user else ":[REDACTED]"
        host_and_rest = _redact_query_params(host_and_rest)
        return f"{scheme}{redacted_userinfo}@{host_and_rest}{trailing}"

    try:
        parsed = urllib.parse.urlparse(raw_uri)
        has_userinfo_creds = parsed.password is not None or (parsed.netloc and "@" in parsed.netloc)
        has_query_creds = False
        if parsed.query:
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            has_query_creds = any(k.lower() in SENSITIVE_PARAM_NAMES for k, _ in query_pairs)

        if not has_userinfo_creds and not has_query_creds:
            return raw_uri + trailing

        netloc = parsed.netloc
        if has_userinfo_creds:
            userinfo = ""
            if parsed.username:
                userinfo = f"{parsed.username}:[REDACTED]"
            else:
                userinfo = ":[REDACTED]"

            host_port = ""
            if parsed.hostname:
                if ":" in parsed.hostname:  # IPv6 address
                    host_port = f"[{parsed.hostname}]"
                else:
                    host_port = parsed.hostname
            if parsed.port:
                host_port += f":{parsed.port}"

            netloc = f"{userinfo}@{host_port}" if userinfo else host_port

        query = parsed.query
        if query and has_query_creds:
            query_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            redacted_pairs = []
            for k, v in query_pairs:
                if k.lower() in SENSITIVE_PARAM_NAMES:
                    redacted_pairs.append((k, "[REDACTED]"))
                else:
                    redacted_pairs.append((k, v))
            query = urllib.parse.urlencode(redacted_pairs)

        return (
            urllib.parse.urlunparse(
                (parsed.scheme, netloc, parsed.path, parsed.params, query, parsed.fragment)
            )
            + trailing
        )
    except Exception:
        return "[REDACTED_URL]" + trailing


def redact_database_url(url: Any) -> str:
    """Safely redact embedded credentials in a database URL, connection string, or error message.

    Handles:
    - Standard URI format with user and password (postgresql://user:pass@host/db)
    - URI format without username (:pass@host/db)
    - Percent-encoded passwords (postgresql://user:p%40ss%2Fword@host/db)
    - Raw/unescaped passwords with @ and /
    - Embedded DSNs inside free-text driver error messages
    - Passwords and keys in query parameters (?password=..., sslpassword=..., sslkey=...)
    - libpq key-value connection strings (host=... password=...)
    - IPv6 addresses in URIs
    """
    if not url or not isinstance(url, str):
        return ""
    clean_url = url.strip()

    # 1. Redact libpq KV patterns
    result = _LIBPQ_KV_PATTERN.sub(r"\1=[REDACTED]", clean_url)

    # 2. Redact URI patterns (both embedded in free text and standalone)
    if "://" in result:
        result = _URI_PATTERN.sub(lambda m: _redact_single_uri(m.group(0)), result)

    return result
