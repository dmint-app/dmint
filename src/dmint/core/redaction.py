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
    r"(?i)\b(password|passwd|sslpassword|sslkey|secret|token)\s*=\s*([^\s]+|\'[^\']*\'|\"[^\"]*\")"
)


def redact_database_url(url: Any) -> str:
    """Safely redact embedded credentials in a database URL or connection string.

    Handles:
    - Standard URI format with user and password (postgresql://user:pass@host/db)
    - URI format without username (:pass@host/db)
    - Passwords and keys in query parameters (?password=..., sslpassword=..., sslkey=...)
    - libpq key-value connection strings (host=... password=...)
    - IPv6 addresses in URIs
    """
    if not url or not isinstance(url, str):
        return ""
    clean_url = url.strip()

    # 1. libpq key-value connection string (e.g., 'host=localhost password=secret dbname=db')
    if "=" in clean_url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        return _LIBPQ_KV_PATTERN.sub(r"\1=[REDACTED]", clean_url)

    # 2. URI connection string format
    try:
        parsed = urllib.parse.urlparse(clean_url)
        netloc = parsed.netloc
        has_userinfo_creds = parsed.password is not None or (parsed.netloc and "@" in parsed.netloc)
        has_query_creds = False
        if parsed.query:
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            has_query_creds = any(k.lower() in SENSITIVE_PARAM_NAMES for k, _ in query_pairs)

        # Fast path: if no sensitive credentials exist, return original url unmodified
        if not has_userinfo_creds and not has_query_creds:
            return clean_url

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

        # Redact sensitive query parameters
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

        return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, query, parsed.fragment))
    except Exception:
        # If parsing fails, avoid leaking potential credentials
        return "[REDACTED_URL]"
