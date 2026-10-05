"""Canonical version and metadata specification for dmint.

Single source of truth for package version, User-Agent strings, and runtime constants.
Supports overriding via environment variables (DMINT_VERSION, DMINT_USER_AGENT).
"""

from __future__ import annotations

import os

# Base package version (single source of truth in code)
DEFAULT_VERSION: str = "2.0.0"

# Canonical package version (overridable via DMINT_VERSION env var)
__version__: str = os.environ.get("DMINT_VERSION", DEFAULT_VERSION)


def get_version() -> str:
    """Return the authoritative package version, respecting DMINT_VERSION if set."""
    return os.environ.get("DMINT_VERSION", DEFAULT_VERSION)


def get_user_agent(component: str | None = None) -> str:
    """Return the canonical User-Agent header string.

    Can be explicitly overridden via DMINT_USER_AGENT environment variable for base client.

    Examples:
        get_user_agent() -> 'dmint-cli/2.0.0'
        get_user_agent('mcp') -> 'dmint-mcp/2.0.0'
        get_user_agent('oauth') -> 'dmint-oauth/2.0.0'
        get_user_agent('webhook') -> 'dmint-webhook/2.0.0'
    """
    version = get_version()
    if component:
        return f"dmint-{component}/{version}"
    return os.environ.get("DMINT_USER_AGENT", f"dmint-cli/{version}")


# Default User-Agent header for HTTP clients
DEFAULT_USER_AGENT: str = os.environ.get("DMINT_USER_AGENT", get_user_agent())

__all__ = [
    "DEFAULT_USER_AGENT",
    "DEFAULT_VERSION",
    "__version__",
    "get_user_agent",
    "get_version",
]
