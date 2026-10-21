"""Authentication, token management, and security utilities for Dmint Dashboard."""

from __future__ import annotations

import os
import stat
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60.0
SESSION_HARD_TIMEOUT_SECONDS = 12 * 3600.0
SESSION_MAX_ENTRIES = 1024


class InsecureTokenFileError(ValueError):
    """Raised when a dashboard token file has permissions looser than 0600."""


def load_token_from_file(path: str | Path) -> str:
    """Read dashboard authentication token from a file.

    Enforces that the file permission is strictly 0600 (or 0400) on POSIX systems,
    preventing other users or unprivileged same-host accounts from reading the token.
    """
    token_path = Path(path).resolve()
    if not token_path.is_file():
        raise FileNotFoundError(f"Dashboard token file not found: {token_path}")

    # Check file permissions on POSIX systems
    if os.name == "posix":
        file_stat = token_path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        # Check if group or other have any read/write/execute permissions (0o077)
        if mode & 0o077 != 0:
            raise InsecureTokenFileError(
                f"Token file '{token_path}' has insecure permissions {oct(mode)}. "
                "Permissions must be 0600 (read/write by owner only) or 0400."
            )

    token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError(f"Dashboard token file '{token_path}' is empty.")
    return token


def prune_sessions(
    sessions: dict[str, Any],
    *,
    now: float | None = None,
    idle_seconds: float = SESSION_IDLE_TIMEOUT_SECONDS,
    max_entries: int = SESSION_MAX_ENTRIES,
) -> int:
    """Drop expired/idle sessions and LRU-evict the oldest down to ``max_entries``.

    Expired sessions used to be removed only when their own cookie was presented
    again, so abandoned entries accumulated for the process lifetime. Unparseable
    entries are evicted too (fail closed). Returns the number of evicted entries.
    """
    current = time.time() if now is None else now
    removed = 0

    for key, data in list(sessions.items()):
        if not isinstance(data, dict):
            sessions.pop(key, None)
            removed += 1
            continue
        try:
            expires_at = float(data.get("expires_at", 0) or 0)
            last_active = float(data.get("last_active", 0) or 0)
        except (TypeError, ValueError):
            sessions.pop(key, None)
            removed += 1
            continue
        if expires_at <= current or last_active + idle_seconds <= current:
            sessions.pop(key, None)
            removed += 1

    overflow = len(sessions) - max_entries
    if overflow > 0:

        def _last_active(entry: Any) -> float:
            if isinstance(entry, dict):
                try:
                    return float(entry.get("last_active", 0) or 0)
                except (TypeError, ValueError):
                    return 0.0
            return 0.0

        for key in sorted(sessions, key=lambda key: _last_active(sessions[key]))[:overflow]:
            sessions.pop(key, None)
            removed += 1

    return removed


class LoginRateLimiter:
    """In-memory sliding window rate limiter for login attempts per client IP."""

    def __init__(self, max_attempts: int = 5, window_seconds: float = 60.0) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def _prune_stale(self, now: float) -> None:
        """Drop per-IP histories whose newest attempt is outside the window.

        Entries used to be pruned only for the IP that came back, so abandoned IPs
        accumulated for the process lifetime. The sliding window is the TTL bound.
        """
        stale = [
            ip for ip, history in self._attempts.items() if not history or now - history[-1] >= self.window_seconds
        ]
        for ip in stale:
            self._attempts.pop(ip, None)

    def is_rate_limited(self, ip: str) -> bool:
        """Check if an IP has exceeded the allowed failure attempts."""
        now = time.monotonic()
        self._prune_stale(now)
        history = [t for t in self._attempts[ip] if now - t < self.window_seconds]
        self._attempts[ip] = history
        return len(history) >= self.max_attempts

    def record_failure(self, ip: str) -> None:
        """Record a failed login attempt."""
        now = time.monotonic()
        self._prune_stale(now)
        history = [t for t in self._attempts[ip] if now - t < self.window_seconds]
        history.append(now)
        self._attempts[ip] = history

    def reset(self, ip: str) -> None:
        """Reset attempts on successful login."""
        self._attempts.pop(ip, None)
