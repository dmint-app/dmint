"""Authentication, token management, and security utilities for Dmint Dashboard."""

from __future__ import annotations

import os
import stat
import time
from collections import defaultdict
from pathlib import Path


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


class LoginRateLimiter:
    """In-memory sliding window rate limiter for login attempts per client IP."""

    def __init__(self, max_attempts: int = 5, window_seconds: float = 60.0) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def is_rate_limited(self, ip: str) -> bool:
        """Check if an IP has exceeded the allowed failure attempts."""
        now = time.monotonic()
        history = self._attempts[ip]
        # Prune old attempts outside window
        history = [t for t in history if now - t < self.window_seconds]
        self._attempts[ip] = history
        return len(history) >= self.max_attempts

    def record_failure(self, ip: str) -> None:
        """Record a failed login attempt."""
        now = time.monotonic()
        self._attempts[ip].append(now)

    def reset(self, ip: str) -> None:
        """Reset attempts on successful login."""
        self._attempts.pop(ip, None)
