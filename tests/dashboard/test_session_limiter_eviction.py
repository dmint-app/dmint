"""Regression tests: dashboard session map and login rate limiter must be bounded (SRC-04).

Both structures live for the lifetime of the dashboard process. Previously, expired
sessions were removed only when their own cookie was presented again, and login
rate-limiter histories were pruned only for the IP that came back — so abandoned
entries accumulated forever.
"""

from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

from dmint.dashboard import auth as auth_module
from dmint.dashboard.app import create_app
from dmint.dashboard.auth import LoginRateLimiter


def _make_app(client_obj):
    return create_app(
        client_obj,
        auth_token="super-secret-token",
        allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
    )


class TestSessionMapEviction:
    def test_ordinary_request_prunes_abandoned_expired_sessions(self, client_obj) -> None:
        app = _make_app(client_obj)
        client = TestClient(app, raise_server_exceptions=False)

        now = time.time()
        app.state.sessions["abandoned-hard"] = {
            "session_id": "abandoned-hard",
            "csrf_token": "t1",
            "identity": "alice",
            "expires_at": now - 60,  # 12h hard limit already passed
            "last_active": now - 60,
        }
        app.state.sessions["abandoned-idle"] = {
            "session_id": "abandoned-idle",
            "csrf_token": "t2",
            "identity": "bob",
            "expires_at": now + 3600,
            "last_active": now - 31 * 60,  # 30m idle limit already passed
        }

        # Any request must sweep the map — these cookies are never presented again.
        resp = client.get("/health")
        assert resp.status_code == 200

        assert "abandoned-hard" not in app.state.sessions
        assert "abandoned-idle" not in app.state.sessions

    def test_session_map_is_capped_with_lru_eviction(self, client_obj) -> None:
        cap = getattr(auth_module, "SESSION_MAX_ENTRIES", None)
        assert isinstance(cap, int) and cap > 0, "dashboard session map must have a max-entries cap"

        app = _make_app(client_obj)
        client = TestClient(app, raise_server_exceptions=False)

        now = time.time()
        for i in range(cap + 25):
            app.state.sessions[f"s{i:05d}"] = {
                "session_id": f"s{i:05d}",
                "csrf_token": "t",
                "identity": "alice",
                "expires_at": now + 3600,
                "last_active": now - (i + 1),  # higher index = older
            }

        resp = client.get("/health")
        assert resp.status_code == 200

        assert len(app.state.sessions) == cap
        assert "s00000" in app.state.sessions  # newest survives
        assert f"s{cap + 24:05d}" not in app.state.sessions  # oldest evicted

    def test_prune_sessions_removes_expired_and_reports_count(self) -> None:
        prune_sessions = getattr(auth_module, "prune_sessions", None)
        assert prune_sessions is not None, "dashboard must expose a session pruning helper"

        now = time.time()
        sessions = {
            "live": {"expires_at": now + 60, "last_active": now},
            "dead-hard": {"expires_at": now - 1, "last_active": now - 1},
            "dead-idle": {"expires_at": now + 3600, "last_active": now - 31 * 60},
        }
        removed = prune_sessions(sessions, now=now, max_entries=10)
        assert removed == 2
        assert set(sessions) == {"live"}


class TestLoginRateLimiterEviction:
    def test_stale_ip_entries_are_pruned_globally(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = {"now": 1000.0}
        monkeypatch.setattr(auth_module.time, "monotonic", lambda: clock["now"])

        limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0)
        for i in range(3):
            limiter.record_failure(f"198.51.100.{i}")
        assert len(limiter._attempts) == 3

        clock["now"] += 61.0
        assert limiter.is_rate_limited("203.0.113.7") is False

        # All three abandoned IP entries must be gone; only the fresh lookup remains.
        assert len(limiter._attempts) == 1
        assert set(limiter._attempts) == {"203.0.113.7"}

    def test_record_failure_prunes_attempts_outside_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = {"now": 500.0}
        monkeypatch.setattr(auth_module.time, "monotonic", lambda: clock["now"])

        limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0)
        for _ in range(4):
            limiter.record_failure("198.51.100.9")
            clock["now"] += 30.0

        # Four attempts spanning 90s inside a 60s window: only the latest are retained.
        assert len(limiter._attempts["198.51.100.9"]) == 2
