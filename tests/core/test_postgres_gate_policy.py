"""Regression tests for the unified PostgreSQL test gate policy (TEST-SKIP-GATING).

PostgreSQL-backed suites must fail loudly when the server is unreachable — never
skip — and the repository must not reintroduce ``skipTest``-style gating.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests import postgres_support

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TESTS_ROOT = REPO_ROOT / "tests"
DEAD_URL = "postgresql://postgres:postgres@127.0.0.1:59999/dmint_test"


def test_gate_fails_loudly_when_server_unreachable() -> None:
    with pytest.raises(RuntimeError, match="unreachable") as ctx:
        postgres_support.require_postgres(DEAD_URL)
    message = str(ctx.value)
    assert "DMINT_TEST_DATABASE_URL" in message
    assert "fail" in message


def test_gate_returns_normalized_url_when_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(postgres_support, "_is_postgres_available", lambda url: True)
    assert postgres_support.require_postgres("postgres://user:pass@db.example:5432/prod").startswith("postgresql")
    assert postgres_support.normalize_pg_url("postgres://u:p@h/db").startswith("postgresql")


def test_no_skiptest_pattern_in_test_suite() -> None:
    pattern = re.compile(r"\.skipTest\s*\(")
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in sorted(TESTS_ROOT.rglob("*.py"))
        if "__pycache__" not in path.parts
        and path != Path(__file__).resolve()
        and pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"self.skipTest is banned by AGENTS.md, found in: {offenders}"


def test_postgres_suites_use_shared_gate() -> None:
    for name in (
        "core/test_postgres_subsystems.py",
        "core/test_postgres_tamper_race_b4.py",
        "core/test_storage_pluggable.py",
    ):
        source = (TESTS_ROOT / name).read_text(encoding="utf-8")
        assert "require_postgres" in source, f"{name} must use the shared require_postgres() gate"
