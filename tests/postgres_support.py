"""Single gate policy for PostgreSQL-backed test suites.

The PostgreSQL-backed suites run against ``DMINT_TEST_DATABASE_URL`` (default:
``postgresql://postgres:postgres@localhost:5432/dmint_test``). Per AGENTS.md the
``self.skipTest`` pattern is banned, so when the server is unreachable these
tests **fail loudly** with an actionable error instead of silently skipping.
CI always provisions a PostgreSQL service (see ``.github/workflows/ci.yml``);
local runs must start a server at the configured URL (see ``CONTRIBUTING.md``).
"""

from __future__ import annotations

import functools
import os

from sqlalchemy import create_engine, text

POSTGRES_TEST_URL = os.environ.get(
    "DMINT_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/dmint_test",
)


def normalize_pg_url(url: str) -> str:
    """Return a SQLAlchemy-compatible PostgreSQL URL using an installed psycopg driver."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        try:
            import psycopg  # noqa: F401
        except ImportError:
            try:
                import psycopg2  # noqa: F401

                url = "postgresql+psycopg2://" + url[len("postgresql://") :]
            except ImportError:
                pass
    return url


@functools.lru_cache(maxsize=8)
def _is_postgres_available(url: str) -> bool:
    """Probe the server; the result is cached once per URL per process."""
    try:
        engine = create_engine(normalize_pg_url(url), connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


def require_postgres(url: str = POSTGRES_TEST_URL) -> str:
    """Fail (never skip) when PostgreSQL is unreachable; return the normalized URL.

    Raises:
        RuntimeError: when the server cannot be reached, with instructions to
            start PostgreSQL or point ``DMINT_TEST_DATABASE_URL`` at a live one.
    """
    if not _is_postgres_available(url):
        raise RuntimeError(
            f"PostgreSQL test server unreachable at {url!r}. The PostgreSQL-backed suites fail "
            "loudly instead of skipping (AGENTS.md bans skipTest-style gating). Start PostgreSQL "
            "and/or set DMINT_TEST_DATABASE_URL, then re-run the tests."
        )
    return normalize_pg_url(url)
