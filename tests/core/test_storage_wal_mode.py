"""Regression: the documented SQLite WAL storage claim must hold for live stores (SRC-16).

SECURITY.md documents "SQLite WAL mode + ``PRAGMA busy_timeout``" as the storage state
machine, but the audited revision opened databases in the default rollback-journal mode
(``journal_mode=delete``). The store must deliberately enable WAL on every connection
and keep the 5000 ms busy timeout, and WAL must persist in the database file.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from dmint.core.storage import SQLiteApprovalStore, ThreadSafeApprovalStore


def test_sqlite_store_uses_wal_mode_and_busy_timeout(tmp_path: Path) -> None:
    db = tmp_path / "approvals.sqlite"
    store = SQLiteApprovalStore(db, deployment_epoch="epoch-wal")
    try:
        assert store._connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert store._connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        store.close()

    # WAL is a persistent database property: an independent connection sees it too.
    con = sqlite3.connect(str(db))
    try:
        assert con.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        con.close()


def test_thread_safe_store_connections_use_wal_mode(tmp_path: Path) -> None:
    db = tmp_path / "approvals-thread-safe.sqlite"
    store = ThreadSafeApprovalStore(db, deployment_epoch="epoch-wal")
    try:
        underlying = store.underlying_store
        assert underlying._connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert underlying._connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        store.close()
