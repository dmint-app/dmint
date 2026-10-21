"""Regression tests for the cross-instance recovery-counter critical section.

The recovery sidecar and the SQLite recovery row are separate state stores.
A reader that samples the database before a concurrent writer commits and the
sidecar after that writer updates it could previously mistake a normal update
for a rollback.  These tests exercise separate store instances, which a
per-instance ``threading.RLock`` cannot serialize.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from dmint import SQLiteApprovalStore
from dmint.errors import ApprovalStoreError


class _PausingConnection:
    """Delegate to a real connection, pausing after the recovery SELECT."""

    def __init__(self, connection: object, *, read_db: threading.Event, release: threading.Event) -> None:
        self._connection = connection
        self._read_db = read_db
        self._release = release

    def execute(self, sql: str, *args: object) -> object:
        result = self._connection.execute(sql, *args)  # type: ignore[attr-defined]
        if "SELECT counter FROM store_recovery" in sql:
            self._read_db.set()
            if not self._release.wait(timeout=5):
                raise AssertionError("test did not release the paused recovery read")
        return result

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)


def _open(path: Path) -> SQLiteApprovalStore:
    return SQLiteApprovalStore(path, deployment_epoch="recovery-race-epoch")


def test_cross_instance_lock_serializes_recovery_counter(tmp_path: Path) -> None:
    """A writer cannot change the sidecar while another instance is mid-check.

    Without the shared file lock the writer completes while the reader is
    paused between its database and sidecar reads.  The reader then observes a
    normal counter increment as a rollback.  With the lock, the writer blocks
    until the reader releases the critical section.
    """

    database = tmp_path / "recovery-race.sqlite3"
    reader = _open(database)
    writer = _open(database)
    real_connection = reader._connection  # type: ignore[attr-defined]
    read_db = threading.Event()
    release = threading.Event()
    writer_started = threading.Event()
    writer_done = threading.Event()
    errors: list[BaseException] = []

    reader._connection = _PausingConnection(  # type: ignore[attr-defined]
        real_connection,
        read_db=read_db,
        release=release,
    )

    def run_reader() -> None:
        try:
            reader._sync_recovery_counter(increment=False)
        except BaseException as exc:  # noqa: BLE001 - re-raised via assertion
            errors.append(exc)

    def run_writer() -> None:
        writer_started.set()
        try:
            writer._sync_recovery_counter(increment=True)
        except BaseException as exc:  # noqa: BLE001 - re-raised via assertion
            errors.append(exc)
        finally:
            writer_done.set()

    reader_thread = threading.Thread(target=run_reader, name="recovery-reader")
    writer_thread = threading.Thread(target=run_writer, name="recovery-writer")
    try:
        reader_thread.start()
        assert read_db.wait(timeout=2), "reader did not reach the recovery SELECT"
        writer_thread.start()
        assert writer_started.wait(timeout=2), "writer did not start"
        time.sleep(0.25)
        assert not writer_done.is_set(), "writer bypassed the cross-instance recovery lock"
        release.set()
        reader_thread.join(timeout=5)
        writer_thread.join(timeout=5)
        assert not reader_thread.is_alive()
        assert not writer_thread.is_alive()
        assert errors == []
    finally:
        release.set()
        reader._connection = real_connection  # type: ignore[attr-defined]
        reader.close()
        writer.close()


def test_actual_counter_rollback_still_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "recovery-rollback.sqlite3"
    store = _open(database)
    try:
        store._sync_recovery_counter(increment=True)
        counter = store._connection.execute(  # type: ignore[attr-defined]
            "SELECT counter FROM store_recovery WHERE id = 1"
        ).fetchone()["counter"]
        store._connection.execute(  # type: ignore[attr-defined]
            "UPDATE store_recovery SET counter = ? WHERE id = 1",
            (counter - 1,),
        )
        store._connection.commit()  # type: ignore[attr-defined]
        with pytest.raises(ApprovalStoreError, match="rollback detected"):
            store._sync_recovery_counter(increment=False)
    finally:
        store.close()


def test_lagging_sidecar_is_repaired_under_lock(tmp_path: Path) -> None:
    database = tmp_path / "recovery-lag.sqlite3"
    store = _open(database)
    try:
        store._sync_recovery_counter(increment=True)
        counter = store._connection.execute(  # type: ignore[attr-defined]
            "SELECT counter FROM store_recovery WHERE id = 1"
        ).fetchone()["counter"]
        sidecar = Path(f"{database}.epoch")
        sidecar.write_text(str(counter - 1), encoding="utf-8")

        store._sync_recovery_counter(increment=False)

        assert sidecar.read_text(encoding="utf-8").strip() == str(counter)
    finally:
        store.close()


def test_concurrent_constructors_do_not_report_false_rollback(tmp_path: Path) -> None:
    """Repeated construction/increment races must not produce rollback errors."""

    database = tmp_path / "recovery-constructors.sqlite3"
    base = _open(database)
    errors: list[BaseException] = []
    start = threading.Event()

    def writer() -> None:
        start.wait(timeout=2)
        try:
            for _ in range(250):
                base._sync_recovery_counter(increment=True)
        except BaseException as exc:  # noqa: BLE001 - re-raised via assertion
            errors.append(exc)

    def constructor() -> None:
        start.wait(timeout=2)
        try:
            for _ in range(20):
                store = _open(database)
                store.close()
        except BaseException as exc:  # noqa: BLE001 - re-raised via assertion
            errors.append(exc)

    threads = [threading.Thread(target=writer) for _ in range(2)]
    threads.extend(threading.Thread(target=constructor) for _ in range(8))
    try:
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=30)
        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
    finally:
        base.close()
