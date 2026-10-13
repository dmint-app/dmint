"""Tests for ThreadSafeApprovalStore connection tracking, lifecycle, and ResourceWarning prevention."""

from __future__ import annotations

import gc
from pathlib import Path
import threading
import warnings

from dmint.core.storage.thread_safe import ThreadSafeApprovalStore
from dmint.core.storage.sqlite import SQLiteApprovalStore


def test_thread_safe_store_context_manager_and_tracking(tmp_path: Path) -> None:
    db = tmp_path / "ts_test.sqlite"

    with ThreadSafeApprovalStore(db, deployment_epoch="epoch-ts") as store:
        assert hasattr(store, "_thread_stores")
        assert hasattr(store, "_atexit_handler")
        assert store._atexit_handler is not None

        # Main thread has its store tracked
        main_tid = threading.get_ident()
        assert main_tid in store._thread_stores

        # Spawn worker threads that use the store
        barrier = threading.Barrier(3)

        def worker() -> None:
            barrier.wait(timeout=5)
            store.list_pending()

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # Worker threads should be tracked in _thread_stores
        assert len(store._thread_stores) >= 3
        assert len(store._all_stores) >= 3

        # Track the underlying stores before exit
        underlying = list(store._all_stores)
        for s in underlying:
            if isinstance(s, SQLiteApprovalStore):
                assert s._connection is not None

    # Exiting context manager must have closed all underlying connections
    for s in underlying:
        if isinstance(s, SQLiteApprovalStore):
            assert s._connection is None

    assert store._atexit_handler is None
    assert len(store._thread_stores) == 0
    assert len(store._all_stores) == 0


def test_no_resource_warning_on_gc_or_thread_exit(tmp_path: Path) -> None:
    db = tmp_path / "ts_warning.sqlite"

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)

        store = ThreadSafeApprovalStore(db, deployment_epoch="epoch-warn")

        def worker(s: ThreadSafeApprovalStore = store) -> None:
            s.list_pending()

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        store.close()
        gc.collect()
