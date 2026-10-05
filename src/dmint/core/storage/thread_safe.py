"""Canonical thread-safe ApprovalStore implementation for Dmint."""

from __future__ import annotations

from collections.abc import Callable, Collection
from datetime import datetime
from pathlib import Path
import threading
from typing import Any

from dmint.core.approvals import ApprovalRecord, ApprovalState, PolicyProvenance
from dmint.core.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.core.models import ToolRequest
from dmint.core.policy import Policy
from .base import ApprovalStore
from .factory import create_approval_store
from .sql import SQLAlchemyApprovalStore
from .sqlite import SQLiteApprovalStore


class ThreadSafeApprovalStore(ApprovalStore):
    """Thread-safe proxy for ApprovalStore ensuring safe multi-threaded access.

    For SQLite backends, uses thread-local store instances to avoid SQLite's
    check_same_thread ProgrammingError under multi-threaded servers (e.g. Uvicorn/AnyIO).
    For PostgreSQL/SQLAlchemy backends, delegates directly to SQLAlchemyApprovalStore,
    which is natively thread-safe via its connection pool.

    Constructed via the same DMINT_DATABASE_URL-aware factory Core already uses internally.
    """

    def __init__(
        self,
        database: str | Path | None = None,
        *,
        deployment_epoch: str = "default",
        database_url: str | None = None,
        default_sqlite_path: str | Path = "dmint.db",
        recovery_epoch_file: str | Path | None = None,
        redact_keys: Collection[str] | None = None,
        max_pending_per_principal: int = 100,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if database is not None:
            if isinstance(database, str) and "://" in database:
                database_url = database
            else:
                default_sqlite_path = database

        self._database_url = database_url
        self._deployment_epoch = deployment_epoch
        self._default_sqlite_path = default_sqlite_path
        self._recovery_epoch_file = recovery_epoch_file
        self._redact_keys = redact_keys
        self._max_pending_per_principal = max_pending_per_principal
        self._clock = clock

        # Instantiate store via create_approval_store (governed by DMINT_DATABASE_URL / database_url)
        self._initial_store = create_approval_store(
            database_url=self._database_url,
            deployment_epoch=self._deployment_epoch,
            default_sqlite_path=self._default_sqlite_path,
            recovery_epoch_file=self._recovery_epoch_file,
            redact_keys=self._redact_keys,
            max_pending_per_principal=self._max_pending_per_principal,
            clock=self._clock,
        )

        self._thread_local = threading.local()
        self._store_lock = threading.Lock()
        self._all_stores: list[ApprovalStore] = [self._initial_store]
        self._thread_local.store = self._initial_store

    @property
    def underlying_store(self) -> ApprovalStore:
        """Return the active underlying ApprovalStore instance for this thread."""
        return self._get_current_store()

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name in ("_clock", "_time_provider"):
            if hasattr(self, "_store_lock") and hasattr(self, "_all_stores"):
                with self._store_lock:
                    for s in self._all_stores:
                        try:
                            setattr(s, "_clock", value)
                        except Exception:
                            pass

    def _get_current_store(self) -> ApprovalStore:
        if isinstance(self._initial_store, SQLAlchemyApprovalStore):
            return self._initial_store

        store = getattr(self._thread_local, "store", None)
        if store is None:
            store = SQLiteApprovalStore(
                self._default_sqlite_path,
                deployment_epoch=self._deployment_epoch,
                recovery_epoch_file=self._recovery_epoch_file,
                redact_keys=self._redact_keys,
                max_pending_per_principal=self._max_pending_per_principal,
                clock=self._clock,
            )
            self._thread_local.store = store
            with self._store_lock:
                self._all_stores.append(store)
        return store

    def save_pending(self, record: ApprovalRecord) -> ApprovalRecord:
        return self._get_current_store().save_pending(record)

    def save_approved(self, record: ApprovalRecord) -> None:
        self._get_current_store().save_approved(record)

    def get(self, approval_id: str) -> ApprovalRecord | None:
        return self._get_current_store().get(approval_id)

    def get_pending(self, approval_id: str) -> ApprovalRecord | None:
        return self._get_current_store().get_pending(approval_id)

    def get_approved(self, approval_id: str) -> ApprovalRecord | None:
        return self._get_current_store().get_approved(approval_id)

    def require_pending(self, approval_id: str) -> ApprovalRecord:
        return self._get_current_store().require_pending(approval_id)

    def invalidate_approved(
        self, record: ApprovalRecord, *, reason: str, now: datetime | None = None
    ) -> ApprovalRecord:
        return self._get_current_store().invalidate_approved(record, reason=reason, now=now)

    def consume_approved(
        self,
        *,
        approval_id: str,
        credential: ApprovalAssertion | bytes,
        expected_request: ToolRequest,
        verifier: ApprovalVerifier,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        return self._get_current_store().consume_approved(
            approval_id=approval_id,
            credential=credential,
            expected_request=expected_request,
            verifier=verifier,
            now=now,
        )

    def set_authoritative_policy(self, policy: Policy, provenance: PolicyProvenance) -> None:
        self._get_current_store().set_authoritative_policy(policy, provenance)

    def get_authoritative_policy(self) -> tuple[Policy, PolicyProvenance] | None:
        return self._get_current_store().get_authoritative_policy()

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        return self._get_current_store().cleanup_expired(now=now)

    def list_pending(self, *, limit: int = 100) -> list[ApprovalRecord]:
        return self._get_current_store().list_pending(limit=limit)

    def list_records(self, *, states: set[ApprovalState] | None = None, limit: int = 100) -> list[ApprovalRecord]:
        return self._get_current_store().list_records(states=states, limit=limit)

    def approve_pending(
        self,
        approval_id: str,
        *,
        authority: LocalApprovalAuthority,
        approved_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        return self._get_current_store().approve_pending(
            approval_id,
            authority=authority,
            approved_by=approved_by,
            reason=reason,
            now=now,
        )

    def reject_pending(
        self,
        approval_id: str,
        *,
        authority: LocalApprovalAuthority,
        rejected_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        return self._get_current_store().reject_pending(
            approval_id,
            authority=authority,
            rejected_by=rejected_by,
            reason=reason,
            now=now,
        )

    def close(self) -> None:
        with self._store_lock:
            for s in self._all_stores:
                try:
                    s.close()
                except Exception:
                    pass
            self._all_stores.clear()
