"""Thin integration layer between the dashboard and Core public APIs.

CoreClient DOES NOT implement approval semantics.
It only calls SQLiteApprovalStore and LocalApprovalAuthority public methods.

Architecture:
    Dashboard routes
        ↓
    CoreClient (this module)
        ↓
    dmint public API (SQLiteApprovalStore, LocalApprovalAuthority)
        ↓
    Core approval engine + Core SQLite
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Collection
from datetime import datetime
from pathlib import Path
from typing import Any

from dmint import (
    ApprovalState,
    ApprovalStore,
    LocalApprovalAuthority,
)
from dmint.approvals import ApprovalRecord
from dmint.core.storage import ThreadSafeApprovalStore


# Default human approver identity used in V1 (no authentication).
DASHBOARD_APPROVER_ID = "dashboard-human"


class CoreClient:
    """Thin wrapper that delegates every operation to Core public APIs.

    No approval logic, no SQL, no private Core access lives here.
    """

    def __init__(
        self,
        store: ApprovalStore | None = None,
        authority: LocalApprovalAuthority | None = None,
        *,
        approver_id: str = DASHBOARD_APPROVER_ID,
        deployment_epoch: str = "default",
        database_url: str | None = None,
        db_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if store is not None and not isinstance(store, ApprovalStore):
            raise TypeError("store must be an ApprovalStore")
        if authority is not None and not isinstance(authority, LocalApprovalAuthority):
            raise TypeError("authority must be a LocalApprovalAuthority")
        if type(approver_id) is not str or not approver_id.strip():
            raise ValueError("approver_id must be a non-empty string")

        if store is None:
            store = ThreadSafeApprovalStore(
                database=db_path,
                database_url=database_url,
                deployment_epoch=deployment_epoch,
                clock=clock,
            )

        if authority is None:
            authority = LocalApprovalAuthority(
                issuer_id=approver_id.strip(),
                audience="dmint/dashboard/v1",
                clock=clock,
            )

        self._store = store
        self._authority = authority
        self._approver_id = approver_id.strip()

    @property
    def store(self) -> ApprovalStore:
        """Return the underlying ApprovalStore."""
        return self._store

    # ------------------------------------------------------------------
    # Query APIs
    # ------------------------------------------------------------------

    def list_pending(self, *, limit: int = 100) -> list[ApprovalRecord]:
        """Return unexpired PENDING records, newest first."""
        return self._store.list_pending(limit=limit)

    def list_records(
        self,
        *,
        states: set[ApprovalState] | None = None,
        limit: int = 200,
    ) -> list[ApprovalRecord]:
        """Return approval records, optionally filtered by state."""
        return self._store.list_records(states=states, limit=limit)

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        """Fetch a single record by approval_id. Returns None if not found."""
        return self._store.get(approval_id)

    def count_by_state(self, state: ApprovalState) -> int:
        """Return a rough count of records in the given state."""
        return len(self._store.list_records(states={state}, limit=1000))

    # ------------------------------------------------------------------
    # Decision APIs — delegate entirely to Core
    # ------------------------------------------------------------------

    def approve(self, approval_id: str, *, reason: str | None = None) -> ApprovalRecord:
        """Approve a PENDING record.  Core owns the full state transition."""
        return self._store.approve_pending(
            approval_id,
            authority=self._authority,
            approved_by=self._approver_id,
            reason=reason or None,
        )

    def reject(self, approval_id: str, *, reason: str | None = None) -> ApprovalRecord:
        """Reject a PENDING record.  Core owns the full state transition."""
        return self._store.reject_pending(
            approval_id,
            authority=self._authority,
            rejected_by=self._approver_id,
            reason=reason or None,
        )

    # ------------------------------------------------------------------
    # Availability probe
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Lightweight availability check; returns True if Core responds."""
        try:
            self._store.list_pending(limit=1)
            return True
        except Exception:
            return False
