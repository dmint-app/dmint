"""Base interface for approval persistence repositories."""

from __future__ import annotations

import abc
from collections.abc import Collection, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..approvals import ApprovalRecord, ApprovalState, PolicyProvenance
    from ..authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
    from ..models import ToolRequest
    from ..policy import Policy


class ApprovalStore(abc.ABC):
    """Abstract base interface for approval persistence repositories.

    Implementations must guarantee deterministic fail-closed behavior,
    exact-request binding, and atomic single-use consumption.
    """

    @abc.abstractmethod
    def close(self) -> None:
        """Close storage resources and release connections."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_authoritative_policy(self, policy: Policy, provenance: PolicyProvenance) -> None:
        """Persist authoritative policy rules and provenance metadata."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_authoritative_policy(self) -> tuple[Policy, PolicyProvenance] | None:
        """Retrieve authoritative policy rules and provenance if stored."""
        raise NotImplementedError

    @abc.abstractmethod
    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        """Delete expired pending records and return count of deleted rows."""
        raise NotImplementedError

    @abc.abstractmethod
    def save_pending(self, record: ApprovalRecord) -> ApprovalRecord:
        """Persist a PENDING approval record with quota and deduplication checks."""
        raise NotImplementedError

    @abc.abstractmethod
    def save_approved(self, record: ApprovalRecord) -> None:
        """Persist or transition an APPROVED approval record."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_pending(self, approval_id: str) -> ApprovalRecord | None:
        """Retrieve a record only if currently PENDING."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_approved(self, approval_id: str) -> ApprovalRecord | None:
        """Retrieve a record only if currently APPROVED."""
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, approval_id: str) -> ApprovalRecord | None:
        """Retrieve an approval record by its unique ID regardless of state."""
        raise NotImplementedError

    @abc.abstractmethod
    def require_pending(self, approval_id: str) -> ApprovalRecord:
        """Retrieve a PENDING record or raise ApprovalNotFoundError."""
        raise NotImplementedError

    @abc.abstractmethod
    def invalidate_approved(
        self,
        record: ApprovalRecord,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Atomically transition an APPROVED record to POLICY_INVALIDATED."""
        raise NotImplementedError

    @abc.abstractmethod
    def consume_approved(
        self,
        *,
        approval_id: str,
        credential: ApprovalAssertion | bytes,
        expected_request: ToolRequest,
        verifier: ApprovalVerifier,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Atomically consume one approved record under strict concurrency guarantees."""
        raise NotImplementedError

    @abc.abstractmethod
    def list_pending(self, *, limit: int = 100) -> list[ApprovalRecord]:
        """List unexpired PENDING records ordered newest first."""
        raise NotImplementedError

    @abc.abstractmethod
    def list_records(
        self,
        *,
        states: set[ApprovalState] | None = None,
        limit: int = 100,
    ) -> list[ApprovalRecord]:
        """List records filtered by optional states ordered newest first."""
        raise NotImplementedError

    @abc.abstractmethod
    def approve_pending(
        self,
        approval_id: str,
        *,
        authority: LocalApprovalAuthority,
        approved_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Atomically approve a PENDING record via human authority."""
        raise NotImplementedError

    @abc.abstractmethod
    def reject_pending(
        self,
        approval_id: str,
        *,
        authority: LocalApprovalAuthority,
        rejected_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Atomically reject a PENDING record via human authority."""
        raise NotImplementedError

    def __enter__(self) -> ApprovalStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
