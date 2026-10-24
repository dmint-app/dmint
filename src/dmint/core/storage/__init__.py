"""Approval persistence interfaces and store implementations."""

from typing import TYPE_CHECKING, Any

from .base import ApprovalStore
from .factory import create_approval_store
from .sqlite import SQLiteApprovalStore
from .thread_safe import ThreadSafeApprovalStore

if TYPE_CHECKING:
    from .sql import SQLAlchemyApprovalStore

__all__ = [
    "ApprovalStore",
    "SQLAlchemyApprovalStore",
    "SQLiteApprovalStore",
    "ThreadSafeApprovalStore",
    "create_approval_store",
]


def __getattr__(name: str) -> Any:
    if name == "SQLAlchemyApprovalStore":
        from .sql import SQLAlchemyApprovalStore

        return SQLAlchemyApprovalStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
