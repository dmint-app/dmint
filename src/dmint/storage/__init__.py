"""Compatibility shim for dmint.storage -> dmint.core.storage."""

from ..core import storage as _mod
from ..core.storage import (
    ApprovalStore,
    SQLiteApprovalStore,
    ThreadSafeApprovalStore,
    create_approval_store,
)


def __getattr__(name: str):
    return getattr(_mod, name)
