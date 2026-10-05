"""Compatibility shim for dmint.approvals -> dmint.core.approvals."""

from .core import approvals as _mod
from .core.approvals import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
