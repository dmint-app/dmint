"""Compatibility shim for dmint.hashing -> dmint.core.hashing."""

from .core import hashing as _mod
from .core.hashing import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
