"""Compatibility shim for dmint.authority -> dmint.core.authority."""

from .core import authority as _mod
from .core.authority import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
