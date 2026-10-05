"""Compatibility shim for dmint.policy -> dmint.core.policy."""

from .core import policy as _mod
from .core.policy import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
