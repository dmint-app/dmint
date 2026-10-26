"""Compatibility shim for dmint.errors -> dmint.core.errors."""

from .core import errors as _mod
from .core.errors import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
