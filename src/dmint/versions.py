"""Compatibility shim for dmint.versions -> dmint.core.versions."""

from .core import versions as _mod
from .core.versions import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
