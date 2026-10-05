"""Compatibility shim for dmint.enforcement -> dmint.core.enforcement."""

from .core import enforcement as _mod
from .core.enforcement import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
