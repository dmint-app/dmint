"""Compatibility shim for dmint.storage.sqlite -> dmint.core.storage.sqlite."""

from ..core.storage import sqlite as _mod
from ..core.storage.sqlite import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
