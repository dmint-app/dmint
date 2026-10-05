"""Compatibility shim for dmint.request_binding -> dmint.core.request_binding."""

from .core import request_binding as _mod
from .core.request_binding import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
