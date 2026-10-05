"""Compatibility shim for dmint.models -> dmint.core.models."""

from .core import models as _mod
from .core.models import *  # noqa: F403


def __getattr__(name: str):
    return getattr(_mod, name)
