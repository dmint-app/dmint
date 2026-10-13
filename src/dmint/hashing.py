"""Compatibility shim for dmint.hashing -> dmint.core.hashing (deprecated)."""

import warnings
from .core import hashing as _mod
from .core.hashing import *  # noqa: F403

warnings.warn(
    "dmint.hashing is deprecated and will be removed in v3.0.0; use dmint.core.hashing instead.",
    DeprecationWarning,
    stacklevel=2,
)


def __getattr__(name: str):
    return getattr(_mod, name)
