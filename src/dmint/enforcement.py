"""Compatibility shim for dmint.enforcement -> dmint.core.enforcement (deprecated)."""

import warnings
from .core import enforcement as _mod
from .core.enforcement import *  # noqa: F403

warnings.warn(
    "dmint.enforcement is deprecated and will be removed in v3.0.0; use dmint.core.enforcement instead.",
    DeprecationWarning,
    stacklevel=2,
)


def __getattr__(name: str):
    return getattr(_mod, name)
