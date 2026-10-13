"""Compatibility shim for dmint.canonicalize -> dmint.core.canonicalize (deprecated)."""

import sys
from types import ModuleType
import warnings
from .core.canonicalize import *  # noqa: F403
import dmint.core

warnings.warn(
    "dmint.canonicalize is deprecated and will be removed in v3.0.0; use dmint.core.canonicalize instead.",
    DeprecationWarning,
    stacklevel=2,
)


class _CanonicalizeModule(ModuleType):
    def __call__(self, *args, **kwargs):
        return dmint.core.canonicalize(*args, **kwargs)


sys.modules[__name__].__class__ = _CanonicalizeModule


def __getattr__(name: str):
    return getattr(sys.modules.get("dmint.core.canonicalize", dmint.core), name)
