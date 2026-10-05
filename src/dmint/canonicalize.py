"""Compatibility shim for dmint.canonicalize -> dmint.core.canonicalize."""

import sys
from types import ModuleType
from .core.canonicalize import *  # noqa: F403
import dmint.core


class _CanonicalizeModule(ModuleType):
    def __call__(self, *args, **kwargs):
        return dmint.core.canonicalize(*args, **kwargs)


sys.modules[__name__].__class__ = _CanonicalizeModule


def __getattr__(name: str):
    return getattr(sys.modules.get("dmint.core.canonicalize", dmint.core), name)
