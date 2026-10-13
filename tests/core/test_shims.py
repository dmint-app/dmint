"""Tests for deprecated compatibility shims."""

import importlib
import sys
import warnings
import pytest


def test_deprecated_canonicalize_shim():
    sys.modules.pop("dmint.canonicalize", None)
    with pytest.deprecated_call(match="dmint.canonicalize is deprecated"):
        shim = importlib.import_module("dmint.canonicalize")

    assert hasattr(shim, "canonicalize")
    result = shim.canonicalize({"b": 1, "a": 2})
    assert result == '{"a":2,"b":1}'
    # Test callable module shim
    assert shim({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_deprecated_enforcement_shim():
    sys.modules.pop("dmint.enforcement", None)
    with pytest.deprecated_call(match="dmint.enforcement is deprecated"):
        shim = importlib.import_module("dmint.enforcement")

    assert hasattr(shim, "Dmint")
    assert hasattr(shim, "Decision")
    assert hasattr(shim, "ToolRequest")


def test_deprecated_hashing_shim():
    sys.modules.pop("dmint.hashing", None)
    with pytest.deprecated_call(match="dmint.hashing is deprecated"):
        shim = importlib.import_module("dmint.hashing")

    assert hasattr(shim, "request_fingerprint")
    assert hasattr(shim, "request_binding_fingerprint")
