"""Branch-coverage edges for invocation snapshots and callable validation (SRC-18).

The Phase-6 branch report flagged `dmint.core.enforcement` below the production
branch-coverage gate. These tests cover the awkward snapshot/target guards:
capability-format validation, tampered variadic snapshots, partial bindings with
omitted defaults, the private authorization token, and classmethod/non-callable
target handling.
"""

from __future__ import annotations

import inspect

import pytest

from dmint.core.enforcement import (
    AuthorizedRequest,
    InvocationSnapshot,
    _capability_parts,
    _validate_function,
)
from dmint.core.errors import RequestValidationError


def test_capability_parts_rejects_malformed_forms() -> None:
    for bad in ("noseparator", "tool.", ".action"):
        with pytest.raises(RequestValidationError):
            _capability_parts(bad)


def test_snapshot_rejects_non_tuple_variadic_snapshot() -> None:
    def varfn(*args: object) -> tuple[object, ...]:
        return args

    bound = inspect.signature(varfn).bind(1, 2)
    bound.arguments["args"] = list(bound.arguments["args"])
    with pytest.raises(RequestValidationError):
        InvocationSnapshot.from_bound(bound)


def test_snapshot_accepts_partial_binding_with_omitted_default() -> None:
    def opt(a: int, b: int = 2) -> int:
        return a + b

    bound = inspect.signature(opt).bind(1)
    snapshot = InvocationSnapshot.from_bound(bound)
    assert snapshot is not None


def test_authorized_request_token_guard() -> None:
    with pytest.raises(TypeError):
        AuthorizedRequest(object(), None, None, None, None)  # type: ignore[arg-type]


def test_validate_function_unwraps_classmethod_and_rejects_non_callable() -> None:
    wrapped = classmethod(lambda cls: None)
    assert _validate_function(wrapped) is wrapped
    with pytest.raises(RequestValidationError):
        _validate_function(42)
