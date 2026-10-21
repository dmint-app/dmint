"""Branch-coverage edges for enforcement internals (SRC-18).

The Phase-6 branch report flagged `dmint.core.enforcement` below the production
branch-coverage gate. These tests cover the protected-binding reference
lifetime guards, snapshot reconstruction branches, resource resolver
validation, and the deterministic constructor guards of the engine.
"""

from __future__ import annotations

import inspect
import weakref

import pytest

from dmint.core.enforcement import (
    Dmint,
    InvocationSnapshot,
    _ProtectedBinding,
    _resolve_resource,
    _weak_callable_ref,
)
from dmint.core.errors import AuthorizationError, PolicyError, RequestValidationError
from dmint.core.models import NO_RESOURCE, TrustedContext
from dmint.core.policy import Decision, Policy, Rule


def test_weak_callable_ref_returns_none_when_not_weakly_referenceable() -> None:
    assert _weak_callable_ref(42) is None  # type: ignore[arg-type]


def test_binding_uses_strong_fallback_when_weak_ref_unavailable() -> None:
    def target() -> None:
        return None

    binding = _ProtectedBinding(
        owner=None,  # type: ignore[arg-type]
        _function_ref=None,
        _function_fallback=target,
        capability="t.a",
        resource=NO_RESOURCE,
    )
    assert binding.function is target


def test_binding_fails_closed_once_weak_target_is_collected() -> None:
    def target() -> None:
        return None

    reference = weakref.ref(target)
    binding = _ProtectedBinding(
        owner=None,  # type: ignore[arg-type]
        _function_ref=reference,
        _function_fallback=None,
        capability="t.a",
        resource=NO_RESOURCE,
    )
    del target
    with pytest.raises(AuthorizationError, match="no longer available"):
        binding.function


def test_snapshot_round_trips_self_variadic_and_keyword_arguments() -> None:
    class _Target:
        def run(self, *args, **kwargs):
            return args, kwargs

    instance = _Target()
    snapshot = InvocationSnapshot.from_bound(inspect.signature(_Target.run).bind(instance, 1, 2, key="v"))
    rebuilt = snapshot.as_bound_arguments()
    assert rebuilt.args == (instance, 1, 2)
    assert rebuilt.kwargs == {"key": "v"}


def test_snapshot_rebuild_skips_parameters_absent_from_arguments() -> None:
    def target(a, b=2):
        return (a, b)

    snapshot = InvocationSnapshot.from_bound(inspect.signature(target).bind(1))
    rebuilt = snapshot.as_bound_arguments()
    assert rebuilt.arguments == {"a": 1}


def test_resolve_resource_rejects_non_callable_and_non_string_results() -> None:
    assert _resolve_resource(NO_RESOURCE, {}) is NO_RESOURCE
    with pytest.raises(RequestValidationError, match="resource must be NO_RESOURCE"):
        _resolve_resource("literal", {})  # type: ignore[arg-type]
    with pytest.raises(RequestValidationError, match="resource resolver must return a string"):
        _resolve_resource(lambda arguments: 123, {})
    assert _resolve_resource(lambda arguments: arguments["path"], {"path": "logs"}) == "logs"


def test_dmint_requires_policy_or_policy_file() -> None:
    with pytest.raises(TypeError, match="either policy or policy_file"):
        Dmint(agent_id="agent-1", context=TrustedContext({}))


def test_dmint_remote_policy_requires_expected_digest() -> None:
    with pytest.raises(PolicyError, match="remote policy loading requires expected_policy_digest"):
        Dmint(agent_id="agent-1", context=TrustedContext({}), policy_file="https://example.com/policy.json")


def test_dmint_rejects_non_policy_object() -> None:
    with pytest.raises(TypeError, match="policy must be a Policy"):
        Dmint(policy="not-a-policy", agent_id="agent-1", context=TrustedContext({}))  # type: ignore[arg-type]


def test_dmint_rejects_expected_digest_mismatch() -> None:
    policy = Policy((Rule(Decision.ALLOW, "db", "query"),))
    with pytest.raises(PolicyError, match="policy digest mismatch"):
        Dmint(
            policy=policy,
            agent_id="agent-1",
            context=TrustedContext({}),
            expected_policy_digest="0" * 64,
        )
