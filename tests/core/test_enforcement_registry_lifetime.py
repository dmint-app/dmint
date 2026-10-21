"""Regression: the enforcement binding registry must not retain dropped callables (SRC-15).

The registry is a ``WeakKeyDictionary``, but each stored ``_ProtectedBinding`` held a
strong reference to the registry key (the protected callable), so a dropped callable
could never die: one entry per dynamically protected callable leaked for the lifetime
of the engine. Entries must be removed as soon as the caller drops the callable, and
the protected callables that are still referenced must keep working.
"""

from __future__ import annotations

import gc

from dmint.core.enforcement import Dmint
from dmint.core.models import TrustedContext
from dmint.core.policy import Policy, Rule


def _engine() -> Dmint:
    return Dmint(
        Policy((Rule.allow("tools", "run"),)),
        agent_id="agent-a",
        context=TrustedContext({"env": "test"}),
    )


def test_registry_returns_to_baseline_after_registered_callable_dropped() -> None:
    """A callable registered via register() must not be retained by the registry."""
    engine = _engine()
    baseline = len(engine._registered)

    def target() -> int:
        return 1

    engine.register(target, "tools.run")
    assert len(engine._registered) == baseline + 1

    del target
    gc.collect()

    assert len(engine._registered) == baseline


def test_registry_returns_to_baseline_after_protected_wrappers_dropped() -> None:
    """Ten protect/drop cycles must leave the registry at its original size."""
    engine = _engine()
    baseline = len(engine._registered)

    def churn() -> None:
        for _ in range(10):

            def other() -> None:
                return None

            engine.protected("tools.run")(other)
            del other

    churn()
    gc.collect()

    assert len(engine._registered) == baseline


def test_protected_callable_still_works_after_registry_churn() -> None:
    """Churn of unrelated protected callables must not affect a live protected callable."""
    engine = _engine()
    calls: list[int] = []

    def target(x: int) -> int:
        calls.append(x)
        return x * 2

    guarded = engine.protected("tools.run")(target)
    assert guarded(21) == 42

    baseline = len(engine._registered)
    assert baseline >= 2  # raw callable + protected wrapper entries

    def churn() -> None:
        for _ in range(10):

            def other() -> None:
                return None

            engine.protected("tools.run")(other)

    churn()
    gc.collect()

    assert len(engine._registered) == baseline

    # The originally protected callable must remain fully functional after churn.
    assert guarded(2) == 4
    assert calls == [21, 2]
