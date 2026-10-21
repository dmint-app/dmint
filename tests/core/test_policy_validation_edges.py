"""Branch-coverage edges for policy condition/rule validation (SRC-18).

The Phase-6 branch report flagged `dmint.core.policy` below the production
branch-coverage gate. These tests cover every condition-matching operator and
the rule construction guards that reject malformed rules at load time.
"""

from __future__ import annotations

import pytest

from dmint.approvals import new_request_id
from dmint.core.errors import PolicyError
from dmint.core.models import ToolRequest, TrustedContext
from dmint.core.policy import Condition, Decision, Rule


def _request(**context_values) -> ToolRequest:
    return ToolRequest(
        request_id=new_request_id(),
        agent_id="agent-1",
        tool="db",
        action="query",
        resource="*",
        arguments={},
        context=TrustedContext(dict(context_values)),
    )


def test_condition_rejects_unknown_operator() -> None:
    with pytest.raises(PolicyError, match="unknown condition operator"):
        Condition("env", "bogus", "production")


def test_condition_operators_require_matching_value_types() -> None:
    with pytest.raises(PolicyError, match="string condition operators require a string value"):
        Condition("env", "startsWith", 123)
    with pytest.raises(PolicyError, match="in requires an array value"):
        Condition("env", "in", "production")


def test_condition_matches_every_supported_operator() -> None:
    request = _request(env="production", replica="none", tier="prod-db", count=3)

    assert Condition("env", "equals", "production").matches(request)
    assert not Condition("env", "equals", "staging").matches(request)
    assert Condition("env", "notEquals", "staging").matches(request)
    assert not Condition("env", "notEquals", "production").matches(request)
    assert Condition("env", "in", ["staging", "production"]).matches(request)
    assert not Condition("env", "in", ["staging"]).matches(request)
    assert Condition("tier", "contains", "prod").matches(request)
    assert not Condition("count", "contains", "3").matches(request)
    assert Condition("tier", "startsWith", "prod").matches(request)
    assert not Condition("count", "startsWith", "3").matches(request)
    assert Condition("tier", "endsWith", "db").matches(request)
    assert not Condition("count", "endsWith", "3").matches(request)
    assert not Condition("missing", "equals", "production").matches(request)


def test_rule_rejects_invalid_effect() -> None:
    with pytest.raises(PolicyError, match="invalid rule effect"):
        Rule("allow", "db", "query")  # type: ignore[arg-type]


def test_rule_rejects_invalid_resource_values() -> None:
    with pytest.raises(PolicyError, match="invalid rule resource"):
        Rule(Decision.ALLOW, "db", "query", resource=123)  # type: ignore[arg-type]
    with pytest.raises(PolicyError, match="unknown resource_kind"):
        Rule(Decision.ALLOW, "db", "query", resource_kind="bogus")


def test_rule_normalizes_resource_kinds() -> None:
    assert Rule(Decision.ALLOW, "db", "query", resource="*").resource_kind == "any"
    assert Rule(Decision.ALLOW, "db", "query", resource_kind="EXACT").resource_kind == "exact"


def test_rule_case_sensitive_guards() -> None:
    with pytest.raises(PolicyError, match="case_sensitive must be a boolean"):
        Rule(Decision.ALLOW, "db", "query", case_sensitive="yes")  # type: ignore[arg-type]
    with pytest.raises(PolicyError, match="case_sensitive is not supported"):
        Rule(
            Decision.ALLOW,
            "db",
            "query",
            resource="https://example.com/x",
            resource_kind="url",
            case_sensitive=False,
        )


def test_rule_rejects_invalid_conditions_sequence() -> None:
    with pytest.raises(PolicyError, match="rule conditions must be a sequence"):
        Rule(Decision.ALLOW, "db", "query", conditions="bad")  # type: ignore[arg-type]
    with pytest.raises(PolicyError, match="rule contains an invalid condition"):
        Rule(Decision.ALLOW, "db", "query", conditions=(object(),))  # type: ignore[arg-type]


def test_deny_rules_reject_constraints() -> None:
    with pytest.raises(PolicyError, match="DENY rules cannot have constraints"):
        Rule(Decision.DENY, "db", "query", constraints={"amount": {"maximum": 10}})
