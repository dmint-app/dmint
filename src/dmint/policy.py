"""Small deterministic policy language for Phase 1."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from typing import Any

import rfc8785

from .canonicalize import canonicalize_frozen, freeze_json, thaw_json
from .errors import PolicyError
from .models import (
    NO_RESOURCE,
    AnyResource,
    Decision,
    NoResource,
    ToolRequest,
    validate_text,
)

_OPERATORS = {"equals", "notEquals", "in", "contains", "startsWith", "endsWith"}


def _strict_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    unknown = set(value) - expected
    if unknown:
        raise PolicyError(f"unknown {name} field")


def _same_json(left: Any, right: Any) -> bool:
    return canonicalize_frozen(left) == canonicalize_frozen(right)


@dataclass(frozen=True)
class Condition:
    """A condition evaluated only against trusted context values."""

    field: str
    operator: str
    value: Any

    def __post_init__(self) -> None:
        validate_text(self.field, "condition field")
        validate_text(self.operator, "condition operator")
        if self.operator not in _OPERATORS:
            raise PolicyError("unknown condition operator")
        object.__setattr__(self, "value", freeze_json(self.value, "condition.value"))
        if self.operator in {"startsWith", "endsWith", "contains"} and not isinstance(
            self.value, str
        ):
            raise PolicyError("string condition operators require a string value")
        if self.operator == "in" and not isinstance(self.value, (tuple, list)):
            raise PolicyError("in requires an array value")

    @classmethod
    def equals(cls, field: str, value: Any) -> "Condition":
        return cls(field, "equals", value)

    def matches(self, request: ToolRequest) -> bool:
        if self.field not in request.context.values:
            return False
        candidate = request.context.values[self.field]
        if self.operator == "equals":
            return _same_json(candidate, self.value)
        if self.operator == "notEquals":
            return not _same_json(candidate, self.value)
        if self.operator == "in":
            return any(_same_json(candidate, item) for item in self.value)
        if self.operator == "contains":
            return isinstance(candidate, str) and self.value in candidate
        if self.operator == "startsWith":
            return isinstance(candidate, str) and candidate.startswith(self.value)
        if self.operator == "endsWith":
            return isinstance(candidate, str) and candidate.endswith(self.value)
        return False


@dataclass(frozen=True)
class Rule:
    """A rule matching exact capability selectors and trusted conditions."""

    effect: Decision
    tool: str
    action: str
    agent_id: str | None = None
    resource: str | NoResource | AnyResource = NO_RESOURCE
    conditions: tuple[Condition, ...] = ()

    def __post_init__(self) -> None:
        if type(self.effect) is not Decision:
            raise PolicyError("invalid rule effect")
        validate_text(self.tool, "rule tool")
        validate_text(self.action, "rule action")
        if self.agent_id is not None:
            validate_text(self.agent_id, "rule agent_id")
        if type(self.resource) is str:
            validate_text(self.resource, "rule resource")
        elif type(self.resource) not in (NoResource, AnyResource):
            raise PolicyError("invalid rule resource")
        if not isinstance(self.conditions, Sequence) or isinstance(self.conditions, (str, bytes)):
            raise PolicyError("rule conditions must be a sequence")
        if not all(type(condition) is Condition for condition in self.conditions):
            raise PolicyError("rule contains an invalid condition")
        object.__setattr__(self, "conditions", tuple(self.conditions))

    @classmethod
    def allow(
        cls,
        tool: str,
        action: str,
        *,
        agent_id: str | None = None,
        resource: str | NoResource | AnyResource = NO_RESOURCE,
        conditions: Sequence[Condition] = (),
    ) -> "Rule":
        return cls(Decision.ALLOW, tool, action, agent_id, resource, tuple(conditions))

    @classmethod
    def deny(
        cls,
        tool: str,
        action: str,
        *,
        agent_id: str | None = None,
        resource: str | NoResource | AnyResource = NO_RESOURCE,
        conditions: Sequence[Condition] = (),
    ) -> "Rule":
        return cls(Decision.DENY, tool, action, agent_id, resource, tuple(conditions))

    @classmethod
    def approval_required(
        cls,
        tool: str,
        action: str,
        *,
        agent_id: str | None = None,
        resource: str | NoResource | AnyResource = NO_RESOURCE,
        conditions: Sequence[Condition] = (),
    ) -> "Rule":
        return cls(Decision.APPROVAL_REQUIRED, tool, action, agent_id, resource, tuple(conditions))

    def matches(self, request: ToolRequest) -> bool:
        if self.tool != request.tool or self.action != request.action:
            return False
        if self.agent_id is not None and self.agent_id != request.agent_id:
            return False
        if type(self.resource) is not AnyResource and self.resource != request.resource:
            return False
        return all(condition.matches(request) for condition in self.conditions)


@dataclass(frozen=True)
class Policy:
    """A validated policy with deny-overrides precedence and default deny."""

    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.rules, Sequence) or isinstance(self.rules, (str, bytes)):
            raise PolicyError("policy rules must be a sequence")
        if not all(type(rule) is Rule for rule in self.rules):
            raise PolicyError("policy contains an invalid rule")
        object.__setattr__(self, "rules", tuple(self.rules))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Policy":
        if not isinstance(value, Mapping):
            raise PolicyError("policy must be a mapping")
        _strict_keys(value, {"rules"}, "policy")
        rules = value.get("rules")
        if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
            raise PolicyError("policy rules must be an array")
        return cls(tuple(cls._rule_from_mapping(item) for item in rules))

    @staticmethod
    def _rule_from_mapping(value: Any) -> Rule:
        if not isinstance(value, Mapping):
            raise PolicyError("rule must be a mapping")
        _strict_keys(value, {"effect", "tool", "action", "agent_id", "resource", "conditions"}, "rule")
        effect_value = value.get("effect")
        if effect_value == "allow":
            effect = Decision.ALLOW
        elif effect_value == "approval_required":
            effect = Decision.APPROVAL_REQUIRED
        elif effect_value == "deny":
            effect = Decision.DENY
        else:
            raise PolicyError("rule effect must be allow, deny, or approval_required")
        conditions_value = value.get("conditions", [])
        if not isinstance(conditions_value, Sequence) or isinstance(conditions_value, (str, bytes)):
            raise PolicyError("rule conditions must be an array")
        conditions = []
        for condition_value in conditions_value:
            if not isinstance(condition_value, Mapping):
                raise PolicyError("condition must be a mapping")
            _strict_keys(condition_value, {"field", "operator", "value"}, "condition")
            if "field" not in condition_value or "operator" not in condition_value or "value" not in condition_value:
                raise PolicyError("condition is missing a required field")
            conditions.append(
                Condition(
                    condition_value["field"],
                    condition_value["operator"],
                    condition_value["value"],
                )
            )
        if "tool" not in value or "action" not in value:
            raise PolicyError("rule is missing tool or action")
        if "resource" in value:
            res_value = value["resource"]
            if res_value == "*":
                resource = AnyResource()
            elif res_value is None:
                raise PolicyError("rule resource cannot be None")
            else:
                resource = res_value
        else:
            resource = NO_RESOURCE

        return Rule(
            effect,
            value["tool"],
            value["action"],
            value.get("agent_id"),
            resource,
            tuple(conditions),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return canonical mapping representation of policy for JCS serialization."""
        rules_list = []
        for r in self.rules:
            rule_dict: dict[str, Any] = {
                "effect": r.effect.value.lower(),
                "tool": r.tool,
                "action": r.action,
            }
            if r.agent_id is not None:
                rule_dict["agent_id"] = r.agent_id
            if type(r.resource) is str:
                rule_dict["resource"] = r.resource
            elif type(r.resource) is AnyResource:
                rule_dict["resource"] = "*"
            if r.conditions:
                conds = []
                for c in r.conditions:
                    conds.append({
                        "field": c.field,
                        "operator": c.operator,
                        "value": thaw_json(c.value),
                    })
                rule_dict["conditions"] = conds
            rules_list.append(rule_dict)
        return {"rules": rules_list}

    def evaluate(self, request: ToolRequest) -> Decision:
        """Evaluate without side effects: deny overrides allow, then default deny."""

        if type(request) is not ToolRequest:
            raise PolicyError("expected a ToolRequest")
        matches = [rule for rule in self.rules if rule.matches(request)]
        if any(rule.effect is Decision.DENY for rule in matches):
            return Decision.DENY
        if any(rule.effect is Decision.APPROVAL_REQUIRED for rule in matches):
            return Decision.APPROVAL_REQUIRED
        if any(rule.effect is Decision.ALLOW for rule in matches):
            return Decision.ALLOW
        return Decision.DENY


_POLICY_DIGEST_DOMAIN = b"dmint/policy-digest/v1\x00"


def policy_digest(policy: Policy | Mapping[str, Any]) -> str:
    """Return the domain-separated SHA-256 digest of canonical policy content."""
    if isinstance(policy, Policy):
        mapping = policy.to_dict()
    elif isinstance(policy, Mapping):
        mapping = Policy.from_mapping(policy).to_dict()
    else:
        raise PolicyError("policy_digest requires a Policy instance or policy mapping")
    try:
        canonical = rfc8785.dumps(mapping)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PolicyError("policy content cannot be canonicalized") from exc
    return hashlib.sha256(_POLICY_DIGEST_DOMAIN + canonical).hexdigest()
