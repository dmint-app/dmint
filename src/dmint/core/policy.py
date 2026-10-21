"""Small deterministic policy language for Phase 1."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from .canonicalize import canonicalize, canonicalize_bytes, canonicalize_frozen, freeze_json, thaw_json
from .errors import CanonicalizationError, PolicyError
from .models import (
    ANY_RESOURCE,
    NO_RESOURCE,
    AnyResource,
    Decision,
    NoResource,
    ToolRequest,
    validate_text,
)
from .resources import ResourceMatchingError, match_resource, validate_resource_syntax
from .constraints import evaluate_constraints, validate_constraints_schema

ConditionOperator = Literal["equals", "notEquals", "in", "contains", "startsWith", "endsWith"]
_OPERATORS: set[str] = {"equals", "notEquals", "in", "contains", "startsWith", "endsWith"}


def _strict_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    unknown = set(value) - expected
    if unknown:
        raise PolicyError(f"unknown {name} field")


def _same_json(left: Any, right: Any) -> bool:
    return canonicalize_frozen(left) == canonicalize_frozen(right)


def compute_tool_schema_hash(
    description: str | None,
    input_schema: Mapping[str, Any] | None,
) -> str:
    """Compute the deterministic SHA-256 digest of a tool's description and JSON Schema."""
    payload = {
        "description": description or "",
        "inputSchema": thaw_json(input_schema) if input_schema is not None else {},
    }
    canonical = canonicalize_bytes(payload)
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class Condition:
    """A condition evaluated only against trusted context values."""

    field: str
    operator: ConditionOperator | str
    value: Any

    def __post_init__(self) -> None:
        validate_text(self.field, "condition field")
        validate_text(self.operator, "condition operator")
        if self.operator not in _OPERATORS:
            raise PolicyError("unknown condition operator")
        object.__setattr__(self, "value", freeze_json(self.value, "condition.value"))
        if self.operator in {"startsWith", "endsWith", "contains"} and not isinstance(self.value, str):
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


_VALID_RESOURCE_KINDS: set[str] = {"exact", "path", "url", "host", "identifier"}


@dataclass(frozen=True)
class Rule:
    """A deterministic authorization rule matching exact capability selectors and trusted conditions.

    Rules evaluate against incoming `ToolRequest` objects. When a request matches all rule
    criteria (tool, action, optional agent_id, optional resource, and conditions), the rule's
    `effect` is triggered.

    Factory methods:
        - `Rule.allow("db", "query")`: Unconditionally allow matching requests.
        - `Rule.deny("db", "drop_table")`: Explicitly deny matching requests.
        - `Rule.approval_required("cloud", "deploy")`: Require human approval before execution.

    Example:
        ```python
        # Allow reading files in /var/log only
        rule = Rule.allow("fs", "read", resource="/var/log/*")

        # Require approval for database mutations in production
        prod_rule = Rule.approval_required("db", "update", conditions=[Condition("env", "equals", "production")])
        ```
    """

    effect: Decision
    tool: str
    action: str
    agent_id: str | None = None
    resource: str | NoResource | AnyResource = NO_RESOURCE
    resource_kind: str | None = None
    case_sensitive: bool = True
    conditions: tuple[Condition, ...] = ()
    constraints: Mapping[str, Any] | None = None
    schema_hash: str | None = None

    def __post_init__(self) -> None:
        if type(self.effect) is not Decision:
            raise PolicyError("invalid rule effect")
        validate_text(self.tool, "rule tool")
        validate_text(self.action, "rule action")
        if self.agent_id is not None:
            validate_text(self.agent_id, "rule agent_id")
        if self.schema_hash is not None:
            validate_text(self.schema_hash, "rule schema_hash")
        if self.resource == "*":
            object.__setattr__(self, "resource", ANY_RESOURCE)
        elif type(self.resource) is str:
            validate_text(self.resource, "rule resource")
        elif type(self.resource) not in (NoResource, AnyResource):
            raise PolicyError("invalid rule resource")

        # Explicit resource_kind: default is "any" for ANY_RESOURCE, "none" for NO_RESOURCE, "exact" for string
        if self.resource_kind is None:
            if type(self.resource) is AnyResource:
                object.__setattr__(self, "resource_kind", "any")
            elif type(self.resource) is NoResource:
                object.__setattr__(self, "resource_kind", "none")
            else:
                object.__setattr__(self, "resource_kind", "exact")
        else:
            validate_text(self.resource_kind, "rule resource_kind")
            normalized_kind = self.resource_kind.lower()
            if normalized_kind not in _VALID_RESOURCE_KINDS and normalized_kind not in ("any", "none"):
                raise PolicyError(f"unknown resource_kind: {self.resource_kind}")
            object.__setattr__(self, "resource_kind", normalized_kind)

        if type(self.case_sensitive) is not bool:
            raise PolicyError("case_sensitive must be a boolean")
        if not self.case_sensitive and self.resource_kind not in ("path", "exact"):
            raise PolicyError(f"case_sensitive is not supported for resource_kind '{self.resource_kind}'")

        if not isinstance(self.conditions, Sequence) or isinstance(self.conditions, (str, bytes)):
            raise PolicyError("rule conditions must be a sequence")
        if not all(type(condition) is Condition for condition in self.conditions):
            raise PolicyError("rule contains an invalid condition")
        object.__setattr__(self, "conditions", tuple(self.conditions))

        if self.constraints is not None:
            if self.effect is Decision.DENY:
                raise PolicyError("DENY rules cannot have constraints")
            validate_constraints_schema(self.constraints)
            object.__setattr__(self, "constraints", freeze_json(self.constraints, "rule.constraints"))

    @classmethod
    def allow(
        cls,
        tool: str,
        action: str,
        *,
        agent_id: str | None = None,
        resource: str | NoResource | AnyResource = NO_RESOURCE,
        resource_kind: str | None = None,
        case_sensitive: bool = True,
        conditions: Sequence[Condition] = (),
        constraints: Mapping[str, Any] | None = None,
        schema_hash: str | None = None,
    ) -> "Rule":
        return cls(
            Decision.ALLOW,
            tool,
            action,
            agent_id,
            resource,
            resource_kind,
            case_sensitive,
            tuple(conditions),
            constraints,
            schema_hash,
        )

    @classmethod
    def deny(
        cls,
        tool: str,
        action: str,
        *,
        agent_id: str | None = None,
        resource: str | NoResource | AnyResource = NO_RESOURCE,
        resource_kind: str | None = None,
        case_sensitive: bool = True,
        conditions: Sequence[Condition] = (),
        constraints: Mapping[str, Any] | None = None,
        schema_hash: str | None = None,
    ) -> "Rule":
        return cls(
            Decision.DENY,
            tool,
            action,
            agent_id,
            resource,
            resource_kind,
            case_sensitive,
            tuple(conditions),
            constraints,
            schema_hash,
        )

    @classmethod
    def approval_required(
        cls,
        tool: str,
        action: str,
        *,
        agent_id: str | None = None,
        resource: str | NoResource | AnyResource = NO_RESOURCE,
        resource_kind: str | None = None,
        case_sensitive: bool = True,
        conditions: Sequence[Condition] = (),
        constraints: Mapping[str, Any] | None = None,
        schema_hash: str | None = None,
    ) -> "Rule":
        return cls(
            Decision.APPROVAL_REQUIRED,
            tool,
            action,
            agent_id,
            resource,
            resource_kind,
            case_sensitive,
            tuple(conditions),
            constraints,
            schema_hash,
        )

    approve = approval_required

    def matches_tool_action(self, request: ToolRequest) -> bool:
        """Return whether the rule's tool/action selectors cover the request.

        ``*`` is the explicit wildcard for a selector; every other value is an
        exact, case-sensitive match.  This helper is shared by candidate
        selection and full rule matching so the two paths cannot diverge.
        """
        tool_matches = self.tool == "*" or self.tool == request.tool
        action_matches = self.action == "*" or self.action == request.action
        return tool_matches and action_matches

    def matches(self, request: ToolRequest) -> bool:
        if not self.matches_tool_action(request):
            return False
        if self.agent_id is not None and self.agent_id != request.agent_id:
            return False
        if type(self.resource) is not AnyResource:
            if type(self.resource) is NoResource:
                if request.resource is not NO_RESOURCE:
                    return False
            elif type(self.resource) is str:
                if request.resource is NO_RESOURCE or type(request.resource) is not str:
                    return False
                if not match_resource(
                    self.resource,
                    request.resource,
                    kind=self.resource_kind or "exact",
                    case_sensitive=self.case_sensitive,
                ):
                    return False
        return all(condition.matches(request) for condition in self.conditions)


@dataclass(frozen=True)
class Policy:
    """An immutable sequence of deterministic authorization rules with fail-closed default.

    Evaluation precedence (zero ambiguity):
        1. Find all rules that match the incoming `ToolRequest`.
        2. If ANY matching rule has effect `DENY`, the decision is `DENY` (deny-overrides).
        3. If ANY matching rule has effect `APPROVAL_REQUIRED`, the decision is `APPROVAL_REQUIRED`.
        4. If ANY matching rule has effect `ALLOW`, the decision is `ALLOW`.
        5. If NO rules match, the decision is `DENY` (fail-closed default).

    Example:
        ```python
        from dmint import Policy, Rule

        policy = Policy(
            [
                Rule.allow("db", "query"),
                Rule.approval_required("db", "update"),
                Rule.deny("db", "drop_table"),
            ]
        )
        ```
    """

    rules: tuple[Rule, ...] = ()
    strict_arguments: bool = False
    tool_schemas: Mapping[str, str] = field(default_factory=dict)
    _file_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rules, Sequence) or isinstance(self.rules, (str, bytes)):
            raise PolicyError("policy rules must be a sequence")
        if not all(type(rule) is Rule for rule in self.rules):
            raise PolicyError("policy contains an invalid rule")
        if type(self.strict_arguments) is not bool:
            raise PolicyError("strict_arguments must be a boolean")
        if not isinstance(self.tool_schemas, Mapping):
            raise PolicyError("policy tool_schemas must be a mapping")
        for k, v in self.tool_schemas.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise PolicyError("policy tool_schemas must be a string to string mapping")
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "strict_arguments", bool(self.strict_arguments))
        object.__setattr__(self, "tool_schemas", MappingProxyType(dict(self.tool_schemas)))

    @property
    def file_digest(self) -> str | None:
        """SHA-256 digest of exact policy file/source bytes if loaded from JSON/file/URL."""
        return self._file_digest

    def get_tool_schema_hash(self, tool_name: str, integration_id: str | None = None) -> str | None:
        """Retrieve the pinned schema hash for a tool, checking tool_schemas and rule schema_hash."""
        schemas = getattr(self, "tool_schemas", {})
        if tool_name in schemas:
            return schemas[tool_name]
        if integration_id:
            combined = f"{integration_id}.{tool_name}"
            if combined in schemas:
                return schemas[combined]
            mcp_combined = f"mcp.{integration_id}.{tool_name}"
            if mcp_combined in schemas:
                return schemas[mcp_combined]
        for r in self.rules:
            if r.schema_hash:
                if r.action == tool_name:
                    return r.schema_hash
                if integration_id and r.action == f"{integration_id}.{tool_name}":
                    return r.schema_hash
                if f"{r.tool}.{r.action}" == tool_name:
                    return r.schema_hash
        return None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Policy":
        if not isinstance(value, Mapping):
            raise PolicyError("policy must be a mapping")
        _strict_keys(value, {"rules", "strict_arguments", "tool_schemas"}, "policy")
        rules = value.get("rules")
        if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
            raise PolicyError("policy rules must be an array")
        strict_args = value.get("strict_arguments", False)
        if type(strict_args) is not bool:
            raise PolicyError("strict_arguments must be a boolean")
        tool_schemas = value.get("tool_schemas", {})
        if tool_schemas is None:
            tool_schemas = {}
        return cls(
            tuple(cls._rule_from_mapping(item) for item in rules),
            strict_arguments=strict_args,
            tool_schemas=tool_schemas,
        )

    @staticmethod
    def _rule_from_mapping(value: Any) -> Rule:
        if not isinstance(value, Mapping):
            raise PolicyError("rule must be a mapping")
        _strict_keys(
            value,
            {
                "effect",
                "tool",
                "action",
                "agent_id",
                "resource",
                "resource_kind",
                "case_sensitive",
                "conditions",
                "constraints",
                "schema_hash",
            },
            "rule",
        )
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
        resource: str | NoResource | AnyResource
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

        resource_kind: str | None = None
        if "resource_kind" in value:
            kind_val = value["resource_kind"]
            if not isinstance(kind_val, str) or kind_val.lower() not in _VALID_RESOURCE_KINDS:
                raise PolicyError(f"unknown resource_kind: {kind_val}")
            resource_kind = kind_val.lower()

        if "case_sensitive" in value:
            case_val = value["case_sensitive"]
            if type(case_val) is not bool:
                raise PolicyError("case_sensitive must be a boolean")
            effective_kind = resource_kind or ("exact" if "resource" in value and value["resource"] != "*" else "exact")
            if not case_val and effective_kind not in ("path", "exact"):
                raise PolicyError(f"case_sensitive is not supported for resource_kind '{effective_kind}'")
            case_sensitive = case_val
        else:
            case_sensitive = True

        constraints = value.get("constraints")
        if constraints is not None:
            if effect is Decision.DENY:
                raise PolicyError("DENY rules cannot have constraints")
            validate_constraints_schema(constraints)

        schema_hash = value.get("schema_hash")
        if schema_hash is not None:
            if not isinstance(schema_hash, str):
                raise PolicyError("rule schema_hash must be a string")
            validate_text(schema_hash, "rule schema_hash")

        return Rule(
            effect,
            value["tool"],
            value["action"],
            value.get("agent_id"),
            resource,
            resource_kind,
            case_sensitive=case_sensitive,
            conditions=tuple(conditions),
            constraints=constraints,
            schema_hash=schema_hash,
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
            if r.resource_kind is not None and r.resource_kind not in ("exact", "any", "none"):
                rule_dict["resource_kind"] = r.resource_kind
            if r.case_sensitive is False:
                rule_dict["case_sensitive"] = False
            if r.conditions:
                conds = []
                for c in r.conditions:
                    conds.append(
                        {
                            "field": c.field,
                            "operator": c.operator,
                            "value": thaw_json(c.value),
                        }
                    )
                rule_dict["conditions"] = conds
            if r.constraints is not None:
                rule_dict["constraints"] = thaw_json(r.constraints)
            if r.schema_hash is not None:
                rule_dict["schema_hash"] = r.schema_hash
            rules_list.append(rule_dict)
        res: dict[str, Any] = {"rules": rules_list}
        if self.strict_arguments:
            res["strict_arguments"] = True
        if self.tool_schemas:
            res["tool_schemas"] = dict(self.tool_schemas)
        return res

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Policy":
        """Load a policy from a dictionary mapping."""
        return cls.from_mapping(value)

    @classmethod
    def from_json(cls, data: str | bytes, *, expected_policy_digest: str | None = None) -> "Policy":
        """Parse and validate a policy from a JSON string or bytes, strictly rejecting duplicate keys."""
        import json

        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        actual_digest = hashlib.sha256(raw_bytes).hexdigest()

        if expected_policy_digest is not None:
            if actual_digest.lower() != expected_policy_digest.strip().lower():
                raise PolicyError(f"policy digest mismatch: expected '{expected_policy_digest}', got '{actual_digest}'")

        def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for k, v in pairs:
                if k in result:
                    raise PolicyError(f"duplicate JSON key: {k!r}")
                result[k] = v
            return result

        try:
            parsed = json.loads(raw_bytes, object_pairs_hook=_reject_duplicate_keys)
        except Exception as exc:
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError(f"Invalid JSON for policy: {exc}") from exc

        policy = cls.from_mapping(parsed)
        object.__setattr__(policy, "_file_digest", actual_digest)
        return policy

    @classmethod
    def from_file(cls, path: str | Path, *, expected_policy_digest: str | None = None) -> "Policy":
        """Load, verify digest, and parse a policy from a local filesystem path."""
        import os
        from pathlib import Path

        p = Path(path).resolve()
        if not p.is_file():
            raise PolicyError(f"policy file '{p}' not found")
        data = p.read_bytes()
        digest = expected_policy_digest or os.environ.get("DMINT_EXPECTED_POLICY_DIGEST")
        return cls.from_json(data, expected_policy_digest=digest)

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        expected_policy_digest: str,
        timeout: float = 15.0,
    ) -> "Policy":
        """Load, SSRF-verify, check digest BEFORE parsing, and load policy from a remote HTTPS URL."""
        import urllib.parse
        import urllib.request
        from dmint.mcp.ssrf import validate_mcp_url

        if not isinstance(url, str) or not url.strip():
            raise PolicyError("remote policy URL must be a non-empty string")
        clean_url = url.strip()
        parsed = urllib.parse.urlparse(clean_url)
        if parsed.scheme.lower() != "https":
            raise PolicyError(f"remote policy loading requires HTTPS, got '{parsed.scheme}'")

        try:
            validate_mcp_url(clean_url, allow_loopback=False, resolve_dns=True)
        except Exception as exc:
            raise PolicyError(f"remote policy URL failed SSRF validation: {exc}") from exc

        req = urllib.request.Request(
            clean_url,
            headers={"User-Agent": "dmint/2.0.1 (policy-fetcher)", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if status and status >= 400:
                    raise PolicyError(f"remote policy fetch returned HTTP {status}")
                body_bytes = resp.read()
        except PolicyError:
            raise
        except Exception as exc:
            raise PolicyError(f"failed to fetch remote policy from '{clean_url}': {exc}") from exc

        actual_digest = hashlib.sha256(body_bytes).hexdigest()
        if actual_digest.lower() != expected_policy_digest.strip().lower():
            raise PolicyError(
                f"remote policy digest mismatch: expected '{expected_policy_digest}', got '{actual_digest}'"
            )

        return cls.from_json(body_bytes, expected_policy_digest=expected_policy_digest)

    def to_json(self, indent: int | None = None) -> str:
        """Serialize policy to a formatted JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=indent)

    def evaluate(self, request: ToolRequest) -> Decision:
        """Evaluate without side effects: fail closed on unnormalizable resources,

        deny overrides allow, then default deny.
        """
        decision, _ = self.evaluate_detailed(request)
        return decision

    def evaluate_detailed(self, request: ToolRequest) -> tuple[Decision, str | None]:
        """Evaluate without side effects: fail closed on unnormalizable resources,

        deny overrides allow, then default deny.
        Pure function: zero object mutation or thread-shared state.
        Returns (decision, error_code_or_reason).
        """
        if type(request) is not ToolRequest:
            raise PolicyError("expected a ToolRequest")

        # 1. Candidate rules for this tool + action (and agent_id if applicable)
        candidate_rules = [
            rule
            for rule in self.rules
            if rule.matches_tool_action(request) and (rule.agent_id is None or rule.agent_id == request.agent_id)
        ]

        # 2. Validate request resource against the explicit kind of EVERY candidate rule
        # Non-string resource for kind other than any/none => fail closed with DMT_RESOURCE_INVALID
        # ANY failure => immediately fail closed with DMT_RESOURCE_INVALID
        for rule in candidate_rules:
            kind = (rule.resource_kind or "exact").lower()
            if kind in ("any", "none"):
                continue
            if not isinstance(request.resource, str):
                return Decision.DENY, "DMT_RESOURCE_INVALID"
            try:
                validate_resource_syntax(request.resource, kind=kind)
            except ResourceMatchingError:
                return Decision.DENY, "DMT_RESOURCE_INVALID"

        # 3. Evaluate argument constraints for candidate rules matching resource & conditions
        # Any constraint error => DENY DMT_CONSTRAINT_VIOLATION before matching effects
        matching_rules: list[Rule] = []
        for rule in candidate_rules:
            if not rule.matches(request):
                continue
            if rule.constraints is not None:
                passed, _ = evaluate_constraints(
                    rule.constraints,
                    request.arguments,
                    default_additional_properties=not self.strict_arguments,
                )
                if not passed:
                    return Decision.DENY, "DMT_CONSTRAINT_VIOLATION"
            matching_rules.append(rule)

        # 4. Deterministic decision precedence among matching rules
        if any(rule.effect is Decision.DENY for rule in matching_rules):
            return Decision.DENY, "DMT_POLICY_DENIED"
        if any(rule.effect is Decision.APPROVAL_REQUIRED for rule in matching_rules):
            return Decision.APPROVAL_REQUIRED, "DMT_APPROVAL_REQUIRED"
        if any(rule.effect is Decision.ALLOW for rule in matching_rules):
            return Decision.ALLOW, None
        return Decision.DENY, "DMT_DEFAULT_DENIED"


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
        canonical = canonicalize_bytes(mapping)
    except (TypeError, ValueError, OverflowError, CanonicalizationError) as exc:
        raise PolicyError("policy content cannot be canonicalized") from exc
    return hashlib.sha256(_POLICY_DIGEST_DOMAIN + canonical).hexdigest()
