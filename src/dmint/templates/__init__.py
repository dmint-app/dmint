"""Production-ready policy templates and deduplication utilities for Dmint.

Provides verified, schema-compliant policy templates for common operational domains:
  - shell: Safe developer shell execution, service management approvals, destructive denials.
  - filesystem: Workspace read/write scopes, strict deny on secrets and credentials.
  - postgres: Safe reads, approval-gated mutations and DDL, strict drop denials.
  - github: Read queries, approval-gated issue/PR mutations, strict repo deletion denials.
  - stripe: Safe customer/charge lookups, approval-gated transactions, strict payout/key denials.
  - aws: Safe resource descriptions, approval-gated provisioning, strict destructive denials.
  - kubernetes: Cluster observation, approval-gated rollouts/scaling, strict deletion denials.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dmint.core.canonicalize import canonicalize_frozen
from dmint.core.policy import Policy, Rule

_DATA_DIR = Path(__file__).resolve().parent / "data"

AVAILABLE_TEMPLATES: dict[str, str] = {
    "shell": "Safe shell commands (git, tests, inspection) with approval for services and strict deny on destructive commands",
    "filesystem": "Path-scoped workspace reads, approval for code changes, strict deny on secrets (.env, keys, certs)",
    "postgres": "Read-only SQL queries allowed, mutations and DDL approval-gated, drop/truncate strictly denied",
    "github": "Read-only repo/issue/PR queries, approval for PRs and issues, strict deny on repo deletion and force push",
    "stripe": "Financial lookups allowed, charge and refund mutations approval-gated, payout and key manipulation denied",
    "aws": "Resource describe/list queries allowed, provisioning approval-gated, deletion strictly denied",
    "kubernetes": "Cluster state queries allowed, workload rollouts/scaling approval-gated, deletion strictly denied",
}


def list_templates() -> list[str]:
    """Return sorted list of available template names."""
    return sorted(AVAILABLE_TEMPLATES.keys())


def get_template_path(name: str) -> Path:
    """Return the filesystem path to a template JSON file."""
    normalized = name.strip().lower()
    if normalized not in AVAILABLE_TEMPLATES:
        raise KeyError(f"Unknown policy template '{name}'. Available templates: {', '.join(list_templates())}")
    path = _DATA_DIR / f"{normalized}.json"
    if not path.is_file():
        raise FileNotFoundError(f"Template file '{path}' not found")
    return path


def get_template_dict(name: str) -> dict[str, Any]:
    """Load a template as a Python dictionary."""
    path = get_template_path(name)
    with open(path, "r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    return data


def get_template_policy(name: str) -> Policy:
    """Load and strictly validate a template as a frozen Policy instance."""
    data = get_template_dict(name)
    return Policy.from_mapping(data)


def deduplicate_policy_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate rules in a policy dictionary while preserving insertion order.

    Rules are considered duplicates if their canonical serialized representation
    is identical.
    """
    if "rules" not in data or not isinstance(data["rules"], list):
        return data

    seen: set[str] = set()
    deduped_rules: list[dict[str, Any]] = []

    for rule in data["rules"]:
        canonical_key = canonicalize_frozen(rule)
        if canonical_key not in seen:
            seen.add(canonical_key)
            deduped_rules.append(rule)

    result = dict(data)
    result["rules"] = deduped_rules
    return result


def deduplicate_policy_rules(policy: Policy) -> Policy:
    """Deduplicate rules in a Policy instance while preserving order.

    Returns a new immutable Policy instance with duplicate rules eliminated.
    """
    seen: set[str] = set()
    deduped: list[Rule] = []

    for rule in policy.rules:
        # Build canonical dict representation of the rule
        rule_dict = {
            "effect": rule.effect.value.lower(),
            "tool": rule.tool,
            "action": rule.action,
            "agent_id": rule.agent_id,
            "resource": rule.resource
            if isinstance(rule.resource, str)
            else (
                "*"
                if getattr(rule.resource, "is_wildcard", False) or rule.resource.__class__.__name__ == "AnyResource"
                else None
            ),
            "resource_kind": rule.resource_kind,
            "case_sensitive": rule.case_sensitive,
            "conditions": [{"field": c.field, "operator": c.operator, "value": c.value} for c in rule.conditions],
            "constraints": rule.constraints,
            "schema_hash": rule.schema_hash,
        }
        canonical_key = canonicalize_frozen(rule_dict)
        if canonical_key not in seen:
            seen.add(canonical_key)
            deduped.append(rule)

    return Policy(
        rules=tuple(deduped),
        strict_arguments=policy.strict_arguments,
        tool_schemas=dict(policy.tool_schemas),
    )


__all__ = [
    "AVAILABLE_TEMPLATES",
    "list_templates",
    "get_template_path",
    "get_template_dict",
    "get_template_policy",
    "deduplicate_policy_dict",
    "deduplicate_policy_rules",
]
