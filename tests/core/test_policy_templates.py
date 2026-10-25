"""Unit tests for Dmint policy templates, per-harness policies, and deduplication engine."""

import unittest

from dmint.core.models import Decision
from dmint.core.policy import Policy, Rule
from dmint.templates import (
    AVAILABLE_TEMPLATES,
    HARNESS_TEMPLATES,
    deduplicate_policy_dict,
    deduplicate_policy_rules,
    get_harness_template_dict,
    get_harness_template_policy,
    get_template_dict,
    get_template_path,
    get_template_policy,
    list_harness_templates,
    list_templates,
)

EXPECTED_TEMPLATES = {
    "shell",
    "filesystem",
    "postgres",
    "github",
    "stripe",
    "aws",
    "kubernetes",
}

EXPECTED_HARNESS_TEMPLATES = {
    "claude-code",
    "codex",
    "opencode",
    "cursor",
    "windsurf",
    "cline",
}


class PolicyTemplatesTestCase(unittest.TestCase):
    def test_list_templates_contains_all_expected(self) -> None:
        templates = list_templates()
        self.assertEqual(set(templates), EXPECTED_TEMPLATES)
        for t in templates:
            self.assertIn(t, AVAILABLE_TEMPLATES)

    def test_list_harness_templates_contains_all_expected(self) -> None:
        h_templates = list_harness_templates()
        self.assertEqual(set(h_templates), EXPECTED_HARNESS_TEMPLATES)
        for h in h_templates:
            self.assertIn(h, HARNESS_TEMPLATES)
            pol = get_harness_template_policy(h)
            self.assertIsInstance(pol, Policy)
            self.assertGreater(len(pol.rules), 100)

    def test_get_template_path_unknown_raises_key_error(self) -> None:
        with self.assertRaises(KeyError):
            get_template_path("non_existent_template")
        with self.assertRaises(KeyError):
            get_harness_template_dict("non_existent_harness")

    def test_all_templates_load_and_validate(self) -> None:
        for name in EXPECTED_TEMPLATES | EXPECTED_HARNESS_TEMPLATES:
            policy = get_template_policy(name)
            self.assertIsInstance(policy, Policy)
            self.assertGreater(len(policy.rules), 0)

            for rule in policy.rules:
                self.assertIsInstance(rule, Rule)
                self.assertIn(
                    rule.effect,
                    (Decision.ALLOW, Decision.DENY, Decision.APPROVAL_REQUIRED),
                )
                self.assertTrue(rule.tool)
                self.assertTrue(rule.action)

    def test_all_templates_have_no_duplicate_rules(self) -> None:
        for name in EXPECTED_TEMPLATES | EXPECTED_HARNESS_TEMPLATES:
            data = get_template_dict(name)
            original_count = len(data["rules"])
            deduped = deduplicate_policy_dict(data)
            self.assertEqual(
                len(deduped["rules"]),
                original_count,
                f"Template '{name}' contains duplicate rules!",
            )

    def test_deduplicate_policy_dict_removes_duplicates(self) -> None:
        policy_dict = {
            "rules": [
                {"effect": "allow", "tool": "shell", "action": "execute", "resource": "ls"},
                {"effect": "allow", "tool": "shell", "action": "execute", "resource": "ls"},
                {"effect": "deny", "tool": "shell", "action": "execute", "resource": "rm -rf /"},
                {"effect": "allow", "tool": "shell", "action": "execute", "resource": "ls"},
            ]
        }
        deduped = deduplicate_policy_dict(policy_dict)
        self.assertEqual(len(deduped["rules"]), 2)
        self.assertEqual(deduped["rules"][0]["resource"], "ls")
        self.assertEqual(deduped["rules"][1]["resource"], "rm -rf /")

    def test_deduplicate_policy_rules_removes_duplicates(self) -> None:
        policy = Policy(
            rules=(
                Rule.allow("postgres", "select"),
                Rule.allow("postgres", "select"),
                Rule.deny("postgres", "drop_table"),
            )
        )
        self.assertEqual(len(policy.rules), 3)
        deduped = deduplicate_policy_rules(policy)
        self.assertEqual(len(deduped.rules), 2)
        self.assertEqual(deduped.rules[0].action, "select")
        self.assertEqual(deduped.rules[1].action, "drop_table")

    def test_deduplicate_policy_dict_non_list_noop(self) -> None:
        non_list_dict = {"rules": "invalid"}
        result = deduplicate_policy_dict(non_list_dict)
        self.assertEqual(result, non_list_dict)
