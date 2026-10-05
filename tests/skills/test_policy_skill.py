"""Unit tests for embedded policy skill prompt (src/dmint_skills/skill.py)."""

import unittest

from dmint.skills.skill import DMINT_POLICY_SYSTEM_PROMPT


class PolicySkillPromptTests(unittest.TestCase):
    def test_skill_prompt_contains_exact_supported_effects(self):
        self.assertIn('"allow"', DMINT_POLICY_SYSTEM_PROMPT)
        self.assertIn('"deny"', DMINT_POLICY_SYSTEM_PROMPT)
        self.assertIn('"approval_required"', DMINT_POLICY_SYSTEM_PROMPT)

    def test_skill_prompt_contains_exact_condition_operators(self):
        for op in ("equals", "notEquals", "in", "contains", "startsWith", "endsWith"):
            self.assertIn(f'"{op}"', DMINT_POLICY_SYSTEM_PROMPT)

    def test_skill_prompt_emphasizes_least_privilege_and_no_permission_expansion(self):
        self.assertIn("Least Privilege", DMINT_POLICY_SYSTEM_PROMPT)
        self.assertIn("No Permission Expansion", DMINT_POLICY_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
