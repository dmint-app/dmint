"""Comprehensive test suite for dmint-policy-manager skill.

Verifies:
1. Basic local policy creation.
2. Basic MCP policy creation.
3. Remote authenticated MCP.
4. User asks for read-only.
5. User asks for read + write.
6. User asks for destructive permission.
7. Ambiguous permission request.
8. MCP discovery failure.
9. Authentication failure.
10. CLI installation failure.
11. Policy verification failure.
12. Successful verification.
13. User asks to modify a policy.
14. Skill refuses direct JSON editing.
15. Multi-MCP policy creation.
16. Unknown MCP tool.
17. Partial MCP discovery failure.
18. Generated policy is never manually modified.
19. Fundamental enforcement invariant (agent cannot bypass proxy).
20. Non-technical language guidance.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from dmint.skills import (
    DMINT_POLICY_MANAGER_SKILL,
    POLICY_MANAGER_SKILL_NAME,
    get_skill_path,
    load_policy_manager_skill,
)


class TestPolicyManagerSkill(unittest.TestCase):
    """Verify that dmint-policy-manager instructions strictly enforce all Dmint architecture and safety invariants."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.skill_text = load_policy_manager_skill()
        cls.skill_path = get_skill_path()

    def test_skill_file_exists_and_has_valid_frontmatter(self) -> None:
        """Skill must exist on disk with correct YAML frontmatter and name."""
        self.assertTrue(self.skill_path.exists(), f"Skill file does not exist at {self.skill_path}")
        self.assertEqual(POLICY_MANAGER_SKILL_NAME, "dmint-policy-manager")
        self.assertTrue(self.skill_text.startswith("---"))
        self.assertIn("name: dmint-policy-manager", self.skill_text)
        self.assertIn("description:", self.skill_text)

    # Scenario 1: Basic local policy creation
    def test_scenario_01_basic_local_policy_creation(self) -> None:
        """Skill must specify 'dmint create-policy -f ... -o ... --tools ...' for local tools without executing code."""
        self.assertIn("dmint create-policy", self.skill_text)
        self.assertIn("--tools", self.skill_text)
        self.assertIn("ast.parse", self.skill_text)
        self.assertIn("without executing any code", self.skill_text)
        self.assertIn("dmint verify-policy", self.skill_text)

    # Scenario 2: Basic MCP policy creation
    def test_scenario_02_basic_mcp_policy_creation(self) -> None:
        """Skill must specify 'dmint create-mcp-policy --command ... --args ...' and output both policy.json and mcp_protection.json."""
        self.assertIn("dmint create-mcp-policy", self.skill_text)
        self.assertIn("--command", self.skill_text)
        self.assertIn("--args", self.skill_text)
        self.assertIn("--integration-id", self.skill_text)
        self.assertIn("policy.json", self.skill_text)
        self.assertIn("mcp_protection.json", self.skill_text)

    # Scenario 3: Remote authenticated MCP
    def test_scenario_03_remote_authenticated_mcp(self) -> None:
        """Skill must support remote MCP via streamable-http and handle OAuth browser sign-in."""
        self.assertIn("streamable-http", self.skill_text)
        self.assertIn("--url", self.skill_text)
        self.assertIn("browser", self.skill_text.lower())
        self.assertIn("oauth", self.skill_text.lower())

    # Scenario 4: User asks for read-only
    def test_scenario_04_user_asks_for_read_only(self) -> None:
        """When user requests read-only, skill must only permit read/view and never grant write or delete."""
        self.assertIn("read", self.skill_text.lower())
        self.assertIn("Least Privilege", self.skill_text)
        # Invariant: do not grant write or delete
        pattern = re.compile(r"read.*do not grant write or delete", re.IGNORECASE | re.DOTALL)
        self.assertTrue(
            pattern.search(self.skill_text) or "do not grant write or delete" in self.skill_text.lower(),
            "Skill must instruct never to grant write or delete when user requests read",
        )

    # Scenario 5: User asks for read + write
    def test_scenario_05_user_asks_for_read_and_write(self) -> None:
        """When user requests read + write, skill handles multi-action scope while keeping destructive actions blocked."""
        self.assertIn("read", self.skill_text.lower())
        self.assertIn("create", self.skill_text.lower())
        self.assertIn("approval", self.skill_text.lower())

    # Scenario 6: User asks for destructive permission
    def test_scenario_06_user_asks_for_destructive_permission(self) -> None:
        """When user requests destructive actions (delete, drop), skill mandates explicit clarification or approval."""
        self.assertIn("delete", self.skill_text.lower())
        self.assertIn("Clarify Destructive Actions", self.skill_text)
        self.assertIn("approval", self.skill_text.lower())

    # Scenario 7: Ambiguous permission request
    def test_scenario_07_ambiguous_permission_request(self) -> None:
        """When user request is ambiguous, skill instructs assistant to stop and ask clarifying questions instead of guessing."""
        self.assertIn("Never guess permissions", self.skill_text)
        self.assertIn("Unclear user request", self.skill_text)

    # Scenario 8: MCP discovery failure
    def test_scenario_08_mcp_discovery_failure(self) -> None:
        """If MCP discovery fails, skill must fail closed: stop immediately, explain plainly, and never guess a policy."""
        self.assertIn("Fail closed", self.skill_text)
        self.assertIn("Tool/Server not found", self.skill_text)
        self.assertIn("DO NOT fallback to writing JSON manually", self.skill_text)

    # Scenario 9: Authentication failure
    def test_scenario_09_authentication_failure(self) -> None:
        """If authentication is needed or fails, skill explains login requirement in plain language."""
        self.assertIn("Authentication required", self.skill_text)
        self.assertIn("sign in", self.skill_text.lower())

    # Scenario 10: CLI installation failure
    def test_scenario_10_cli_installation_failure(self) -> None:
        """Skill must check 'dmint --version', attempt 'pip install dmint', and if that fails, stop without creating JSON."""
        self.assertIn("dmint --version", self.skill_text)
        self.assertIn("pip install dmint", self.skill_text)
        self.assertIn("DO NOT fallback to writing JSON manually", self.skill_text)

    # Scenario 11: Policy verification failure
    def test_scenario_11_policy_verification_failure(self) -> None:
        """If verify-policy fails, skill must never treat policy as ready or claim success."""
        self.assertIn("Verification failed", self.skill_text)
        self.assertIn("Never claim success on a failed verification", self.skill_text)
        self.assertIn("Mandatory Offline Verification", self.skill_text)

    # Scenario 12: Successful verification
    def test_scenario_12_successful_verification(self) -> None:
        """When verify-policy exits with 0, skill provides a clear, structured output report."""
        self.assertIn("dmint verify-policy policy.json", self.skill_text)
        self.assertIn("Standard Output Report Template", self.skill_text)
        self.assertIn("Verified & Safe", self.skill_text)

    # Scenario 13: User asks to modify a policy
    def test_scenario_13_user_asks_to_modify_policy(self) -> None:
        """When user asks to change permissions, skill updates natural language requirements and regenerates via CLI."""
        self.assertIn("Workflow 3: Changing an Existing Policy", self.skill_text)
        self.assertIn("Update Intent", self.skill_text)
        self.assertIn("Re-Run the CLI", self.skill_text)
        self.assertIn("Re-Verify", self.skill_text)

    # Scenario 14: Skill refuses direct JSON editing
    def test_scenario_14_skill_refuses_direct_json_editing(self) -> None:
        """Skill must explicitly forbid manual editing of policy.json under all circumstances."""
        self.assertIn("NEVER Manually Write, Modify, or Patch Policy JSON", self.skill_text)
        self.assertIn("WRONG: Open policy.json", self.skill_text)
        self.assertIn("FORBIDDEN", self.skill_text)

    # Scenario 15: Multi-MCP policy creation
    def test_scenario_15_multi_mcp_policy_creation(self) -> None:
        """When protecting multiple MCP servers, skill uses distinct integration IDs and explains namespace isolation."""
        self.assertIn("Workflow 5: Protecting Multiple MCP Servers", self.skill_text)
        self.assertIn("Preserve Distinct Identities", self.skill_text)
        self.assertIn("Namespace Isolation", self.skill_text)
        self.assertIn("--integration-id", self.skill_text)

    # Scenario 16: Unknown MCP tool
    def test_scenario_16_unknown_mcp_tool(self) -> None:
        """Skill forbids inventing tool names or schemas not discovered by the CLI."""
        self.assertIn("Never Invent Capabilities or Guess Permissions", self.skill_text)
        self.assertIn("must never invent tool names", self.skill_text.lower())

    # Scenario 17: Partial MCP discovery failure
    def test_scenario_17_partial_mcp_discovery_failure(self) -> None:
        """If discovery fails on one of multiple servers, skill forbids creating a partial policy."""
        self.assertIn("Atomic Safety", self.skill_text)
        self.assertIn("do not create a partial policy", self.skill_text.lower())

    # Scenario 18: Generated policy is never manually modified
    def test_scenario_18_generated_policy_never_manually_modified(self) -> None:
        """Skill mandates warning the user in every report that generated files must never be edited manually."""
        self.assertIn("Treat Generated Policies as Read-Only Artifacts", self.skill_text)
        self.assertIn("Do not edit them by hand", self.skill_text)
        self.assertIn("Important Note on Generated Files", self.skill_text)

    # Scenario 19: Fundamental enforcement invariant
    def test_scenario_19_fundamental_enforcement_invariant(self) -> None:
        """Skill must explicitly explain that Dmint does not secure an MCP server if the agent bypasses the proxy."""
        expected_text = (
            "Dmint does not secure an MCP server if the agent can bypass the protected "
            "execution path and call the original capability directly."
        )
        self.assertIn(expected_text, self.skill_text)

    # Scenario 20: Non-technical language guidance
    def test_scenario_20_non_technical_language_guidance(self) -> None:
        """Skill must provide explicit guidance translating technical jargon into plain conversational language."""
        self.assertIn("Language Rules for Non-Technical Users", self.skill_text)
        self.assertIn("Do NOT Say (Technical Jargon)", self.skill_text)
        self.assertIn("DO Say (Non-Technical Language)", self.skill_text)

    def test_version_matches_cli(self) -> None:
        """dmint-skills version must be 2.0.0 to match dmint monorepo."""
        from dmint import skills as dmint_skills
        import re

        self.assertEqual(dmint_skills.__version__, "2.0.0")
        pyproject_text = (Path(__file__).resolve().parent.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'version\s*=\s*"([^"]+)"', pyproject_text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "2.0.0")


if __name__ == "__main__":
    unittest.main()
