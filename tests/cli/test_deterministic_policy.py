"""Phase 7 tests: Deterministic policy generation.

Verifies:
1. Generated policies conform exactly to Policy.from_mapping().
2. Default behavior remains deny.
3. Every rule has required fields (effect, tool, action).
4. No LLM authorization delegation — deterministic validation is authoritative.
5. Policy generation is reproducible: same input → byte-equivalent JSON output.
6. Tool and rule ordering is deterministic.
7. JSON serialization is deterministic (sort_keys, consistent whitespace).
8. No secrets in policies.
9. Missing/failed MCP source fails closed (Req 14/15).
10. Partial discovery across multi-server setup aborts entirely.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.policy import Decision, Policy, PolicyError, ToolRequest
from dmint import TrustedContext
from dmint.cli.errors import CLIError, PolicyValidationError
from dmint.cli.create_mcp_policy import (
    _assert_no_secrets_in_policy,
    _sort_integrations_deterministically,
    _sort_tools_deterministically,
    _validate_rule_completeness,
    run_create_mcp_policy_wizard,
)
from dmint.cli.io_utils import (
    _deterministic_json,
    atomic_write_json,
    atomic_write_policy_json,
)


def _req(tool: str, action: str, resource: str = "*") -> ToolRequest:
    return ToolRequest(
        request_id="r",
        agent_id="a",
        tool=tool,
        action=action,
        resource=resource,
        arguments={},
        context=TrustedContext({}),
    )


class DeterministicJsonTests(unittest.TestCase):
    """Req 12: JSON serialization is deterministic."""

    def test_same_dict_same_bytes(self):
        data = {"rules": [{"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"}]}
        s1 = _deterministic_json(data)
        s2 = _deterministic_json(data)
        self.assertEqual(s1, s2)

    def test_key_order_does_not_affect_output(self):
        d1 = {"rules": [{"tool": "postgres", "effect": "allow", "action": "query"}]}
        d2 = {"rules": [{"effect": "allow", "tool": "postgres", "action": "query"}]}
        self.assertEqual(_deterministic_json(d1), _deterministic_json(d2))

    def test_nested_keys_are_sorted(self):
        s = _deterministic_json({"z": 1, "a": 2})
        parsed = json.loads(s)
        keys = list(parsed.keys())
        self.assertEqual(keys, sorted(keys))

    def test_atomic_write_json_produces_deterministic_file(self):
        data = {
            "rules": [
                {"effect": "allow", "tool": "alpha", "action": "read", "resource": "*"},
                {"effect": "deny", "tool": "beta", "action": "delete"},
            ]
        }
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.json"
            atomic_write_json(p, data)
            content1 = p.read_text()
            atomic_write_json(p, data)
            content2 = p.read_text()
        self.assertEqual(content1, content2)

    def test_atomic_write_json_ends_with_newline(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.json"
            atomic_write_json(p, {"rules": []})
            self.assertTrue(p.read_text().endswith("\n"))

    def test_atomic_write_json_chmod_0600(self):
        import stat

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.json"
            atomic_write_json(p, {"rules": []})
            mode = p.stat().st_mode
            # Owner must have rw, group and other must have none
            self.assertTrue(mode & stat.S_IRUSR)
            self.assertTrue(mode & stat.S_IWUSR)
            self.assertFalse(mode & stat.S_IRGRP)
            self.assertFalse(mode & stat.S_IROTH)

    def test_atomic_write_policy_json_uses_canonical_to_dict(self):
        """atomic_write_policy_json writes Policy.to_dict() output — not arbitrary LLM dicts."""
        policy = Policy.from_mapping({"rules": [{"effect": "allow", "tool": "pg", "action": "query", "resource": "*"}]})
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.json"
            atomic_write_policy_json(p, policy)
            content = json.loads(p.read_text())
        self.assertIn("rules", content)
        self.assertEqual(content["rules"][0]["effect"], "allow")
        self.assertEqual(content["rules"][0]["tool"], "pg")
        self.assertEqual(content["rules"][0]["action"], "query")


class GoldenOutputTests(unittest.TestCase):
    """Req 9: Same input → byte-equivalent output."""

    def _write_and_read(self, policy: Policy) -> str:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.json"
            atomic_write_policy_json(p, policy)
            return p.read_text()

    def test_single_rule_golden(self):
        policy = Policy.from_mapping(
            {"rules": [{"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"}]}
        )
        out1 = self._write_and_read(policy)
        out2 = self._write_and_read(policy)
        self.assertEqual(out1, out2)

    def test_multi_rule_ordering_is_stable(self):
        """Req 11: Rule ordering is deterministic — Policy preserves insertion order from mapping."""
        mapping = {
            "rules": [
                {"effect": "allow", "tool": "analytics", "action": "query", "resource": "*"},
                {"effect": "deny", "tool": "analytics", "action": "delete"},
                {"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"},
            ]
        }
        policy = Policy.from_mapping(mapping)
        out1 = self._write_and_read(policy)
        out2 = self._write_and_read(policy)
        self.assertEqual(out1, out2)
        parsed = json.loads(out1)
        # Verify rule ordering is preserved exactly
        self.assertEqual(parsed["rules"][0]["tool"], "analytics")
        self.assertEqual(parsed["rules"][0]["action"], "query")
        self.assertEqual(parsed["rules"][1]["action"], "delete")
        self.assertEqual(parsed["rules"][2]["tool"], "postgres")


class RuleCompletenessValidationTests(unittest.TestCase):
    """Req 3 & 4: Every generated rule must have required fields."""

    def test_valid_rule_passes(self):
        _validate_rule_completeness([{"effect": "allow", "tool": "pg", "action": "query", "resource": "*"}])

    def test_missing_effect_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"tool": "pg", "action": "query"}])
        self.assertIn("missing required fields", str(ctx.exception))
        self.assertIn("effect", str(ctx.exception))

    def test_missing_tool_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"effect": "allow", "action": "query"}])
        self.assertIn("missing required fields", str(ctx.exception))
        self.assertIn("tool", str(ctx.exception))

    def test_missing_action_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"effect": "allow", "tool": "pg"}])
        self.assertIn("missing required fields", str(ctx.exception))
        self.assertIn("action", str(ctx.exception))

    def test_invalid_effect_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"effect": "ALLOW", "tool": "pg", "action": "q"}])
        self.assertIn("invalid effect", str(ctx.exception))

    def test_effect_llm_truthy_shortcut_fails(self):
        """LLM cannot produce truthy shortcuts — only exact strings are valid."""
        for bad_effect in ("Allow", "ALLOW", "True", "yes", "1", "permitted", "grant"):
            with self.assertRaises(PolicyError, msg=f"Should fail for effect={bad_effect!r}"):
                _validate_rule_completeness([{"effect": bad_effect, "tool": "t", "action": "a"}])

    def test_resource_null_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness([{"effect": "allow", "tool": "t", "action": "a", "resource": None}])
        self.assertIn("'resource': null", str(ctx.exception))

    def test_resource_omitted_is_valid(self):
        # Omitting resource entirely is valid (means "no resource concept")
        _validate_rule_completeness([{"effect": "allow", "tool": "t", "action": "a"}])

    def test_non_dict_rule_fails(self):
        with self.assertRaises(PolicyError) as ctx:
            _validate_rule_completeness(["allow t a *"])
        self.assertIn("must be a mapping", str(ctx.exception))


class NoSecretsInPolicyTests(unittest.TestCase):
    """Req 13: No secrets in policies."""

    def test_clean_policy_passes(self):
        _assert_no_secrets_in_policy({"rules": [{"effect": "allow", "tool": "pg", "action": "query", "resource": "*"}]})

    def test_secret_key_in_rule_fails(self):
        with self.assertRaises(CLIError) as ctx:
            _assert_no_secrets_in_policy(
                {"rules": [{"effect": "allow", "tool": "pg", "action": "query", "access_token": "tok_abc123"}]}
            )
        self.assertIn("secret field", str(ctx.exception))

    def test_bearer_token_in_value_fails(self):
        with self.assertRaises(CLIError) as ctx:
            _assert_no_secrets_in_policy(
                {
                    "rules": [
                        {"effect": "allow", "tool": "pg", "action": "query", "resource": "bearer mysecrettoken12345"}
                    ]
                }
            )
        self.assertIn("embedded credential", str(ctx.exception))

    def test_sk_key_in_value_fails(self):
        with self.assertRaises(CLIError) as ctx:
            _assert_no_secrets_in_policy(
                {"rules": [{"effect": "allow", "tool": "pg", "action": "query", "resource": "sk-proj-abc123def456"}]}
            )
        self.assertIn("embedded credential", str(ctx.exception))


class DeterministicSortingTests(unittest.TestCase):
    """Req 10 & 11: Tool and integration ordering is deterministic."""

    def test_tools_sorted_by_name(self):
        tools = [
            {"name": "zebra", "description": "z"},
            {"name": "alpha", "description": "a"},
            {"name": "middle", "description": "m"},
        ]
        sorted_tools = _sort_tools_deterministically(tools)
        names = [t["name"] for t in sorted_tools]
        self.assertEqual(names, ["alpha", "middle", "zebra"])

    def test_tools_already_sorted_unchanged(self):
        tools = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        self.assertEqual(_sort_tools_deterministically(tools), tools)

    def test_integrations_sorted_by_integration_id(self):
        class FakeInteg:
            def __init__(self, id_):
                self.integration_id = id_

        integs = [FakeInteg("z-server"), FakeInteg("a-server"), FakeInteg("m-server")]
        sorted_ = _sort_integrations_deterministically(integs)
        ids = [i.integration_id for i in sorted_]
        self.assertEqual(ids, ["a-server", "m-server", "z-server"])


class DefaultDenyTests(unittest.TestCase):
    """Req 3: Default behavior remains deny."""

    def test_no_matching_rule_is_denied(self):
        policy = Policy.from_mapping(
            {"rules": [{"effect": "allow", "tool": "postgres", "action": "query", "resource": "*"}]}
        )
        # Different tool — no rule matches
        result = policy.evaluate(_req("other_tool", "other_action"))
        self.assertEqual(result, Decision.DENY)

    def test_empty_rules_denies_everything(self):
        policy = Policy.from_mapping({"rules": []})
        self.assertEqual(policy.evaluate(_req("any_tool", "any_action")), Decision.DENY)

    def test_allow_rule_does_not_affect_other_tools(self):
        policy = Policy.from_mapping({"rules": [{"effect": "allow", "tool": "pg", "action": "query", "resource": "*"}]})
        self.assertEqual(policy.evaluate(_req("pg", "query")), Decision.ALLOW)
        self.assertEqual(policy.evaluate(_req("pg", "delete")), Decision.DENY)
        self.assertEqual(policy.evaluate(_req("other", "query")), Decision.DENY)


class PartialDiscoveryFailsClosedTests(unittest.TestCase):
    """Req 14 & 15: Missing or failed MCP source must fail closed."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.md_file = Path(self.temp_dir.name) / "access.md"
        self.md_file.write_text("Allow read-only queries.", encoding="utf-8")
        self.json_file = Path(self.temp_dir.name) / "policy.json"
        self.config_file = Path(self.temp_dir.name) / "mcp_protection.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_empty_tool_discovery_aborts(self, mock_client_cls, mock_discover):
        """Req 14: No tools discovered → fail closed, no partial policy written."""
        mock_discover.return_value = []  # Server exposes zero tools
        mock_client_cls.return_value = MagicMock()

        with self.assertRaises(CLIError) as ctx:
            run_create_mcp_policy_wizard(
                command="mcp-server-postgres",
                integration_id="postgres",
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                config_output_file=self.config_file,
                api_key="sk-test",
                non_interactive=True,
                auto_confirm=True,
            )
        self.assertIn("No tools discovered", str(ctx.exception))
        # Must not have written any partial policy file
        self.assertFalse(self.json_file.exists(), "Partial policy must NOT be written on discovery failure")

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_discovery_exception_aborts_all_servers(self, mock_client_cls, mock_discover):
        """Req 15: Discovery exception on any server aborts rather than generating partial artifact."""
        # Single server raises during discovery
        mock_discover.side_effect = Exception("Connection refused: server unreachable")
        mock_client_cls.return_value = MagicMock(model="gpt-4o-mini", base_url="https://api.openai.com/v1")

        with self.assertRaises(CLIError) as ctx:
            run_create_mcp_policy_wizard(
                command="mcp-server-postgres",
                integration_id="postgres",
                access_md_file=self.md_file,
                output_json_file=self.json_file,
                config_output_file=self.config_file,
                api_key="sk-test",
                non_interactive=True,
                auto_confirm=False,
            )
        err = str(ctx.exception)
        # Must cite the integration that failed and the abort directive
        self.assertIn("Aborting policy generation", err)
        self.assertIn("postgres", err)
        # Must not have written any partial policy file
        self.assertFalse(self.json_file.exists(), "Partial policy must NOT be written on discovery failure")


class PolicySchemaConformanceTests(unittest.TestCase):
    """Req 1 & 2: Generated policies must conform exactly to Policy.from_mapping(). No alternate schema."""

    def test_policy_from_mapping_round_trip(self):
        """Policy.to_dict() → Policy.from_mapping() is stable (no data loss)."""
        mapping = {
            "rules": [
                {"effect": "allow", "tool": "pg", "action": "query", "resource": "*"},
                {"effect": "deny", "tool": "pg", "action": "delete"},
                {
                    "effect": "approval_required",
                    "tool": "pg",
                    "action": "drop",
                    "resource": "*",
                    "agent_id": "agent-007",
                },
            ]
        }
        policy = Policy.from_mapping(mapping)
        canonical = policy.to_dict()
        policy2 = Policy.from_mapping(canonical)
        # Policies should be equivalent
        self.assertEqual(len(policy.rules), len(policy2.rules))
        for r1, r2 in zip(policy.rules, policy2.rules):
            self.assertEqual(r1.tool, r2.tool)
            self.assertEqual(r1.action, r2.action)
            self.assertEqual(r1.effect, r2.effect)

    def test_only_rules_key_allowed_at_top_level(self):
        """Policy.from_mapping() rejects unknown top-level keys."""
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"rules": [], "metadata": "extra"})

    def test_no_unknown_keys_in_rule_accepted(self):
        """Policy.from_mapping() rejects unknown rule-level keys."""
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"rules": [{"effect": "allow", "tool": "t", "action": "a", "extra_key": "value"}]})

    def test_atomic_write_policy_json_round_trip(self):
        """File written by atomic_write_policy_json must be loadable by Policy.from_mapping()."""
        policy = Policy.from_mapping({"rules": [{"effect": "allow", "tool": "pg", "action": "query", "resource": "*"}]})
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.json"
            atomic_write_policy_json(p, policy)
            loaded = json.loads(p.read_text())
        # Must be re-parseable by Policy.from_mapping without error
        reparsed = Policy.from_mapping(loaded)
        self.assertEqual(len(reparsed.rules), 1)
        self.assertEqual(reparsed.rules[0].tool, "pg")


class LLMOutputUntrustedTests(unittest.TestCase):
    """Req 7 & 8: No authorization is delegated to LLM; invalid output is rejected."""

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_llm_missing_effect_fails_rejected(self, mock_client_cls, mock_discover):
        """LLM output missing 'effect' is rejected deterministically, not silently accepted."""
        mock_discover.return_value = [
            {
                "name": "query",
                "description": "q",
                "input_schema": {},
                "integration_id": "postgres",
                "capability": "mcp.postgres.query",
                "annotations": {},
            }
        ]
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        # LLM omits required 'effect' field in all retries
        mock_client.chat_completion.return_value = json.dumps(
            {"type": "policy_ready", "rules": [{"tool": "postgres", "action": "query", "resource": "*"}]}
        )
        mock_client_cls.return_value = mock_client

        import tempfile

        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "access.md"
            md.write_text("Allow read-only access.", encoding="utf-8")
            with self.assertRaises(PolicyValidationError) as ctx:
                run_create_mcp_policy_wizard(
                    command="mcp-server-postgres",
                    integration_id="postgres",
                    access_md_file=md,
                    output_json_file=Path(d) / "policy.json",
                    config_output_file=Path(d) / "mcp_protection.json",
                    api_key="sk-test",
                    non_interactive=True,
                    auto_confirm=True,
                )
        self.assertIn("Dmint validation failed", str(ctx.exception))

    @patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock)
    @patch("dmint.cli.create_mcp_policy.OpenAICompatClient")
    def test_llm_secret_in_rule_rejected(self, mock_client_cls, mock_discover):
        """LLM output containing a secret field is rejected by _assert_no_secrets_in_policy."""
        mock_discover.return_value = [
            {
                "name": "query",
                "description": "q",
                "input_schema": {},
                "integration_id": "postgres",
                "capability": "mcp.postgres.query",
                "annotations": {},
            }
        ]
        mock_client = MagicMock()
        mock_client.model = "gpt-4o-mini"
        mock_client.base_url = "https://api.openai.com/v1"
        mock_client.chat_completion.return_value = json.dumps(
            {
                "type": "policy_ready",
                "rules": [
                    {
                        "effect": "allow",
                        "tool": "postgres",
                        "action": "query",
                        "resource": "*",
                        "access_token": "tok_supersecret",
                    }
                ],
            }
        )
        mock_client_cls.return_value = mock_client

        import tempfile

        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "access.md"
            md.write_text("Allow read-only access.", encoding="utf-8")
            with self.assertRaises(PolicyValidationError) as ctx:
                run_create_mcp_policy_wizard(
                    command="mcp-server-postgres",
                    integration_id="postgres",
                    access_md_file=md,
                    output_json_file=Path(d) / "policy.json",
                    config_output_file=Path(d) / "mcp_protection.json",
                    api_key="sk-test",
                    non_interactive=True,
                    auto_confirm=True,
                )
        self.assertIn("Dmint validation failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
