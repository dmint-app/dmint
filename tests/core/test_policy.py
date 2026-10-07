import unittest

from dmint import ANY_RESOURCE, NO_RESOURCE, Condition, Decision, Policy, Rule, ToolRequest, TrustedContext
from dmint.policy import policy_digest
from dmint.errors import PolicyError


def make_request(**changes):
    values = {
        "request_id": "request-1",
        "agent_id": "agent-a",
        "tool": "database",
        "action": "read",
        "resource": "users/123",
        "arguments": {"user_id": 123},
        "context": TrustedContext({"environment": "development"}),
    }
    values.update(changes)
    return ToolRequest(**values)


class PolicyTests(unittest.TestCase):
    def test_exact_allow(self):
        policy = Policy((Rule.allow("database", "read", agent_id="agent-a", resource="users/123"),))
        self.assertIs(policy.evaluate(make_request()), Decision.ALLOW)
        self.assertIs(policy.evaluate(make_request(resource="users/999")), Decision.DENY)

    def test_conditions_use_trusted_context(self):
        policy = Policy(
            (
                Rule.allow(
                    "database",
                    "update",
                    resource=ANY_RESOURCE,
                    conditions=(Condition.equals("environment", "development"),),
                ),
            )
        )
        request = make_request(action="update")
        self.assertIs(policy.evaluate(request), Decision.ALLOW)
        self.assertIs(
            policy.evaluate(make_request(action="update", context=TrustedContext({"environment": "production"}))),
            Decision.DENY,
        )

    def test_deny_overrides_allow_regardless_of_rule_order(self):
        allow = Rule.allow("database", "delete")
        deny = Rule.deny("database", "delete", resource="users/123")
        request = make_request(action="delete")
        self.assertIs(Policy((allow, deny)).evaluate(request), Decision.DENY)
        self.assertIs(Policy((deny, allow)).evaluate(request), Decision.DENY)

    def test_default_is_deny(self):
        self.assertIs(Policy().evaluate(make_request()), Decision.DENY)

    def test_decisions_cannot_be_used_as_boolean_authorization(self):
        with self.assertRaises(TypeError):
            bool(Decision.DENY)

    def test_resource_semantics_are_explicit_and_conservative(self):
        no_resource = make_request(resource=NO_RESOURCE)
        targeted = make_request(resource="users/123")

        self.assertIs(Policy((Rule.allow("database", "read"),)).evaluate(no_resource), Decision.ALLOW)
        self.assertIs(Policy((Rule.allow("database", "read"),)).evaluate(targeted), Decision.DENY)
        self.assertIs(
            Policy((Rule.allow("database", "read", resource=ANY_RESOURCE),)).evaluate(targeted),
            Decision.ALLOW,
        )

    def test_mapping_policy_defaults_to_no_resource_not_wildcard(self):
        policy = Policy.from_mapping({"rules": [{"effect": "allow", "tool": "database", "action": "read"}]})
        self.assertIs(policy.evaluate(make_request(resource=NO_RESOURCE)), Decision.ALLOW)
        self.assertIs(policy.evaluate(make_request(resource="users/123")), Decision.DENY)

    def test_malformed_policy_is_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"rules": [{"effect": "allow", "tool": "database", "action": "read", "unknown": True}]})
        with self.assertRaises(PolicyError):
            Policy.from_mapping({"rules": [{"effect": "maybe", "tool": "database", "action": "read"}]})
        with self.assertRaises(PolicyError):
            Policy.from_mapping(
                {"rules": [{"effect": "allow", "tool": "database", "action": "read", "resource": None}]}
            )

    def test_evaluation_is_deterministic(self):
        policy = Policy(
            (
                Rule.allow("database", "read", resource=ANY_RESOURCE),
                Rule.deny("database", "delete", resource=ANY_RESOURCE),
            )
        )
        request = make_request()
        results = [policy.evaluate(request) for _ in range(20)]
        self.assertEqual(results, [Decision.ALLOW] * 20)

    def test_agent_change_is_authorized_separately(self):
        policy = Policy((Rule.allow("database", "read", agent_id="agent-a", resource=ANY_RESOURCE),))
        self.assertIs(policy.evaluate(make_request()), Decision.ALLOW)
        self.assertIs(policy.evaluate(make_request(agent_id="agent-b")), Decision.DENY)

    def test_policy_digest_is_deterministic(self):
        policy_dict = {
            "rules": [
                {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
                {"effect": "deny", "tool": "database", "action": "delete", "resource": "*"},
            ]
        }
        digest1 = policy_digest(policy_dict)
        digest2 = policy_digest(policy_dict)
        policy_obj = Policy.from_mapping(policy_dict)
        digest3 = policy_digest(policy_obj)

        self.assertEqual(digest1, digest2)
        self.assertEqual(digest1, digest3)
        self.assertEqual(len(digest1), 64)

    def test_policy_digest_is_sensitive_to_content_changes(self):
        policy1 = Policy.from_mapping(
            {
                "rules": [
                    {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
                ]
            }
        )
        policy2 = Policy.from_mapping(
            {
                "rules": [
                    {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
                    {"effect": "deny", "tool": "database", "action": "delete", "resource": "*"},
                ]
            }
        )
        policy3 = Policy.from_mapping(
            {
                "rules": [
                    {"effect": "deny", "tool": "database", "action": "read", "resource": "*"},
                ]
            }
        )

        self.assertNotEqual(policy_digest(policy1), policy_digest(policy2))
        self.assertNotEqual(policy_digest(policy1), policy_digest(policy3))
        self.assertNotEqual(policy_digest(policy2), policy_digest(policy3))

    def test_convenience_json_and_dict_serialization(self):
        policy_dict = {
            "rules": [
                {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
            ]
        }
        policy = Policy.from_dict(policy_dict)
        self.assertEqual(len(policy.rules), 1)

        json_str = policy.to_json()
        loaded = Policy.from_json(json_str)
        self.assertEqual(policy_digest(policy), policy_digest(loaded))

    def test_rule_approve_alias(self):
        rule1 = Rule.approval_required("db", "delete")
        rule2 = Rule.approve("db", "delete")
        self.assertEqual(rule1, rule2)
        self.assertIs(rule2.effect, Decision.APPROVAL_REQUIRED)

    def test_concurrent_evaluations_thread_safety(self):
        """Verify thread-safety and isolation of error codes across concurrent evaluations."""
        import concurrent.futures

        policy = Policy(
            [
                Rule.deny("fs", "read", resource="/etc/passwd", resource_kind="path"),
                Rule.allow("fs", "read", resource="/var/log/*.log", resource_kind="path"),
                Rule.approval_required("admin", "restart", resource="*"),
                Rule.deny("admin", "nuke", resource="*"),
            ]
        )

        test_cases = [
            # (tool, action, resource, expected_decision, expected_code)
            ("fs", "read", "/../etc/passwd", Decision.DENY, "DMT_RESOURCE_INVALID"),
            ("fs", "read", "/etc/passwd", Decision.DENY, "DMT_POLICY_DENIED"),
            ("fs", "read", "/var/log/app.log", Decision.ALLOW, None),
            ("admin", "restart", "cluster-1", Decision.APPROVAL_REQUIRED, "DMT_APPROVAL_REQUIRED"),
            ("admin", "nuke", "all", Decision.DENY, "DMT_POLICY_DENIED"),
            ("unknown", "action", "res", Decision.DENY, "DMT_POLICY_DENIED"),
        ]

        def worker(idx: int) -> None:
            # Deterministically cycle through test cases
            tc = test_cases[idx % len(test_cases)]
            tool, action, res, expected_dec, expected_code = tc
            req = make_request(tool=tool, action=action, resource=res)
            dec, code = policy.evaluate_detailed(req)
            self.assertEqual(dec, expected_dec, f"Thread {idx} got unexpected decision {dec}")
            self.assertEqual(code, expected_code, f"Thread {idx} got unexpected code {code}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(worker, i) for i in range(200)]
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def test_evaluator_fails_closed_when_any_candidate_rule_kind_fails(self):
        """ALLOW fs.read on '*' + DENY on '/etc/passwd' (path) + request '/../etc/passwd' => DENY DMT_RESOURCE_INVALID."""
        policy = Policy(
            [
                Rule.allow("fs", "read", resource="*"),
                Rule.deny("fs", "read", resource="/etc/passwd", resource_kind="path"),
            ]
        )
        req = make_request(tool="fs", action="read", resource="/../etc/passwd")
        decision, code = policy.evaluate_detailed(req)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(code, "DMT_RESOURCE_INVALID")

    def test_relative_paths_without_slash_escapes(self):
        """Relative paths escaping start directory fail closed with DMT_RESOURCE_INVALID."""
        policy = Policy(
            [
                Rule.allow("fs", "read", resource="*"),
                Rule.deny("fs", "read", resource="secret.txt", resource_kind="path"),
            ]
        )
        for bad_rel in ("../secret.txt", "dir/../../secret.txt"):
            req = make_request(tool="fs", action="read", resource=bad_rel)
            decision, code = policy.evaluate_detailed(req)
            self.assertEqual(decision, Decision.DENY)
            self.assertEqual(code, "DMT_RESOURCE_INVALID")

    def test_mixed_kind_candidate_rules(self):
        """If ANY candidate rule's kind fails syntax validation, evaluation fails closed."""
        policy = Policy(
            [
                Rule.allow("net", "fetch", resource="api.github.com", resource_kind="host"),
                Rule.deny("net", "fetch", resource="https://api.github.com/admin", resource_kind="url"),
            ]
        )
        # Invalid URL syntax with double-encoded traversal
        req = make_request(tool="net", action="fetch", resource="https://api.github.com/%252e%252e")
        decision, code = policy.evaluate_detailed(req)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(code, "DMT_RESOURCE_INVALID")

    def test_case_insensitive_option_from_policy_json(self):
        """Verify case_sensitive option is configured from policy.json and enforced."""
        import json

        policy_json = json.dumps(
            {
                "rules": [
                    {
                        "effect": "allow",
                        "tool": "fs",
                        "action": "read",
                        "resource": "/var/log/*.log",
                        "resource_kind": "path",
                        "case_sensitive": False,
                    }
                ]
            }
        )
        policy = Policy.from_json(policy_json)
        self.assertEqual(len(policy.rules), 1)
        self.assertFalse(policy.rules[0].case_sensitive)

        # Uppercase input matches when case_sensitive=False
        req = make_request(tool="fs", action="read", resource="/VAR/LOG/APP.LOG")
        decision, code = policy.evaluate_detailed(req)
        self.assertEqual(decision, Decision.ALLOW)
        self.assertIsNone(code)

        # Non-boolean case_sensitive must be rejected
        bad_json = json.dumps(
            {
                "rules": [
                    {
                        "effect": "allow",
                        "tool": "fs",
                        "action": "read",
                        "case_sensitive": "false",
                    }
                ]
            }
        )
        with self.assertRaises(PolicyError):
            Policy.from_json(bad_json)
