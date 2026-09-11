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
            policy.evaluate(
                make_request(action="update", context=TrustedContext({"environment": "production"}))
            ),
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
        policy = Policy.from_mapping(
            {"rules": [{"effect": "allow", "tool": "database", "action": "read"}]}
        )
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
        policy1 = Policy.from_mapping({
            "rules": [
                {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
            ]
        })
        policy2 = Policy.from_mapping({
            "rules": [
                {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
                {"effect": "deny", "tool": "database", "action": "delete", "resource": "*"},
            ]
        })
        policy3 = Policy.from_mapping({
            "rules": [
                {"effect": "deny", "tool": "database", "action": "read", "resource": "*"},
            ]
        })

        self.assertNotEqual(policy_digest(policy1), policy_digest(policy2))
        self.assertNotEqual(policy_digest(policy1), policy_digest(policy3))
        self.assertNotEqual(policy_digest(policy2), policy_digest(policy3))
