import unittest

from dmint import Dmint, Policy, Rule, ToolRequest, TrustedContext, request_fingerprint
from dmint.errors import AuthorizationError
from dmint.models import Decision


class SecurityTests(unittest.TestCase):
    def test_each_security_relevant_selector_change_invalidates_specific_allow(self):
        policy = Policy(
            (
                Rule.allow(
                    "database",
                    "read",
                    agent_id="agent-a",
                    resource="users/123",
                    conditions=(),
                ),
            )
        )
        base = ToolRequest(
            "request-1",
            "agent-a",
            "database",
            "read",
            "users/123",
            {"user_id": 123},
            TrustedContext({}),
        )
        mutations = (
            {"tool": "filesystem"},
            {"action": "delete"},
            {"resource": "users/999"},
            {"agent_id": "agent-b"},
        )
        self.assertIs(policy.evaluate(base), Decision.ALLOW)
        for mutation in mutations:
            values = {
                "request_id": base.request_id,
                "agent_id": base.agent_id,
                "tool": base.tool,
                "action": base.action,
                "resource": base.resource,
                "arguments": {"user_id": 123},
                "context": TrustedContext({}),
            }
            values.update(mutation)
            self.assertIs(policy.evaluate(ToolRequest(**values)), Decision.DENY)

    def test_argument_mutation_changes_fingerprint(self):
        base = ToolRequest("request-1", "agent-a", "database", "read", "users/123", {"user_id": 123}, TrustedContext({}))
        changed = ToolRequest("request-1", "agent-a", "database", "read", "users/123", {"user_id": 999}, TrustedContext({}))
        self.assertNotEqual(request_fingerprint(base), request_fingerprint(changed))

    def test_authorized_artifact_cannot_be_replaced_with_changed_request_fields(self):
        calls = []
        policy = Policy(
            (
                Rule.allow(
                    "database",
                    "read",
                    agent_id="agent-a",
                    resource="users/123",
                ),
            )
        )
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        def read_user(user_id):
            calls.append(user_id)

        dmint.register(
            read_user,
            "database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        authorized = dmint.authorize(
            read_user,
            123,
            capability="database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        dmint.execute(authorized)

        for capability, user_id, resource in (
            ("filesystem.read", 123, lambda arguments: f"users/{arguments['user_id']}"),
            ("database.delete", 123, lambda arguments: f"users/{arguments['user_id']}"),
            ("database.read", 999, lambda arguments: f"users/{arguments['user_id']}"),
        ):
            with self.assertRaises(AuthorizationError):
                dmint.authorize(
                    read_user,
                    user_id,
                    capability=capability,
                    resource=resource,
                )

        other_agent = Dmint(policy, agent_id="agent-b", context=TrustedContext({}))
        with self.assertRaises(AuthorizationError):
            other_agent.authorize(
                read_user,
                123,
                capability="database.read",
                resource=lambda arguments: f"users/{arguments['user_id']}",
            )
        self.assertEqual(calls, [123])
