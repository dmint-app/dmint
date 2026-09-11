import unittest
from functools import wraps
from unittest.mock import patch

from dmint import (
    ANY_RESOURCE,
    Dmint,
    NO_RESOURCE,
    Policy,
    Rule,
    TrustedContext,
)
from dmint.errors import AuthorizationError, RequestValidationError


class EnforcementTests(unittest.TestCase):
    def test_allowed_request_executes_once_from_authorized_snapshot(self):
        calls = []
        policy = Policy((Rule.allow("database", "read", resource="users/123"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({"environment": "test"}))

        @dmint.protected(
            "database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        def read_user(user_id, options=None):
            calls.append((user_id, options))
            return user_id

        options = {"include_email": True}
        self.assertEqual(read_user(123, options), 123)
        options["include_email"] = False
        self.assertEqual(calls, [(123, {"include_email": True})])

    def test_denied_request_never_executes(self):
        calls = []
        dmint = Dmint(Policy(), agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected("database.delete", resource=lambda arguments: f"users/{arguments['user_id']}")
        def delete_user(user_id):
            calls.append(user_id)

        with self.assertRaises(AuthorizationError) as raised:
            delete_user(123)
        self.assertEqual(raised.exception.code, "DMT_POLICY_DENIED")
        self.assertEqual(calls, [])

    def test_resource_substitution_is_denied_before_execution(self):
        calls = []
        policy = Policy((Rule.allow("database", "delete", resource="users/123"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected(
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        def delete_user(user_id):
            calls.append(user_id)

        with self.assertRaises(AuthorizationError):
            delete_user(999)
        self.assertEqual(calls, [])

    def test_authorization_happens_before_execution(self):
        events = []
        policy = Policy((Rule.allow("database", "read", resource="users/123"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected(
            "database.read",
            resource=lambda arguments: events.append("authorize") or f"users/{arguments['user_id']}",
        )
        def read_user(user_id):
            events.append("execute")

        read_user(123)
        self.assertEqual(events, ["authorize", "execute"])

    def test_authorization_exception_fails_closed(self):
        calls = []
        dmint = Dmint(Policy((Rule.allow("database", "read"),)), agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected("database.read")
        def read_user(user_id):
            calls.append(user_id)

        with patch.object(Policy, "evaluate", side_effect=RuntimeError("policy failure")):
            with self.assertRaises(AuthorizationError) as raised:
                read_user(123)
        self.assertEqual(raised.exception.code, "DMT_AUTHORIZATION_ERROR")
        self.assertEqual(calls, [])

    def test_public_artifact_binds_arguments_and_is_reusable_only_as_same_snapshot(self):
        calls = []
        policy = Policy((Rule.allow("database", "read", resource="users/123"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        def read_user(user_id, options):
            calls.append((user_id, options))

        dmint.register(
            read_user,
            "database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        options = {"include_email": True}
        authorized = dmint.authorize(
            read_user,
            123,
            options,
            capability="database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        options["include_email"] = False

        dmint.execute(authorized)
        self.assertEqual(calls, [(123, {"include_email": True})])
        with self.assertRaises(AttributeError):
            authorized._request = None

    def test_authorized_artifact_cannot_be_executed_by_another_dmint(self):
        policy = Policy((Rule.allow("database", "read", resource=ANY_RESOURCE),))
        first = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))
        second = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        def read_user(user_id):
            return user_id

        first.register(read_user, "database.read")
        authorized = first.authorize(read_user, 123, capability="database.read")
        with self.assertRaises(AuthorizationError) as raised:
            second.execute(authorized)
        self.assertEqual(raised.exception.code, "DMT_INVALID_AUTHORIZATION")

    def test_changed_principal_is_denied(self):
        policy = Policy((Rule.allow("database", "read", agent_id="agent-a", resource=ANY_RESOURCE),))
        dmint = Dmint(policy, agent_id="agent-b", context=TrustedContext({}))

        def read_user(user_id):
            return user_id

        dmint.register(read_user, "database.read")
        with self.assertRaises(AuthorizationError):
            dmint.authorize(read_user, 123, capability="database.read")

    def test_malformed_arguments_fail_closed(self):
        calls = []
        dmint = Dmint(Policy((Rule.allow("database", "read"),)), agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected("database.read")
        def read_user(value):
            calls.append(value)

        with self.assertRaises(AuthorizationError):
            read_user(object())
        self.assertEqual(calls, [])

    def test_json_unsupported_tuple_argument_fails_closed(self):
        calls = []
        dmint = Dmint(Policy((Rule.allow("tool", "use"),)), agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected("tool.use")
        def use_tool(value):
            calls.append(value)

        with self.assertRaises(AuthorizationError):
            use_tool((1, 2))
        self.assertEqual(calls, [])

    def test_variadic_and_keyword_signatures_execute_correctly(self):
        calls = []
        dmint = Dmint(Policy((Rule.allow("tool", "use"),)), agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected("tool.use")
        def use_tool(first, second=2, *values, enabled=False, **metadata):
            calls.append((first, second, values, enabled, metadata))

        use_tool(1, 3, 4, 5, enabled=True, source="test")
        self.assertEqual(calls, [(1, 3, (4, 5), True, {"source": "test"})])

    def test_positional_only_and_keyword_only_signatures_execute_correctly(self):
        calls = []
        dmint = Dmint(Policy((Rule.allow("tool", "use"),)), agent_id="agent-a", context=TrustedContext({}))

        @dmint.protected("tool.use")
        def use_tool(first, /, second=2, *, enabled=False):
            calls.append((first, second, enabled))

        use_tool(1, enabled=True)
        self.assertEqual(calls, [(1, 2, True)])

    def test_static_methods_work_and_instance_methods_fail_closed(self):
        calls = []
        dmint = Dmint(Policy((Rule.allow("tool", "use"),)), agent_id="agent-a", context=TrustedContext({}))

        class Tools:
            @staticmethod
            @dmint.protected("tool.use")
            def static(value):
                calls.append(("static", value))

            @dmint.protected("tool.use")
            def instance(self, value):
                calls.append(("instance", value))

        Tools.static(1)
        with self.assertRaises(AuthorizationError):
            Tools().instance(1)
        self.assertEqual(calls, [("static", 1)])

    def test_static_resource_is_rejected_by_protected_api(self):
        dmint = Dmint(Policy(), agent_id="agent-a", context=TrustedContext({}))
        with self.assertRaises(RequestValidationError):
            dmint.protected("database.delete", resource="users/123")

    def test_async_functions_are_rejected(self):
        dmint = Dmint(Policy(), agent_id="agent-a", context=TrustedContext({}))

        async def read_user():
            return 1

        with self.assertRaises(RequestValidationError):
            dmint.protected("database.read")(read_user)

    def test_dmint_outside_wrapped_function_is_rejected(self):
        dmint = Dmint(Policy(), agent_id="agent-a", context=TrustedContext({}))

        def rewrite(function):
            @wraps(function)
            def wrapper(user_id):
                return function(999)

            return wrapper

        def delete_user(user_id):
            return user_id

        with self.assertRaises(RequestValidationError):
            dmint.protected(
                "database.delete",
                resource=lambda arguments: f"users/{arguments['user_id']}",
            )(rewrite(delete_user))

    def test_dmint_inside_transforming_decorator_authorizes_transformed_values(self):
        calls = []
        policy = Policy((Rule.allow("database", "delete", resource="users/999"),))
        dmint = Dmint(policy, agent_id="agent-a", context=TrustedContext({}))

        def rewrite(function):
            @wraps(function)
            def wrapper(user_id):
                return function(999)

            return wrapper

        @rewrite
        @dmint.protected(
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        def delete_user(user_id):
            calls.append(user_id)

        delete_user(123)
        self.assertEqual(calls, [999])
