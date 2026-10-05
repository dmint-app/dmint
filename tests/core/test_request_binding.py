import unittest

import rfc8785

from dmint import Dmint, Policy, Rule, ToolRequest, TrustedContext, new_request_id
from dmint.request_binding import (
    canonical_request_binding,
    request_binding_envelope,
    request_binding_fingerprint,
)
from dmint.errors import UnknownApprovalVersionError


class RequestBindingTests(unittest.TestCase):
    def setUp(self):
        self.dmint = Dmint(
            Policy((Rule.allow("database", "read", resource="users/123"),)),
            agent_id="agent-a",
            context=TrustedContext({"environment": "production"}),
        )

        def read_user(user_id):
            return user_id

        self.dmint.register(
            read_user,
            "database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.read_user = read_user

    def request(self, user_id=123):
        return self.dmint.authorize(
            self.read_user,
            user_id,
            capability="database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        ).request

    def test_jcs_binding_is_deterministic_and_excludes_workflow_id(self):
        self.assertEqual(rfc8785.dumps({"b": 2, "a": 1}), b'{"a":1,"b":2}')
        first = self.request()
        second = self.request()
        first_bytes = canonical_request_binding(
            first,
            integration_id="local-runtime",
            capability_id="database.read",
        )
        second_bytes = canonical_request_binding(
            second,
            integration_id="local-runtime",
            capability_id="database.read",
        )

        self.assertEqual(first_bytes, second_bytes)
        self.assertNotIn(b"request_id", first_bytes)
        self.assertEqual(
            request_binding_fingerprint(
                first,
                integration_id="local-runtime",
                capability_id="database.read",
            ),
            request_binding_fingerprint(
                second,
                integration_id="local-runtime",
                capability_id="database.read",
            ),
        )

    def test_security_relevant_changes_change_fingerprint(self):
        base = self.request()
        base_fingerprint = request_binding_fingerprint(
            base,
            integration_id="local-runtime",
            capability_id="database.read",
        )
        changed = ToolRequest(
            request_id=new_request_id(),
            agent_id="agent-a",
            tool="database",
            action="read",
            resource="users/999",
            arguments={"user_id": 999},
            context=TrustedContext({"environment": "production"}),
        )
        self.assertNotEqual(
            base_fingerprint,
            request_binding_fingerprint(
                changed,
                integration_id="local-runtime",
                capability_id="database.read",
            ),
        )
        self.assertNotEqual(
            base_fingerprint,
            request_binding_fingerprint(
                base,
                integration_id="other-runtime",
                capability_id="database.read",
            ),
        )

    def test_resource_representation_is_explicit(self):
        envelope = request_binding_envelope(
            self.request(),
            integration_id="local-runtime",
            capability_id="database.read",
        )
        self.assertEqual(envelope["resource"], {"kind": "value", "value": "users/123"})

    def test_public_fingerprint_api_matches_jcs_request_binding_fingerprint(self):
        req = self.request()
        jcs_fp = request_binding_fingerprint(
            req,
            integration_id="local-runtime",
            capability_id="database.read",
        )
        self.assertEqual(req.request_id.startswith("req_"), True)
        authorized = self.dmint.authorize(
            self.read_user,
            123,
            capability="database.read",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.assertEqual(authorized.fingerprint, jcs_fp)
        with self.assertRaises(UnknownApprovalVersionError):
            canonical_request_binding(
                self.request(),
                integration_id="local-runtime",
                capability_id="database.read",
                binding_version="dmint/request-binding/v999",
            )
        with self.assertRaises(UnknownApprovalVersionError):
            canonical_request_binding(
                self.request(),
                integration_id="local-runtime",
                capability_id="database.read",
                canonicalization_profile="dmint/python-json-v1",
            )
