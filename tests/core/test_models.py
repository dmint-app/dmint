import unittest

from dmint import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.errors import RequestValidationError


class ModelTests(unittest.TestCase):
    def test_context_must_be_explicit_trusted_context(self):
        with self.assertRaises(RequestValidationError):
            ToolRequest("id", "agent", "tool", "action", None, {}, {})

    def test_identifiers_reject_ambiguous_whitespace(self):
        with self.assertRaises(RequestValidationError):
            ToolRequest(" id", "agent", "tool", "action", None, {}, TrustedContext({}))

    def test_context_is_snapshotted(self):
        values = {"environment": "development"}
        context = TrustedContext(values)
        values["environment"] = "production"

        self.assertEqual(context.values["environment"], "development")

    def test_missing_resource_is_explicit(self):
        request = ToolRequest("id", "agent", "tool", "action", NO_RESOURCE, {}, TrustedContext({}))
        self.assertEqual(request.resource, NO_RESOURCE)

    def test_none_resource_and_tuple_arguments_are_rejected(self):
        with self.assertRaises(RequestValidationError):
            ToolRequest("id", "agent", "tool", "action", None, {}, TrustedContext({}))
        with self.assertRaises(RequestValidationError):
            ToolRequest("id", "agent", "tool", "action", NO_RESOURCE, {"value": (1, 2)}, TrustedContext({}))
