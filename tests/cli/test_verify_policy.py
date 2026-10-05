"""Unit tests for verify-policy command (src/dmint_cli/verify_policy.py)."""

import json
from pathlib import Path
import tempfile
import unittest

from dmint.cli.errors import (
    InputFileError,
    JSONExtractionError,
    PolicyValidationError,
)
from dmint.cli.verify_policy import main_verify, verify_policy_file


class VerifyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.valid_json = self.base_path / "valid.json"
        self.invalid_json = self.base_path / "invalid.json"
        self.not_json = self.base_path / "not_json.txt"

        self.valid_json.write_text(
            json.dumps({"rules": [{"effect": "allow", "tool": "postgres", "action": "query"}]}),
            encoding="utf-8",
        )
        self.invalid_json.write_text(
            json.dumps({"rules": [{"effect": "INVALID_EFFECT", "tool": "postgres", "action": "query"}]}),
            encoding="utf-8",
        )
        self.not_json.write_text("NOT JSON CONTENT", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verify_valid_policy_file_succeeds(self):
        policy = verify_policy_file(self.valid_json)
        self.assertEqual(len(policy.rules), 1)

    def test_verify_valid_policy_main_exits_0(self):
        code = main_verify(["-f", str(self.valid_json)])
        self.assertEqual(code, 0)

    def test_verify_invalid_policy_raises_validation_error(self):
        with self.assertRaises(PolicyValidationError):
            verify_policy_file(self.invalid_json)

    def test_verify_invalid_policy_main_exits_nonzero(self):
        code = main_verify([str(self.invalid_json)])
        self.assertNotEqual(code, 0)

    def test_verify_non_json_raises_extraction_error(self):
        with self.assertRaises(JSONExtractionError):
            verify_policy_file(self.not_json)

    def test_verify_non_json_main_exits_nonzero(self):
        code = main_verify([str(self.not_json)])
        self.assertNotEqual(code, 0)

    def test_verify_missing_file_raises_input_file_error(self):
        missing = self.base_path / "missing.json"
        with self.assertRaises(InputFileError):
            verify_policy_file(missing)

    def test_verify_missing_args_main_exits_2(self):
        code = main_verify([])
        self.assertEqual(code, 2)
