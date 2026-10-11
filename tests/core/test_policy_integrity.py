import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dmint.cli.__main__ import main
from dmint.core.enforcement import Dmint
from dmint.core.errors import PolicyError
from dmint.core.policy import Policy, Rule
from dmint.core import TrustedContext
from dmint.mcp.config_loader import load_protection_config
from dmint.mcp.errors import MCPConfigurationError
from dmint.mcp.gateway import MCPGateway


class PolicyIntegrityTests(unittest.TestCase):
    def test_duplicate_rules_key_rejected(self) -> None:
        raw = '{"rules": [], "rules": [{"effect": "allow", "tool": "db", "action": "read", "resource": "*"}]}'
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_json(raw)
        self.assertIn("duplicate", str(ctx.exception).lower())

    def test_duplicate_nested_key_in_constraints_rejected(self) -> None:
        raw = (
            '{"rules": [{"effect": "allow", "tool": "db", "action": "query", "resource": "*", '
            '"constraints": {"properties": {"limit": {"type": "integer", "minimum": 1}, '
            '"limit": {"type": "integer", "minimum": 10}}}}]}'
        )
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_json(raw)
        self.assertIn("duplicate", str(ctx.exception).lower())

        from dmint.core.constraints import parse_constraints
        with self.assertRaises(PolicyError) as ctx:
            parse_constraints('{"properties": {"limit": {"type": "integer", "minimum": 1}, "limit": {"type": "integer"}}}')
        self.assertIn("duplicate", str(ctx.exception).lower())

    def test_expected_policy_digest_mismatch_refused(self) -> None:
        policy_json = json.dumps({
            "rules": [{"effect": "allow", "tool": "db", "action": "read", "resource": "*"}]
        })
        wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000"
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_json(policy_json, expected_policy_digest=wrong_digest)
        self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_same_user_edit_restart_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.json"
            policy_content_v1 = json.dumps({
                "rules": [{"effect": "allow", "tool": "db", "action": "read", "resource": "*"}]
            }).encode("utf-8")
            policy_file.write_bytes(policy_content_v1)
            v1_digest = hashlib.sha256(policy_content_v1).hexdigest()

            # Start engine with expected digest matching v1
            engine = Dmint(
                agent_id="test-agent",
                context=TrustedContext({}),
                policy_file=policy_file,
                expected_policy_digest=v1_digest,
            )
            self.assertEqual(len(engine._policy.rules), 1)

            # Adversary / user modifies policy.json in place
            policy_content_v2 = json.dumps({
                "rules": [
                    {"effect": "allow", "tool": "db", "action": "read", "resource": "*"},
                    {"effect": "allow", "tool": "shell", "action": "exec", "resource": "*"},
                ]
            }).encode("utf-8")
            policy_file.write_bytes(policy_content_v2)

            # Restart / reload with original expected digest must fail closed
            with self.assertRaises(PolicyError) as ctx:
                Dmint(
                    agent_id="test-agent",
                    context=TrustedContext({}),
                    policy_file=policy_file,
                    expected_policy_digest=v1_digest,
                )
            self.assertIn("digest mismatch", str(ctx.exception).lower())

            with self.assertRaises(PolicyError) as ctx:
                engine.reload_policy()
            self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_gateway_expected_policy_digest_refuses_mismatched_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            p_file = Path(tmpdir) / "policy.json"
            p_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
            correct_digest = hashlib.sha256(p_file.read_bytes()).hexdigest()
            wrong_digest = "f" * 64

            cfg_file = Path(tmpdir) / "mcp_protection.json"
            cfg_file.write_text(
                json.dumps({
                    "policy_file": str(p_file),
                    "expected_policy_digest": wrong_digest,
                    "integrations": [{
                        "integration_id": "test",
                        "transport": "stdio",
                        "connection": {"command": "echo"},
                        "tool_bindings": {"echo": {"tool_name": "echo", "capability": "test.echo"}},
                    }],
                }),
                encoding="utf-8",
            )

            with self.assertRaises(MCPConfigurationError) as ctx:
                load_protection_config(cfg_file)
            self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_remote_policy_non_https_refused(self) -> None:
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_url("http://example.com/policy.json", expected_policy_digest="a" * 64)
        self.assertIn("https", str(ctx.exception).lower())

    def test_remote_policy_tampered_body_refused_before_parsing(self) -> None:
        fake_body = b'{"rules": [{"corrupt_json":'
        expected_digest = "e" * 64  # Does not match sha256(fake_body)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = fake_body
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with patch("urllib.request.urlopen", return_value=mock_resp), patch(
            "dmint.mcp.ssrf.validate_mcp_url", return_value="https://example.com/policy.json"
        ):
            with self.assertRaises(PolicyError) as ctx:
                Policy.from_url("https://example.com/policy.json", expected_policy_digest=expected_digest)
            self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_cli_policy_digest_command(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write('{"rules": []}')
            f_path = Path(f.name)
        try:
            expected_digest = hashlib.sha256(f_path.read_bytes()).hexdigest()
            with patch("sys.stdout.write") as mock_stdout, patch("builtins.print") as mock_print:
                rc = main(["policy-digest", str(f_path)])
                self.assertEqual(rc, 0)
                mock_print.assert_called_with(expected_digest)
        finally:
            f_path.unlink(missing_ok=True)
