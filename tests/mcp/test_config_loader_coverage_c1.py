"""Tests for uncovered error handling and validation branches in dmint.mcp.config_loader."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from dmint.core.policy import Policy, Rule
from dmint.mcp.config_loader import (
    DisclosureMode,
    DiscoveryMode,
    MCPConfigurationError,
    MCPGatewayConfig,
    MCPTransportType,
    load_protection_config,
    parse_protection_config,
)


class ConfigLoaderCoverageC1Tests(unittest.TestCase):
    """Test error paths in configuration loading and parsing."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.policy_path = self.tmp_path / "policy.json"
        self.policy_data = {"rules": [{"tool": "test_tool", "action": "run", "resource": "*", "effect": "allow"}]}
        self.policy_path.write_text(json.dumps(self.policy_data), encoding="utf-8")
        self.valid_policy_digest = hashlib.sha256(self.policy_path.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _base_config(self) -> dict:
        return {
            "policy_file": str(self.policy_path),
            "integrations": [
                {
                    "integration_id": "test_integ",
                    "transport": "stdio",
                    "connection": {
                        "command": "python",
                        "args": ["-m", "test"],
                    },
                    "tool_bindings": {
                        "test_tool": "test_integ.run",
                    },
                }
            ],
        }

    def test_policy_file_validation_branches(self) -> None:
        """parse_protection_config validates policy_file options."""
        cfg = self._base_config()

        # Non-empty string check
        cfg["policy_file"] = "   "
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["policy_file"] = 123
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Relative path without base_dir
        cfg["policy_file"] = "relative_pol.json"
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg, base_dir=None)
        self.assertIn("base_dir is required", str(ctx.exception))

        # Remote policy without expected digest
        cfg["policy_file"] = "https://example.com/pol.json"
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("remote policy loading requires expected_policy_digest", str(ctx.exception))

        # Remote policy load failure
        with patch.object(Policy, "from_url", side_effect=Exception("network down")):
            with self.assertRaises(MCPConfigurationError) as ctx:
                parse_protection_config(cfg, expected_policy_digest="a" * 64)
            self.assertIn("failed to load remote policy", str(ctx.exception))

        # Local policy digest mismatch
        cfg["policy_file"] = str(self.policy_path)
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg, expected_policy_digest="0" * 64)
        self.assertIn("policy digest mismatch", str(ctx.exception))

        # Corrupt policy file
        corrupt_path = self.tmp_path / "corrupt.json"
        corrupt_path.write_text("{bad json", encoding="utf-8")
        cfg["policy_file"] = str(corrupt_path)
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("failed to load policy", str(ctx.exception))

    def test_embedded_policy_validation_branches(self) -> None:
        """parse_protection_config validates embedded policy dictionary."""
        cfg = self._base_config()
        del cfg["policy_file"]

        # Missing policy and policy_file
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("missing valid 'policy_file' or 'policy'", str(ctx.exception))

        # Non-dict policy
        cfg["policy"] = "not_a_dict"
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("embedded 'policy' must be a dictionary", str(ctx.exception))

        # Parse failure for embedded policy
        cfg["policy"] = {"rules": "not_a_list"}
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("failed to parse embedded policy", str(ctx.exception))

        # Embedded policy digest mismatch
        cfg["policy"] = self.policy_data
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg, expected_policy_digest="0" * 64)
        self.assertIn("policy digest mismatch", str(ctx.exception))

    def test_transport_and_connection_validations(self) -> None:
        """parse_protection_config validates transports, stdio, and streamable-http connection args."""
        cfg = self._base_config()

        # Non-string transport
        cfg["integrations"][0]["transport"] = 123
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Unsupported transport
        cfg["integrations"][0]["transport"] = "websocket"
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("unsupported transport", str(ctx.exception))

        # Connection not a dict
        cfg["integrations"][0]["transport"] = "stdio"
        cfg["integrations"][0]["connection"] = "not_a_dict"
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Stdio missing command
        cfg["integrations"][0]["connection"] = {"command": ""}
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("missing valid 'command'", str(ctx.exception))

        # Stdio args not a list of strings
        cfg["integrations"][0]["connection"] = {"command": "python", "args": "not_a_list"}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["integrations"][0]["connection"] = {"command": "python", "args": [1, 2]}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Stdio env not a dict
        cfg["integrations"][0]["connection"] = {"command": "python", "env": "not_dict"}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Stdio unsupported url or headers
        cfg["integrations"][0]["connection"] = {"command": "python", "url": "http://bad"}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["integrations"][0]["connection"] = {"command": "python", "headers": {"h": "v"}}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Streamable-http missing url
        cfg["integrations"][0]["transport"] = "streamable-http"
        cfg["integrations"][0]["connection"] = {"url": ""}
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("missing valid 'url'", str(ctx.exception))

        # Streamable-http unsupported connection command, args, env, cwd
        cfg["integrations"][0]["connection"] = {"url": "http://localhost:8000", "command": "not-allowed"}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["integrations"][0]["connection"] = {"url": "http://localhost:8000", "args": ["a"]}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["integrations"][0]["connection"] = {"url": "http://localhost:8000", "env": {"k": "v"}}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["integrations"][0]["connection"] = {"url": "http://localhost:8000", "cwd": "/tmp"}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Streamable-http headers validations
        cfg["integrations"][0]["connection"] = {"url": "http://localhost:8000", "headers": "not_dict"}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["integrations"][0]["connection"] = {"url": "http://localhost:8000", "headers": {"k": 123}}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

    def test_tool_bindings_validations(self) -> None:
        """parse_protection_config validates dict and list tool bindings."""
        cfg = self._base_config()

        # Empty capability in dict binding
        cfg["integrations"][0]["tool_bindings"] = {"tool1": "   "}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Invalid spec in dict binding
        cfg["integrations"][0]["tool_bindings"] = {"tool1": 12345}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # List bindings
        cfg["integrations"][0]["tool_bindings"] = [{"tool_name": "tool1", "capability": "cap.one"}]
        parsed = parse_protection_config(cfg)
        self.assertEqual(len(parsed.integrations[0].tool_bindings), 1)

        # List binding missing tool_name / capability
        cfg["integrations"][0]["tool_bindings"] = [{"only_tool": "t"}]
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # List binding empty capability
        cfg["integrations"][0]["tool_bindings"] = [{"tool_name": "t", "capability": "   "}]
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # Duplicate tool name in integration
        cfg["integrations"][0]["tool_bindings"] = [
            {"tool_name": "dup", "capability": "cap.one"},
            {"tool_name": "dup", "capability": "cap.two"},
        ]
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("duplicate tool name", str(ctx.exception))

    def test_top_level_settings_and_issuers_validations(self) -> None:
        """parse_protection_config validates approval_db, approval_ttl, disclosure_mode, and trusted_issuers."""
        cfg = self._base_config()

        # approval_db empty string
        cfg["approval_db"] = "   "
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # approval_db relative path resolution
        cfg["approval_db"] = "relative.db"
        parsed = parse_protection_config(cfg, base_dir=self.tmp_path)
        self.assertEqual(parsed.approval_store_path, str((self.tmp_path / "relative.db").resolve()))

        # approval_ttl <= 0 or bool
        cfg["approval_db"] = "approvals.db"
        cfg["approval_ttl"] = 0
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["approval_ttl"] = True
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # disclosure_mode invalid
        cfg["approval_ttl"] = 300
        cfg["disclosure_mode"] = "invalid_mode"
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["disclosure_mode"] = 1234
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # agent_id invalid
        cfg["disclosure_mode"] = "dog"
        cfg["agent_id"] = "   "
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # context not a dict
        cfg["agent_id"] = "valid_agent"
        cfg["context"] = "not_dict"
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # approval_audience empty
        cfg["context"] = {"user": "bob"}
        cfg["approval_audience"] = "   "
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # trusted_issuers validations
        cfg["approval_audience"] = "dmint-aud"
        cfg["trusted_issuers"] = "not_a_list"
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["trusted_issuers"] = ["not_a_dict"]
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["trusted_issuers"] = [{"issuer_id": ""}]
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        cfg["trusted_issuers"] = [
            {"issuer_id": "iss1", "public_key_hex": "a" * 64},
            {"issuer_id": "iss1", "public_key_hex": "b" * 64},
        ]
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(cfg)
        self.assertIn("duplicate issuer_id", str(ctx.exception))

        # public_key_hex not 64 chars
        cfg["trusted_issuers"] = [{"issuer_id": "iss1", "public_key_hex": "abcd"}]
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

        # public_key_hex not valid hex
        cfg["trusted_issuers"] = [{"issuer_id": "iss1", "public_key_hex": "z" * 64}]
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(cfg)

    def test_load_protection_config_file_errors(self) -> None:
        """load_protection_config catches file existence, type, duplicate keys, and malformed json."""
        # Nonexistent file
        with self.assertRaises(MCPConfigurationError):
            load_protection_config(self.tmp_path / "absent.json")

        # Path is a directory
        with self.assertRaises(MCPConfigurationError):
            load_protection_config(self.tmp_path)

        # Duplicate JSON keys
        dup_file = self.tmp_path / "dup.json"
        dup_file.write_text('{"policy_file": "p1", "policy_file": "p2"}', encoding="utf-8")
        with self.assertRaises(MCPConfigurationError) as ctx:
            load_protection_config(dup_file)
        self.assertIn("duplicate JSON key", str(ctx.exception))

        # Malformed JSON
        mal_file = self.tmp_path / "mal.json"
        mal_file.write_text('{"policy_file": ', encoding="utf-8")
        with self.assertRaises(MCPConfigurationError) as ctx:
            load_protection_config(mal_file)
        self.assertIn("malformed JSON", str(ctx.exception))
