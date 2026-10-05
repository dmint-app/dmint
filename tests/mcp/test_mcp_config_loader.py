"""Tests for Dmint MCP protection configuration loader (mcp_protection.json)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from dmint.policy import Policy
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    MCPConfigurationError,
    MCPGatewayConfig,
    MCPTransportType,
    load_protection_config,
    parse_protection_config,
)


class TestMCPConfigLoader(unittest.TestCase):
    """Test suite for config_loader.py."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create a valid policy file
        self.policy_data = {
            "rules": [
                {
                    "tool": "mcp.postgres.query",
                    "action": "execute",
                    "effect": "allow",
                }
            ],
        }
        self.policy_file = self.tmppath / "policy.json"
        self.policy_file.write_text(json.dumps(self.policy_data), encoding="utf-8")

        self.valid_config_data = {
            "policy_file": "policy.json",
            "agent_id": "test-agent",
            "disclosure_mode": "dog",
            "integrations": [
                {
                    "integration_id": "postgres",
                    "transport": "stdio",
                    "connection": {
                        "command": "mcp-server-postgres",
                        "args": ["postgresql://localhost/db"],
                        "env": {"LANG": "C"},
                        "cwd": str(self.tmppath),
                        "timeout": 30.0,
                    },
                    "tool_bindings": {
                        "query": {
                            "tool_name": "query",
                            "capability": "mcp.postgres.query",
                            "discovery": "exposed",
                            "description": "Run read-only queries",
                        }
                    },
                }
            ],
        }

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_load_valid_file_with_relative_policy(self) -> None:
        """Loading a valid file should resolve relative policy_file against config file dir."""
        cfg_file = self.tmppath / "mcp_protection.json"
        cfg_file.write_text(json.dumps(self.valid_config_data), encoding="utf-8")

        config = load_protection_config(cfg_file)
        self.assertIsInstance(config, MCPGatewayConfig)
        self.assertEqual(config.agent_id, "test-agent")
        self.assertEqual(config.disclosure_mode, DisclosureMode.DOG)
        self.assertEqual(len(config.integrations), 1)

        integ = config.integrations[0]
        self.assertEqual(integ.integration_id, "postgres")
        self.assertEqual(integ.transport_type, MCPTransportType.STDIO)
        self.assertEqual(integ.command, "mcp-server-postgres")
        self.assertEqual(integ.args, ("postgresql://localhost/db",))
        self.assertEqual(integ.call_timeout, 30.0)
        self.assertEqual(len(integ.tool_bindings), 1)
        self.assertEqual(integ.tool_bindings["query"].capability, "mcp.postgres.query")
        self.assertEqual(integ.tool_bindings["query"].discovery, DiscoveryMode.EXPOSED)

    def test_parse_valid_dict_with_embedded_policy(self) -> None:
        """Config can embed the policy dict directly instead of pointing to policy_file."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "sqlite",
                    "connection": {
                        "command": "sqlite-server",
                    },
                    "tool_bindings": {
                        "query": {
                            "tool_name": "query",
                            "capability": "mcp.sqlite.query",
                        }
                    },
                }
            ],
        }
        config = parse_protection_config(data)
        self.assertIsInstance(config.policy, Policy)
        self.assertIsNone(config.policy_file)
        self.assertEqual(config.integrations[0].integration_id, "sqlite")
        self.assertEqual(config.integrations[0].tool_bindings["query"].discovery, DiscoveryMode.EXPOSED)

    def test_missing_file_raises(self) -> None:
        """Loading a non-existent file raises MCPConfigurationError."""
        non_existent = self.tmppath / "non_existent.json"
        with self.assertRaises(MCPConfigurationError) as ctx:
            load_protection_config(non_existent)
        self.assertTrue("does not exist" in str(ctx.exception).lower() or "not found" in str(ctx.exception).lower())

    def test_non_dict_raises(self) -> None:
        """Non-dict JSON raises MCPConfigurationError."""
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(["not", "a", "dict"])  # type: ignore
        self.assertIn("dictionary", str(ctx.exception).lower())

    def test_missing_policy_and_policy_file_raises(self) -> None:
        """Config without policy or policy_file raises MCPConfigurationError."""
        data = {
            "integrations": [
                {
                    "integration_id": "postgres",
                    "connection": {"command": "pg"},
                    "tool_bindings": {"q": {"tool_name": "q", "capability": "mcp.q"}},
                }
            ]
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("policy", str(ctx.exception).lower())

    def test_both_policy_and_policy_file_raises(self) -> None:
        """Config with both policy and policy_file raises MCPConfigurationError."""
        data = dict(self.valid_config_data)
        data["policy"] = self.policy_data
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data, base_dir=self.tmppath)
        self.assertIn("both", str(ctx.exception).lower())

    def test_policy_file_not_found_raises(self) -> None:
        """If policy_file points to non-existent file, raises MCPConfigurationError."""
        data = dict(self.valid_config_data)
        data["policy_file"] = "missing_policy.json"
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data, base_dir=self.tmppath)
        self.assertTrue("does not exist" in str(ctx.exception).lower() or "not found" in str(ctx.exception).lower())

    def test_missing_or_empty_integrations_raises(self) -> None:
        """Missing or empty integrations list raises MCPConfigurationError."""
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config({"policy": self.policy_data})
        self.assertIn("integrations", str(ctx.exception).lower())

        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config({"policy": self.policy_data, "integrations": []})
        self.assertIn("integrations", str(ctx.exception).lower())

    def test_max_integrations_limit_raises(self) -> None:
        """Config with more than 50 integrations raises MCPConfigurationError."""
        integrations = [
            {
                "integration_id": f"srv_{i}",
                "connection": {"command": f"cmd_{i}"},
                "tool_bindings": {"t": {"tool_name": "t", "capability": "mcp.t"}},
            }
            for i in range(51)
        ]
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config({"policy": self.policy_data, "integrations": integrations})
        self.assertIn("exceeds", str(ctx.exception).lower())

    def test_duplicate_integration_id_raises(self) -> None:
        """Duplicate integration IDs raise MCPConfigurationError."""
        integrations = [
            {
                "integration_id": "postgres",
                "connection": {"command": "pg1"},
                "tool_bindings": {"q": {"tool_name": "q", "capability": "mcp.q"}},
            },
            {
                "integration_id": "postgres",
                "connection": {"command": "pg2"},
                "tool_bindings": {"q": {"tool_name": "q", "capability": "mcp.q"}},
            },
        ]
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config({"policy": self.policy_data, "integrations": integrations})
        self.assertIn("duplicate integration", str(ctx.exception).lower())

    def test_invalid_integration_id_characters_raises(self) -> None:
        """Invalid characters in integration_id raise MCPConfigurationError."""
        for bad_id in ("srv.1", "srv/2", "srv@3", "srv 4", ""):
            data = {
                "policy": self.policy_data,
                "integrations": [
                    {
                        "integration_id": bad_id,
                        "connection": {"command": "cmd"},
                        "tool_bindings": {"t": {"tool_name": "t", "capability": "mcp.t"}},
                    }
                ],
            }
            with self.assertRaises(MCPConfigurationError):
                parse_protection_config(data)

    def test_secret_detection_raises(self) -> None:
        """Embedded secrets or credentials raise MCPConfigurationError."""
        bad_configs = [
            {
                "policy": self.policy_data,
                "integrations": [
                    {
                        "integration_id": "srv",
                        "connection": {"command": "cmd", "env": {"AUTH_TOKEN": "Bearer secret-token-value-12345"}},
                        "tool_bindings": {"t": {"tool_name": "t", "capability": "mcp.t"}},
                    }
                ],
            },
            {
                "policy": self.policy_data,
                "integrations": [
                    {
                        "integration_id": "srv",
                        "connection": {"command": "cmd", "env": {"OPENAI_API_KEY": "sk-abcdef123456789012345678"}},
                        "tool_bindings": {"t": {"tool_name": "t", "capability": "mcp.t"}},
                    }
                ],
            },
            {
                "policy": self.policy_data,
                "integrations": [
                    {
                        "integration_id": "srv",
                        "connection": {"command": "cmd", "args": ["--password=supersecretpasswordlongvalue"]},
                        "tool_bindings": {"t": {"tool_name": "t", "capability": "mcp.t"}},
                    }
                ],
            },
        ]
        for bad_cfg in bad_configs:
            with self.assertRaises(MCPConfigurationError) as ctx:
                parse_protection_config(bad_cfg)
            self.assertIn("security violation", str(ctx.exception).lower())

    def test_invalid_timeouts_raise(self) -> None:
        """Non-positive or invalid timeouts raise MCPConfigurationError."""
        for bad_timeout in (0, -5, "not_a_number", None):
            if bad_timeout is None:
                continue
            data = {
                "policy": self.policy_data,
                "integrations": [
                    {
                        "integration_id": "srv",
                        "connection": {"command": "cmd", "timeout": bad_timeout},
                        "tool_bindings": {"t": {"tool_name": "t", "capability": "mcp.t"}},
                    }
                ],
            }
            with self.assertRaises(MCPConfigurationError):
                parse_protection_config(data)

    def test_invalid_tool_bindings_raise(self) -> None:
        """Missing or malformed tool bindings raise MCPConfigurationError."""
        # Empty tool bindings
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "srv",
                    "connection": {"command": "cmd"},
                    "tool_bindings": {},
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("at least one tool binding", str(ctx.exception))

        # Missing capability
        data["integrations"][0]["tool_bindings"] = {"tool1": {"tool_name": "tool1"}}
        with self.assertRaises(MCPConfigurationError):
            parse_protection_config(data)

        # Invalid discovery mode
        data["integrations"][0]["tool_bindings"] = {
            "tool1": {"tool_name": "tool1", "capability": "c", "discovery": "invalid_mode"}
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("invalid discovery mode", str(ctx.exception).lower())

    def test_duplicate_tool_name_within_integration_raises(self) -> None:
        """Tool binding with colliding tool_name within the same integration raises."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "srv",
                    "connection": {"command": "cmd"},
                    "tool_bindings": {
                        "alias1": {"tool_name": "same_tool", "capability": "cap.1"},
                        "alias2": {"tool_name": "same_tool", "capability": "cap.2"},
                    },
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("duplicate tool name", str(ctx.exception).lower())

    def test_multi_server_config_loaded_successfully(self) -> None:
        """Multi-server integration config parses all servers and bindings."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "srv1",
                    "connection": {"command": "cmd1", "timeout": 15.0},
                    "tool_bindings": {"toolA": {"tool_name": "toolA", "capability": "cap.a"}},
                },
                {
                    "integration_id": "srv2",
                    "connection": {"command": "cmd2", "timeout": 20.0},
                    "tool_bindings": {"toolB": {"tool_name": "toolB", "capability": "cap.b"}},
                },
            ],
        }
        config = parse_protection_config(data)
        self.assertEqual(len(config.integrations), 2)
        srv1 = config.get_integration("srv1")
        srv2 = config.get_integration("srv2")
        self.assertIsNotNone(srv1)
        self.assertIsNotNone(srv2)
        self.assertEqual(srv1.call_timeout, 15.0)
        self.assertEqual(srv2.call_timeout, 20.0)

    def test_streamable_http_config_loaded_successfully(self) -> None:
        """Streamable HTTP integration parses url, headers, and timeouts."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "remote-api",
                    "transport": "streamable-http",
                    "connection": {
                        "url": "http://localhost:8080/mcp",
                        "headers": {
                            "Authorization": "$MCP_TOKEN",
                            "X-Custom": "custom-val",
                        },
                        "timeout": 25.0,
                    },
                    "tool_bindings": {"fetch": {"tool_name": "fetch", "capability": "mcp.remote.fetch"}},
                }
            ],
        }
        config = parse_protection_config(data)
        integ = config.get_integration("remote-api")
        self.assertIsNotNone(integ)
        self.assertEqual(integ.transport_type, MCPTransportType.STREAMABLE_HTTP)
        self.assertEqual(integ.url, "http://localhost:8080/mcp")
        self.assertEqual(integ.headers["Authorization"], "$MCP_TOKEN")
        self.assertEqual(integ.headers["X-Custom"], "custom-val")
        self.assertIsNone(integ.command)
        self.assertEqual(integ.call_timeout, 25.0)

        # Ensure repr redacts the Authorization header
        rep = repr(integ)
        self.assertNotIn("$MCP_TOKEN", rep)
        self.assertIn("[REDACTED]", rep)

    def test_streamable_http_embedded_bearer_secret_rejected(self) -> None:
        """Hardcoded bearer token in protection config is rejected by secret scanner."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "remote-api",
                    "transport": "streamable-http",
                    "connection": {
                        "url": "http://localhost:8080/mcp",
                        "headers": {
                            "Authorization": "Bearer real-secret-token",
                        },
                    },
                    "tool_bindings": {"fetch": {"tool_name": "fetch", "capability": "mcp.remote.fetch"}},
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("embedded credential", str(ctx.exception).lower())

    def test_streamable_http_missing_url_rejected(self) -> None:
        """Streamable HTTP integration missing url is rejected."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "remote-api",
                    "transport": "streamable-http",
                    "connection": {
                        "headers": {"X-Test": "val"},
                    },
                    "tool_bindings": {"fetch": {"tool_name": "fetch", "capability": "mcp.remote.fetch"}},
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("missing valid 'url'", str(ctx.exception).lower())

    def test_streamable_http_invalid_ssrf_url_rejected(self) -> None:
        """Streamable HTTP integration pointing to private IP is rejected."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "remote-api",
                    "transport": "streamable-http",
                    "connection": {
                        "url": "https://192.168.1.10/mcp",
                    },
                    "tool_bindings": {"fetch": {"tool_name": "fetch", "capability": "mcp.remote.fetch"}},
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("ssrf violation", str(ctx.exception).lower())

    def test_streamable_http_with_command_rejected(self) -> None:
        """Streamable HTTP integration with command is rejected."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "remote-api",
                    "transport": "streamable-http",
                    "connection": {
                        "url": "http://localhost:8080/mcp",
                        "command": "python",
                    },
                    "tool_bindings": {"fetch": {"tool_name": "fetch", "capability": "mcp.remote.fetch"}},
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("command is not supported", str(ctx.exception).lower())

    def test_stdio_with_url_rejected(self) -> None:
        """Stdio integration with url is rejected."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "stdio-api",
                    "transport": "stdio",
                    "connection": {
                        "command": "python",
                        "url": "http://localhost:8080/mcp",
                    },
                    "tool_bindings": {"fetch": {"tool_name": "fetch", "capability": "mcp.remote.fetch"}},
                }
            ],
        }
        with self.assertRaises(MCPConfigurationError) as ctx:
            parse_protection_config(data)
        self.assertIn("url is not supported", str(ctx.exception).lower())

    def test_mixed_transports_config(self) -> None:
        """Config with both stdio and streamable-http integrations loads cleanly."""
        data = {
            "policy": self.policy_data,
            "integrations": [
                {
                    "integration_id": "local-srv",
                    "transport": "stdio",
                    "connection": {"command": "cat"},
                    "tool_bindings": {"local_tool": {"tool_name": "local_tool", "capability": "cap.local"}},
                },
                {
                    "integration_id": "remote-srv",
                    "transport": "streamable_http",
                    "connection": {"url": "http://127.0.0.1:9000/mcp"},
                    "tool_bindings": {"remote_tool": {"tool_name": "remote_tool", "capability": "cap.remote"}},
                },
            ],
        }
        config = parse_protection_config(data)
        self.assertEqual(len(config.integrations), 2)
        local_cfg = config.get_integration("local-srv")
        remote_cfg = config.get_integration("remote-srv")
        self.assertIsNotNone(local_cfg)
        self.assertIsNotNone(remote_cfg)
        self.assertEqual(local_cfg.transport_type, MCPTransportType.STDIO)
        self.assertEqual(remote_cfg.transport_type, MCPTransportType.STREAMABLE_HTTP)


if __name__ == "__main__":
    unittest.main()
