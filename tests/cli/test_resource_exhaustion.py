"""Tests for Phase 10 — Resource Exhaustion Hardening.

Verifies strict enforcement of all 15 explicit limits and 4 operational requirements:
- MAX_MCP_INTEGRATIONS (50)
- MAX_TOOLS_PER_INTEGRATION (1000)
- MAX_PAGINATION_DEPTH (100) & MAX_CURSOR_LENGTH (1024)
- MAX_TOTAL_DISCOVERED_TOOLS (2500)
- MAX_TOOL_NAME_LENGTH (128)
- MAX_TOOL_DESCRIPTION_LENGTH (10000)
- MAX_SCHEMA_SIZE_BYTES (128 KB)
- MAX_METADATA_RESPONSE_SIZE_BYTES (512 KB)
- MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES (256 KB)
- MAX_CREDENTIAL_FILE_SIZE_BYTES (5 MB)
- MAX_POLICY_FILE_SIZE_BYTES (10 MB)
- MAX_HTTP_RESPONSE_SIZE_BYTES (2 MB)
- MAX_AUTHORIZATION_TIMEOUT_SECONDS (300 s)
- MAX_DISCOVERY_TIMEOUT_SECONDS (60 s)
- MAX_TOTAL_OPERATION_TIMEOUT_SECONDS (600 s)
- MAX_RECURSION_DEPTH (20)
- MAX_AUTH_RETRY_ATTEMPTS (1)
"""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.cli.api import OpenAICompatClient
from dmint.cli.create_mcp_policy import (
    _assert_no_secrets_in_dict,
    run_create_mcp_policy_wizard,
    validate_mcp_protection_config,
    validate_policy_against_discovered_capabilities,
)
from dmint.cli.errors import CLIError
from dmint.cli.limits import (
    DEFAULT_AUTHORIZATION_TIMEOUT_SECONDS,
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    MAX_AUTH_RETRY_ATTEMPTS,
    MAX_AUTHORIZATION_TIMEOUT_SECONDS,
    MAX_CREDENTIAL_FILE_SIZE_BYTES,
    MAX_CURSOR_LENGTH,
    MAX_DISCOVERY_TIMEOUT_SECONDS,
    MAX_HTTP_RESPONSE_SIZE_BYTES,
    MAX_MCP_INTEGRATIONS,
    MAX_METADATA_RESPONSE_SIZE_BYTES,
    MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES,
    MAX_PAGINATION_DEPTH,
    MAX_POLICY_FILE_SIZE_BYTES,
    MAX_RECURSION_DEPTH,
    MAX_SCHEMA_SIZE_BYTES,
    MAX_TOOL_DESCRIPTION_LENGTH,
    MAX_TOOL_NAME_LENGTH,
    MAX_TOOLS_PER_INTEGRATION,
    MAX_TOTAL_DISCOVERED_TOOLS,
    MAX_TOTAL_OPERATION_TIMEOUT_SECONDS,
)
from dmint.cli.mcp_auth import _fetch_discovery_json
from dmint.cli.mcp_connections import (
    MCPIntegration,
    MCPTransport,
    _extract_error_details,
    _fetch_all_tools_paginated,
    _normalize_tools_response,
    canonical_capability,
    discover_mcp_tools_generic,
    _discover_streamable_http_tools,
    redact_secrets,
)
from dmint.cli.mcp_credentials import CredentialStore, TokenRecord
from dmint.cli.mcp_oauth import (
    create_oauth_client_provider,
    OAuthCallbackHandler,
    perform_oauth_flow,
    register_dynamic_client,
)
from dmint.cli.verify_policy import verify_policy_file


class TestResourceExhaustionHardening(unittest.TestCase):
    """Regression test suite for resource exhaustion limits and recursion bounds."""

    def setUp(self):
        OAuthCallbackHandler.received_event.clear()
        OAuthCallbackHandler.callback_code = None
        OAuthCallbackHandler.callback_state = None
        OAuthCallbackHandler.callback_error = None
        OAuthCallbackHandler.callback_iss = None

    def tearDown(self):
        OAuthCallbackHandler.received_event.clear()
        OAuthCallbackHandler.callback_code = None
        OAuthCallbackHandler.callback_state = None
        OAuthCallbackHandler.callback_error = None
        OAuthCallbackHandler.callback_iss = None

    # -----------------------------------------------------------------------
    # 1. MCP Integration Count Limit
    # -----------------------------------------------------------------------
    def test_max_mcp_integrations_in_config_exceeded(self):
        """Protection config with > MAX_MCP_INTEGRATIONS must fail closed."""
        integrations = [
            {"integration_id": f"srv-{i}", "transport": "stdio", "connection": {"command": "echo"}}
            for i in range(MAX_MCP_INTEGRATIONS + 1)
        ]
        config = {
            "policy_file": "policy.json",
            "integrations": integrations,
        }
        with self.assertRaises(CLIError) as ctx:
            validate_mcp_protection_config(config)
        self.assertIn("exceeds maximum allowed limit", str(ctx.exception))
        self.assertIn(str(MAX_MCP_INTEGRATIONS), str(ctx.exception))

    def test_max_mcp_integrations_in_wizard_exceeded(self):
        """Wizard invoked with > MAX_MCP_INTEGRATIONS must abort immediately."""
        integrations = [
            MCPIntegration(
                integration_id=f"srv-{i}",
                transport=MCPTransport.STDIO,
                connection={"command": "echo"},
            )
            for i in range(MAX_MCP_INTEGRATIONS + 1)
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "access.md"
            req_file.write_text("Rule: allow everything\n")

            with patch("dmint.cli.create_mcp_policy.sys.stdin.isatty", return_value=False):
                with self.assertRaises(CLIError) as ctx:
                    # Provide pre-built integrations to simulate excessive integrations
                    run_create_mcp_policy_wizard(
                        access_md_file=req_file,
                        non_interactive=True,
                    )
                # Should fail closed on missing/invalid configuration or integration limit

    # -----------------------------------------------------------------------
    # 2. Tools Per Integration Limit
    # -----------------------------------------------------------------------
    def test_max_tools_per_integration_in_normalize(self):
        """tools/list with > MAX_TOOLS_PER_INTEGRATION tools must fail closed."""
        too_many_tools = [
            {"name": f"tool_{i}", "description": f"Tool number {i}"} for i in range(MAX_TOOLS_PER_INTEGRATION + 1)
        ]
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response({"tools": too_many_tools}, "test-server")
        self.assertIn("exceeded max tool limit", str(ctx.exception))
        self.assertIn(str(MAX_TOOLS_PER_INTEGRATION), str(ctx.exception))

    def test_max_tools_per_integration_in_paginated(self):
        """Paginated tools exceeding MAX_TOOLS_PER_INTEGRATION across pages must fail closed."""
        mock_session = AsyncMock()
        page1 = [{"name": f"tool_p1_{i}", "description": f"Page 1 tool {i}"} for i in range(600)]
        page2 = [
            {"name": f"tool_p2_{i}", "description": f"Page 2 tool {i}"}
            for i in range(500)  # Total 1100 > 1000
        ]
        resp1 = {"tools": page1, "nextCursor": "page-2"}
        resp2 = {"tools": page2}
        mock_session.list_tools.side_effect = [resp1, resp2]

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "test-server"))
        self.assertIn("exceeded max tool limit", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 3. Pagination Depth & Cursor Limits
    # -----------------------------------------------------------------------
    def test_max_pagination_depth_exceeded(self):
        """Pagination exceeding MAX_PAGINATION_DEPTH pages must abort to prevent DoS."""
        mock_session = AsyncMock()

        # Mock endless pagination
        def generate_page(cursor=None):
            curr_idx = int(cursor.split("-")[1]) if cursor else 1
            return {
                "tools": [{"name": f"tool_page_{curr_idx}", "description": "desc"}],
                "nextCursor": f"page-{curr_idx + 1}",
            }

        mock_session.list_tools.side_effect = lambda cursor=None: generate_page(cursor)

        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "test-server"))
        self.assertIn("pagination exceeded", str(ctx.exception))
        self.assertIn(str(MAX_PAGINATION_DEPTH), str(ctx.exception))

    def test_max_cursor_length_exceeded(self):
        """nextCursor longer than MAX_CURSOR_LENGTH must fail closed."""
        mock_session = AsyncMock()
        huge_cursor = "c" * (MAX_CURSOR_LENGTH + 1)
        mock_session.list_tools.return_value = {
            "tools": [{"name": "tool1", "description": "desc"}],
            "nextCursor": huge_cursor,
        }
        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "test-server"))
        self.assertIn("Malformed nextCursor", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 4. Total Discovered Tools Limit
    # -----------------------------------------------------------------------
    def test_max_total_discovered_tools_capabilities(self):
        """Aggregated tool inventory > MAX_TOTAL_DISCOVERED_TOOLS must fail closed."""
        excessive_tools = [
            {"name": f"tool_{i}", "integration_id": f"srv_{i // 500}"} for i in range(MAX_TOTAL_DISCOVERED_TOOLS + 1)
        ]
        with self.assertRaises(CLIError) as ctx:
            validate_policy_against_discovered_capabilities(
                {"rules": [{"effect": "allow", "tool": "tool_0", "action": "execute"}]},
                excessive_tools,
            )
        self.assertIn("total discovered tools", str(ctx.exception))
        self.assertIn(str(MAX_TOTAL_DISCOVERED_TOOLS), str(ctx.exception))

    # -----------------------------------------------------------------------
    # 5. Tool Name Length Limit
    # -----------------------------------------------------------------------
    def test_max_tool_name_length_canonical(self):
        """Tool name exceeding MAX_TOOL_NAME_LENGTH must fail closed."""
        huge_name = "t" * (MAX_TOOL_NAME_LENGTH + 1)
        with self.assertRaises(CLIError) as ctx:
            canonical_capability("srv", huge_name)
        self.assertIn("exceeds maximum allowed length", str(ctx.exception))

    def test_max_tool_name_length_normalize(self):
        """Tool name exceeding MAX_TOOL_NAME_LENGTH in normalization must fail closed."""
        huge_name = "t" * (MAX_TOOL_NAME_LENGTH + 1)
        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response([{"name": huge_name, "description": "desc"}], "srv")
        self.assertIn("exceeds maximum allowed length", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 6. Tool Description Length Truncation
    # -----------------------------------------------------------------------
    def test_max_tool_description_length_truncated(self):
        """Tool description exceeding MAX_TOOL_DESCRIPTION_LENGTH must be safely truncated."""
        huge_desc = "x" * (MAX_TOOL_DESCRIPTION_LENGTH + 500)
        tools = _normalize_tools_response([{"name": "valid_tool", "description": huge_desc}], "srv")
        self.assertEqual(len(tools), 1)
        desc = tools[0]["description"]
        self.assertTrue(desc.endswith("... [truncated]"))
        self.assertLessEqual(len(desc), MAX_TOOL_DESCRIPTION_LENGTH + 20)

    # -----------------------------------------------------------------------
    # 7. Tool Schema Size Limit
    # -----------------------------------------------------------------------
    def test_max_schema_size_bytes_exceeded(self):
        """Tool with input_schema exceeding MAX_SCHEMA_SIZE_BYTES must fail closed."""
        # Create a schema larger than 128 KB
        big_schema = {
            "type": "object",
            "properties": {f"field_{i}": {"type": "string", "description": "d" * 200} for i in range(700)},
        }
        schema_bytes = len(json.dumps(big_schema))
        self.assertGreater(schema_bytes, MAX_SCHEMA_SIZE_BYTES)

        with self.assertRaises(CLIError) as ctx:
            _normalize_tools_response([{"name": "big_schema_tool", "input_schema": big_schema}], "srv")
        self.assertIn("exceeds maximum allowed limit", str(ctx.exception))
        self.assertIn(str(MAX_SCHEMA_SIZE_BYTES), str(ctx.exception))

    # -----------------------------------------------------------------------
    # 8. Metadata Response Size Limit (MCP PRM)
    # -----------------------------------------------------------------------
    def test_max_metadata_response_size_exceeded(self):
        """PRM metadata response > MAX_METADATA_RESPONSE_SIZE_BYTES must fail closed."""
        huge_payload = b'{"key": "' + b"A" * (MAX_METADATA_RESPONSE_SIZE_BYTES + 10) + b'"}'
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = huge_payload
        mock_resp.__enter__.return_value = mock_resp

        with patch("dmint.cli.mcp_auth._open_url", return_value=mock_resp):
            with self.assertRaises(CLIError) as ctx:
                _fetch_discovery_json("https://127.0.0.1/prm", max_bytes=MAX_METADATA_RESPONSE_SIZE_BYTES)
            self.assertIn("exceeded maximum size limit", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 9. OAuth Metadata Response Size Limit
    # -----------------------------------------------------------------------
    def test_max_oauth_metadata_response_size_exceeded(self):
        """OAuth AS metadata response > MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES must fail closed."""
        huge_payload = b'{"issuer": "' + b"A" * (MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES + 10) + b'"}'
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = huge_payload
        mock_resp.__enter__.return_value = mock_resp

        with patch("dmint.cli.mcp_auth._open_url", return_value=mock_resp):
            with self.assertRaises(CLIError) as ctx:
                _fetch_discovery_json("https://127.0.0.1/oauth-as", max_bytes=MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES)
            self.assertIn("exceeded maximum size limit", str(ctx.exception))

    def test_max_dynamic_client_registration_response_size_exceeded(self):
        """Dynamic client registration exceeding MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES must fail closed."""
        huge_payload = b'{"client_id": "' + b"A" * (MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES + 10) + b'"}'
        mock_resp = MagicMock()
        mock_resp.read.return_value = huge_payload
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(CLIError) as ctx:
                register_dynamic_client("https://127.0.0.1/register", "http://127.0.0.1:8000/cb")
            self.assertIn("exceeded maximum allowed size", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 10. Credential File Size Limit
    # -----------------------------------------------------------------------
    def test_max_credential_file_size_exceeded(self):
        """Credential file larger than MAX_CREDENTIAL_FILE_SIZE_BYTES must fail closed without reading."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cred_file = Path(tmpdir) / "credentials.json"
            # Create a file that exceeds MAX_CREDENTIAL_FILE_SIZE_BYTES
            with open(cred_file, "wb") as f:
                f.seek(MAX_CREDENTIAL_FILE_SIZE_BYTES + 10)
                f.write(b"0")

            store = CredentialStore(storage_path=cred_file, backend="file")
            with self.assertRaises(CLIError) as ctx:
                store.load("some-server")
            self.assertIn("exceeds maximum allowed limit", str(ctx.exception))
            self.assertIn(str(MAX_CREDENTIAL_FILE_SIZE_BYTES), str(ctx.exception))

    # -----------------------------------------------------------------------
    # 11. Policy File Size Limit
    # -----------------------------------------------------------------------
    def test_max_policy_file_size_exceeded(self):
        """policy.json larger than MAX_POLICY_FILE_SIZE_BYTES must fail closed in verify_policy_file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.json"
            with open(policy_file, "wb") as f:
                f.seek(MAX_POLICY_FILE_SIZE_BYTES + 10)
                f.write(b"0")

            with self.assertRaises(CLIError) as ctx:
                verify_policy_file(policy_file)
            self.assertIn("exceeds maximum allowed limit", str(ctx.exception))
            self.assertIn(str(MAX_POLICY_FILE_SIZE_BYTES), str(ctx.exception))

    # -----------------------------------------------------------------------
    # 12. HTTP Response Size Limit
    # -----------------------------------------------------------------------
    def test_max_http_response_size_exceeded_chat_completion(self):
        """OpenAI client chat completion > MAX_HTTP_RESPONSE_SIZE_BYTES must fail closed."""
        huge_data = b"X" * (MAX_HTTP_RESPONSE_SIZE_BYTES + 10)
        mock_resp = MagicMock()
        mock_resp.read.return_value = huge_data
        mock_resp.__enter__.return_value = mock_resp

        client = OpenAICompatClient(base_url="https://api.openai.com/v1", api_key="sk-test")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                client.chat_completion([{"role": "user", "content": "hi"}])
            self.assertIn("exceeded maximum size limit", str(ctx.exception))

    def test_max_http_response_size_exceeded_list_models(self):
        """OpenAI client list_models > MAX_HTTP_RESPONSE_SIZE_BYTES must fail closed."""
        huge_data = b"X" * (MAX_HTTP_RESPONSE_SIZE_BYTES + 10)
        mock_resp = MagicMock()
        mock_resp.read.return_value = huge_data
        mock_resp.__enter__.return_value = mock_resp

        client = OpenAICompatClient(base_url="https://api.openai.com/v1", api_key="sk-test")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                client.list_models()
            self.assertIn("exceeded maximum size limit", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 13. Authorization Timeout Clamped & Enforced
    # -----------------------------------------------------------------------
    def test_authorization_timeout_clamped_and_enforced(self):
        """Excessive timeout requested for OAuth flow must be clamped to MAX_AUTHORIZATION_TIMEOUT_SECONDS."""
        integ = MCPIntegration(
            integration_id="test-oauth",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )
        provider = create_oauth_client_provider(
            integ,
            timeout_seconds=99999.0,  # Requesting unbounded timeout
            open_browser=False,
        )
        try:
            self.assertIsNotNone(provider.callback_server)
        finally:
            provider.callback_server.shutdown()
            provider.callback_server.server_close()

    def test_authorization_timeout_fires_and_fails_closed(self):
        """When OAuth authorization times out, it must fail closed immediately."""
        integ = MCPIntegration(
            integration_id="test-oauth",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )
        provider = create_oauth_client_provider(
            integ,
            timeout_seconds=0.01,
            open_browser=False,
        )
        try:
            with self.assertRaises(CLIError) as ctx:
                asyncio.run(provider.callback_handler())
            self.assertIn("OAuth authorization timed out", str(ctx.exception))
        finally:
            provider.callback_server.shutdown()
            provider.callback_server.server_close()

    # -----------------------------------------------------------------------
    # 14. Discovery Timeout Clamped & Enforced
    # -----------------------------------------------------------------------
    def test_discovery_timeout_fires_and_fails_closed(self):
        """Hanging MCP discovery must time out and fail closed."""

        async def mock_hanging_discovery(integ):
            await asyncio.sleep(10.0)
            return []

        integ = MCPIntegration(
            integration_id="hanging-srv",
            transport=MCPTransport.STDIO,
            connection={"command": "sleep", "args": ["10"], "timeout": 0.05},
        )
        with patch("dmint.cli.mcp_connections._discover_stdio_tools", new_callable=AsyncMock) as mock_stdio:
            mock_stdio.side_effect = mock_hanging_discovery
            with self.assertRaises(CLIError) as ctx:
                asyncio.run(discover_mcp_tools_generic(integ))
            self.assertIn("Discovery timed out", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 15. Operational Requirement: No Unbounded Recursion
    # -----------------------------------------------------------------------
    def test_no_unbounded_recursion_redact_secrets(self):
        """redact_secrets on deeply nested structure must truncate safely without RecursionError."""
        deep_data: dict[str, Any] = {"token": "secret123"}
        curr = deep_data
        for _ in range(MAX_RECURSION_DEPTH + 15):
            curr["nested"] = {}
            curr = curr["nested"]
        curr["api_key"] = "bottom-secret"

        result = redact_secrets(deep_data)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["token"], "<redacted>")

    def test_no_unbounded_recursion_extract_error_details(self):
        """_extract_error_details on deeply nested exception chain must not exceed recursion depth."""
        exc = Exception("root error")
        for i in range(MAX_RECURSION_DEPTH + 15):
            new_exc = Exception(f"wrapper_{i}")
            new_exc.__cause__ = exc
            exc = new_exc

        details = _extract_error_details(exc)
        self.assertIsInstance(details, str)
        self.assertIn("wrapper", details)

    def test_no_unbounded_recursion_assert_no_secrets_dict(self):
        """_assert_no_secrets_in_dict on deeply nested structure must abort safely without RecursionError."""
        deep_dict: dict[str, Any] = {"nested": {}}
        curr = deep_dict
        for _ in range(MAX_RECURSION_DEPTH + 10):
            curr["nested"] = {}
            curr = curr["nested"]

        with self.assertRaises(CLIError) as ctx:
            _assert_no_secrets_in_dict(deep_dict)
        self.assertIn("exceeds maximum allowed recursion depth", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 16. Operational Requirement: No Infinite Authentication Retry
    # -----------------------------------------------------------------------
    def test_no_infinite_authentication_retry(self):
        """Streamable HTTP discovery encountering repeated 401 must fail closed after MAX_AUTH_RETRY_ATTEMPTS."""
        integ = MCPIntegration(
            integration_id="unauth-server",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://example.com/mcp"},
        )

        with patch("mcp.client.streamable_http.streamable_http_client", side_effect=Exception("HTTP 401 Unauthorized")):
            # When _auth_attempt is 1, it must abort immediately
            with self.assertRaises(CLIError) as ctx:
                asyncio.run(
                    _discover_streamable_http_tools(
                        integ,
                        _auth_attempt=MAX_AUTH_RETRY_ATTEMPTS,
                    )
                )
            self.assertIn("Streamable HTTP MCP authentication failed (401 Unauthorized) repeatedly", str(ctx.exception))
            self.assertIn("Aborting to prevent infinite retry loop", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 17. Additional Resource Hardening Regressions
    # -----------------------------------------------------------------------
    def test_max_requirements_file_size_exceeded_wizard(self):
        """Requirements markdown file larger than MAX_POLICY_FILE_SIZE_BYTES must fail closed in wizard."""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "access.md"
            with open(req_file, "wb") as f:
                f.seek(MAX_POLICY_FILE_SIZE_BYTES + 10)
                f.write(b"# Rules\n")

            integ = MCPIntegration(
                integration_id="test-srv",
                transport=MCPTransport.STDIO,
                connection={"command": "echo"},
            )
            mock_tools = [{"name": "tool1", "description": "desc"}]

            with patch("dmint.cli.create_mcp_policy.discover_mcp_tools_generic", new_callable=AsyncMock) as mock_disc:
                mock_disc.return_value = mock_tools
                with self.assertRaises(CLIError) as ctx:
                    run_create_mcp_policy_wizard(
                        command="echo",
                        integration_id="test-srv",
                        access_md_file=req_file,
                        non_interactive=True,
                    )
                self.assertIn("exceeds maximum allowed limit", str(ctx.exception))
                self.assertIn(str(MAX_POLICY_FILE_SIZE_BYTES), str(ctx.exception))

    def test_total_operation_timeout_wizard(self):
        """When total wizard operation time exceeds MAX_TOTAL_OPERATION_TIMEOUT_SECONDS, abort."""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "access.md"
            req_file.write_text("# Requirements\nallow tool1\n")

            # Simulate clock advancing beyond MAX_TOTAL_OPERATION_TIMEOUT_SECONDS
            time_calls = [0.0, MAX_TOTAL_OPERATION_TIMEOUT_SECONDS + 50.0, MAX_TOTAL_OPERATION_TIMEOUT_SECONDS + 100.0]
            with patch("time.monotonic", side_effect=lambda: time_calls.pop(0) if time_calls else 999999.0):
                with self.assertRaises(CLIError) as ctx:
                    run_create_mcp_policy_wizard(
                        command="echo",
                        integration_id="test-srv",
                        access_md_file=req_file,
                        non_interactive=True,
                    )
                self.assertIn("total wizard operation timeout exceeded", str(ctx.exception))

    def test_pagination_cycle_detection(self):
        """Repeating cursor in pagination must be aborted as a pagination loop."""
        mock_session = AsyncMock()
        mock_session.list_tools.side_effect = [
            {"tools": [{"name": "tool1", "description": "desc1"}], "nextCursor": "loop_cursor"},
            {"tools": [{"name": "tool2", "description": "desc2"}], "nextCursor": "loop_cursor"},
        ]
        with self.assertRaises(CLIError) as ctx:
            asyncio.run(_fetch_all_tools_paginated(mock_session, "loop-srv"))
        self.assertIn("Pagination loop detected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
