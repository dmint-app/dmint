"""Comprehensive tests covering uncovered error and execution paths in dmint.mcp.gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from mcp import types
from mcp.server.lowlevel.server import ServerRequestContext

import uvicorn
from starlette.applications import Starlette

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.core.approvals import PolicyProvenance
from dmint.core.errors import ApprovalRequiredError, AuthorizationError
from dmint.core.keys import public_key_hex
from dmint.core.policy import Policy, Rule
from dmint.core.storage.base import ApprovalStore
from dmint.core.storage.sqlite import SQLiteApprovalStore
from dmint.core.storage.thread_safe import ThreadSafeApprovalStore
from dmint.mcp.client import DownstreamMCPClient
from dmint.mcp.config_loader import (
    DisclosureMode,
    DiscoveryMode,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPToolBinding,
    MCPTransportType,
    TrustedIssuerConfig,
)
from mcp.shared.exceptions import MCPError as SDKMCPError

from dmint.mcp.errors import (
    MCPConfigurationError,
    MCPConnectionError,
    MCPMappingError,
    MCPProtocolError,
    MCPTimeoutError,
)
from dmint.mcp.proxy import MCPProxyError
from dmint.mcp.gateway import MCPGateway, parse_gateway_request


class GatewayCoverageC1Tests(unittest.IsolatedAsyncioTestCase):
    """Test error paths and edge cases in MCPGateway."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

        self.policy = Policy(
            [
                Rule.allow("integ1.tool1", "run"),
                Rule.allow("integ2.tool1", "run"),
            ]
        )
        self.prov = PolicyProvenance("v1", hashlib.sha256(b"pol").hexdigest(), datetime.now(timezone.utc))

        self.int1_cfg = MCPIntegrationConfig(
            integration_id="integ1",
            command="echo",
            args=["hello"],
            transport_type=MCPTransportType.STDIO,
            tool_bindings=[MCPToolBinding("tool1", "integ1.tool1")],
        )
        self.int2_cfg = MCPIntegrationConfig(
            integration_id="integ2",
            command="echo",
            args=["world"],
            transport_type=MCPTransportType.STDIO,
            tool_bindings=[MCPToolBinding("tool1", "integ2.tool1")],
        )

        self.gateway_config = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.prov,
            integrations=(self.int1_cfg, self.int2_cfg),
            agent_id="test-agent",
            disclosure_mode=DisclosureMode.DOG,
        )

        self.mock_client1 = MagicMock(spec=DownstreamMCPClient)
        self.mock_client1.connect = AsyncMock()
        self.mock_client1.disconnect = AsyncMock()
        self.mock_client1.list_tools = AsyncMock(return_value=[types.Tool(name="tool1", input_schema={})])
        self.mock_client1.call_tool = AsyncMock(return_value=types.CallToolResult(content=[]))

        self.mock_client2 = MagicMock(spec=DownstreamMCPClient)
        self.mock_client2.connect = AsyncMock()
        self.mock_client2.disconnect = AsyncMock()
        self.mock_client2.list_tools = AsyncMock(return_value=[types.Tool(name="tool1", input_schema={})])
        self.mock_client2.call_tool = AsyncMock(return_value=types.CallToolResult(content=[]))

        def client_factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            return self.mock_client1 if cfg.integration_id == "integ1" else self.mock_client2

        self.client_factory = client_factory

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_parse_raw_message_errors(self) -> None:
        """parse_gateway_request validates UTF-8, type, and JSON format."""
        # Invalid UTF-8
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request(b"\xff\xfe\x00")
        self.assertEqual(ctx.exception.code, "DMT_MCP_PROTOCOL_ERROR")

        # Non-string/non-bytes
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request(12345)  # type: ignore[arg-type]
        self.assertIn("must be text or bytes", str(ctx.exception))

        # Malformed JSON
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request("{not json")
        self.assertIn("malformed JSON", str(ctx.exception))

        # Non-dict JSON
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request("[1, 2, 3]")
        self.assertIn("must be a JSON object", str(ctx.exception))

    def test_gateway_init_validations(self) -> None:
        """MCPGateway constructor validates config and wraps sqlite store."""
        # Non-MCPGatewayConfig
        with self.assertRaises(MCPConfigurationError):
            MCPGateway(config="not_a_config")  # type: ignore[arg-type]

        # Non-ApprovalStore
        with self.assertRaises(TypeError):
            MCPGateway(config=self.gateway_config, approval_store="not_a_store")  # type: ignore[arg-type]

        # SQLiteApprovalStore wrapped in ThreadSafeApprovalStore
        db_file = self.tmp_path / "appr.db"
        sqlite_store = SQLiteApprovalStore(db_file, deployment_epoch="ep1")
        gw = MCPGateway(config=self.gateway_config, approval_store=sqlite_store)
        self.assertIsInstance(gw.approval_store, ThreadSafeApprovalStore)
        if gw.approval_store is not None:
            gw.approval_store.close()

    def test_properties_and_policy_reload(self) -> None:
        """Test properties and reload_policy method."""
        pol_file = self.tmp_path / "reload_policy.json"
        pol_file.write_text(
            json.dumps({"rules": [{"tool": "integ1.tool1", "action": "run", "resource": "*", "effect": "allow"}]}),
            encoding="utf-8",
        )

        cfg = MCPGatewayConfig(
            policy=self.policy,
            policy_file=str(pol_file),
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            agent_id="test-agent",
        )
        gw = MCPGateway(config=cfg, client_factory=self.client_factory)
        self.assertEqual(gw.config, cfg)
        self.assertIn("integ1", gw.integrations)
        self.assertFalse(gw.is_connected)

        # Reload success
        gw.reload_policy()

        # Reload error: no policy_file configured
        gw_no_file = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        with self.assertRaises(MCPConfigurationError) as ctx:
            gw_no_file.reload_policy()
        self.assertIn("no policy_file configured", str(ctx.exception))

        # Reload error: https policy without expected digest
        cfg_https = MCPGatewayConfig(
            policy=self.policy,
            policy_file="https://example.com/pol.json",
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            agent_id="test-agent",
        )
        gw_https = MCPGateway(config=cfg_https, client_factory=self.client_factory)
        with self.assertRaises(MCPConfigurationError) as ctx:
            gw_https.reload_policy()
        self.assertIn("remote policy loading requires expected_policy_digest", str(ctx.exception))

    def test_resolve_tool_routing_errors(self) -> None:
        """resolve_tool fails closed on unknown, empty, or ambiguous tools."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)

        # Empty tool name
        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("   ")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

        # Unknown tool with dot
        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("integ1.unknown_tool")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

        # Unknown tool with slash
        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("integ1/unknown_tool")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

        # Ambiguous bare tool name across multiple integrations
        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("tool1")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_AMBIGUOUS")

        # Unknown bare tool
        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("no_such_tool")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

    async def test_connect_failures_and_cleanup(self) -> None:
        """connect disconnects and raises MCPConnectionError when any client fails."""
        failing_client = MagicMock(spec=DownstreamMCPClient)
        failing_client.connect = AsyncMock(side_effect=Exception("connection refused"))
        failing_client.disconnect = AsyncMock()

        def factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            return failing_client

        gw = MCPGateway(config=self.gateway_config, client_factory=factory)
        with self.assertRaises(MCPConnectionError) as ctx:
            await gw.connect()
        self.assertIn("failed to connect downstream integration", str(ctx.exception))
        failing_client.disconnect.assert_awaited()

    async def test_list_tools_not_connected_and_error(self) -> None:
        """_handle_list_tools raises MCPProxyError when not connected and translates MCPConnectionError."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        ctx = MagicMock(spec=ServerRequestContext)

        # Not connected
        with self.assertRaises(MCPProxyError):
            await gw._handle_list_tools(ctx, types.PaginatedRequestParams())

        # Connected, but downstream list_tools raises
        await gw.connect()
        self.mock_client1.list_tools.side_effect = Exception("stream died")
        with self.assertRaises(SDKMCPError) as ctx_err:
            await gw._handle_list_tools(ctx, types.PaginatedRequestParams())
        self.assertIn("failed to list tools from integration", str(ctx_err.exception.message))

    async def test_handle_call_tool_validation_and_spoofing(self) -> None:
        """_handle_call_tool validates connection, name, arguments, and prevents agent spoofing."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        ctx = MagicMock(spec=ServerRequestContext)

        # 1. Not connected
        params_bad = types.CallToolRequestParams(name="integ1.tool1", arguments={})
        with self.assertRaises(MCPProxyError):
            await gw._handle_call_tool(ctx, params_bad)

        await gw.connect()

        # 2. Empty tool name
        params_no_name = types.CallToolRequestParams(name="", arguments={})
        with self.assertRaises(MCPProtocolError):
            await gw._handle_call_tool(ctx, params_no_name)

        # 3. Non-dict arguments
        params_non_dict = MagicMock()
        params_non_dict.name = "integ1.tool1"
        params_non_dict.arguments = "bad"
        with self.assertRaises(MCPProtocolError):
            await gw._handle_call_tool(ctx, params_non_dict)

        # 4. Agent spoofing in arguments
        params_spoof_args = types.CallToolRequestParams(
            name="integ1.tool1",
            arguments={"agent_id": "malicious-impersonator"},
        )
        res = await gw._handle_call_tool(ctx, params_spoof_args)
        self.assertTrue(res.is_error)
        self.assertIn("DMT_AGENT_IDENTITY_MISMATCH", res.content[0].text)

        # 5. Agent spoofing in params.model_extra
        params_spoof_extra = MagicMock()
        params_spoof_extra.name = "integ1.tool1"
        params_spoof_extra.arguments = {"cmd": "ls"}
        params_spoof_extra.agent_id = None
        params_spoof_extra.model_extra = {"agent_id": "malicious-impersonator"}
        res_extra = await gw._handle_call_tool(ctx, params_spoof_extra)
        self.assertTrue(res_extra.is_error)
        self.assertIn("DMT_AGENT_IDENTITY_MISMATCH", res_extra.content[0].text)

    def test_disclosure_formatting_modes(self) -> None:
        """_format_approval_required_result and _format_authorization_error_result obey GOD and CAT modes."""
        cfg_god = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            disclosure_mode=DisclosureMode.GOD,
        )
        gw_god = MCPGateway(config=cfg_god, client_factory=self.client_factory)

        exc_req = ApprovalRequiredError(
            "approval needed",
            request_id="req_1",
            approval_id="apr_1",
            request_fingerprint="fp1",
        )
        res_god_req = gw_god._format_approval_required_result(exc_req)
        self.assertIn("access denied", res_god_req.content[0].text)

        res_god_auth = gw_god._format_authorization_error_result(AuthorizationError("forbidden"))
        self.assertIn("access denied", res_god_auth.content[0].text)

        res_god_err = gw_god._format_error_result(Exception("crash"))
        self.assertIn("execution failed", res_god_err.content[0].text)

        # CAT mode
        cfg_cat = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            disclosure_mode=DisclosureMode.CAT,
        )
        gw_cat = MCPGateway(config=cfg_cat, client_factory=self.client_factory)
        res_cat = gw_cat._format_approval_required_result(exc_req)
        self.assertIn("DMT_APPROVAL_REQUIRED", res_cat.content[0].text)
        self.assertIn("req_1", res_cat.content[0].text)

    def test_http_transport_security_and_auth_checks(self) -> None:
        """create_http_app and serve_http reject insecure public binding and wildcards."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)

        # Public bind without auth raises MCPConfigurationError
        with self.assertRaises(MCPConfigurationError) as ctx:
            gw.create_http_app(host="0.0.0.0")
        self.assertIn("without transport authentication configured", str(ctx.exception))

        # Wildcard CORS with auth raises MCPConfigurationError
        with self.assertRaises(MCPConfigurationError) as ctx:
            gw.create_http_app(
                host="127.0.0.1",
                auth_token="token123",
                allowed_origins=["*"],
            )
        self.assertIn("Permissive wildcard CORS ('*') is forbidden", str(ctx.exception))

        # Token mapping initializes AgentAuthenticator
        app = gw.create_http_app(
            host="127.0.0.1",
            token_mapping={"tok1": "agent1"},
        )
        self.assertIsNotNone(app)

    def test_parse_gateway_request_empty_and_non_dict(self) -> None:
        """parse_gateway_request handles empty objects and rejects non-dict JSON."""
        self.assertEqual(parse_gateway_request("{}"), {})
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request("[1, 2, 3]")
        self.assertIn("must be a JSON object", str(ctx.exception))

    def test_trusted_issuers_and_custom_stores(self) -> None:
        """MCPGateway initialization handles trusted issuers and diverse approval stores."""
        priv = Ed25519PrivateKey.generate()
        pub_hex = public_key_hex(priv.public_key())

        # Valid trusted issuer
        cfg_valid = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            trusted_issuers=(TrustedIssuerConfig(issuer_id="iss1", public_key_hex=pub_hex),),
        )
        gw_valid = MCPGateway(config=cfg_valid, client_factory=self.client_factory)
        self.assertIsNotNone(gw_valid._approval_verifier)

        # Invalid trusted issuer hex
        cfg_invalid = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            trusted_issuers=(TrustedIssuerConfig(issuer_id="bad", public_key_hex="not-hex"),),
        )
        with self.assertRaises(MCPConfigurationError):
            MCPGateway(config=cfg_invalid, client_factory=self.client_factory)

        # ThreadSafeApprovalStore pass-through
        ts_store = ThreadSafeApprovalStore(str(self.tmp_path / "ts.db"))
        gw_ts = MCPGateway(config=self.gateway_config, approval_store=ts_store, client_factory=self.client_factory)
        self.assertIs(gw_ts.approval_store, ts_store)
        ts_store.close()

        # SQLiteApprovalStore exception on PRAGMA database_list fallback
        mock_sqlite = MagicMock()
        mock_sqlite.__class__ = SQLiteApprovalStore
        mock_sqlite._connection = MagicMock()
        mock_sqlite._connection.execute.side_effect = RuntimeError("pragma failed")
        gw_sqlite = MCPGateway(
            config=self.gateway_config, approval_store=mock_sqlite, client_factory=self.client_factory
        )
        self.assertIs(gw_sqlite.approval_store, mock_sqlite)

        # Generic ApprovalStore subclass
        mock_generic = MagicMock(spec=ApprovalStore)
        gw_dummy = MCPGateway(
            config=self.gateway_config, approval_store=mock_generic, client_factory=self.client_factory
        )
        self.assertIs(gw_dummy.approval_store, mock_generic)

    async def test_connect_verify_schema_failure(self) -> None:
        """connect() rolls back and disconnects if schema verification fails."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        with patch.object(
            gw._integrations["integ1"].gate,
            "verify_all_tool_schemas",
            AsyncMock(side_effect=RuntimeError("schema mismatch")),
        ):
            with self.assertRaises(RuntimeError):
                await gw.connect()
            self.assertFalse(gw.is_connected)

    async def test_disconnect_handles_store_close_error(self) -> None:
        """disconnect() catches and suppresses errors when closing owned approval store."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        mock_store = MagicMock()
        mock_store.close.side_effect = RuntimeError("close failed")
        gw._own_store = True
        gw._approval_store = mock_store
        await gw.disconnect()
        self.assertIsNone(gw._approval_store)

    async def test_list_tools_timeout_propagation(self) -> None:
        """list_tools() re-raises MCPTimeoutError directly without wrapping."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        with patch.object(
            gw._integrations["integ1"].gate, "list_tools", AsyncMock(side_effect=MCPTimeoutError("timed out"))
        ):
            with self.assertRaises(MCPTimeoutError):
                await gw.list_tools()

    def test_resolve_tool_namespacing(self) -> None:
        """resolve_tool correctly handles dot and slash namespacing and missing tools."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)

        # Dot namespacing
        integ, downstream = gw.resolve_tool("integ1.tool1")
        self.assertEqual(integ.config.integration_id, "integ1")
        self.assertEqual(downstream, "tool1")

        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("integ1.nonexistent")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

        # Slash namespacing
        integ_s, downstream_s = gw.resolve_tool("integ2/tool1")
        self.assertEqual(integ_s.config.integration_id, "integ2")
        self.assertEqual(downstream_s, "tool1")

        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("integ2/nonexistent")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

        # Unknown prefix with slash falls through to bare lookup
        with self.assertRaises(MCPMappingError) as ctx:
            gw.resolve_tool("unknown_integ/tool1")
        self.assertEqual(ctx.exception.code, "DMT_MCP_TOOL_NOT_FOUND")

    async def test_handle_call_tool_dict_cred_and_error_branches(self) -> None:
        """_handle_call_tool serializes dict approval credentials and maps connection/internal errors."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        await gw.connect()
        ctx = MagicMock(spec=ServerRequestContext)

        # Dict credential converts via canonicalize_bytes and calls retry_call
        gw.retry_call = AsyncMock(
            return_value=types.CallToolResult(content=[types.TextContent(type="text", text="retried")])
        )
        params_dict = types.CallToolRequestParams(name="tool1", arguments={"approval_credential": {"id": "apr_123"}})
        res_dict = await gw._handle_call_tool(ctx, params_dict)
        self.assertFalse(res_dict.is_error)
        gw.retry_call.assert_called_once()

        # Connection / protocol error mapping
        gw.route_call = AsyncMock(side_effect=MCPConnectionError("downstream severed"))
        res_conn = await gw._handle_call_tool(ctx, types.CallToolRequestParams(name="tool1", arguments={}))
        self.assertTrue(res_conn.is_error)
        self.assertIn("DMT_MCP_CONNECTION_ERROR", res_conn.content[0].text)

        # Internal / unexpected error mapping
        gw.route_call = AsyncMock(side_effect=RuntimeError("unexpected bug"))
        res_int = await gw._handle_call_tool(ctx, types.CallToolRequestParams(name="tool1", arguments={}))
        self.assertTrue(res_int.is_error)
        self.assertIn("DMT_INTERNAL_ERROR", res_int.content[0].text)
        await gw.disconnect()

    async def test_serve_stdio_lifecycle(self) -> None:
        """serve_stdio connects, runs server, and disconnects."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_ctx.__aexit__.return_value = None

        with patch("dmint.mcp.gateway.stdio_server", return_value=mock_ctx):
            with patch.object(gw._server, "run", AsyncMock()) as mock_run:
                await gw.serve_stdio()
                mock_run.assert_called_once()
        self.assertFalse(gw.is_connected)

    async def test_http_non_loopback_and_lifespan(self) -> None:
        """create_http_app supports non-loopback host with auth, and lifespan connects."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        app = gw.create_http_app(
            host="192.168.1.50",
            auth_token="secret-token",
            allowed_origins=["https://dashboard.internal"],
        )
        self.assertIsNotNone(app)

        # Lifespan connects gateway
        async with app.router.lifespan_context(app):
            self.assertTrue(gw.is_connected)
        await gw.disconnect()

    async def test_serve_http_lifecycle(self) -> None:
        """serve_http binds, serves, and safely disconnects."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        with patch.object(uvicorn.Server, "serve", AsyncMock()) as mock_serve:
            await gw.serve_http(host="127.0.0.1", port=9999, auth_token="tok")
            mock_serve.assert_called_once()
        self.assertFalse(gw.is_connected)

    def test_reload_policy_error_paths(self) -> None:
        """reload_policy enforces policy_file existence and remote digest requirements."""
        gw = MCPGateway(config=self.gateway_config, client_factory=self.client_factory)
        with self.assertRaises(MCPConfigurationError) as ctx:
            gw.reload_policy()
        self.assertIn("no policy_file configured", str(ctx.exception))

        gw._config = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.prov,
            integrations=(self.int1_cfg,),
            policy_file="https://example.com/policy.json",
        )
        with self.assertRaises(MCPConfigurationError) as ctx2:
            gw.reload_policy()
        self.assertIn("remote policy loading requires expected_policy_digest", str(ctx2.exception))
