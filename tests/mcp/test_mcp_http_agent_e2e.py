"""End-to-end integration test: Remote HTTP Client -> Dmint HTTP Gateway -> Core -> Downstream MCP."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
import mcp.types as types
import uvicorn

from dmint.approvals import ApprovalAuthority, ApprovalAuthorityKind, PolicyProvenance
from dmint.authority import ApprovalVerifier, LocalApprovalAuthority
from dmint.models import AnyResource
from dmint.policy import Policy, Rule, policy_digest
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPToolBinding,
    MCPTransportType,
)

ISSUER = "local-sec-ops"
AUDIENCE = "dmint-gateway"


class TestAgentFacingHTTPEndToEnd(unittest.IsolatedAsyncioTestCase):
    """Full E2E test verifying remote AI agent communication over Streamable HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.store_path = Path(cls.temp_dir.name) / "approvals.db"

        # 1. Start downstream MCP server (echo & calculator tools)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.downstream_port = s.getsockname()[1]

        cls.downstream_mcp = MCPServer("downstream-calc-server")
        cls.downstream_calls: list[dict] = []

        @cls.downstream_mcp.tool()
        def add(a: int, b: int) -> int:
            cls.downstream_calls.append({"tool": "add", "args": {"a": a, "b": b}})
            return a + b

        @cls.downstream_mcp.tool()
        def wipe_database(confirm: bool) -> str:
            cls.downstream_calls.append({"tool": "wipe_database", "args": {"confirm": confirm}})
            return "all data wiped"

        @cls.downstream_mcp.tool()
        def admin_shutdown() -> str:
            cls.downstream_calls.append({"tool": "admin_shutdown", "args": {}})
            return "system shutdown"

        downstream_app = cls.downstream_mcp.streamable_http_app(transport_security=None)
        cls.downstream_server = uvicorn.Server(
            uvicorn.Config(downstream_app, host="127.0.0.1", port=cls.downstream_port, log_level="error")
        )
        cls.downstream_thread = threading.Thread(target=cls.downstream_server.run, daemon=True)
        cls.downstream_thread.start()

        for _ in range(50):
            time.sleep(0.05)
            if cls.downstream_server.started:
                break

        cls.downstream_url = f"http://127.0.0.1:{cls.downstream_port}/mcp"

        # 2. Setup Dmint Gateway and Core
        cls.authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE)
        cls.verifier = ApprovalVerifier(trusted_issuers={ISSUER: cls.authority.public_key}, audience=AUDIENCE)

        cls.policy = Policy(
            rules=(
                Rule.allow("calc", "add", resource=AnyResource()),
                Rule.deny("calc", "shutdown", resource=AnyResource()),
                Rule.approval_required("calc", "wipe", resource=AnyResource()),
            )
        )

        cls.provenance = PolicyProvenance(
            "v1",
            policy_digest(cls.policy),
            datetime.now(timezone.utc),
        )

        cls.integ_cfg = MCPIntegrationConfig(
            integration_id="calc",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url=cls.downstream_url,
            connect_timeout=10.0,
            call_timeout=10.0,
            tool_bindings=[
                MCPToolBinding("add", "calc.add", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("admin_shutdown", "calc.shutdown", discovery=DiscoveryMode.EXPOSED),
                MCPToolBinding("wipe_database", "calc.wipe", discovery=DiscoveryMode.EXPOSED),
            ],
        )

        cls.config = MCPGatewayConfig(
            server_name="agent-facing-gateway",
            agent_id="worker-agent",
            policy=cls.policy,
            policy_provenance=cls.provenance,
            integrations=[cls.integ_cfg],
            approval_store_path=cls.store_path,
            disclosure_mode=DisclosureMode.DOG,
            approval_ttl=timedelta(minutes=5),
        )

        cls.gateway = MCPGateway(
            cls.config,
            approval_verifier=cls.verifier,
        )

        # 3. Start agent-facing gateway Uvicorn server (gateway_lifespan connects automatically)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.gateway_port = s.getsockname()[1]

        cls.auth_token = "valid_agent_bearer_token_123"
        cls.gateway_url = f"http://127.0.0.1:{cls.gateway_port}/mcp"

        cls.gateway_app = cls.gateway.create_http_app(
            host="127.0.0.1",
            auth_token=f"{cls.auth_token}=worker-agent",
        )

        cls.uv_gateway = uvicorn.Server(
            uvicorn.Config(cls.gateway_app, host="127.0.0.1", port=cls.gateway_port, log_level="error")
        )
        cls.gateway_thread = threading.Thread(target=cls.uv_gateway.run, daemon=True)
        cls.gateway_thread.start()

        for _ in range(50):
            time.sleep(0.05)
            if cls.uv_gateway.started:
                break

    @classmethod
    def tearDownClass(cls):
        cls.uv_gateway.should_exit = True
        cls.gateway_thread.join(timeout=3.0)

        cls.downstream_server.should_exit = True
        cls.downstream_thread.join(timeout=3.0)

        cls.temp_dir.cleanup()

    def setUp(self):
        self.downstream_calls.clear()

    async def test_1_unauthenticated_agent_rejected_with_401(self):
        """AI agent connecting without valid bearer token fails immediately with HTTP 401."""
        async with httpx2.AsyncClient() as client:
            resp = await client.post(self.gateway_url, json={"method": "tools/list"})
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.headers.get("www-authenticate"), 'Bearer error="invalid_token"')

            # Invalid token
            resp_bad = await client.post(
                self.gateway_url,
                json={"method": "tools/list"},
                headers={"Authorization": "Bearer bad_secret"},
            )
            self.assertEqual(resp_bad.status_code, 401)

    async def test_2_authenticated_agent_session_e2e_lifecycle(self):
        """AI agent connects with Bearer auth, lists tools, executes ALLOW, DENY, and APPROVAL retry."""
        headers = {"Authorization": f"Bearer {self.auth_token}"}

        async with httpx2.AsyncClient(headers=headers) as http_client:
            async with streamable_http_client(self.gateway_url, http_client=http_client) as (read_s, write_s):
                async with ClientSession(read_s, write_s) as session:
                    await session.initialize()

                    # 1. Discover tools
                    tools_res = await session.list_tools()
                    discovered_names = {t.name for t in tools_res.tools}
                    self.assertIn("add", discovered_names)
                    self.assertIn("admin_shutdown", discovered_names)
                    self.assertIn("wipe_database", discovered_names)

                    # 2. ALLOW: call 'add' tool -> forwards downstream and returns result
                    add_res = await session.call_tool("add", {"a": 15, "b": 27})
                    self.assertFalse(add_res.is_error)
                    self.assertEqual(len(self.downstream_calls), 1)
                    self.assertEqual(self.downstream_calls[0]["tool"], "add")

                    # 3. DENY: call 'admin_shutdown' tool -> rejected by Core policy, zero downstream execution
                    calls_before = len(self.downstream_calls)
                    deny_res = await session.call_tool("admin_shutdown", {})
                    self.assertTrue(deny_res.is_error)
                    self.assertIn("DMT_POLICY_DENIED", deny_res.content[0].text)
                    self.assertEqual(len(self.downstream_calls), calls_before)

                    # 4. APPROVAL_REQUIRED: call 'wipe_database' -> challenged with pending record
                    wipe_res = await session.call_tool("wipe_database", {"confirm": True})
                    self.assertTrue(wipe_res.is_error)
                    err_data = json.loads(wipe_res.content[0].text)
                    self.assertEqual(err_data["code"], "DMT_APPROVAL_REQUIRED")
                    approval_id = err_data["approval_id"]
                    self.assertEqual(len(self.downstream_calls), calls_before)

                    # 5. Sign approval and transition to approved
                    record = self.gateway.approval_store.get(approval_id)
                    approver = ApprovalAuthority._from_trusted_boundary(
                        "ui", "human-admin", ApprovalAuthorityKind.HUMAN
                    )
                    assertion = self.authority.issue(record, approver)
                    self.gateway.approval_store.save_approved(record.approve(approver))
                    cred_token = assertion.to_bytes().decode("latin-1")

                    # 6. Retry with approval credential -> executes downstream!
                    retry_res = await session.call_tool(
                        "wipe_database",
                        {"confirm": True, "_dmint_approval": cred_token},
                    )
                    self.assertFalse(retry_res.is_error)
                    self.assertEqual(len(self.downstream_calls), calls_before + 1)
                    self.assertEqual(self.downstream_calls[-1]["tool"], "wipe_database")

                    # 7. Replay attempt with same approval -> rejected!
                    replay_res = await session.call_tool(
                        "wipe_database",
                        {"confirm": True, "_dmint_approval": cred_token},
                    )
                    self.assertTrue(replay_res.is_error)
                    self.assertEqual(len(self.downstream_calls), calls_before + 1)

    async def test_3_client_identity_spoofing_rejected(self):
        """Client connected with transport token for 'worker-agent' cannot spoof 'admin' in arguments."""
        headers = {"Authorization": f"Bearer {self.auth_token}"}

        async with httpx2.AsyncClient(headers=headers) as http_client:
            async with streamable_http_client(self.gateway_url, http_client=http_client) as (read_s, write_s):
                async with ClientSession(read_s, write_s) as session:
                    await session.initialize()

                    # Attempt to spoof identity as admin
                    calls_before = len(self.downstream_calls)
                    spoof_res = await session.call_tool(
                        "add",
                        {"a": 1, "b": 2, "agent_id": "admin"},
                    )
                    self.assertTrue(spoof_res.is_error)
                    self.assertIn("DMT_AGENT_IDENTITY_MISMATCH", spoof_res.content[0].text)
                    # Downstream was never executed
                    self.assertEqual(len(self.downstream_calls), calls_before)


if __name__ == "__main__":
    unittest.main()
