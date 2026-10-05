"""End-to-end stdio integration test: agent connects through DmintMCPProxy to downstream server."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import mcp.types as types
from mcp import ClientSession, StdioServerParameters, stdio_client
from dmint.storage import SQLiteApprovalStore

BASE = Path(__file__).parent
MOCK_SERVER_SCRIPT = str(BASE / "mock_server.py")
PROXY_ENTRYPOINT = str(BASE / "proxy_entrypoint.py")


def stdio_server_params(env_override=None):
    env = dict(os.environ)
    env.update(
        {
            "DMINT_INTEGRATION_ID": "e2e-server",
            "DMINT_DOWNSTREAM_COMMAND": sys.executable,
            "DMINT_DOWNSTREAM_ARGS": MOCK_SERVER_SCRIPT,
        }
    )
    if env_override:
        env.update(env_override)
    return StdioServerParameters(
        command=sys.executable,
        args=[PROXY_ENTRYPOINT],
        cwd=str(BASE),
        env=env,
    )


class EndToEndProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_initialize_list_and_call_through_proxy_stdio(self):
        async with stdio_client(stdio_server_params()) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                tools_result = await session.list_tools()
                tool_names = {t.name for t in tools_result.tools}
                self.assertIn("echo", tool_names)
                self.assertIn("delete_database", tool_names)

                call_result = await session.call_tool("echo", {"message": "hi from agent"})
                self.assertEqual(call_result.content[0].text, "echo: hi from agent")

    async def test_unknown_tool_rejected_end_to_end(self):
        async with stdio_client(stdio_server_params()) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("nope", {})
                self.assertTrue(result.is_error)

    async def test_discovery_through_real_stdio_matches_documented_policy(self):
        # The entrypoint config exposes echo + delete_database (trusted bound,
        # default hidden). This verifies tools/list honors discovery over the
        # real stdio transport, not just in-process calls.
        async with stdio_client(stdio_server_params()) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tool_names = {t.name for t in tools_result.tools}
                self.assertIn("echo", tool_names)
                self.assertIn("delete_database", tool_names)
                # The downstream fake tool list has exactly these two; neither
                # an unknown tool nor any hidden tool is injected by the agent.
                self.assertEqual(tool_names, {"echo", "delete_database"})

    async def test_call_tool_with_resource_derivation_end_to_end(self):
        async with stdio_client(stdio_server_params()) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                # delete_database is configured with resource_key="target"
                call_result = await session.call_tool("delete_database", {"target": "prod-db-1"})
                self.assertEqual(call_result.content[0].text, "deleted: prod-db-1")

    async def test_call_tool_missing_resource_fails_closed_end_to_end(self):
        async with stdio_client(stdio_server_params()) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                # Missing resource_key "target" -> mapping fails closed before downstream call
                result = await session.call_tool("delete_database", {"not_target": "val"})
                self.assertTrue(result.is_error)
                self.assertIn("DMT_MCP_RESOURCE_INVALID", result.content[0].text)

    async def test_approval_required_persisted_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "e2e_approvals.db")
            params = stdio_server_params({"DMINT_APPROVAL_DB": db_path})

            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool("delete_database", {"target": "prod-db-1"})
                    self.assertTrue(result.is_error)
                    data = json.loads(result.content[0].text)
                    self.assertEqual(data["status"], "approval_required")
                    self.assertEqual(data["code"], "DMT_APPROVAL_REQUIRED")
                    self.assertIn("approval_id", data)
                    self.assertIn("request_id", data)
                    self.assertIn("request_fingerprint", data)

                    # Verify persisted in SQLite database
                    store = SQLiteApprovalStore(db_path, deployment_epoch="ep_1")
                    record = store.get(data["approval_id"])
                    self.assertIsNotNone(record)
                    self.assertEqual(record.request.request_id, data["request_id"])
                    self.assertEqual(record.request_fingerprint, data["request_fingerprint"])
                    self.assertEqual(record.request.resource, "prod-db-1")
                    store.close()
