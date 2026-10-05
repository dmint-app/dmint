"""Unit and security tests for authenticated capability discovery (Section 6)."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dmint.cli.errors import CLIError
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport, discover_mcp_tools_generic


class AuthenticatedDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("mcp.client.streamable_http.streamable_http_client")
    @patch("mcp.ClientSession")
    def test_authenticated_discovery_with_annotations(self, mock_session_cls, mock_http_client):
        mock_session = AsyncMock()

        mock_tool1 = MagicMock()
        mock_tool1.name = "use_figma"
        mock_tool1.description = "Use Figma design"
        mock_tool1.input_schema = {"type": "object"}
        mock_tool1.annotations = {"readOnly": True}

        mock_tool2 = MagicMock()
        mock_tool2.name = "create_new_file"
        mock_tool2.description = "Create Figma file"
        mock_tool2.input_schema = {"type": "object"}
        mock_tool2.annotations = {"destructive": False}

        mock_session.list_tools.return_value = MagicMock(tools=[mock_tool1, mock_tool2], nextCursor=None)
        mock_session_cls.return_value.__aenter__.return_value = mock_session

        mock_read, mock_write = MagicMock(), MagicMock()
        mock_http_client.return_value.__aenter__.return_value = (mock_read, mock_write)

        integ = MCPIntegration(
            integration_id="figma",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.figma.com/stream"},
            authentication={"token": "authenticated-access-token"},
        )

        import asyncio

        tools = asyncio.run(discover_mcp_tools_generic(integ))
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[0]["capability"], "mcp.figma.use_figma")
        self.assertEqual(tools[0]["annotations"], {"readOnly": True})
        self.assertEqual(tools[1]["capability"], "mcp.figma.create_new_file")

        # ASSERTION: call_tool MUST NEVER BE CALLED DURING DISCOVERY
        mock_session.call_tool.assert_not_called()

    @patch("mcp.client.streamable_http.streamable_http_client")
    @patch("mcp.ClientSession")
    def test_paginated_tools_list_discovery(self, mock_session_cls, mock_http_client):
        mock_session = AsyncMock()

        t1 = MagicMock(name="tool1", description="d1", input_schema={})
        t1.name = "tool1"
        t1.description = "d1"
        t1.input_schema = {}

        t2 = MagicMock(name="tool2", description="d2", input_schema={})
        t2.name = "tool2"
        t2.description = "d2"
        t2.input_schema = {}

        page1 = MagicMock(tools=[t1], nextCursor="page-2-cursor")
        page2 = MagicMock(tools=[t2], nextCursor=None)

        mock_session.list_tools.side_effect = [page1, page2]
        mock_session_cls.return_value.__aenter__.return_value = mock_session

        mock_read, mock_write = MagicMock(), MagicMock()
        mock_http_client.return_value.__aenter__.return_value = (mock_read, mock_write)

        integ = MCPIntegration(
            integration_id="paginated-mcp",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://mcp.example.com/paginated"},
        )

        import asyncio

        tools = asyncio.run(discover_mcp_tools_generic(integ))
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[0]["name"], "tool1")
        self.assertEqual(tools[1]["name"], "tool2")
        mock_session.call_tool.assert_not_called()
