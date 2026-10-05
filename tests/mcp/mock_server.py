"""Isolated downstream MCP server process for testing Dmint MCP client integration."""

import sys
import anyio
import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("mock-downstream-mcp-server")


async def handle_list_tools(ctx, params: types.PaginatedRequestParams) -> types.ListToolsResult:
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name="echo",
                description="Echo input text",
                inputSchema={
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                },
            ),
            types.Tool(
                name="delete_database",
                description="Delete database target",
                inputSchema={
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            ),
        ]
    )


async def handle_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
    if params.name == "echo":
        args = params.arguments or {}
        msg = args.get("message", "")
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"echo: {msg}")])
    if params.name == "delete_database":
        args = params.arguments or {}
        target = args.get("target", "")
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"deleted: {target}")])
    raise ValueError(f"unknown tool: {params.name}")


server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)


async def main():
    if "--fail-init" in sys.argv:
        sys.exit(1)
    async with stdio_server() as (read_stream, write_stream):
        if "--exit-early" in sys.argv:
            sys.exit(0)
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    try:
        anyio.run(main)
    except BaseException:
        sys.exit(1)
