"""Pure-Python JSON-RPC 2.0 MCP fallback when the external `mcp` SDK is not installed.

Provides full stdio and streamable-HTTP client/server interoperability for:
- `dmint create-mcp-policy` (live tool discovery over stdio & streamable-http)
- `dmint-mcp` (`DownstreamMCPClient`, `MCPGateway`, and `DmintMCPProxy`)
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
import json
import os
import sys
from typing import Any, AsyncIterator, Callable, Mapping


class ErrorData:
    def __init__(self, code: int = -32000, message: str = "", data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data


class MCPError(Exception):
    def __init__(self, code: int | ErrorData = -32000, message: str = "") -> None:
        if isinstance(code, ErrorData):
            self.error = code
            self.code = code.code
            self.message = code.message
            super().__init__(code.message)
        else:
            self.code = int(code)
            self.message = str(message)
            self.error = ErrorData(code=self.code, message=self.message)
            super().__init__(self.message)


@dataclass
class TransportSecuritySettings:
    enable_dns_rebinding_protection: bool = True
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)


class Tool:
    def __init__(
        self,
        *,
        name: str,
        description: str | None = "",
        inputSchema: dict[str, Any] | None = None,
        input_schema: dict[str, Any] | None = None,
        annotations: dict[str, Any] | None = None,
        **extra: Any,
    ) -> None:
        self.name = str(name)
        self.description = description if description is not None else ""
        schema = inputSchema if inputSchema is not None else (input_schema if input_schema is not None else {"type": "object", "properties": {}})
        self.inputSchema = dict(schema) if isinstance(schema, Mapping) else {"type": "object", "properties": {}}
        self.input_schema = self.inputSchema
        self.annotations = dict(annotations) if isinstance(annotations, Mapping) else {}
        self.model_extra = extra

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.inputSchema,
        }
        if self.annotations:
            out["annotations"] = self.annotations
        return out

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self.to_dict()


class TextContent:
    def __init__(self, *, type: str = "text", text: str = "", **extra: Any) -> None:
        self.type = str(type)
        self.text = str(text)
        self.model_extra = extra

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "text": self.text}

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self.to_dict()


class CallToolResult:
    def __init__(
        self,
        *,
        content: list[Any] | None = None,
        isError: bool | None = None,
        is_error: bool | None = None,
        **extra: Any,
    ) -> None:
        norm_content: list[Any] = []
        for item in (content or []):
            if isinstance(item, TextContent):
                norm_content.append(item)
            elif isinstance(item, Mapping):
                norm_content.append(
                    TextContent(
                        type=str(item.get("type", "text")),
                        text=str(item.get("text", "")),
                    )
                )
            else:
                norm_content.append(TextContent(type="text", text=str(item)))
        self.content = norm_content
        err_flag = bool(is_error if is_error is not None else (isError if isError is not None else False))
        self.isError = err_flag
        self.is_error = err_flag
        self.model_extra = extra

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": [c.to_dict() if hasattr(c, "to_dict") else {"type": "text", "text": str(c)} for c in self.content],
            "isError": self.isError,
        }

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self.to_dict()


class ListToolsResult:
    def __init__(
        self,
        *,
        tools: list[Any] | None = None,
        nextCursor: str | None = None,
        next_cursor: str | None = None,
        **extra: Any,
    ) -> None:
        norm_tools: list[Tool] = []
        for t in (tools or []):
            if isinstance(t, Tool):
                norm_tools.append(t)
            elif isinstance(t, Mapping):
                norm_tools.append(
                    Tool(
                        name=str(t.get("name", "")),
                        description=t.get("description", ""),
                        inputSchema=t.get("inputSchema") or t.get("input_schema") or {"type": "object", "properties": {}},
                        annotations=t.get("annotations"),
                    )
                )
        self.tools = norm_tools
        cur = nextCursor if nextCursor is not None else next_cursor
        self.nextCursor = cur
        self.next_cursor = cur
        self.model_extra = extra

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"tools": [t.to_dict() for t in self.tools]}
        if self.nextCursor is not None:
            out["nextCursor"] = self.nextCursor
        return out

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self.to_dict()


class PaginatedRequestParams:
    def __init__(self, cursor: str | None = None, **extra: Any) -> None:
        self.cursor = cursor
        self.model_extra = extra


class CallToolRequestParams:
    def __init__(
        self,
        name: str = "",
        arguments: dict[str, Any] | None = None,
        **extra: Any,
    ) -> None:
        self.name = name
        self.arguments = arguments
        self.agent_id = extra.get("agent_id")
        self.model_extra = extra


class ListToolsRequest:
    def __init__(self, method: str = "tools/list", params: Any = None) -> None:
        self.method = method
        self.params = params


class CallToolRequest:
    def __init__(self, method: str = "tools/call", params: Any = None) -> None:
        self.method = method
        self.params = params


class ServerResult:
    def __init__(self, root: Any = None) -> None:
        self.root = root


class _StdlibTypesModule:
    Tool = Tool
    TextContent = TextContent
    CallToolResult = CallToolResult
    ListToolsResult = ListToolsResult
    PaginatedRequestParams = PaginatedRequestParams
    CallToolRequestParams = CallToolRequestParams
    ListToolsRequest = ListToolsRequest
    CallToolRequest = CallToolRequest
    ServerResult = ServerResult
    ErrorData = ErrorData


types = _StdlibTypesModule()


@dataclass
class StdioServerParameters:
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    cwd: str | os.PathLike[str] | None = None


class _AsyncLineReadStream:
    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader

    async def readline(self) -> str:
        line = await self._reader.readline()
        if not line:
            return ""
        return line.decode("utf-8", errors="replace")


class _AsyncLineWriteStream:
    def __init__(self, writer: asyncio.StreamWriter | Callable[[bytes], None]) -> None:
        self._writer = writer

    async def write_line(self, text: str) -> None:
        payload = (text.rstrip("\r\n") + "\n").encode("utf-8")
        if callable(self._writer):
            self._writer(payload)
            return
        self._writer.write(payload)
        await self._writer.drain()


@contextlib.asynccontextmanager
async def stdio_client(server: StdioServerParameters) -> AsyncIterator[tuple[Any, Any]]:
    proc = await asyncio.create_subprocess_exec(
        server.command,
        *(server.args or []),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=server.env,
        cwd=str(server.cwd) if server.cwd is not None else None,
    )
    assert proc.stdout is not None and proc.stdin is not None
    read_stream = _AsyncLineReadStream(proc.stdout)
    write_stream = _AsyncLineWriteStream(proc.stdin)
    try:
        yield read_stream, write_stream
    finally:
        try:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception:
            pass
        if proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


class _HttpRpcChannel:
    def __init__(self, url: str, http_client: Any) -> None:
        self.url = str(url)
        self.http_client = http_client
        self._queue: asyncio.Queue[str] = asyncio.Queue()

    async def send(self, text: str) -> None:
        msg = json.loads(text)
        resp = await self.http_client.post(
            self.url,
            content=text.encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        # Notifications may return 202/204 with empty body
        if "id" in msg and resp.content:
            body_text = resp.text.strip()
            # Handle SSE 'data: {...}' if server streams SSE
            for line in body_text.splitlines():
                s = line.strip()
                if s.startswith("data:"):
                    s = s[5:].strip()
                if s.startswith("{"):
                    await self._queue.put(s)
                    return
            if body_text:
                await self._queue.put(body_text)

    async def readline(self) -> str:
        return await self._queue.get()


@contextlib.asynccontextmanager
async def streamable_http_client(url: Any, http_client: Any = None) -> AsyncIterator[tuple[Any, Any]]:
    import httpx

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(verify=True, follow_redirects=False, timeout=30.0)
    channel = _HttpRpcChannel(str(url), client)

    class _HttpWrite:
        async def write_line(self, text: str) -> None:
            await channel.send(text)

    try:
        yield channel, _HttpWrite()
    finally:
        if owns_client:
            await client.aclose()


class ClientSession:
    """JSON-RPC 2.0 MCP ClientSession supporting stdio and streamable-HTTP streams."""

    def __init__(self, read_stream: Any, write_stream: Any) -> None:
        self._read = read_stream
        self._write = write_stream
        self._next_id = 0
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "ClientSession":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with self._lock:
            self._next_id += 1
            req_id = self._next_id
            req: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
            if params is not None:
                req["params"] = params
            await self._write.write_line(json.dumps(req))
            while True:
                line = await self._read.readline()
                if not line:
                    raise EOFError(f"MCP server closed stream while awaiting response to '{method}'")
                line_s = line.strip()
                if not line_s:
                    continue
                msg = json.loads(line_s)
                if not isinstance(msg, dict):
                    continue
                if msg.get("id") == req_id:
                    if "error" in msg and msg["error"] is not None:
                        err = msg["error"]
                        code = err.get("code", -32000) if isinstance(err, dict) else -32000
                        emsg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                        raise MCPError(code=code, message=emsg)
                    res = msg.get("result")
                    return res if isinstance(res, dict) else {}

    async def initialize(self) -> dict[str, Any]:
        res = await self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "dmint-mcp-client", "version": "2.0.4"},
            },
        )
        # Send initialized notification
        try:
            await self._write.write_line(
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            )
        except Exception:
            pass
        return res

    async def list_tools(self, cursor: str | None = None) -> ListToolsResult:
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor
        res = await self._rpc("tools/list", params)
        return ListToolsResult(
            tools=res.get("tools", []),
            nextCursor=res.get("nextCursor") or res.get("next_cursor"),
        )

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> CallToolResult:
        res = await self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        return CallToolResult(
            content=res.get("content", []),
            isError=bool(res.get("isError", res.get("is_error", False))),
        )


@contextlib.asynccontextmanager
async def stdio_server() -> AsyncIterator[tuple[Any, Any]]:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    def _sync_stdout_write(data: bytes) -> None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    yield _AsyncLineReadStream(reader), _AsyncLineWriteStream(_sync_stdout_write)


class Server:
    """Pure-Python JSON-RPC 2.0 MCP Server supporting stdio and Starlette Streamable HTTP."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._handlers: dict[str, tuple[Any, Callable[..., Any]]] = {}

    def add_request_handler(self, method: str, param_cls: Any, handler: Callable[..., Any]) -> None:
        self._handlers[method] = (param_cls, handler)

    def list_tools(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            async def _wrapped(ctx: Any, params: Any) -> Any:
                res = await fn()
                return ListToolsResult(tools=res) if isinstance(res, list) else res

            self._handlers["tools/list"] = (PaginatedRequestParams, _wrapped)
            return fn

        return _decorator

    def call_tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            async def _wrapped(ctx: Any, params: CallToolRequestParams) -> Any:
                res = await fn(params.name, params.arguments or {})
                return CallToolResult(content=res) if isinstance(res, list) else res

            self._handlers["tools/call"] = (CallToolRequestParams, _wrapped)
            return fn

        return _decorator

    def create_initialization_options(self) -> dict[str, Any]:
        return {"server_name": self.name, "version": "2.0.4"}

    async def _dispatch_message(self, raw_line: str, request_obj: Any = None) -> dict[str, Any] | None:
        from .gateway import parse_gateway_request

        try:
            msg = parse_gateway_request(raw_line)
        except Exception as exc:
            code = getattr(exc, "code", "DMT_MCP_PROTOCOL_ERROR")
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Dmint enforcement [{code}]: {exc}"},
            }

        method = msg.get("method")
        msg_id = msg.get("id")
        raw_params = msg.get("params") or {}

        # Notifications have no id
        if msg_id is None and isinstance(method, str) and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": "2.0.4"},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method in self._handlers:
            param_cls, handler = self._handlers[method]
            if not isinstance(raw_params, Mapping):
                raw_params = {}
            if param_cls is CallToolRequestParams:
                extra = {k: v for k, v in raw_params.items() if k not in ("name", "arguments")}
                params_inst = CallToolRequestParams(
                    name=raw_params.get("name", ""),
                    arguments=raw_params.get("arguments"),
                    **extra,
                )
            elif param_cls is PaginatedRequestParams:
                params_inst = PaginatedRequestParams(cursor=raw_params.get("cursor"))
            else:
                params_inst = raw_params

            class _Ctx:
                request = request_obj

            try:
                res = await handler(_Ctx(), params_inst)
                res_dict = res.to_dict() if hasattr(res, "to_dict") else (res.model_dump() if hasattr(res, "model_dump") else res)
                return {"jsonrpc": "2.0", "id": msg_id, "result": res_dict}
            except MCPError as exc:
                return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": exc.code, "message": exc.message}}
            except Exception as exc:
                code = getattr(exc, "code", "DMT_MCP_ERROR")
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": f"Dmint enforcement [{code}]: {exc}"},
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    async def run(self, read_stream: Any, write_stream: Any, init_options: Any = None) -> None:
        while True:
            line = await read_stream.readline()
            if not line:
                break
            line_s = line.strip()
            if not line_s:
                continue
            resp = await self._dispatch_message(line_s)
            if resp is not None:
                await write_stream.write_line(json.dumps(resp))

    def streamable_http_app(
        self,
        *,
        streamable_http_path: str = "/mcp",
        max_request_body_size: int = 1048576,
        transport_security: TransportSecuritySettings | None = None,
        host: str = "127.0.0.1",
    ) -> Any:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response
        from starlette.routing import Route

        server_ref = self

        async def _handle_http_mcp(request: Request) -> Response:
            body_bytes = request.scope.get("_dmint_cached_body") if "_dmint_cached_body" in request.scope else await request.body()
            if len(body_bytes) > max_request_body_size:
                return JSONResponse({"error": "Request body too large"}, status_code=413)
            raw_text = body_bytes.decode("utf-8", errors="replace")
            resp = await server_ref._dispatch_message(raw_text, request_obj=request)
            if resp is None:
                return Response(status_code=202)
            return JSONResponse(resp, status_code=200)

        return Starlette(routes=[Route(streamable_http_path, _handle_http_mcp, methods=["POST"])])
