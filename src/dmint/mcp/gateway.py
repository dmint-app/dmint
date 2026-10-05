"""Multi-server MCP enforcement gateway for Dmint."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from collections.abc import Callable, Collection, Mapping
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.context import ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError as SDKMCPError, ErrorData
import rfc8785

from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
import uvicorn

from dmint.approvals import ApprovalRecord, PolicyProvenance
from dmint.authority import ApprovalAssertion, ApprovalVerifier
from dmint.errors import (
    ApprovalError,
    ApprovalRequiredError,
    AuthorizationError,
)
from dmint.models import ToolRequest
from dmint.policy import Policy
from dmint.core.storage import ApprovalStore, SQLiteApprovalStore, ThreadSafeApprovalStore
from dmint.core.webhooks import WebhookNotifier
from .auth import (
    AgentAuthenticator,
    AgentAuthMiddleware,
    CURRENT_AGENT_ID,
    DEFAULT_MAX_REQUEST_BODY_SIZE,
)
from .client import DownstreamMCPClient
from .config import DisclosureMode, MCPIntegrationConfig
from .config_loader import MCPGatewayConfig
from .errors import (
    MCPConfigurationError,
    MCPConnectionError,
    MCPMappingError,
    MCPProtocolError,
    MCPTimeoutError,
)
from .proxy import EnforcementGate, MCPProxyError
from .ssrf import is_loopback_host


class GatewayIntegration:
    """Encapsulates runtime state and enforcement gate for one downstream integration."""

    __slots__ = ("config", "client", "gate")

    def __init__(
        self,
        config: MCPIntegrationConfig,
        client: DownstreamMCPClient,
        gate: EnforcementGate,
    ) -> None:
        self.config = config
        self.client = client
        self.gate = gate


class MCPGateway:
    """Agent-facing multi-server MCP enforcement gateway.

    Routes MCP tools/list and tools/call requests across one or more downstream
    MCP servers while enforcing Dmint Core deterministic authorization policies.
    """

    def __init__(
        self,
        config: MCPGatewayConfig,
        *,
        client_factory: Callable[[MCPIntegrationConfig], DownstreamMCPClient] | None = None,
        approval_store: ApprovalStore | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        webhook_notifier: WebhookNotifier | None = None,
    ) -> None:
        if not isinstance(config, MCPGatewayConfig):
            raise MCPConfigurationError("config must be an MCPGatewayConfig")

        self._config = config
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._webhook_notifier = webhook_notifier

        self._own_store = False
        self._approval_store: ApprovalStore | None = None
        if approval_store is not None:
            if not isinstance(approval_store, ApprovalStore):
                raise TypeError("approval_store must be an ApprovalStore")
            if isinstance(approval_store, ThreadSafeApprovalStore):
                self._approval_store = approval_store
            elif isinstance(approval_store, SQLiteApprovalStore):
                try:
                    db_row = approval_store._connection.execute("PRAGMA database_list").fetchone()
                    db_file = db_row["file"] if db_row else None
                except Exception:
                    db_file = None
                if db_file:
                    self._approval_store = ThreadSafeApprovalStore(
                        db_file,
                        deployment_epoch=approval_store._deployment_epoch,
                        recovery_epoch_file=approval_store._recovery_file,
                        redact_keys=approval_store._redact_keys,
                        max_pending_per_principal=approval_store._max_pending_per_principal,
                        clock=approval_store._clock,
                    )
                    self._own_store = True
                else:
                    self._approval_store = approval_store
            else:
                self._approval_store = approval_store
        elif config.approval_store_path or os.environ.get("DMINT_DATABASE_URL"):
            self._approval_store = ThreadSafeApprovalStore(
                database=config.approval_store_path,
                deployment_epoch="gateway_epoch",
                clock=self._clock,
            )
            self._own_store = True
        else:
            self._approval_store = None

        self._approval_verifier = approval_verifier
        self._integrations: dict[str, GatewayIntegration] = {}

        for integ_cfg in config.integrations:
            if client_factory is not None:
                client = client_factory(integ_cfg)
            else:
                client = DownstreamMCPClient(integ_cfg)

            gate = EnforcementGate(
                client=client,
                integration_config=integ_cfg,
                policy=config.policy,
                agent_id=config.agent_id,
                context=config.context,
                approval_store=self._approval_store,
                approval_verifier=self._approval_verifier,
                policy_provenance=config.policy_provenance,
                approval_ttl=config.approval_ttl,
                clock=self._clock,
                disclosure_mode=config.disclosure_mode,
                webhook_notifier=self._webhook_notifier,
            )
            self._integrations[integ_cfg.integration_id] = GatewayIntegration(integ_cfg, client, gate)

        self._is_connected = False
        self._server = Server(config.server_name)

    @property
    def config(self) -> MCPGatewayConfig:
        return self._config

    @property
    def integrations(self) -> Mapping[str, GatewayIntegration]:
        return self._integrations

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def approval_store(self) -> ApprovalStore | None:
        """Underlying approval store if persistence is configured."""
        return self._approval_store

    def resolve_tool(self, tool_name: str) -> tuple[GatewayIntegration, str]:
        """Resolve a requested tool name to the target integration and downstream tool name.

        Routing resolution order:
        1. Namespaced with dot: '<integration_id>.<downstream_tool>'
        2. Namespaced with slash: '<integration_id>/<downstream_tool>'
        3. Bare tool name:
           - Matches uniquely against exactly 1 integration -> routed.
           - Matches multiple integrations -> fails closed with DMT_MCP_TOOL_AMBIGUOUS.
           - Matches no integration -> fails closed with DMT_MCP_TOOL_NOT_FOUND.
        """
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise MCPMappingError("invalid tool name", code="DMT_MCP_TOOL_NOT_FOUND")
        clean_name = tool_name.strip()

        # 1. Namespaced with dot
        if "." in clean_name:
            integ_id, _, downstream_name = clean_name.partition(".")
            if integ_id in self._integrations:
                integ = self._integrations[integ_id]
                if downstream_name in integ.config.tool_bindings:
                    return integ, downstream_name
                raise MCPMappingError(
                    f"unknown tool '{downstream_name}' in integration '{integ_id}'",
                    code="DMT_MCP_TOOL_NOT_FOUND",
                )

        # 2. Namespaced with slash
        if "/" in clean_name:
            integ_id, _, downstream_name = clean_name.partition("/")
            if integ_id in self._integrations:
                integ = self._integrations[integ_id]
                if downstream_name in integ.config.tool_bindings:
                    return integ, downstream_name
                raise MCPMappingError(
                    f"unknown tool '{downstream_name}' in integration '{integ_id}'",
                    code="DMT_MCP_TOOL_NOT_FOUND",
                )

        # 3. Bare tool name
        matching = [integ for integ in self._integrations.values() if clean_name in integ.config.tool_bindings]
        if len(matching) == 1:
            return matching[0], clean_name
        elif len(matching) > 1:
            ids = sorted([integ.config.integration_id for integ in matching])
            candidates = [f"{integ_id}.{clean_name}" for integ_id in ids]
            raise MCPMappingError(
                f"ambiguous tool name '{clean_name}' discovered across multiple integrations {ids}. "
                f"Must qualify as one of {candidates}.",
                code="DMT_MCP_TOOL_AMBIGUOUS",
            )
        else:
            raise MCPMappingError(f"unknown tool: '{clean_name}'", code="DMT_MCP_TOOL_NOT_FOUND")

    async def connect(self) -> None:
        """Connect to all downstream MCP servers and register protocol handlers."""
        if self._is_connected:
            return

        connect_tasks = [integ.client.connect() for integ in self._integrations.values()]
        results = await asyncio.gather(*connect_tasks, return_exceptions=True)

        failures = [
            (integ.config.integration_id, res)
            for integ, res in zip(self._integrations.values(), results)
            if isinstance(res, Exception)
        ]

        if failures:
            # Cleanup any successfully connected clients on connection failure
            await self.disconnect()
            first_id, first_exc = failures[0]
            raise MCPConnectionError(
                f"failed to connect downstream integration '{first_id}': {first_exc}"
            ) from first_exc

        self._server.add_request_handler(
            "tools/list",
            types.PaginatedRequestParams,
            self._handle_list_tools,
        )
        self._server.add_request_handler(
            "tools/call",
            types.CallToolRequestParams,
            self._handle_call_tool,
        )
        self._is_connected = True

    async def disconnect(self) -> None:
        """Disconnect all downstream clients and clean up resources."""
        self._is_connected = False
        disconnect_tasks = [integ.client.disconnect() for integ in self._integrations.values()]
        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)

        if self._own_store and self._approval_store is not None:
            try:
                self._approval_store.close()
            except Exception:
                pass
            finally:
                self._approval_store = None

    async def list_tools(self) -> types.ListToolsResult:
        """Aggregate visible tools across all connected integrations."""
        is_multi = len(self._integrations) > 1
        aggregated_tools: list[types.Tool] = []

        # Count occurrences of tool names to identify collisions
        tool_counts: dict[str, int] = {}
        for integ in self._integrations.values():
            for b in integ.config.tool_bindings.values():
                tool_counts[b.tool_name] = tool_counts.get(b.tool_name, 0) + 1

        for integ_id, integ in sorted(self._integrations.items()):
            try:
                sub_res = await integ.gate.list_tools()
            except Exception as exc:
                # Preserve timeout / connection error behavior
                if isinstance(exc, (MCPTimeoutError, MCPConnectionError)):
                    raise
                raise MCPConnectionError(f"failed to list tools from integration '{integ_id}': {exc}") from exc

            for t in sub_res.tools:
                schema = getattr(t, "input_schema", getattr(t, "inputSchema", {}))
                # If colliding across integrations, namespace with integration_id
                if is_multi and tool_counts.get(t.name, 1) > 1:
                    exposed_name = f"{integ_id}.{t.name}"
                else:
                    exposed_name = t.name
                aggregated_tools.append(
                    types.Tool(
                        name=exposed_name,
                        description=t.description,
                        input_schema=schema,
                    )
                )

        return types.ListToolsResult(tools=aggregated_tools)

    async def route_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
    ) -> types.CallToolResult:
        """Route a tool call to the resolved integration enforcement gate."""
        integ, downstream_tool = self.resolve_tool(tool_name)
        return await integ.gate.route_call(
            integration_id=integ.config.integration_id,
            tool_name=downstream_tool,
            arguments=arguments,
            agent_id=agent_id,
        )

    async def retry_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        approval_credential: ApprovalAssertion | bytes,
        agent_id: str | None = None,
    ) -> types.CallToolResult:
        """Route an approved retry to the resolved integration enforcement gate."""
        integ, downstream_tool = self.resolve_tool(tool_name)
        return await integ.gate.retry_call(
            integration_id=integ.config.integration_id,
            tool_name=downstream_tool,
            arguments=arguments,
            approval_credential=approval_credential,
            agent_id=agent_id,
        )

    def _format_approval_required_result(self, exc: ApprovalRequiredError) -> types.CallToolResult:
        mode = self._config.disclosure_mode
        if mode is DisclosureMode.GOD:
            text = "Dmint enforcement [DMT_403]: access denied"
        elif mode is DisclosureMode.CAT:
            text = f"Dmint enforcement [DMT_APPROVAL_REQUIRED]: approval requested (workflow {exc.request_id})"
        else:  # DOG mode
            payload = {
                "status": "approval_required",
                "code": "DMT_APPROVAL_REQUIRED",
                "request_id": exc.request_id,
                "approval_id": exc.approval_id,
                "request_fingerprint": exc.request_fingerprint,
                "message": "Trusted approval is required for this request.",
            }
            text = json.dumps(payload, sort_keys=True)
        return types.CallToolResult(
            is_error=True,
            content=[types.TextContent(type="text", text=text)],
        )

    def _format_authorization_error_result(self, exc: Exception) -> types.CallToolResult:
        mode = self._config.disclosure_mode
        code = getattr(exc, "code", "DMT_ERROR")
        if mode is DisclosureMode.GOD:
            text = "Dmint enforcement [DMT_403]: access denied"
        else:
            text = f"Dmint enforcement [{code}]: {exc}"
        return types.CallToolResult(
            is_error=True,
            content=[types.TextContent(type="text", text=text)],
        )

    def _format_error_result(self, exc: Exception, default_code: str = "DMT_MCP_ERROR") -> types.CallToolResult:
        mode = self._config.disclosure_mode
        code = getattr(exc, "code", default_code)
        if mode is DisclosureMode.GOD:
            text = f"Dmint enforcement [{code}]: execution failed"
        else:
            msg = str(exc)
            text = f"Dmint enforcement [{code}]: {msg}"
        return types.CallToolResult(
            is_error=True,
            content=[types.TextContent(type="text", text=text)],
        )

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: types.PaginatedRequestParams,
    ) -> types.ListToolsResult:
        if not self._is_connected:
            raise MCPProxyError("gateway is not connected to downstream servers")
        try:
            return await self.list_tools()
        except (MCPTimeoutError, MCPConnectionError, MCPProtocolError) as exc:
            code = getattr(exc, "code", "DMT_MCP_ERROR")
            raise SDKMCPError(code=-32000, message=f"Dmint enforcement [{code}]: {exc}") from exc

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        if not self._is_connected:
            raise MCPProxyError("gateway is not connected to downstream servers")

        tool_name = params.name
        if not isinstance(tool_name, str) or not tool_name:
            raise MCPProtocolError("tools/call requires a tool name")

        arguments = params.arguments
        if arguments is not None and not isinstance(arguments, dict):
            raise MCPProtocolError("tool arguments must be an object")

        # Determine authenticated agent identity
        bound_agent_id = None
        if ctx is not None and getattr(ctx, "request", None) is not None:
            bound_agent_id = getattr(getattr(ctx.request, "state", None), "agent_id", None)
        if not bound_agent_id:
            bound_agent_id = CURRENT_AGENT_ID.get() or self._config.agent_id

        # Anti-spoofing check on client-supplied arguments
        if arguments is not None and "agent_id" in arguments:
            client_agent = arguments["agent_id"]
            if client_agent != bound_agent_id:
                return self._format_authorization_error_result(
                    AuthorizationError(
                        f"client-supplied agent_id '{client_agent}' does not match authenticated identity '{bound_agent_id}'",
                        code="DMT_AGENT_IDENTITY_MISMATCH",
                    )
                )

        # Anti-spoofing check on client-supplied request params
        param_agent = getattr(params, "agent_id", None)
        if param_agent is None and hasattr(params, "model_extra") and params.model_extra:
            param_agent = params.model_extra.get("agent_id")
        if param_agent is not None and param_agent != bound_agent_id:
            return self._format_authorization_error_result(
                AuthorizationError(
                    f"client-supplied agent_id '{param_agent}' does not match authenticated identity '{bound_agent_id}'",
                    code="DMT_AGENT_IDENTITY_MISMATCH",
                )
            )

        # Check for retry credential in arguments
        approval_cred = None
        call_arguments = arguments
        if arguments is not None:
            for cred_key in ("_dmint_approval", "dmint_approval", "approval_credential"):
                if cred_key in arguments:
                    approval_cred = arguments[cred_key]
                    call_arguments = {k: v for k, v in arguments.items() if k != cred_key}
                    break

        try:
            if approval_cred is not None:
                if isinstance(approval_cred, str):
                    approval_cred = approval_cred.encode("utf-8")
                elif isinstance(approval_cred, dict):
                    approval_cred = rfc8785.dumps(approval_cred)

                return await self.retry_call(
                    tool_name=tool_name,
                    arguments=call_arguments,
                    approval_credential=approval_cred,
                    agent_id=bound_agent_id,
                )
            else:
                return await self.route_call(
                    tool_name=tool_name,
                    arguments=call_arguments,
                    agent_id=bound_agent_id,
                )
        except ApprovalRequiredError as exc:
            return self._format_approval_required_result(exc)
        except (AuthorizationError, ApprovalError, MCPMappingError) as exc:
            return self._format_authorization_error_result(exc)
        except MCPTimeoutError as exc:
            return self._format_error_result(exc, default_code="DMT_MCP_TIMEOUT")
        except (MCPConnectionError, MCPProtocolError) as exc:
            return self._format_error_result(exc, default_code="DMT_MCP_CONNECTION_ERROR")
        except Exception as exc:
            return self._format_error_result(exc, default_code="DMT_INTERNAL_ERROR")

    async def serve_stdio(self) -> None:
        """Run the agent-facing MCP gateway server over stdio until shutdown."""
        async with stdio_server() as (read_stream, write_stream):
            if not self._is_connected:
                await self.connect()
            try:
                await self._server.run(
                    read_stream,
                    write_stream,
                    self._server.create_initialization_options(),
                )
            finally:
                await self.disconnect()

    def create_http_app(
        self,
        *,
        authenticator: AgentAuthenticator | None = None,
        auth_token: str | None = None,
        token_mapping: Mapping[str, str] | None = None,
        host: str = "127.0.0.1",
        streamable_http_path: str = "/mcp",
        max_request_body_size: int = DEFAULT_MAX_REQUEST_BODY_SIZE,
        allowed_origins: list[str] | None = None,
    ) -> Starlette:
        """Create a Starlette ASGI app for agent-facing Streamable HTTP transport.

        Enforces DNS rebinding protection, request size bounds, safe host binding,
        and agent transport authentication.
        """
        is_loopback = is_loopback_host(host)
        has_auth = (
            (authenticator is not None and authenticator.has_tokens)
            or (auth_token is not None and bool(auth_token.strip()))
            or (token_mapping is not None and len(token_mapping) > 0)
        )
        if not is_loopback and not has_auth:
            raise MCPConfigurationError(f"Cannot bind public host '{host}' without transport authentication configured")

        # Build authenticator if token spec provided
        if authenticator is None:
            if token_mapping:
                authenticator = AgentAuthenticator(token_mapping=token_mapping, default_agent_id=self._config.agent_id)
            elif auth_token:
                authenticator = AgentAuthenticator.from_spec(auth_token, default_agent_id=self._config.agent_id)

        # Build transport security settings
        if allowed_origins is not None:
            if "*" in allowed_origins and has_auth:
                raise MCPConfigurationError(
                    "Permissive wildcard CORS ('*') is forbidden when authentication is enabled"
                )
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[f"{host}:*", "127.0.0.1:*", "localhost:*", "[::1]:*"],
                allowed_origins=allowed_origins,
            )
        elif is_loopback:
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
                allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
            )
        else:
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=False,
                allowed_hosts=[f"{host}:*"],
                allowed_origins=[],
            )

        app = self._server.streamable_http_app(
            streamable_http_path=streamable_http_path,
            max_request_body_size=max_request_body_size,
            transport_security=transport_security,
            host=host,
        )

        app.add_middleware(
            AgentAuthMiddleware,
            authenticator=authenticator,
            default_agent_id=self._config.agent_id,
            max_request_body_size=max_request_body_size,
        )

        original_lifespan = app.router.lifespan_context

        @contextlib.asynccontextmanager
        async def gateway_lifespan(starlette_app: Starlette):
            if not self._is_connected:
                await self.connect()
            async with original_lifespan(starlette_app):
                yield

        app.router.lifespan_context = gateway_lifespan

        return app

    async def serve_http(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        *,
        authenticator: AgentAuthenticator | None = None,
        auth_token: str | None = None,
        token_mapping: Mapping[str, str] | None = None,
        streamable_http_path: str = "/mcp",
        max_request_body_size: int = DEFAULT_MAX_REQUEST_BODY_SIZE,
        allowed_origins: list[str] | None = None,
        log_level: str = "info",
    ) -> None:
        """Run the agent-facing MCP gateway server over Streamable HTTP until shutdown."""
        # Fail immediately if unsafe public bind
        is_loopback = is_loopback_host(host)
        has_auth = (
            (authenticator is not None and authenticator.has_tokens)
            or (auth_token is not None and bool(auth_token.strip()))
            or (token_mapping is not None and len(token_mapping) > 0)
        )
        if not is_loopback and not has_auth:
            raise MCPConfigurationError(f"Cannot bind public host '{host}' without transport authentication configured")

        if not self._is_connected:
            await self.connect()

        app = self.create_http_app(
            authenticator=authenticator,
            auth_token=auth_token,
            token_mapping=token_mapping,
            host=host,
            streamable_http_path=streamable_http_path,
            max_request_body_size=max_request_body_size,
            allowed_origins=allowed_origins,
        )

        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            log_level=log_level,
            timeout_keep_alive=30,
        )
        server = uvicorn.Server(config)

        try:
            await server.serve()
        finally:
            await self.disconnect()
