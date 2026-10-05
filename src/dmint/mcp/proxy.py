"""Agent-facing Dmint MCP proxy server (protocol/session bridge)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any, Callable

import mcp.types as types
from mcp.server import Server
from mcp.server.context import ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError as SDKMCPError
import rfc8785

from dmint.approvals import ApprovalRecord, ApprovalState, PolicyProvenance
from dmint.authority import ApprovalAssertion, ApprovalVerifier
from dmint.core.canonicalize import thaw_json
from dmint.errors import (
    ApprovalCredentialInvalidError,
    ApprovalError,
    ApprovalIntegrationMismatchError,
    ApprovalPolicyInvalidError,
    ApprovalRequestMismatchError,
    ApprovalRequiredError,
    AuthorizationError,
)
from .errors import (
    MCPConfigurationError,
    MCPConnectionError,
    MCPError,
    MCPMappingError,
    MCPProtocolError,
    MCPTimeoutError,
)
from dmint.models import Decision, ToolRequest, TrustedContext
from dmint.policy import Policy
from dmint.request_binding import request_binding_fingerprint
from dmint.storage import ApprovalStore, SQLiteApprovalStore
from dmint.core.webhooks import (
    WebhookNotifier,
    dispatch_approval_webhook,
    dispatch_denial_webhook,
)
from .client import DownstreamMCPClient
from .config import DiscoveryMode, DisclosureMode, MCPIntegrationConfig
from .mapper import MCPMappedRequest, MCPRequestMapper

logger = logging.getLogger(__name__)


class MCPProxyError(Exception):
    """Marker for a controlled proxy-level error separate from Dmint errors."""


class EnforcementGate:
    """Internal security gate enforcing Dmint policy on MCP tools/call.

    Maps every tools/call request to a canonical Dmint ToolRequest and
    evaluates policy using Core's public API. On ALLOW, exact authorized
    arguments are forwarded downstream.
    On APPROVAL_REQUIRED, a pending approval record is persisted in SQLiteApprovalStore.
    On retry_call(), verified approved credentials atomically consume the record in
    SQLiteApprovalStore and execute the exact authorized request downstream.
    """

    def __init__(
        self,
        client: DownstreamMCPClient,
        integration_config: MCPIntegrationConfig,
        policy: Policy | None = None,
        *,
        agent_id: str = "mcp-agent",
        context: TrustedContext | None = None,
        approval_store: ApprovalStore | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        policy_provenance: PolicyProvenance | None = None,
        approval_ttl: timedelta | None = None,
        clock: Callable[[], datetime] | None = None,
        disclosure_mode: DisclosureMode | str = DisclosureMode.DOG,
        webhook_notifier: WebhookNotifier | None = None,
    ) -> None:
        if not isinstance(client, DownstreamMCPClient):
            raise MCPConfigurationError("client must be a DownstreamMCPClient")
        if not isinstance(integration_config, MCPIntegrationConfig):
            raise MCPConfigurationError("integration_config must be an MCPIntegrationConfig")
        self._client = client
        self._config = integration_config
        self._context = context or TrustedContext({})

        if type(disclosure_mode) is str:
            try:
                disclosure_mode = DisclosureMode(disclosure_mode)
            except ValueError as exc:
                raise MCPConfigurationError("invalid disclosure_mode") from exc
        elif type(disclosure_mode) is not DisclosureMode:
            raise MCPConfigurationError("invalid disclosure_mode")
        self._disclosure_mode = disclosure_mode

        if isinstance(policy, Policy) or policy is None:
            self._policy = policy or Policy()
        else:
            raise MCPConfigurationError("policy must be a Policy instance or None")

        if approval_store is not None and not isinstance(approval_store, ApprovalStore):
            raise MCPConfigurationError("approval_store must be an ApprovalStore")
        self._approval_store = approval_store

        if approval_verifier is not None and type(approval_verifier) is not ApprovalVerifier:
            raise MCPConfigurationError("approval_verifier must be an ApprovalVerifier")
        self._approval_verifier = approval_verifier

        if policy_provenance is not None and type(policy_provenance) is not PolicyProvenance:
            raise MCPConfigurationError("policy_provenance must be a PolicyProvenance")
        self._policy_provenance = policy_provenance

        if approval_ttl is not None and (type(approval_ttl) is not timedelta or approval_ttl <= timedelta(0)):
            raise MCPConfigurationError("approval_ttl must be a positive timedelta")
        self._approval_ttl = approval_ttl

        self._clock = clock or (lambda: datetime.now(timezone.utc))

        if webhook_notifier is not None and not isinstance(webhook_notifier, WebhookNotifier):
            raise MCPConfigurationError("webhook_notifier must be a WebhookNotifier")
        self._webhook_notifier = webhook_notifier

        # Synchronize authoritative policy into store via public API if empty
        if self._approval_store is not None and self._policy_provenance is not None:
            if self._approval_store.get_authoritative_policy() is None:
                self._approval_store.set_authoritative_policy(self._policy, self._policy_provenance)

        self._agent_id = agent_id
        self._mapper = MCPRequestMapper(
            integration_config,
            agent_id=agent_id,
            context=self._context,
        )
        self._last_mapped_request: MCPMappedRequest | None = None

    @property
    def webhook_notifier(self) -> WebhookNotifier | None:
        return self._webhook_notifier

    @property
    def mapper(self) -> MCPRequestMapper:
        return self._mapper

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def disclosure_mode(self) -> DisclosureMode:
        return self._disclosure_mode

    @property
    def last_mapped_request(self) -> MCPMappedRequest | None:
        return self._last_mapped_request

    def _is_visible(self, tool_name: str) -> bool:
        """Apply trusted discovery policy for one downstream tool name."""
        binding = self._config.tool_bindings.get(tool_name)
        if binding is not None:
            return binding.discovery is DiscoveryMode.EXPOSED
        return self._config.default_discovery is DiscoveryMode.EXPOSED

    async def list_tools(self) -> types.ListToolsResult:
        tools = await self._client.list_tools()
        visible = [t for t in tools if self._is_visible(t.name)]
        return types.ListToolsResult(tools=visible)

    def _evaluate_request(
        self,
        request: ToolRequest,
        *,
        expected_agent_id: str | None = None,
    ) -> Decision:
        """Evaluate policy on a validated ToolRequest using Core's policy engine."""
        if type(request) is not ToolRequest:
            raise AuthorizationError("invalid authorization request", code="DMT_INVALID_REQUEST")
        check_agent = expected_agent_id or self._agent_id
        if request.agent_id != check_agent or request.context.values != self._context.values:
            raise AuthorizationError(
                "request identity or trusted context mismatch",
                code="DMT_INVALID_REQUEST",
                request_id=request.request_id,
            )
        try:
            decision = self._policy.evaluate(request)
        except Exception as exc:
            raise AuthorizationError(
                "authorization failed",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            ) from exc
        if decision not in (Decision.ALLOW, Decision.DENY, Decision.APPROVAL_REQUIRED):
            raise AuthorizationError(
                "authorization returned an invalid decision",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            )
        return decision

    def _persist_pending(self, request: ToolRequest) -> ApprovalRecord:
        """Persist a pending approval record using Core's ApprovalRecord and SQLiteApprovalStore."""
        if self._approval_store is None or self._policy_provenance is None or self._approval_ttl is None:
            raise AuthorizationError(
                "approval storage and policy provenance are required",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            )
        now = self._clock()
        provenance = PolicyProvenance(
            self._policy_provenance.version_id,
            self._policy_provenance.policy_digest,
            now,
        )
        record = ApprovalRecord.create(
            request=request,
            integration_id=self._config.integration_id,
            capability_id=f"{request.tool}.{request.action}",
            policy_provenance=provenance,
            created_at=now,
            expires_at=now + self._approval_ttl,
        )
        try:
            persisted = self._approval_store.save_pending(record)
        except Exception as exc:
            raise AuthorizationError(
                "approval request could not be persisted",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            ) from exc
        return persisted

    def _notify_approval_required(self, record: ApprovalRecord) -> None:
        try:
            if self._webhook_notifier is not None:
                self._webhook_notifier.send_approval_required(record)
            else:
                dispatch_approval_webhook(record)
        except Exception as exc:
            logger.warning("Failed to dispatch approval webhook: %s", exc)

    def _notify_denial(self, request: ToolRequest) -> None:
        try:
            if self._webhook_notifier is not None:
                self._webhook_notifier.send_policy_denied(request)
            else:
                dispatch_denial_webhook(request)
        except Exception as exc:
            logger.warning("Failed to dispatch policy denial webhook: %s", exc)

    async def route_call(
        self,
        *,
        integration_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        agent_id: str | None = None,
    ) -> types.CallToolResult:
        """Map the MCP tool call to a Dmint ToolRequest, evaluate policy, and route.

        Only ALLOW requests forward to the downstream MCP server. DENY,
        APPROVAL_REQUIRED, and mapping failures stop execution with ZERO downstream
        tool execution.
        """
        effective_agent_id = agent_id or self._agent_id
        mapped = self._mapper.map(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=effective_agent_id,
        )
        self._last_mapped_request = mapped

        decision = self._evaluate_request(
            mapped.tool_request,
            expected_agent_id=effective_agent_id,
        )

        if decision is Decision.DENY:
            self._notify_denial(mapped.tool_request)
            raise AuthorizationError(
                "policy denied the request",
                code="DMT_POLICY_DENIED",
                request_id=mapped.tool_request.request_id,
                decision=decision.value,
            )

        if decision is Decision.APPROVAL_REQUIRED:
            if (
                self._approval_store is not None
                and self._policy_provenance is not None
                and self._approval_ttl is not None
            ):
                persisted = self._persist_pending(mapped.tool_request)
                self._notify_approval_required(persisted)
                raise ApprovalRequiredError(
                    "trusted approval is required",
                    request_id=persisted.request_id,
                    approval_id=persisted.approval_id,
                    request_fingerprint=persisted.request_fingerprint,
                )
            raise AuthorizationError(
                "approval is required for this request",
                code="DMT_APPROVAL_REQUIRED",
                request_id=mapped.tool_request.request_id,
                decision=decision.value,
            )

        if decision is not Decision.ALLOW:
            raise AuthorizationError(
                "authorization returned an invalid decision",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=mapped.tool_request.request_id,
            )

        exact_arguments = thaw_json(mapped.tool_request.arguments)
        return await self._client.call_tool(tool_name, arguments=exact_arguments)

    async def retry_call(
        self,
        *,
        integration_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        approval_credential: ApprovalAssertion | bytes,
        agent_id: str | None = None,
    ) -> types.CallToolResult:
        """Verify an approved credential, re-evaluate policy, atomically consume, and execute downstream."""
        if self._approval_store is None or self._approval_verifier is None:
            raise AuthorizationError(
                "approval retry is not configured",
                code="DMT_AUTHORIZATION_FAILED",
            )

        if type(approval_credential) is bytes:
            try:
                approval_credential = ApprovalAssertion.from_bytes(approval_credential)
            except Exception as exc:
                raise ApprovalCredentialInvalidError("approval credential is invalid") from exc
        if type(approval_credential) is not ApprovalAssertion:
            raise ApprovalCredentialInvalidError("approval credential is invalid")

        record = self._approval_store.get(approval_credential.approval_id)
        if record is None:
            raise AuthorizationError("approval not found", code="DMT_APPROVAL_NOT_FOUND")

        if record.integration_id != self._config.integration_id:
            raise ApprovalIntegrationMismatchError("approval integration_id mismatch")

        effective_agent_id = agent_id or self._agent_id
        mapped = self._mapper.map(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=effective_agent_id,
        )
        self._last_mapped_request = mapped

        if record.capability_id != mapped.capability:
            raise ApprovalRequestMismatchError("approval capability mismatch")

        expected_request = ToolRequest(
            request_id=record.request.request_id,
            agent_id=effective_agent_id,
            tool=mapped.tool_request.tool,
            action=mapped.tool_request.action,
            resource=mapped.tool_request.resource,
            arguments=dict(thaw_json(mapped.tool_request.arguments)),
            context=self._context,
        )

        retry_fingerprint = request_binding_fingerprint(
            expected_request,
            integration_id=self._config.integration_id,
            capability_id=mapped.capability,
        )

        if retry_fingerprint != record.request_fingerprint:
            raise ApprovalRequestMismatchError("approval request fingerprint mismatch")

        store_policy_info = self._approval_store.get_authoritative_policy()
        if store_policy_info is not None:
            store_policy, store_provenance = store_policy_info
            if (
                record.policy_provenance.version_id != store_provenance.version_id
                or record.policy_provenance.policy_digest != store_provenance.policy_digest
            ):
                if record.state is ApprovalState.APPROVED:
                    self._approval_store.invalidate_approved(record, reason="shared store policy provenance changed")
                raise ApprovalPolicyInvalidError("approval policy provenance is stale per shared store")
            store_decision = store_policy.evaluate(expected_request)
            if store_decision is Decision.DENY:
                if record.state is ApprovalState.APPROVED:
                    self._approval_store.invalidate_approved(record, reason="shared store policy denied request")
                raise ApprovalPolicyInvalidError("current shared store policy denies the approved request")

        if self._policy_provenance is None:
            raise ApprovalPolicyInvalidError("current policy provenance is unavailable")
        if (
            record.policy_provenance.version_id != self._policy_provenance.version_id
            or record.policy_provenance.policy_digest != self._policy_provenance.policy_digest
        ):
            if record.state is ApprovalState.APPROVED:
                self._approval_store.invalidate_approved(record, reason="policy provenance changed")
            raise ApprovalPolicyInvalidError("approval policy provenance is stale")

        decision = self._evaluate_request(expected_request, expected_agent_id=effective_agent_id)
        if decision is Decision.DENY:
            if record.state is ApprovalState.APPROVED:
                self._approval_store.invalidate_approved(record, reason="current policy denied request")
            raise ApprovalPolicyInvalidError("current policy denies the approved request")

        self._approval_store.consume_approved(
            approval_id=record.approval_id,
            credential=approval_credential,
            expected_request=expected_request,
            verifier=self._approval_verifier,
            now=self._clock(),
        )

        exact_arguments = thaw_json(expected_request.arguments)
        return await self._client.call_tool(tool_name, arguments=exact_arguments)


class DmintMCPProxy:
    """MCP server that bridges one trusted integration to the agent."""

    def __init__(
        self,
        integration_config: MCPIntegrationConfig,
        policy: Policy | None = None,
        *,
        agent_id: str = "mcp-agent",
        context: TrustedContext | None = None,
        approval_store: ApprovalStore | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        policy_provenance: PolicyProvenance | None = None,
        approval_ttl: timedelta | None = None,
        clock: Callable[[], datetime] | None = None,
        disclosure_mode: DisclosureMode | str = DisclosureMode.DOG,
        server_name: str = "dmint-mcp-proxy",
    ) -> None:
        if not isinstance(integration_config, MCPIntegrationConfig):
            raise MCPConfigurationError("integration_config must be an MCPIntegrationConfig")
        self._integration_config = integration_config
        self._integration_id = integration_config.integration_id
        self._policy = policy
        self._agent_id = agent_id
        self._context = context or TrustedContext({})
        self._approval_store = approval_store
        self._approval_verifier = approval_verifier
        self._policy_provenance = policy_provenance
        self._approval_ttl = approval_ttl
        self._clock = clock
        self._disclosure_mode = disclosure_mode
        self._gate: EnforcementGate | None = None
        self._server = Server(server_name)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def gate(self) -> EnforcementGate | None:
        return self._gate

    def _check_ready(self) -> None:
        if self._gate is None:
            raise MCPProxyError("proxy is not connected to downstream server")

    async def connect(self) -> None:
        """Connect to the downstream client and register MCP handlers."""
        if self._gate is not None:
            return
        client = DownstreamMCPClient(self._integration_config)
        await client.connect()
        self._gate = EnforcementGate(
            client,
            self._integration_config,
            policy=self._policy,
            agent_id=self._agent_id,
            context=self._context,
            approval_store=self._approval_store,
            approval_verifier=self._approval_verifier,
            policy_provenance=self._policy_provenance,
            approval_ttl=self._approval_ttl,
            clock=self._clock,
            disclosure_mode=self._disclosure_mode,
        )
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

    async def disconnect(self) -> None:
        """Shut down the proxy and downstream connection."""
        gate = self._gate
        self._gate = None
        if gate is not None:
            client = getattr(gate, "_client", None)
            if client is not None:
                await client.disconnect()

    async def list_tools(self) -> types.ListToolsResult:
        """Public helper to list downstream tools (used by tests)."""
        gate = self._gate
        if gate is None:
            raise MCPProxyError("proxy is not connected to downstream server")
        return await gate.list_tools()

    async def retry_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None,
        approval_credential: ApprovalAssertion | bytes,
    ) -> types.CallToolResult:
        """Execute an approved retry for one tool call."""
        self._check_ready()
        assert self._gate is not None
        return await self._gate.retry_call(
            integration_id=self._integration_id,
            tool_name=tool_name,
            arguments=arguments,
            approval_credential=approval_credential,
        )

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: types.PaginatedRequestParams,
    ) -> types.ListToolsResult:
        self._check_ready()
        assert self._gate is not None
        try:
            return await self._gate.list_tools()
        except (MCPTimeoutError, MCPConnectionError, MCPProtocolError) as exc:
            code = getattr(exc, "code", "DMT_MCP_ERROR")
            raise SDKMCPError(-32000, f"Dmint enforcement [{code}]: {exc}") from exc

    def _format_approval_required_result(self, exc: ApprovalRequiredError) -> types.CallToolResult:
        mode = getattr(self._gate, "disclosure_mode", DisclosureMode.DOG)
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
        mode = getattr(self._gate, "disclosure_mode", DisclosureMode.DOG)
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
        mode = getattr(self._gate, "disclosure_mode", DisclosureMode.DOG)
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

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        self._check_ready()
        assert self._gate is not None

        tool_name = params.name
        if type(tool_name) is not str or not tool_name:
            raise MCPProtocolError("tools/call requires a tool name")

        arguments = params.arguments
        if arguments is not None and type(arguments) is not dict:
            raise MCPProtocolError("tool arguments must be an object")

        # Check if caller included an approval credential for an approved retry
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

                return await self._gate.retry_call(
                    integration_id=self._integration_id,
                    tool_name=tool_name,
                    arguments=call_arguments,
                    approval_credential=approval_cred,
                )
            else:
                return await self._gate.route_call(
                    integration_id=self._integration_id,
                    tool_name=tool_name,
                    arguments=call_arguments,
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
        """Run the agent-facing MCP server over stdio until shutdown."""
        async with stdio_server() as (read_stream, write_stream):
            if self._gate is None:
                await self.connect()
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )
