"""Map MCP tools/call requests into the existing Dmint request model (MCP-5).

This module translates an untrusted MCP tool call into a canonical
:class:`~dmint.models.ToolRequest` using ONLY the trusted integration/binding
configuration and the existing Dmint core primitives. It introduces no second
policy engine, no second request-binding implementation, and no second approval
model.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dmint.approvals import new_request_id
from dmint.errors import RequestValidationError
from .errors import MCPMappingError, MCPConfigurationError
from dmint.models import NO_RESOURCE, NoResource, ToolRequest, TrustedContext, validate_text
from dmint.request_binding import request_binding_fingerprint
from .config import MCPIntegrationConfig, MCPToolBinding


@dataclass(frozen=True)
class MCPMappedRequest:
    """The trusted Dmint request plus its semantic fingerprint for one MCP call."""

    tool_request: ToolRequest
    binding: MCPToolBinding
    capability: str
    integration_id: str
    fingerprint: str
    resource: str | NoResource


def _split_capability(capability: str) -> tuple[str, str]:
    """Split a trusted capability (e.g. "github.merge") into tool and action."""
    try:
        capability = validate_text(capability, "capability")
    except RequestValidationError as exc:
        raise MCPConfigurationError("invalid capability in trusted binding") from exc
    tool, separator, action = capability.partition(".")
    if not separator or not tool or not action:
        raise MCPConfigurationError("capability must have the form tool.action")
    return tool, action


def _resolve_resource(
    binding: MCPToolBinding,
    arguments: Mapping[str, Any],
) -> str | NoResource:
    """Derive the request resource from the trusted resource_key, or NO_RESOURCE."""
    if binding.resource_key is None:
        return NO_RESOURCE
    if binding.resource_key not in arguments:
        raise MCPMappingError(
            f"missing resource argument: {binding.resource_key}",
            code="DMT_MCP_RESOURCE_INVALID",
        )
    value = arguments[binding.resource_key]
    if type(value) is not str or not value or value != value.strip():
        raise MCPMappingError(
            "resource argument must be a non-empty string",
            code="DMT_MCP_RESOURCE_INVALID",
        )
    return value


class MCPRequestMapper:
    """Trusted mapper from MCP tool calls to Dmint ToolRequest objects."""

    def __init__(
        self,
        integration_config: MCPIntegrationConfig,
        *,
        agent_id: str,
        context: TrustedContext,
    ) -> None:
        if type(integration_config) is not MCPIntegrationConfig:
            raise MCPConfigurationError("integration_config must be an MCPIntegrationConfig")
        try:
            agent_id = validate_text(agent_id, "agent_id")
        except RequestValidationError as exc:
            raise MCPConfigurationError("invalid agent_id") from exc
        if type(context) is not TrustedContext:
            raise MCPConfigurationError("context must be TrustedContext")
        self._config = integration_config
        self._agent_id = agent_id
        self._context = context

    @property
    def integration_id(self) -> str:
        return self._config.integration_id

    def resolve_binding(self, tool_name: str) -> MCPToolBinding:
        """Resolve a downstream tool name through trusted bindings, fail closed."""
        if type(tool_name) is not str or not tool_name or tool_name != tool_name.strip():
            raise MCPMappingError("invalid tool name", code="DMT_MCP_TOOL_UNKNOWN")
        binding = self._config.tool_bindings.get(tool_name)
        if binding is None:
            raise MCPMappingError(
                f"tool is not bound: {tool_name}",
                code="DMT_MCP_TOOL_UNKNOWN",
            )
        return binding

    def map(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        request_id: str | None = None,
        agent_id: str | None = None,
    ) -> MCPMappedRequest:
        """Map an MCP tool call into a Dmint ToolRequest and semantic fingerprint.

        Args:
            tool_name: downstream MCP tool name (untrusted).
            arguments: untrusted MCP arguments, validated and frozen here.
            request_id: optional explicit request id (normally auto-generated).
            agent_id: optional authenticated agent identity (defaults to mapper agent_id).

        Raises:
            MCPMappingError: on any invalid/unbound/malformed input.
        """
        binding = self.resolve_binding(tool_name)

        if arguments is None:
            arguments = {}
        if type(arguments) is not dict:
            raise MCPMappingError(
                "tool arguments must be a JSON object",
                code="DMT_MCP_ARGUMENT_INVALID",
            )

        if agent_id is not None:
            try:
                effective_agent_id = validate_text(agent_id, "agent_id")
            except RequestValidationError as exc:
                raise MCPMappingError("invalid agent_id", code="DMT_MCP_ARGUMENT_INVALID") from exc
        else:
            effective_agent_id = self._agent_id

        tool, action = _split_capability(binding.capability)
        resource = _resolve_resource(binding, arguments)

        # ToolRequest freezes/normalizes arguments via the same canonical JSON
        # path used by the rest of Dmint (freeze_json + canonicalize_frozen).
        request = ToolRequest(
            request_id=request_id or new_request_id(),
            agent_id=effective_agent_id,
            tool=tool,
            action=action,
            resource=resource,
            arguments=dict(arguments),
            context=self._context,
        )

        capability = binding.capability
        fingerprint = request_binding_fingerprint(
            request,
            integration_id=self._config.integration_id,
            capability_id=capability,
        )

        return MCPMappedRequest(
            tool_request=request,
            binding=binding,
            capability=capability,
            integration_id=self._config.integration_id,
            fingerprint=fingerprint,
            resource=resource,
        )
