"""Dmint MCP Enforcement Package."""

from dmint.version import __version__

from .config import DiscoveryMode, DisclosureMode, MCPIntegrationConfig, MCPToolBinding, MCPTransportType
from .config_loader import MCPGatewayConfig, load_protection_config, parse_protection_config
from .errors import (
    MCPConfigurationError,
    MCPConnectionError,
    MCPError,
    MCPMappingError,
    MCPProtocolError,
    MCPTimeoutError,
)
from .mapper import MCPMappedRequest, MCPRequestMapper
from .ssrf import is_loopback_host, validate_mcp_url

try:
    from .client import DownstreamMCPClient
    from .gateway import GatewayIntegration, MCPGateway
    from .proxy import DmintMCPProxy, EnforcementGate, MCPProxyError
except ImportError:
    DownstreamMCPClient = None  # type: ignore[assignment, misc]
    GatewayIntegration = None  # type: ignore[assignment, misc]
    MCPGateway = None  # type: ignore[assignment, misc]
    DmintMCPProxy = None  # type: ignore[assignment, misc]
    EnforcementGate = None  # type: ignore[assignment, misc]
    MCPProxyError = None  # type: ignore[assignment, misc]

__all__ = [
    "__version__",
    "DownstreamMCPClient",
    "DmintMCPProxy",
    "DiscoveryMode",
    "DisclosureMode",
    "EnforcementGate",
    "GatewayIntegration",
    "MCPConfigurationError",
    "MCPConnectionError",
    "MCPError",
    "MCPGateway",
    "MCPGatewayConfig",
    "MCPIntegrationConfig",
    "MCPMappedRequest",
    "MCPMappingError",
    "MCPProtocolError",
    "MCPProxyError",
    "MCPRequestMapper",
    "MCPTimeoutError",
    "MCPToolBinding",
    "MCPTransportType",
    "load_protection_config",
    "parse_protection_config",
    "validate_mcp_url",
]
