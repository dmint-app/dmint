"""Machine-readable MCP integration errors."""

from dmint.errors import DmintError


class MCPError(DmintError):
    """Base class for MCP integration failures."""

    code = "DMT_MCP_ERROR"


class MCPConfigurationError(MCPError):
    """The MCP integration configuration is invalid."""

    code = "DMT_MCP_CONFIG_ERROR"


class MCPConnectionError(MCPError):
    """Connection to downstream MCP server failed or was interrupted."""

    code = "DMT_MCP_CONNECTION_ERROR"


class MCPTimeoutError(MCPError):
    """Downstream MCP operation timed out."""

    code = "DMT_MCP_TIMEOUT"


class MCPProtocolError(MCPError):
    """Downstream MCP server returned an invalid or unparseable protocol message."""

    code = "DMT_MCP_PROTOCOL_ERROR"


class MCPMappingError(MCPError):
    """An MCP tools/call could not be mapped to a valid Dmint request."""

    code = "DMT_MCP_REQUEST_INVALID"
