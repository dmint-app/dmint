"""Resource limits and thresholds for dmint-cli to prevent resource exhaustion attacks.

This module defines hard, documented bounds for:
- Number of MCP integrations
- Number of tools per integration and across all integrations
- Pagination depth and cursor size
- Tool name and description lengths
- Input argument/schema size
- Network response sizes (HTTP, metadata, OAuth discovery)
- File sizes (credential store, policy files)
- Timeouts (authorization, discovery, total operation)
- Recursion depth and retry attempts
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Integration & Tool Cardinality Limits
# ---------------------------------------------------------------------------

# Maximum number of MCP integrations allowed in a single protection configuration or wizard session.
MAX_MCP_INTEGRATIONS: int = 50

# Maximum number of tools permitted from a single MCP integration.
MAX_TOOLS_PER_INTEGRATION: int = 1000

# Maximum total number of discovered tools aggregated across all integrations.
MAX_TOTAL_DISCOVERED_TOOLS: int = 2500

# ---------------------------------------------------------------------------
# String Length & Schema Size Limits
# ---------------------------------------------------------------------------

# Maximum character length for an MCP tool name.
MAX_TOOL_NAME_LENGTH: int = 128

# Maximum character length for a tool description before truncation.
MAX_TOOL_DESCRIPTION_LENGTH: int = 10000

# Maximum allowed JSON serialization size in bytes for a tool's input schema.
MAX_SCHEMA_SIZE_BYTES: int = 128 * 1024  # 128 KB

# ---------------------------------------------------------------------------
# Pagination Limits
# ---------------------------------------------------------------------------

# Maximum number of pagination pages to fetch before aborting (prevents DoS).
MAX_PAGINATION_DEPTH: int = 100

# Maximum character length for a cursor token string.
MAX_CURSOR_LENGTH: int = 1024

# ---------------------------------------------------------------------------
# Network Response Size Limits (prevents unbounded memory consumption / OOM)
# ---------------------------------------------------------------------------

# Maximum response size in bytes for general HTTP discovery responses.
MAX_HTTP_RESPONSE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2 MB

# Maximum response size in bytes for MCP protected resource metadata (PRM) responses.
MAX_METADATA_RESPONSE_SIZE_BYTES: int = 512 * 1024  # 512 KB

# Maximum response size in bytes for OAuth authorization server metadata discovery.
MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES: int = 256 * 1024  # 256 KB

# ---------------------------------------------------------------------------
# File Size Limits
# ---------------------------------------------------------------------------

# Maximum file size in bytes for credential store (credentials.json).
MAX_CREDENTIAL_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB

# Maximum file size in bytes for policy files (policy.json).
MAX_POLICY_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

# ---------------------------------------------------------------------------
# Timeout Bounds (seconds)
# ---------------------------------------------------------------------------

# Default network timeout for an individual discovery probe.
DEFAULT_DISCOVERY_TIMEOUT_SECONDS: float = 15.0

# Upper bound on configurable discovery timeout.
MAX_DISCOVERY_TIMEOUT_SECONDS: float = 60.0

# Default timeout waiting for user OAuth completion in browser.
DEFAULT_AUTHORIZATION_TIMEOUT_SECONDS: float = 300.0  # 5 minutes

# Upper bound on OAuth callback timeout.
MAX_AUTHORIZATION_TIMEOUT_SECONDS: float = 300.0

# Maximum overall wall-clock time permitted for an entire wizard operation.
MAX_TOTAL_OPERATION_TIMEOUT_SECONDS: float = 600.0  # 10 minutes

# ---------------------------------------------------------------------------
# Recursion & Retry Bounds
# ---------------------------------------------------------------------------

# Maximum recursion depth when inspecting nested dicts/exceptions/data structures.
MAX_RECURSION_DEPTH: int = 20

# Maximum authentication retry attempts before aborting (prevents infinite loop).
MAX_AUTH_RETRY_ATTEMPTS: int = 1
