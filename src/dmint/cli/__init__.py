"""Dmint CLI package."""

from .api import OpenAICompatClient, mask_secret
from .approvals import main_approve, main_pending, main_reject
from .compile_policy import compile_policy_file, main_compile
from .create_policy import main_create, run_create_policy_wizard
from .errors import (
    APIError,
    CLIError,
    InputFileError,
    JSONExtractionError,
    OutputWriteError,
    PolicyValidationError,
)
from .install_skill import install_skill_file, main_install_skill
from .mcp_connections import MCPIntegration, MCPTransport, canonical_capability
from .mcp_credentials import CredentialStore, TokenRecord
from .verify_policy import main_verify, verify_policy_file
from .version import DEFAULT_USER_AGENT, __version__, get_user_agent

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .create_mcp_policy import main_create_mcp, run_create_mcp_policy_wizard
    from .mcp_auth import MCPAuthRequirements, discover_mcp_auth_requirements
    from .mcp_oauth import PKCEParameters, perform_oauth_flow
else:
    try:
        from .create_mcp_policy import main_create_mcp, run_create_mcp_policy_wizard
        from .mcp_auth import MCPAuthRequirements, discover_mcp_auth_requirements
        from .mcp_oauth import PKCEParameters, perform_oauth_flow
    except ImportError:
        main_create_mcp = None
        run_create_mcp_policy_wizard = None
        MCPAuthRequirements = None
        discover_mcp_auth_requirements = None
        PKCEParameters = None
        perform_oauth_flow = None

__all__ = [
    "APIError",
    "CLIError",
    "CredentialStore",
    "DEFAULT_USER_AGENT",
    "InputFileError",
    "JSONExtractionError",
    "MCPAuthRequirements",
    "MCPIntegration",
    "MCPTransport",
    "OpenAICompatClient",
    "OutputWriteError",
    "PKCEParameters",
    "PolicyValidationError",
    "TokenRecord",
    "__version__",
    "canonical_capability",
    "compile_policy_file",
    "discover_mcp_auth_requirements",
    "get_user_agent",
    "install_skill_file",
    "main_approve",
    "main_compile",
    "main_create",
    "main_create_mcp",
    "main_install_skill",
    "main_pending",
    "main_reject",
    "main_verify",
    "mask_secret",
    "perform_oauth_flow",
    "run_create_mcp_policy_wizard",
    "run_create_policy_wizard",
    "verify_policy_file",
]
