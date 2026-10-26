"""Dmint CLI package with lazy attribute loading for fast hook startup."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from .version import DEFAULT_USER_AGENT, __version__, get_user_agent

if TYPE_CHECKING:
    from .api import OpenAICompatClient, mask_secret
    from .approvals import main_approve, main_pending, main_reject
    from .compile_policy import compile_policy_file, main_compile
    from .create_mcp_policy import main_create_mcp, run_create_mcp_policy_wizard
    from .create_policy import main_create, run_create_policy_wizard
    from .errors import (
        APIError,
        CLIError,
        InputFileError,
        JSONExtractionError,
        OutputWriteError,
        PolicyValidationError,
    )
    from .hooks import (
        evaluate_hook_request,
        install_harness_hooks,
        main_check,
        main_hook,
        main_init,
        normalize_harness_payload,
    )
    from .install_skill import install_skill_file, main_install_skill
    from .mcp_auth import MCPAuthRequirements, discover_mcp_auth_requirements
    from .mcp_connections import MCPIntegration, MCPTransport, canonical_capability
    from .mcp_credentials import CredentialStore, TokenRecord
    from .mcp_oauth import PKCEParameters, perform_oauth_flow
    from .verify_policy import main_verify, verify_policy_file

_LAZY_MAP: dict[str, tuple[str, str]] = {
    "OpenAICompatClient": (".api", "OpenAICompatClient"),
    "mask_secret": (".api", "mask_secret"),
    "main_approve": (".approvals", "main_approve"),
    "main_pending": (".approvals", "main_pending"),
    "main_reject": (".approvals", "main_reject"),
    "compile_policy_file": (".compile_policy", "compile_policy_file"),
    "main_compile": (".compile_policy", "main_compile"),
    "main_create": (".create_policy", "main_create"),
    "run_create_policy_wizard": (".create_policy", "run_create_policy_wizard"),
    "APIError": (".errors", "APIError"),
    "CLIError": (".errors", "CLIError"),
    "InputFileError": (".errors", "InputFileError"),
    "JSONExtractionError": (".errors", "JSONExtractionError"),
    "OutputWriteError": (".errors", "OutputWriteError"),
    "PolicyValidationError": (".errors", "PolicyValidationError"),
    "evaluate_hook_request": (".hooks", "evaluate_hook_request"),
    "install_harness_hooks": (".hooks", "install_harness_hooks"),
    "main_check": (".hooks", "main_check"),
    "main_hook": (".hooks", "main_hook"),
    "main_init": (".hooks", "main_init"),
    "normalize_harness_payload": (".hooks", "normalize_harness_payload"),
    "install_skill_file": (".install_skill", "install_skill_file"),
    "main_install_skill": (".install_skill", "main_install_skill"),
    "MCPIntegration": (".mcp_connections", "MCPIntegration"),
    "MCPTransport": (".mcp_connections", "MCPTransport"),
    "canonical_capability": (".mcp_connections", "canonical_capability"),
    "CredentialStore": (".mcp_credentials", "CredentialStore"),
    "TokenRecord": (".mcp_credentials", "TokenRecord"),
    "main_verify": (".verify_policy", "main_verify"),
    "verify_policy_file": (".verify_policy", "verify_policy_file"),
    "main_create_mcp": (".create_mcp_policy", "main_create_mcp"),
    "run_create_mcp_policy_wizard": (".create_mcp_policy", "run_create_mcp_policy_wizard"),
    "MCPAuthRequirements": (".mcp_auth", "MCPAuthRequirements"),
    "discover_mcp_auth_requirements": (".mcp_auth", "discover_mcp_auth_requirements"),
    "PKCEParameters": (".mcp_oauth", "PKCEParameters"),
    "perform_oauth_flow": (".mcp_oauth", "perform_oauth_flow"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_MAP:
        mod_name, attr_name = _LAZY_MAP[name]
        try:
            mod = importlib.import_module(mod_name, __package__)
            val = getattr(mod, attr_name)
        except ImportError:
            val = None
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    "evaluate_hook_request",
    "get_user_agent",
    "install_harness_hooks",
    "install_skill_file",
    "main_approve",
    "main_check",
    "main_compile",
    "main_create",
    "main_create_mcp",
    "main_hook",
    "main_init",
    "main_install_skill",
    "main_pending",
    "main_reject",
    "main_verify",
    "mask_secret",
    "normalize_harness_payload",
    "perform_oauth_flow",
    "run_create_mcp_policy_wizard",
    "run_create_policy_wizard",
    "verify_policy_file",
]
