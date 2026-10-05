"""Shared error types for dmint-cli with stable, documented exit codes.

Stable Exit Code Specification:
  0: Success
  1: General error or user aborted operation
  2: Command-line usage or argument parsing error (argparse standard)
  3: Input file error (file not found, unreadable, or empty)
  4: API / LLM provider communication error (network, auth, rate limit)
  5: JSON extraction / contract error (model output not matching contract)
  6: Policy validation error (schema or semantic invariant failure)
  7: Output file write error (atomic write or permission failure)
  8: Resource exhaustion error (size, cardinality, recursion, or timeout limit)
"""

from __future__ import annotations

EXIT_CODES: dict[str, int] = {
    "SUCCESS": 0,
    "GENERAL_ERROR": 1,
    "USAGE_ERROR": 2,
    "INPUT_FILE_ERROR": 3,
    "API_ERROR": 4,
    "JSON_EXTRACTION_ERROR": 5,
    "POLICY_VALIDATION_ERROR": 6,
    "OUTPUT_WRITE_ERROR": 7,
    "RESOURCE_EXHAUSTION_ERROR": 8,
}


class CLIError(Exception):
    """Base CLI error with an explicit, stable exit code."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class InputFileError(CLIError):
    """Raised when an input file is missing, empty, or unreadable (Exit Code 3)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=3)


class APIError(CLIError):
    """Raised when an external API / LLM request fails or network times out (Exit Code 4)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=4)


class JSONExtractionError(CLIError):
    """Raised when an LLM response fails output format contract or JSON parsing (Exit Code 5)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=5)


class PolicyValidationError(CLIError):
    """Raised when a policy fails Dmint schema or semantic invariant verification (Exit Code 6)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=6)


class OutputWriteError(CLIError):
    """Raised when writing output files (policy.json, mcp_protection.json) fails (Exit Code 7)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=7)


class ResourceExhaustionError(CLIError):
    """Raised when a resource, cardinality, pagination, or timeout limit is exceeded (Exit Code 8)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=8)
