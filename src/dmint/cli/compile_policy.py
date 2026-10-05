"""Thin compatibility wrapper for legacy compile-policy command."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dmint.policy import Policy
from dmint.cli.errors import (
    APIError,
    CLIError,
    InputFileError,
    JSONExtractionError,
    OutputWriteError,
    PolicyValidationError,
)
from dmint.cli.io_utils import atomic_write_json, load_system_prompt


def compile_policy_file(
    *,
    input_file: str | Path,
    output_file: str | Path,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    timeout: float = 60.0,
) -> Policy:
    """Thin compatibility wrapper delegating to create-policy non-interactive policy generation."""
    from dmint.cli.create_policy import run_create_policy_wizard

    return run_create_policy_wizard(
        access_md_file=input_file,
        output_json_file=output_file,
        base_url=base_url,
        api_key=api_key,
        model=model,
        provider=provider,
        non_interactive=True,
        auto_confirm=True,
        timeout=timeout,
    )


def main_compile(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dmint compile-policy",
        description="[Compatibility] Compile natural language policy requirements into a validated Dmint policy.json file.\n"
        "Note: For modern interactive policy authoring or MCP tool discovery, prefer 'dmint create-policy' or 'dmint create-mcp-policy'.",
    )
    parser.add_argument("-f", "--file", required=True, help="Input policy markdown/text file (e.g. access.md)")
    parser.add_argument("-o", "--output", required=True, help="Output policy JSON file (e.g. policy.json)")
    parser.add_argument("-provider", "--provider", help="LLM provider (e.g. openai, gemini, groq, openrouter, ollama)")
    parser.add_argument(
        "-base_url", "--base-url", help="OpenAI-compatible base URL (default: https://api.openai.com/v1)"
    )
    parser.add_argument("-api_key", "--api-key", help="API key (or via OPENAI_API_KEY / GEMINI_API_KEY env vars)")
    parser.add_argument("-model", "--model", help="Model name (e.g. gpt-4o-mini, gemini-1.5-flash)")
    parser.add_argument("--timeout", type=float, default=60.0, help="API request timeout in seconds (default: 60.0)")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    try:
        compile_policy_file(
            input_file=parsed.file,
            output_file=parsed.output,
            base_url=parsed.base_url,
            api_key=parsed.api_key,
            model=parsed.model,
            provider=parsed.provider,
            timeout=parsed.timeout,
        )
        print("✓ Policy generated")
        print("✓ Dmint schema validation passed")
        print("✓ Semantic validation passed")
        print(f"→ {parsed.output}")
        return 0
    except CLIError as exc:
        print(f"✗ Policy compilation failed: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:
        print(f"✗ Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main_compile())
