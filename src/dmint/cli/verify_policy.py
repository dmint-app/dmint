"""Standalone module to verify a policy.json file against Dmint policy schema and semantics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dmint.policy import Policy, PolicyError
from dmint.cli.errors import CLIError, InputFileError, JSONExtractionError, PolicyValidationError
from dmint.cli.limits import MAX_POLICY_FILE_SIZE_BYTES


def verify_policy_file(policy_file: str | Path) -> Policy:
    """Load, parse, and validate a policy.json file using Policy.from_mapping()."""
    policy_path = Path(policy_file).resolve()
    if not policy_path.exists():
        raise InputFileError(f"policy file not found: {policy_path}")

    st = policy_path.stat()
    if st.st_size > MAX_POLICY_FILE_SIZE_BYTES:
        raise CLIError(
            f"Resource exhaustion error: policy file '{policy_path}' size ({st.st_size} bytes) "
            f"exceeds maximum allowed limit of {MAX_POLICY_FILE_SIZE_BYTES} bytes."
        )

    try:
        content = policy_path.read_text(encoding="utf-8")
    except Exception as exc:
        raise InputFileError(f"failed to read policy file: {exc}") from exc

    if not content.strip():
        raise InputFileError(f"policy file is empty: {policy_path}")

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise JSONExtractionError(f"invalid JSON in policy file: {exc}") from exc

    try:
        policy = Policy.from_mapping(data)
    except PolicyError as exc:
        raise PolicyValidationError(f"Dmint policy validation failed: {exc}") from exc
    except Exception as exc:
        raise PolicyValidationError(f"invalid policy structure: {exc}") from exc

    return policy


def print_policy_summary(policy: Policy, policy_file: str | Path) -> None:
    """Print checkmark and rule-by-rule summary."""
    print(f"✓ Verified {policy_file}: {len(policy.rules)} rule(s)")
    for r in policy.rules:
        res_str = r.resource if isinstance(r.resource, str) else type(r.resource).__name__
        print(f"  [{r.effect.value.upper()}] tool='{r.tool}', action='{r.action}', resource='{res_str}'")


def main_verify(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dmint verify-policy",
        description="Verify a policy.json file against Dmint schema and semantic invariants (100% offline, zero network, LLM-free).",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to policy.json file to verify",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file_option",
        help="Path to policy.json file to verify",
    )

    try:
        parsed = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    target_file = parsed.file_option or parsed.file
    if not target_file:
        print(
            "✗ Error: missing policy file argument. Provide path to policy.json (e.g. 'dmint verify-policy policy.json')",
            file=sys.stderr,
        )
        parser.print_help(file=sys.stderr)
        return 2

    try:
        policy = verify_policy_file(target_file)
        print_policy_summary(policy, target_file)
        return 0
    except CLIError as exc:
        print(f"✗ Verification failed: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:
        print(f"✗ Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main_verify())
