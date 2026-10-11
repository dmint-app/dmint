"""CLI command to compute and print the SHA-256 digest of policy file bytes."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import Sequence


def compute_policy_file_digest(policy_path: str | Path) -> str:
    """Compute the SHA-256 hex digest of exact file bytes for a policy file."""
    path = Path(policy_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    if not path.is_file():
        raise ValueError(f"policy path is not a file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main_policy_digest(argv: Sequence[str] | None = None) -> int:
    """Entry point for 'dmint policy-digest <policy.json>'."""
    parser = argparse.ArgumentParser(
        prog="dmint policy-digest",
        description="Compute the SHA-256 digest of exact policy file bytes.",
    )
    parser.add_argument("policy_file", help="Path to policy.json file")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        digest = compute_policy_file_digest(args.policy_file)
        print(digest)
        return 0
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1
