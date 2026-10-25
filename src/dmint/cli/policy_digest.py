"""CLI command to compute and print the SHA-256 digest of policy file bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Sequence

from dmint.cli.ui import DmintHelpFormatter


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
        formatter_class=DmintHelpFormatter,
        description="Compute the SHA-256 digest of exact policy file bytes.",
        epilog="""Examples:
  dmint policy-digest policy.json
  dmint policy-digest -f policy.json --json
""",
    )
    parser.add_argument("policy_file", nargs="?", help="Path to policy.json file")
    parser.add_argument("-f", "--file", "-p", "--policy", dest="file_opt", help="Path to policy.json file")
    parser.add_argument("--json", action="store_true", help="Output digest as JSON")

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    target = args.file_opt or args.policy_file
    if not target:
        if Path("policy.json").is_file():
            target = "policy.json"
        else:
            sys.stderr.write("Error: missing policy_file argument (e.g. 'dmint policy-digest policy.json')\n")
            return 2

    try:
        digest = compute_policy_file_digest(target)
        if args.json:
            print(json.dumps({"file": str(target), "policy_digest": digest, "sha256": digest}, indent=2))
        else:
            print(digest)
        return 0
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1
