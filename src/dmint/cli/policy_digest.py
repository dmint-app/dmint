"""CLI command to compute and print policy digests.

Two digest domains are supported:

* ``file_sha256`` — SHA-256 of the exact policy file bytes. This is the value
  verified before parsing for remote policy sources and the default output.
* ``canonical_policy_digest`` — domain-separated SHA-256 over RFC 8785 (JCS)
  canonical policy content (``dmint/policy-digest/v1\\x00``). Use
  ``--canonical`` to print it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Sequence

from dmint.cli.ui import DmintHelpFormatter
from dmint.core.policy import Policy, policy_digest


def compute_policy_file_digest(policy_path: str | Path) -> str:
    """Compute the SHA-256 hex digest of exact file bytes for a policy file."""
    path = Path(policy_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    if not path.is_file():
        raise ValueError(f"policy path is not a file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_policy_canonical_digest(policy_path: str | Path) -> str:
    """Compute the domain-separated canonical digest of a policy file."""
    path = Path(policy_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    if not path.is_file():
        raise ValueError(f"policy path is not a file: {path}")
    return policy_digest(Policy.from_file(path))


def main_policy_digest(argv: Sequence[str] | None = None) -> int:
    """Entry point for 'dmint policy-digest <policy.json>'."""
    parser = argparse.ArgumentParser(
        prog="dmint policy-digest",
        formatter_class=DmintHelpFormatter,
        description="Compute the SHA-256 digest of exact policy file bytes or canonical policy content.",
        epilog="""Examples:
  dmint policy-digest policy.json
  dmint policy-digest -f policy.json --json
  dmint policy-digest policy.json --canonical
""",
    )
    parser.add_argument("policy_file", nargs="?", help="Path to policy.json file")
    parser.add_argument("-f", "--file", "-p", "--policy", dest="file_opt", help="Path to policy.json file")
    parser.add_argument(
        "--canonical",
        action="store_true",
        help="Print the canonical policy digest instead of the raw file SHA-256",
    )
    parser.add_argument("--json", action="store_true", help="Output both digests as JSON")

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
        file_digest = compute_policy_file_digest(target)
        if args.json:
            canonical_digest = compute_policy_canonical_digest(target)
            print(
                json.dumps(
                    {
                        "file": str(target),
                        "file_sha256": file_digest,
                        "canonical_policy_digest": canonical_digest,
                        # Backward-compatible keys retained for existing scripts.
                        "policy_digest": canonical_digest,
                        "sha256": file_digest,
                    },
                    indent=2,
                )
            )
        elif args.canonical:
            print(compute_policy_canonical_digest(target))
        else:
            print(file_digest)
        return 0
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1
