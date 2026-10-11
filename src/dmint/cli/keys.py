"""CLI commands for Ed25519 key management: init-keys and export-public-key."""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

from dmint.core.keys import (
    DEFAULT_KEY_FILE,
    DEFAULT_INTEGRITY_KEY_FILE,
    KeyExistsError,
    KeyLoadError,
    load_private_key_from_file,
    public_key_hex,
    public_key_pem,
    write_private_key_atomic,
    write_integrity_key_atomic,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ─── dmint init-keys ───────────────────────────────────────────────────────────


def main_init_keys(args: list[str]) -> int:
    """Generate and persist a new Ed25519 signing key and HMAC integrity key."""
    parser = argparse.ArgumentParser(
        prog="dmint init-keys",
        description="Generate and persist new signing and HMAC storage integrity keys.",
    )
    parser.add_argument(
        "--key-file",
        default=str(DEFAULT_KEY_FILE),
        help=f"Destination for the signing key file (default: {DEFAULT_KEY_FILE})",
    )
    parser.add_argument(
        "--integrity-key-file",
        default=None,
        help="Destination for the HMAC storage integrity key file (default: integrity.key next to key-file)",
    )
    parser.add_argument(
        "--issuer-id",
        default=os.environ.get("DMINT_ISSUER_ID", "dmint-authority"),
        help="Issuer ID to associate with this key (informational only; printed on success)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=("Overwrite existing key files. WARNING: invalidates pending approvals signed with the old key."),
    )
    opts = parser.parse_args(args)

    key_path = Path(opts.key_file)
    integrity_path = Path(opts.integrity_key_file) if opts.integrity_key_file else key_path.parent / "integrity.key"

    try:
        private_key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_path, private_key, force=opts.force)
        integrity_bytes = secrets.token_bytes(32)
        write_integrity_key_atomic(integrity_path, integrity_bytes, force=opts.force)
    except KeyExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "Hint: use --force to overwrite (WARNING: invalidates pending approvals).",
            file=sys.stderr,
        )
        return 1
    except OSError:
        # Do NOT include exc in output — it may contain path details.
        print(
            "error: could not write key files (check directory permissions).",
            file=sys.stderr,
        )
        return 1

    pub_hex = public_key_hex(private_key.public_key())
    pub_pem = public_key_pem(private_key.public_key())

    print("Ed25519 signing key and HMAC integrity key generated successfully.", file=sys.stderr)
    print(f"  Signing key file:   {key_path}", file=sys.stderr)
    print(f"  Integrity key file: {integrity_path}", file=sys.stderr)
    print(f"  Issuer ID:          {opts.issuer_id}", file=sys.stderr)
    print(file=sys.stderr)
    print("Public key (paste into gateway trusted_issuers):", file=sys.stderr)
    print(f'  public_key_hex: "{pub_hex}"', file=sys.stderr)
    print(f'  issuer_id: "{opts.issuer_id}"', file=sys.stderr)
    print(file=sys.stderr)
    print("PEM format:", file=sys.stderr)
    print(pub_pem, file=sys.stderr)
    print(
        "Keep the key file readable ONLY by the approver process. "
        "The private key must NEVER be shared with the agent process.",
        file=sys.stderr,
    )
    return 0


# ─── dmint export-public-key ───────────────────────────────────────────────────


def main_export_public_key(args: list[str]) -> int:
    """Print the public key and issuer ID for pasting into the gateway config.

    Usage:
        dmint export-public-key [--key-file PATH] [--issuer-id ID]

    Only the PUBLIC key is ever printed — the private key stays on disk.
    """
    parser = argparse.ArgumentParser(
        prog="dmint export-public-key",
        description="Print the public key and issuer ID for the gateway trusted_issuers.",
    )
    parser.add_argument(
        "--key-file",
        default=str(DEFAULT_KEY_FILE),
        help=f"Path to the private key file (default: {DEFAULT_KEY_FILE})",
    )
    parser.add_argument(
        "--issuer-id",
        default=os.environ.get("DMINT_ISSUER_ID", "dmint-authority"),
        help="Issuer ID label to display (should match what was used at init-keys time)",
    )
    parser.add_argument(
        "--format",
        choices=["hex", "pem", "both", "json"],
        default="both",
        help="Output format (default: both)",
    )
    opts = parser.parse_args(args)

    key_path = Path(opts.key_file)
    try:
        private_key = load_private_key_from_file(key_path)
    except KeyLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    pub = private_key.public_key()
    pub_hex_str = public_key_hex(pub)
    pub_pem_str = public_key_pem(pub)

    fmt = opts.format
    if fmt == "json":
        import json

        entry = {
            "issuer_id": opts.issuer_id,
            "public_key_hex": pub_hex_str,
        }
        print(json.dumps(entry, indent=2))
    elif fmt == "hex":
        print(pub_hex_str)
    elif fmt == "pem":
        print(pub_pem_str, end="")
    else:  # both
        print(f"issuer_id:      {opts.issuer_id}")
        print(f"public_key_hex: {pub_hex_str}")
        print()
        print(pub_pem_str, end="")

    return 0
