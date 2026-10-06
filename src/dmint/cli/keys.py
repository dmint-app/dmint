"""CLI commands for Ed25519 key management: init-keys and export-public-key."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dmint.core.keys import (
    DEFAULT_KEY_FILE,
    KeyExistsError,
    KeyLoadError,
    load_private_key_from_file,
    public_key_hex,
    public_key_pem,
    write_private_key_atomic,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ─── dmint init-keys ───────────────────────────────────────────────────────────


def main_init_keys(args: list[str]) -> int:
    """Generate and persist a new Ed25519 signing key for the approval authority.

    Usage:
        dmint init-keys [--key-file PATH] [--issuer-id ID] [--force]

    The key file is created with mode 0600 atomically — there is no window
    during which it is world-readable.  Use ``dmint export-public-key`` to
    get the public key for pasting into the gateway's ``trusted_issuers``.

    Key rotation procedure:
        1. Run ``dmint init-keys --key-file new.key --issuer-id my-auth-v2``
        2. Run ``dmint export-public-key --key-file new.key --issuer-id my-auth-v2``
        3. Add the new issuer entry to the gateway ``trusted_issuers`` config.
        4. Deploy the updated gateway config (supports both old and new keys).
        5. Switch the authority process to use the new key file.
        6. Wait for all pending assertions signed with the old key to expire or
           be consumed, then remove the old issuer from ``trusted_issuers``.

    WARNING: Use --force only if you understand that overwriting the key file
    will invalidate any pending approvals signed with the old key.
    """
    parser = argparse.ArgumentParser(
        prog="dmint init-keys",
        description="Generate and persist a new Ed25519 signing key.",
    )
    parser.add_argument(
        "--key-file",
        default=str(DEFAULT_KEY_FILE),
        help=f"Destination for the private key file (default: {DEFAULT_KEY_FILE})",
    )
    parser.add_argument(
        "--issuer-id",
        default=os.environ.get("DMINT_ISSUER_ID", "dmint-authority"),
        help="Issuer ID to associate with this key (informational only; printed on success)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=("Overwrite an existing key file. WARNING: invalidates pending approvals signed with the old key."),
    )
    opts = parser.parse_args(args)

    key_path = Path(opts.key_file)

    try:
        private_key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_path, private_key, force=opts.force)
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
            "error: could not write key file (check directory permissions).",
            file=sys.stderr,
        )
        return 1

    pub_hex = public_key_hex(private_key.public_key())
    pub_pem = public_key_pem(private_key.public_key())

    print("Ed25519 signing key generated successfully.", file=sys.stderr)
    print(f"  Key file:  {key_path}", file=sys.stderr)
    print(f"  Issuer ID: {opts.issuer_id}", file=sys.stderr)
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
