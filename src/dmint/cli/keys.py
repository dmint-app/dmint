"""CLI commands for Ed25519 key management: init-keys and export-public-key."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.cli.ui import DmintHelpFormatter
from dmint.core.keys import (
    DEFAULT_INTEGRITY_KEY_FILE,
    DEFAULT_KEY_FILE,
    KeyExistsError,
    KeyLoadError,
    load_private_key_from_file,
    public_key_hex,
    public_key_pem,
    write_integrity_key_atomic,
    write_private_key_atomic,
)


def main_init_keys(args: list[str] | None = None) -> int:
    """Generate and persist a new Ed25519 signing key and HMAC integrity key."""
    parser = argparse.ArgumentParser(
        prog="dmint init-keys",
        formatter_class=DmintHelpFormatter,
        description="Generate and persist new Ed25519 signing and HMAC storage integrity keys (0600, atomic).",
        epilog="""Examples:
  dmint init-keys
  dmint init-keys --dir .dmint
  dmint init-keys --key-file .dmint/signing.key --integrity-key-file .dmint/integrity.key --force
""",
    )
    parser.add_argument(
        "--dir",
        "-d",
        dest="key_dir",
        default=None,
        help="Directory in which to generate signing.key and integrity.key",
    )
    parser.add_argument(
        "--key-file",
        default=None,
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
        help="Issuer ID to associate with this key (default: dmint-authority)",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing key files. WARNING: invalidates pending approvals signed with the old key.",
    )
    try:
        opts = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    if opts.key_dir:
        base_dir = Path(opts.key_dir).expanduser()
        key_path = Path(opts.key_file).expanduser() if opts.key_file else (base_dir / "signing.key")
        integrity_path = (
            Path(opts.integrity_key_file).expanduser() if opts.integrity_key_file else (base_dir / "integrity.key")
        )
    else:
        from dmint.core import keys as _keys_mod_def

        default_k = _keys_mod_def.DEFAULT_KEY_FILE
        key_path = Path(opts.key_file).expanduser() if opts.key_file else default_k
        integrity_path = (
            Path(opts.integrity_key_file).expanduser()
            if opts.integrity_key_file
            else (key_path.parent / "integrity.key")
        )

    from dmint.core import keys as _keys_mod

    try:
        private_key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_path, private_key, force=opts.force)
        integrity_bytes = secrets.token_bytes(32)
        write_integrity_key_atomic(integrity_path, integrity_bytes, force=opts.force)
        if (
            not opts.key_dir
            and not opts.integrity_key_file
            and _keys_mod.DEFAULT_INTEGRITY_KEY_FILE != integrity_path
            and _keys_mod.DEFAULT_INTEGRITY_KEY_FILE != (Path.home() / ".config" / "dmint" / "integrity.key")
        ):
            write_integrity_key_atomic(_keys_mod.DEFAULT_INTEGRITY_KEY_FILE, integrity_bytes, force=True)
    except KeyExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "Hint: use --force to overwrite (WARNING: invalidates pending approvals) "
            "or --key-file / --integrity-key-file to write to different paths.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(f"error: failed to generate key files: {exc}", file=sys.stderr)
        return 1

    pub = private_key.public_key()
    hex_str = public_key_hex(pub)
    pem_str = public_key_pem(pub)

    for _line in (
        "Ed25519 signing key and HMAC integrity key generated successfully.",
        f"  Signing key file:   {key_path}",
        f"  Integrity key file: {integrity_path}",
        f"  Issuer ID:          {opts.issuer_id}",
        "",
        "Public key (paste into gateway trusted_issuers):",
        f'  public_key_hex: "{hex_str}"',
        f'  issuer_id: "{opts.issuer_id}"',
        "",
        "PEM format:",
        pem_str,
        "Keep the key file readable ONLY by the approver process. The private key must NEVER be shared with the agent process.",
    ):
        print(_line, file=sys.stderr)
    return 0


def main_export_public_key(args: list[str] | None = None) -> int:
    """Print the public key and issuer ID for gateway configuration."""
    parser = argparse.ArgumentParser(
        prog="dmint export-public-key",
        formatter_class=DmintHelpFormatter,
        description="Print the Ed25519 public key and issuer ID for gateway trusted_issuers.",
        epilog="""Examples:
  dmint export-public-key
  dmint export-public-key --dir .dmint --format json
  dmint export-public-key --key-file .dmint/signing.key --format hex
""",
    )
    parser.add_argument(
        "--dir",
        "-d",
        dest="key_dir",
        default=None,
        help="Directory containing signing.key (e.g. .dmint)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help=f"Path to the private key file (default: .dmint/signing.key or {DEFAULT_KEY_FILE})",
    )
    parser.add_argument(
        "--issuer-id",
        default=os.environ.get("DMINT_ISSUER_ID", "dmint-authority"),
        help="Issuer ID label to display (default: dmint-authority)",
    )
    parser.add_argument(
        "--format",
        choices=["hex", "pem", "both", "json"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Shortcut for --format json",
    )
    try:
        opts = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    if opts.json:
        opts.format = "json"

    if opts.key_file:
        key_path = Path(opts.key_file).expanduser()
    elif opts.key_dir:
        key_path = Path(opts.key_dir).expanduser() / "signing.key"
    elif Path(".dmint/signing.key").exists() and not (Path.home() / ".config/dmint/signing.key").exists():
        key_path = Path(".dmint/signing.key")
    else:
        key_path = DEFAULT_KEY_FILE

    try:
        private_key = load_private_key_from_file(key_path)
    except KeyLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "Hint: run 'dmint init-keys' first to generate a signing key, or pass --key-file.",
            file=sys.stderr,
        )
        return 1

    pub = private_key.public_key()
    hex_str = public_key_hex(pub)
    pem_str = public_key_pem(pub)

    if opts.format == "hex":
        print(hex_str)
    elif opts.format == "pem":
        print(pem_str, end="")
    elif opts.format == "json":
        print(
            json.dumps(
                {
                    "issuer_id": opts.issuer_id,
                    "public_key_hex": hex_str,
                    "public_key_pem": pem_str.strip(),
                },
                indent=2,
            )
        )
    else:
        print(f"issuer_id:      {opts.issuer_id}")
        print(f"public_key_hex: {hex_str}")
        print()
        print("PEM format:")
        print(pem_str, end="")

    return 0
