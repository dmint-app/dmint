"""Ed25519 key management for Dmint approval authority.

This module handles:
- Atomic, permission-safe key file creation (0600, no group/other access).
- Strict key-file and parent-directory permission enforcement.
- Loading private keys from a file (preferred) or environment variable.
- Public key export in hex and PEM formats.
- Zero key material leakage in exceptions, reprs, or tracebacks.

The gateway (ApprovalVerifier) imports ONLY public-key helpers from this module.
Private-key loading functions are kept here and MUST NOT be imported by dmint.mcp.gateway.
"""

from __future__ import annotations

import os
import platform
import stat
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

__all__ = [
    # Paths
    "DEFAULT_KEY_DIR",
    "DEFAULT_KEY_FILE",
    # Public-key helpers (safe for gateway import)
    "public_key_hex",
    "public_key_pem",
    "public_key_from_hex",
    "public_key_from_pem",
    # Private-key management (authority process only)
    "check_key_file_permissions",
    "load_private_key_from_file",
    "load_private_key",
    "write_private_key_atomic",
]

DEFAULT_KEY_DIR = Path.home() / ".config" / "dmint"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "signing.key"
_PRIVATE_KEY_ENV = "DMINT_PRIVATE_KEY"
_KEY_FILE_ENV = "DMINT_KEY_FILE"
_POSIX = platform.system() != "Windows"

# ─── Public-key helpers ────────────────────────────────────────────────────────


def public_key_hex(public_key: Ed25519PublicKey) -> str:
    """Return the raw 32-byte Ed25519 public key as a lowercase hex string (64 chars)."""
    raw = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return raw.hex()


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    """Return the public key as a PEM-encoded SubjectPublicKeyInfo string."""
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    """Load an Ed25519PublicKey from a 64-char lowercase hex string.

    Raises ValueError on invalid input.
    """
    if not isinstance(hex_str, str) or len(hex_str) != 64:
        raise ValueError("public_key_hex must be a 64-character hex string")
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("public_key_hex contains non-hex characters") from exc
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_from_pem(pem_str: str) -> Ed25519PublicKey:
    """Load an Ed25519PublicKey from a PEM string.

    Raises ValueError on invalid input.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        key = load_pem_public_key(pem_str.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("PEM key is not an Ed25519 public key")
    return key


# ─── Permission checks ─────────────────────────────────────────────────────────


class KeyPermissionError(PermissionError):
    """Raised when key file or parent directory permissions are too loose."""


def check_key_file_permissions(path: Path) -> None:
    """Verify that the key file and its parent directory have safe permissions.

    Rules (POSIX only; on Windows, a warning is emitted but no error is raised):
      - Key file must NOT be readable/writable/executable by group or others
        (only modes 0600 and 0400 are accepted).
      - Parent directory must NOT be writable by group or others
        (group/world-writable parent could allow file replacement).

    Raises:
        KeyPermissionError: if any permission check fails.
        FileNotFoundError: if the path does not exist.
    """
    if not _POSIX:
        import warnings

        warnings.warn(
            "Key file permission checks are not enforced on non-POSIX systems.",
            stacklevel=2,
        )
        return

    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(f"key file does not exist: {path.name}")

    # --- Key file permissions ---
    try:
        file_stat = path.stat()
    except OSError as exc:
        raise KeyPermissionError("cannot stat key file") from exc

    file_mode = stat.S_IMODE(file_stat.st_mode)
    if file_mode & 0o077:  # any group or other bits set
        raise KeyPermissionError(
            f"key file has unsafe permissions {oct(file_mode)}; "
            "expected 0600 or 0400 (no group/other access). "
            f"Fix with: chmod 0600 {path.name}"
        )

    # --- Parent directory permissions ---
    parent = path.parent
    try:
        parent_stat = parent.stat()
    except OSError as exc:
        raise KeyPermissionError("cannot stat key file parent directory") from exc

    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    if parent_mode & 0o022:  # group-write or other-write
        raise KeyPermissionError(
            f"key file parent directory has unsafe permissions {oct(parent_mode)}; "
            "group-writable or world-writable parent directories allow key file replacement. "
            f"Fix with: chmod 755 {parent} or stricter."
        )


# ─── Private-key loading ───────────────────────────────────────────────────────


class KeyLoadError(RuntimeError):
    """Raised when a private key cannot be loaded.

    Key material is NEVER included in the message or attached cause.
    """


def load_private_key_from_file(path: Path | str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a file.

    The file must contain exactly 64 hex characters (the raw 32-byte key).

    Security:
        - Enforces strict file and parent-directory permissions on POSIX.
        - Never includes path contents, key material, or raw OS errors in
          the raised exception message.

    Raises:
        KeyLoadError: on any failure (bad permissions, bad format, missing file).
    """
    path = Path(path).resolve()

    # Permission check (raises KeyPermissionError which is a PermissionError
    # subclass — re-raise as KeyLoadError to unify the interface and avoid
    # leaking the path in chained exceptions).
    try:
        check_key_file_permissions(path)
    except FileNotFoundError:
        raise KeyLoadError("key file does not exist") from None
    except KeyPermissionError as exc:
        raise KeyLoadError(str(exc)) from None

    # Read file — suppress OS error details (they often contain the path).
    try:
        raw_text = path.read_text(encoding="ascii").strip()
    except Exception:
        raise KeyLoadError("failed to read key file") from None

    return _parse_private_key_hex(raw_text)


def load_private_key(
    key_file: Path | str | None = None,
    *,
    env_var: str = _PRIVATE_KEY_ENV,
) -> Ed25519PrivateKey:
    """Load a private key from a file (preferred) or environment variable.

    Resolution order:
      1. ``key_file`` argument (if given).
      2. ``DMINT_KEY_FILE`` environment variable.
      3. ``env_var`` (default ``DMINT_PRIVATE_KEY``) environment variable.

    Raises:
        KeyLoadError: if no key source is available or parsing fails.
    """
    # 1. Explicit file argument
    if key_file is not None:
        return load_private_key_from_file(key_file)

    # 2. DMINT_KEY_FILE env var -> file path
    env_key_file = os.environ.get(_KEY_FILE_ENV, "").strip()
    if env_key_file:
        return load_private_key_from_file(env_key_file)

    # 3. Inline hex env var (less secure — visible to same-user processes)
    hex_key = os.environ.get(env_var, "").strip()
    if hex_key:
        return _parse_private_key_hex(hex_key)

    raise KeyLoadError(
        f"no private key source found; set {_KEY_FILE_ENV} or {env_var}, or pass key_file to load_private_key()"
    )


def _parse_private_key_hex(hex_str: str) -> Ed25519PrivateKey:
    """Parse a 64-char hex string into an Ed25519PrivateKey.

    Raises KeyLoadError on invalid input without including the raw value.
    """
    if len(hex_str) != 64:
        raise KeyLoadError("private key must be exactly 64 hex characters (32 bytes)")
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        raise KeyLoadError("private key contains non-hex characters") from None
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise KeyLoadError("invalid Ed25519 private key bytes") from None


# ─── Atomic key-file creation ──────────────────────────────────────────────────


class KeyExistsError(FileExistsError):
    """Raised by write_private_key_atomic when the key file already exists and force=False."""


def write_private_key_atomic(
    path: Path | str,
    private_key: Ed25519PrivateKey,
    *,
    force: bool = False,
) -> None:
    """Write an Ed25519 private key to a file atomically with mode 0600.

    The file is first written to a sibling temporary file (in the same
    directory) and then atomically renamed into place, so there is never
    a window during which the key file is world-readable.

    Args:
        path: Destination file path.
        private_key: The Ed25519 private key to persist.
        force: If True, overwrite an existing file.  If False (default),
               raise KeyExistsError when the file already exists.

    Raises:
        KeyExistsError: if the file exists and force=False.
        OSError: on filesystem errors (permission denied, disk full, etc.).
    """
    path = Path(path).resolve()

    if path.exists() and not force:
        raise KeyExistsError(
            "key file already exists; pass --force to overwrite. "
            "Overwriting rotates the signing key — any pending approvals "
            "signed with the old key will be rejected."
        )

    # Ensure parent directory exists.
    path.parent.mkdir(parents=True, exist_ok=True)

    # Extract raw 32-byte private key as hex (64 chars).
    raw_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    hex_content = raw_bytes.hex() + "\n"

    # Write to a temp file in the same directory (same filesystem for atomic rename).
    try:
        fd, tmp_path_str = tempfile.mkstemp(dir=path.parent, prefix=".dmint_key_tmp_")
        tmp_path = Path(tmp_path_str)
        try:
            # Set 0600 BEFORE writing key material.
            if _POSIX:
                os.chmod(fd, 0o600)
            os.write(fd, hex_content.encode("ascii"))
        finally:
            os.close(fd)
        # Atomic rename — replaces destination if force=True.
        tmp_path.replace(path)
    except Exception:
        # Clean up the temp file on failure.
        try:
            Path(tmp_path_str).unlink(missing_ok=True)
        except Exception:
            pass
        raise

    # Final permission set (in case the rename destination had other perms).
    if _POSIX:
        path.chmod(0o600)
