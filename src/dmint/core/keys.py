"""Ed25519 key management for Dmint approval authority.

This module handles:
- Atomic, permission-safe key file creation (0600, no group/other access).
- Strict key-file and parent-directory permission enforcement using O_NOFOLLOW + fstat(fd).
- Enforcing file ownership matches current effective UID (st_uid == os.geteuid()).
- Safe loading of private keys from a file (preferred) or opt-in environment variable.
- Non-POSIX fail-closed enforcement (requires DMINT_ALLOW_INSECURE_KEY_PERMISSIONS=1).
- Public-key export (re-exported from .verification).

The gateway (ApprovalVerifier) imports ONLY from dmint.core.verification.
This module is strictly for the authority/signer process.
"""

from __future__ import annotations

import os
import platform
import stat
import tempfile
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

# Re-export public-key helpers from verification module
from .verification import (
    public_key_from_hex,
    public_key_from_pem,
    public_key_hex,
    public_key_pem,
)

__all__ = [
    # Paths
    "DEFAULT_KEY_DIR",
    "DEFAULT_KEY_FILE",
    # Public-key helpers (safe for gateway import via .verification)
    "public_key_hex",
    "public_key_pem",
    "public_key_from_hex",
    "public_key_from_pem",
    # Private-key management (authority process only)
    "check_key_file_permissions",
    "load_private_key_from_file",
    "load_private_key",
    "write_private_key_atomic",
    "KeyExistsError",
    "KeyLoadError",
    "KeyPermissionError",
]

DEFAULT_KEY_DIR = Path.home() / ".config" / "dmint"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "signing.key"
_PRIVATE_KEY_ENV = "DMINT_PRIVATE_KEY"
_KEY_FILE_ENV = "DMINT_KEY_FILE"
_ALLOW_INLINE_KEY_ENV = "DMINT_ALLOW_INLINE_KEY"
_ALLOW_INSECURE_PERMS_ENV = "DMINT_ALLOW_INSECURE_KEY_PERMISSIONS"
_POSIX = platform.system() != "Windows"


from .errors import (
    KeyExistsError,
    KeyLoadError,
    KeyPermissionError,
)


def _check_parent_dir_permissions(parent: Path) -> None:
    """Verify that the key file parent directory has safe permissions."""
    try:
        parent_stat = parent.stat()
    except OSError:
        raise KeyLoadError("cannot stat key file parent directory") from None

    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    if parent_mode & 0o022:
        raise KeyPermissionError(
            f"key file parent directory has unsafe permissions {oct(parent_mode)}; "
            "group-writable or world-writable parent directories allow key file replacement. "
            f"Fix with: chmod 755 {parent} or stricter."
        )


def check_key_file_permissions(path: Path | str) -> None:
    """Public helper to verify key file and parent directory permissions.

    On POSIX: checks mode 0600/0400, ownership by geteuid(), and parent directory.
    On non-POSIX: fails closed unless DMINT_ALLOW_INSECURE_KEY_PERMISSIONS=1 is set.
    """
    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"key file does not exist: {path.name}")

    if not _POSIX:
        if os.environ.get(_ALLOW_INSECURE_PERMS_ENV, "").lower() not in ("1", "true", "yes"):
            raise KeyPermissionError(
                "Key file permission enforcement is not supported on non-POSIX platforms; "
                f"set {_ALLOW_INSECURE_PERMS_ENV}=1 or pass --allow-insecure-key-permissions to proceed."
            )
        return

    _check_parent_dir_permissions(path.parent)

    try:
        file_stat = path.stat()
    except OSError as exc:
        raise KeyPermissionError("cannot stat key file") from exc

    if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
        raise KeyPermissionError(
            f"key file owner UID {file_stat.st_uid} does not match current process UID {os.geteuid()}"
        )

    file_mode = stat.S_IMODE(file_stat.st_mode)
    if file_mode & 0o077:
        raise KeyPermissionError(
            f"key file has unsafe permissions {oct(file_mode)}; "
            "expected 0600 or 0400 (no group/other access). "
            f"Fix with: chmod 0600 {path.name}"
        )


def load_private_key_from_file(
    path: Path | str,
    *,
    allow_insecure_permissions: bool = False,
) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a file using secure descriptor operations.

    Security guarantees:
      - Opens with O_RDONLY | O_NOFOLLOW (refuses symlinks).
      - fstat(fd) on the open descriptor (eliminates TOCTOU stat-then-open race).
      - Checks st_uid == geteuid() (must be owned by the running process user).
      - Checks file mode (must be 0600 or 0400, no group/other access).
      - Checks parent directory permissions (must not be group/world-writable).
      - Fails closed on non-POSIX platforms unless allow_insecure_permissions or
        DMINT_ALLOW_INSECURE_KEY_PERMISSIONS=1 is set.
      - Never includes path contents or key material in exceptions.

    Raises:
        KeyLoadError: on any failure (bad permissions, symlink, bad format, missing file).
    """
    path = Path(path)

    # 1. Non-POSIX check
    if not _POSIX:
        env_allowed = os.environ.get(_ALLOW_INSECURE_PERMS_ENV, "").lower() in ("1", "true", "yes")
        if not (allow_insecure_permissions or env_allowed):
            raise KeyLoadError(
                "Key file permission enforcement is not supported on non-POSIX platforms; "
                f"set {_ALLOW_INSECURE_PERMS_ENV}=1 or pass --allow-insecure-key-permissions to allow."
            )
        try:
            raw_text = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            raise KeyLoadError("key file does not exist") from None
        except Exception:
            raise KeyLoadError("failed to read key file") from None
        return _parse_private_key_hex(raw_text)

    # 2. Check parent directory permissions
    try:
        parent = path.resolve().parent
        _check_parent_dir_permissions(parent)
    except KeyPermissionError as exc:
        raise KeyLoadError(str(exc)) from None
    except Exception:
        raise KeyLoadError("cannot verify key file parent directory") from None

    # 3. Open with O_RDONLY | O_NOFOLLOW | O_CLOEXEC (no TOCTOU race, rejects symlinks)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        raise KeyLoadError("key file does not exist") from None
    except OSError as exc:
        import errno

        if exc.errno == errno.ELOOP or os.path.islink(path):
            raise KeyLoadError("key file is a symlink; symlinks are rejected for security") from None
        raise KeyLoadError("cannot open key file") from None

    try:
        # 4. fstat the opened fd directly
        file_stat = os.fstat(fd)

        if not stat.S_ISREG(file_stat.st_mode):
            raise KeyLoadError("key file is not a regular file")

        # Ownership check: must match current process effective UID
        if hasattr(os, "geteuid"):
            current_uid = os.geteuid()
            if file_stat.st_uid != current_uid:
                raise KeyLoadError(
                    f"key file owner UID {file_stat.st_uid} does not match current process UID {current_uid}; "
                    "key files must be owned by the running process user"
                )

        # Mode check: no group or other access
        file_mode = stat.S_IMODE(file_stat.st_mode)
        if file_mode & 0o077:
            raise KeyLoadError(
                f"key file has unsafe permissions {oct(file_mode)}; "
                "expected 0600 or 0400 (no group/other access). "
                f"Fix with: chmod 0600 {path.name}"
            )

        # 5. Read from the verified open fd
        raw_bytes = os.read(fd, 256)
    finally:
        os.close(fd)

    try:
        raw_text = raw_bytes.decode("ascii").strip()
    except Exception:
        raise KeyLoadError("failed to decode key file content") from None

    return _parse_private_key_hex(raw_text)


def load_private_key(
    key_file: Path | str | None = None,
    *,
    env_var: str = _PRIVATE_KEY_ENV,
    allow_inline_key: bool = False,
    allow_insecure_permissions: bool = False,
) -> Ed25519PrivateKey:
    """Load a private key from a file (preferred) or opt-in environment variable.

    Resolution order:
      1. ``key_file`` argument (if given).
      2. ``DMINT_KEY_FILE`` environment variable.
      3. ``DEFAULT_KEY_FILE`` (~/.config/dmint/signing.key) if it exists.
      4. ``env_var`` (default ``DMINT_PRIVATE_KEY``) inline hex ONLY IF
         explicitly opted-in via allow_inline_key or DMINT_ALLOW_INLINE_KEY=1.

    Raises:
        KeyLoadError: if no key source is available, opt-in is missing, or parsing fails.
    """
    # 1. Explicit file argument
    if key_file is not None:
        return load_private_key_from_file(key_file, allow_insecure_permissions=allow_insecure_permissions)

    # 2. DMINT_KEY_FILE env var -> file path
    env_key_file = os.environ.get(_KEY_FILE_ENV, "").strip()
    if env_key_file:
        return load_private_key_from_file(env_key_file, allow_insecure_permissions=allow_insecure_permissions)

    # 3. Default config directory key file if present
    if DEFAULT_KEY_FILE.exists():
        return load_private_key_from_file(DEFAULT_KEY_FILE, allow_insecure_permissions=allow_insecure_permissions)

    # 4. Inline hex env var: OPT-IN ONLY with security warning
    hex_key = os.environ.get(env_var, "").strip()
    if hex_key:
        opted_in = allow_inline_key or os.environ.get(_ALLOW_INLINE_KEY_ENV, "").lower() in ("1", "true", "yes")
        if not opted_in:
            raise KeyLoadError(
                f"{env_var} contains inline private key material, which is exposed to "
                "same-user processes via /proc/<pid>/environ. To use inline keys, explicitly "
                f"opt-in by setting {_ALLOW_INLINE_KEY_ENV}=1."
            )
        warnings.warn(
            f"{env_var} contains inline private key material visible in process environment. "
            "Use a restricted key file (mode 0600) instead.",
            UserWarning,
            stacklevel=2,
        )
        return _parse_private_key_hex(hex_key)

    raise KeyLoadError(
        f"no private key source found; an Ed25519 signing key must be provided via key_file, "
        f"{_KEY_FILE_ENV}, or generated with 'dmint init-keys'."
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


def write_private_key_atomic(
    path: Path | str,
    private_key: Ed25519PrivateKey,
    *,
    force: bool = False,
    allow_insecure_permissions: bool = False,
) -> None:
    """Write an Ed25519 private key to a file atomically with mode 0600.

    The file is first written to a sibling temporary file (in the same
    directory) and then atomically renamed into place, so there is never
    a window during which the key file is world-readable.

    Args:
        path: Destination file path.
        private_key: The Ed25519 private key to persist.
        force: If True, overwrite an existing file. If False (default),
               raise KeyExistsError when the file already exists.
        allow_insecure_permissions: If True on non-POSIX, bypass permission enforcement.

    Raises:
        KeyExistsError: if the file exists and force=False.
        KeyPermissionError: if non-POSIX without opt-in.
        OSError: on filesystem errors.
    """
    path = Path(path).resolve()

    if not _POSIX:
        env_allowed = os.environ.get(_ALLOW_INSECURE_PERMS_ENV, "").lower() in ("1", "true", "yes")
        if not (allow_insecure_permissions or env_allowed):
            raise KeyPermissionError(
                "Key file permission enforcement is not supported on non-POSIX platforms; "
                f"set {_ALLOW_INSECURE_PERMS_ENV}=1 or pass --allow-insecure-key-permissions to allow."
            )

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
