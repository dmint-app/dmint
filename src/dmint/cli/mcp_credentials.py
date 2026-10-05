"""Secure MCP credential storage for Dmint CLI with OS Keyring and hardened file fallback."""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import json
import logging
import os
from pathlib import Path
import tempfile
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from dmint.cli.errors import CLIError
from dmint.cli.limits import MAX_CREDENTIAL_FILE_SIZE_BYTES, MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES
from dmint.cli.mcp_connections import redact_secrets, redact_text
from dmint.cli.version import get_user_agent

logger = logging.getLogger(__name__)

KEYRING_SERVICE_NAME = "dmint-mcp-credentials"
DEFAULT_CREDENTIAL_FILE = Path.home() / ".config" / "dmint" / "credentials.json"


def normalize_resource_url(url_str: str) -> str:
    """Canonicalize a resource URL for server identity binding."""
    if not url_str or not isinstance(url_str, str):
        return ""
    parsed = urllib.parse.urlparse(url_str.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip standard default ports
    if ":" in netloc:
        host, port = netloc.split(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host

    path = parsed.path.rstrip("/")
    return urllib.parse.urlunparse((scheme, netloc, path, "", "", ""))


def canonical_server_identity(
    resource_url: str,
    *,
    issuer: str | None = None,
    client_id: str | None = None,
    integration_id: str | None = None,
) -> str:
    """Build a canonical, strongly bound compound server identity key.

    Key structure:
    canonical_url[#issuer][@client_id][::integration_id]
    """
    canonical_url = normalize_resource_url(resource_url)
    parts = [canonical_url]

    if issuer:
        norm_issuer = normalize_resource_url(issuer)
        parts.append(f"#{norm_issuer}")
    if client_id:
        parts.append(f"@{client_id.strip()}")
    if integration_id:
        parts.append(f"::{integration_id.strip()}")

    return "".join(parts)


def is_keyring_available() -> bool:
    """Detect if a functional OS Keyring backend is available."""
    try:
        import keyring

        backend = keyring.get_keyring()
        name = backend.__class__.__name__.lower()
        if "fail" in name or "null" in name or "disabled" in name:
            return False
        return True
    except Exception:
        return False


def _check_symlink_safety(path: Path) -> None:
    """Ensure path and parent components are not symlinks (anti-symlink attack)."""
    try:
        if path.is_symlink() or os.path.islink(path):
            raise CLIError(
                f"Security violation: credential path '{path}' is a symbolic link. "
                "Symlinks are rejected to prevent symlink attacks."
            )
        # Check all parent directories up to root
        curr = path.parent
        while curr and curr != curr.parent:
            if curr.is_symlink() or os.path.islink(curr):
                raise CLIError(
                    f"Security violation: parent directory '{curr}' of credential file is a symbolic link. "
                    "Symlinks are rejected to prevent symlink attacks."
                )
            curr = curr.parent
    except OSError as exc:
        raise CLIError(f"Filesystem safety check failed for '{path}': {exc}") from exc


class FileLock:
    """Advisory file lock using fcntl.flock to serialize concurrent credential writers."""

    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self._fd: int | None = None

    def __enter__(self) -> FileLock:
        _check_symlink_safety(self.lock_path)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._fd = os.open(self.lock_path, flags, 0o600)
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


@dataclass
class TokenRecord:
    """OAuth token record with expiration tracking, identity binding, and secret redaction."""

    server_identity: str
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_at: float | None = None
    issued_at: float = field(default_factory=time.time)
    issuer: str | None = None
    client_id: str | None = None

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        # 30-second safety window to prevent edge-of-expiry race conditions
        return time.time() >= (self.expires_at - 30.0)

    def __repr__(self) -> str:
        safe_acc = "<redacted>" if self.access_token else None
        safe_ref = "<redacted>" if self.refresh_token else None
        return (
            f"TokenRecord(server_identity={self.server_identity!r}, "
            f"access_token={safe_acc!r}, refresh_token={safe_ref!r}, "
            f"expires_at={self.expires_at}, is_expired={self.is_expired})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_identity": self.server_identity,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "client_id": self.client_id,
        }

    def to_safe_dict(self) -> dict[str, Any]:
        d = self.to_dict()
        return redact_secrets(d)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenRecord:
        if not isinstance(data, dict) or "server_identity" not in data or "access_token" not in data:
            raise CLIError("Corrupted token record format.")
        return cls(
            server_identity=data["server_identity"],
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_at=data.get("expires_at"),
            issued_at=data.get("issued_at", time.time()),
            issuer=data.get("issuer"),
            client_id=data.get("client_id"),
        )


class CredentialStore:
    """Secure credential store supporting OS Keyring and strict atomic file permission storage (0600)."""

    def __init__(
        self,
        storage_path: Path | str | None = None,
        use_keyring: bool = True,
        backend: str = "auto",  # "auto", "keyring", "file"
        allow_file_fallback: bool = True,
    ):
        raw_path = Path(os.path.abspath(str(storage_path or DEFAULT_CREDENTIAL_FILE)))
        _check_symlink_safety(raw_path)
        self.storage_path = raw_path
        if not use_keyring or backend == "file":
            self.backend = "file"
        elif backend == "keyring":
            self.backend = "keyring"
        else:
            self.backend = "auto"
        self.allow_file_fallback = allow_file_fallback

    def _get_keyring(self) -> Any | None:
        if self.backend == "file":
            return None
        try:
            import keyring

            return keyring
        except Exception:
            return None

    def save(
        self,
        server_identity: str,
        tokens: dict[str, Any],
        *,
        issuer: str | None = None,
        client_id: str | None = None,
    ) -> TokenRecord:
        """Save tokens bound to server_identity and optional issuer."""
        if not server_identity or not isinstance(server_identity, str) or not server_identity.strip():
            raise CLIError("server_identity must be a non-empty string.")

        access_token = tokens.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise CLIError("Cannot save credentials: missing access_token in token payload.")

        expires_in = tokens.get("expires_in")
        raw_expires_at = tokens.get("expires_at")
        if expires_in is not None:
            expires_at: float | None = time.time() + float(expires_in)
        elif raw_expires_at is not None:
            expires_at = float(raw_expires_at)
        else:
            expires_at = None

        rec_issuer = issuer or tokens.get("issuer")
        rec_client_id = client_id or tokens.get("client_id")

        record = TokenRecord(
            server_identity=server_identity.strip(),
            access_token=access_token,
            refresh_token=tokens.get("refresh_token"),
            token_type=tokens.get("token_type", "Bearer"),
            expires_at=expires_at,
            issuer=rec_issuer,
            client_id=rec_client_id,
        )

        # 1. Explicit Keyring backend requested
        if self.backend == "keyring":
            if not is_keyring_available():
                raise CLIError(
                    "OS Keyring was requested but is not available on this system. "
                    "Refusing to silently downgrade to file storage. "
                    "Configure backend='file' or backend='auto' to permit secure file storage."
                )
            kr = self._get_keyring()
            if kr is not None:
                try:
                    kr.set_password(KEYRING_SERVICE_NAME, server_identity, json.dumps(record.to_dict()))
                    return record
                except Exception as exc:
                    raise CLIError(
                        f"Failed to write credentials to OS Keyring: {exc}. Refusing to silently downgrade."
                    ) from exc

        # 2. Auto backend
        if self.backend == "auto":
            if is_keyring_available():
                kr = self._get_keyring()
                if kr is not None:
                    try:
                        kr.set_password(KEYRING_SERVICE_NAME, server_identity, json.dumps(record.to_dict()))
                        return record
                    except Exception as exc:
                        if not self.allow_file_fallback:
                            raise CLIError(f"OS Keyring write failed ({exc}) and file fallback is disabled.") from exc
            elif not self.allow_file_fallback:
                raise CLIError("OS Keyring is unavailable and file fallback is disabled.")

        # 3. Secure file storage fallback
        self._write_file_record(record)
        return record

    def load(
        self,
        server_identity: str,
        *,
        issuer: str | None = None,
        strict: bool = False,
    ) -> TokenRecord | None:
        """Load TokenRecord bound to server_identity with optional issuer validation."""
        if not server_identity:
            return None

        # Try keyring first if applicable
        if self.backend in ("auto", "keyring"):
            kr = self._get_keyring()
            if kr:
                try:
                    raw = kr.get_password(KEYRING_SERVICE_NAME, server_identity)
                    if raw:
                        rec = TokenRecord.from_dict(json.loads(raw))
                        if issuer and rec.issuer and rec.issuer != issuer:
                            return None
                        return rec
                except Exception as exc:
                    if self.backend == "keyring":
                        raise CLIError(f"Failed to read from OS Keyring: {exc}") from exc

        # Load from file storage
        records = self._read_file_records(strict=strict)
        raw_data = records.get(server_identity)
        if raw_data and isinstance(raw_data, dict):
            try:
                rec = TokenRecord.from_dict(raw_data)
                if issuer and rec.issuer and rec.issuer != issuer:
                    return None
                return rec
            except Exception as exc:
                if strict:
                    raise CLIError(f"Corrupted token record for '{server_identity}': {exc}") from exc
                return None
        return None

    def save_client_info(self, server_identity: str, client_info: dict[str, Any]) -> None:
        """Persist dynamic client registration info for an authorization server identity."""
        if not server_identity or not isinstance(server_identity, str) or not server_identity.strip():
            raise CLIError("server_identity must be a non-empty string.")

        lock_path = self.storage_path.parent / f"{self.storage_path.name}.lock"
        with FileLock(lock_path):
            records = self._read_file_records(strict=True)
            records[f"{server_identity.strip()}::client_info"] = client_info
            self._write_all_file_records(records)

    def load_client_info(self, server_identity: str, strict: bool = False) -> dict[str, Any] | None:
        """Load stored dynamic client registration info for a server identity."""
        if not server_identity:
            return None
        records = self._read_file_records(strict=strict)
        data = records.get(f"{server_identity.strip()}::client_info")
        return data if isinstance(data, dict) else None

    def delete(self, server_identity: str) -> None:
        """Delete credentials and client info for server_identity (logout)."""
        kr = self._get_keyring()
        if kr:
            try:
                kr.delete_password(KEYRING_SERVICE_NAME, server_identity)
            except Exception:
                pass

        lock_path = self.storage_path.parent / f"{self.storage_path.name}.lock"
        with FileLock(lock_path):
            records = self._read_file_records(strict=False)
            changed = False
            if server_identity in records:
                del records[server_identity]
                changed = True
            client_key = f"{server_identity}::client_info"
            if client_key in records:
                del records[client_key]
                changed = True
            if changed:
                self._write_all_file_records(records)

    def logout(self, server_identity: str) -> None:
        """Explicit logout semantic: alias for delete()."""
        self.delete(server_identity)

    def clear(self) -> None:
        """Clear all stored credentials and delete the store file (logout all)."""
        records = self._read_file_records(strict=False)
        kr = self._get_keyring()
        if kr:
            for s_id in list(records.keys()):
                try:
                    kr.delete_password(KEYRING_SERVICE_NAME, s_id)
                except Exception:
                    pass

        lock_path = self.storage_path.parent / f"{self.storage_path.name}.lock"
        with FileLock(lock_path):
            if self.storage_path.exists():
                try:
                    self.storage_path.unlink()
                except OSError:
                    pass

    def logout_all(self) -> None:
        """Explicit logout all semantic: alias for clear()."""
        self.clear()

    def validate_store(self) -> None:
        """Check store integrity; raises CLIError if file is corrupted."""
        self._read_file_records(strict=True)

    def _read_file_records(self, strict: bool = False) -> dict[str, Any]:
        if not self.storage_path.exists():
            return {}

        _check_symlink_safety(self.storage_path)

        try:
            if hasattr(os, "stat"):
                st = os.stat(self.storage_path)
                if st.st_size > MAX_CREDENTIAL_FILE_SIZE_BYTES:
                    raise CLIError(
                        f"Resource exhaustion error: Credential file '{self.storage_path}' size ({st.st_size} bytes) "
                        f"exceeds maximum allowed limit of {MAX_CREDENTIAL_FILE_SIZE_BYTES} bytes."
                    )
                mode = st.st_mode & 0o777
                if mode & 0o077:  # World or group readable
                    os.chmod(self.storage_path, 0o600)

            content = self.storage_path.read_text(encoding="utf-8")
            if not content.strip():
                return {}
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("Credential file content must be a JSON object.")
            return data
        except CLIError:
            raise
        except Exception as exc:
            msg = (
                f"Credential file '{self.storage_path}' is corrupted: {exc}. "
                f"Manual recovery guidance: Inspect the file, restore it from backup, "
                f"or remove it manually (e.g. `rm '{self.storage_path}'`) before continuing."
            )
            logger.warning(msg)
            if strict:
                raise CLIError(msg) from exc
            return {}

    def _write_file_record(self, record: TokenRecord) -> None:
        lock_path = self.storage_path.parent / f"{self.storage_path.name}.lock"
        with FileLock(lock_path):
            records = self._read_file_records(strict=True)
            records[record.server_identity] = record.to_dict()
            self._write_all_file_records(records)

    def _write_all_file_records(self, records: dict[str, Any]) -> None:
        """Atomic file write with tempfile, fchmod 0600, fsync, and atomic replace."""
        _check_symlink_safety(self.storage_path)

        parent_dir = self.storage_path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "chmod"):
            try:
                os.chmod(parent_dir, 0o700)
            except OSError:
                pass

        content = json.dumps(records, indent=2).encode("utf-8")

        # 1. Create temporary file in the same directory
        temp_prefix = f".{self.storage_path.name}.tmp."
        temp_fd, temp_path = tempfile.mkstemp(prefix=temp_prefix, dir=parent_dir)
        closed = False
        try:
            # 2. Strict mode 0600 on file descriptor
            if hasattr(os, "fchmod"):
                os.fchmod(temp_fd, 0o600)
            else:
                os.chmod(temp_path, 0o600)

            # 3. Write data
            os.write(temp_fd, content)

            # 4. Flush kernel cache to disk
            os.fsync(temp_fd)
            os.close(temp_fd)
            closed = True

            # 5. Verify symlink safety before replacement
            _check_symlink_safety(self.storage_path)

            # 6. Atomic replacement
            os.replace(temp_path, self.storage_path)
        except Exception as exc:
            if not closed:
                os.close(temp_fd)
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise CLIError(f"Failed to write credentials file: {exc}") from exc


def refresh_token(
    record: TokenRecord,
    token_endpoint: str,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    credential_store: CredentialStore | None = None,
) -> TokenRecord:
    """Perform RFC 6749 token refresh using the stored refresh_token."""
    if not record.refresh_token:
        raise CLIError("Cannot refresh token: no refresh_token available in record.")

    payload: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": record.refresh_token,
    }
    if client_id:
        payload["client_id"] = client_id
    if client_secret:
        payload["client_secret"] = client_secret

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        token_endpoint,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": get_user_agent()},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            raw_bytes = resp.read(MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES + 1)
            if len(raw_bytes) > MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES:
                raise CLIError(
                    f"Resource exhaustion error: token refresh response exceeded "
                    f"maximum allowed size of {MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES} bytes."
                )
            data = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(data, dict) or "access_token" not in data:
                raise CLIError("Token refresh response missing access_token.")
            if "refresh_token" not in data and record.refresh_token:
                data["refresh_token"] = record.refresh_token
            store = credential_store or CredentialStore()
            new_record = store.save(
                record.server_identity,
                data,
                issuer=record.issuer,
                client_id=record.client_id or client_id,
            )
            return new_record
    except CLIError:
        raise
    except Exception as exc:
        msg = str(exc)
        if record.refresh_token:
            msg = msg.replace(record.refresh_token, "<redacted>")
        if record.access_token:
            msg = msg.replace(record.access_token, "<redacted>")
        if client_secret:
            msg = msg.replace(client_secret, "<redacted>")
        safe_msg = redact_text(msg)
        raise CLIError(f"Token refresh failed: {safe_msg}") from exc
