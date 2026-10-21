"""Tests for dmint.core.keys — Ed25519 key management, permission checks, atomic writes."""

from __future__ import annotations

import os
import platform
import stat
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from dmint.core.keys import (
    KeyExistsError,
    KeyLoadError,
    KeyPermissionError,
    check_key_file_permissions,
    load_private_key,
    load_private_key_from_file,
    public_key_from_hex,
    public_key_from_pem,
    public_key_hex,
    public_key_pem,
    write_private_key_atomic,
)

IS_POSIX = platform.system() != "Windows"
posix_only = pytest.mark.skipif(not IS_POSIX, reason="POSIX-only permission tests")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _gen_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _write_hex_key(path: Path, private_key: Ed25519PrivateKey, mode: int = 0o600) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    raw = private_key.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    path.write_text(raw.hex() + "\n", encoding="ascii")
    if IS_POSIX:
        path.chmod(mode)


# ─── public_key_hex / public_key_pem round-trips ─────────────────────────────


class TestPublicKeyExport:
    def test_hex_is_64_chars(self) -> None:
        key = _gen_key()
        hex_str = public_key_hex(key.public_key())
        assert len(hex_str) == 64
        assert hex_str == hex_str.lower()

    def test_pem_starts_with_header(self) -> None:
        key = _gen_key()
        pem_str = public_key_pem(key.public_key())
        assert pem_str.startswith("-----BEGIN PUBLIC KEY-----")

    def test_hex_roundtrip(self) -> None:
        key = _gen_key()
        pub = key.public_key()
        hex_str = public_key_hex(pub)
        recovered = public_key_from_hex(hex_str)
        assert isinstance(recovered, Ed25519PublicKey)
        assert public_key_hex(recovered) == hex_str

    def test_pem_roundtrip(self) -> None:
        key = _gen_key()
        pub = key.public_key()
        pem_str = public_key_pem(pub)
        recovered = public_key_from_pem(pem_str)
        assert isinstance(recovered, Ed25519PublicKey)
        assert public_key_hex(recovered) == public_key_hex(pub)

    def test_hex_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="64-character"):
            public_key_from_hex("aabb")

    def test_hex_bad_chars_raises(self) -> None:
        with pytest.raises(ValueError):
            public_key_from_hex("z" * 64)

    def test_pem_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid PEM"):
            public_key_from_pem("not a pem")


# ─── write_private_key_atomic ─────────────────────────────────────────────────


class TestWritePrivateKeyAtomic:
    def test_creates_file(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        assert dest.exists()

    @posix_only
    def test_creates_with_0600(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        mode = stat.S_IMODE(dest.stat().st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_content_is_valid_hex(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        content = dest.read_text(encoding="ascii").strip()
        assert len(content) == 64
        bytes.fromhex(content)  # must not raise

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        with pytest.raises(KeyExistsError, match="already exists"):
            write_private_key_atomic(dest, key, force=False)

    def test_allows_overwrite_with_force(self, tmp_path: Path) -> None:
        key1 = _gen_key()
        key2 = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key1)
        write_private_key_atomic(dest, key2, force=True)
        content = dest.read_text(encoding="ascii").strip()
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        raw2 = key2.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        assert content == raw2.hex()

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "nested" / "deep" / "signing.key"
        write_private_key_atomic(dest, key)
        assert dest.exists()

    def test_round_trip_key_matches(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        loaded = load_private_key_from_file(dest)
        assert public_key_hex(loaded.public_key()) == public_key_hex(key.public_key())


# ─── check_key_file_permissions ───────────────────────────────────────────────


@posix_only
class TestCheckKeyFilePermissions:
    def test_0600_passes(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o600)
        check_key_file_permissions(dest)  # must not raise

    def test_0400_passes(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o400)
        check_key_file_permissions(dest)  # must not raise

    def test_0644_raises(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o644)
        with pytest.raises(KeyPermissionError, match="unsafe permissions"):
            check_key_file_permissions(dest)

    def test_0660_raises(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o660)
        with pytest.raises(KeyPermissionError, match="unsafe permissions"):
            check_key_file_permissions(dest)

    def test_0755_raises(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o755)
        with pytest.raises(KeyPermissionError, match="unsafe permissions"):
            check_key_file_permissions(dest)

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            check_key_file_permissions(tmp_path / "missing.key")

    def test_parent_dir_group_writable_raises(self, tmp_path: Path) -> None:
        # Create a subdirectory that is group-writable
        subdir = tmp_path / "gwdir"
        subdir.mkdir(mode=0o775)
        subdir.chmod(0o775)
        key = _gen_key()
        dest = subdir / "signing.key"
        _write_hex_key(dest, key, mode=0o600)
        with pytest.raises(KeyPermissionError, match="parent directory"):
            check_key_file_permissions(dest)

    def test_parent_dir_world_writable_raises(self, tmp_path: Path) -> None:
        subdir = tmp_path / "wwdir"
        subdir.mkdir(mode=0o777)
        subdir.chmod(0o777)
        key = _gen_key()
        dest = subdir / "signing.key"
        _write_hex_key(dest, key, mode=0o600)
        with pytest.raises(KeyPermissionError, match="parent directory"):
            check_key_file_permissions(dest)

    def test_parent_dir_0700_passes(self, tmp_path: Path) -> None:
        subdir = tmp_path / "private"
        subdir.mkdir(mode=0o700)
        key = _gen_key()
        dest = subdir / "signing.key"
        _write_hex_key(dest, key, mode=0o600)
        check_key_file_permissions(dest)  # must not raise

    def test_parent_dir_wrong_owner_raises(self, tmp_path: Path) -> None:
        """Parent directory not owned by current euid or root must be rejected."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o600)
        with patch("os.geteuid", return_value=os.geteuid() + 5000):
            with pytest.raises(KeyPermissionError, match="parent directory owner UID"):
                check_key_file_permissions(dest)

    def test_parent_dir_root_owned_passes(self, tmp_path: Path) -> None:
        """Parent directory owned by root (UID 0) must pass when process is non-root."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o600)

        real_stat = dest.parent.stat()

        class FakeStat:
            st_uid = 0
            st_mode = real_stat.st_mode

        parent_str = str(dest.parent.resolve())

        orig_stat = Path.stat

        def fake_stat(self_path: Path) -> Any:
            try:
                if str(self_path) == parent_str:
                    return FakeStat()
            except Exception:
                pass
            return orig_stat(self_path)

        with patch.object(Path, "stat", fake_stat):
            check_key_file_permissions(dest)  # must not raise


# ─── load_private_key_from_file ───────────────────────────────────────────────


class TestLoadPrivateKeyFromFile:
    def test_loads_valid_key(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        loaded = load_private_key_from_file(dest)
        assert isinstance(loaded, Ed25519PrivateKey)

    def test_missing_file_raises_key_load_error(self, tmp_path: Path) -> None:
        with pytest.raises(KeyLoadError, match="does not exist"):
            load_private_key_from_file(tmp_path / "missing.key")

    @posix_only
    def test_loose_permissions_raises_key_load_error(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o644)
        with pytest.raises(KeyLoadError, match="unsafe permissions"):
            load_private_key_from_file(dest)

    def test_bad_hex_content_raises_key_load_error(self, tmp_path: Path) -> None:
        dest = tmp_path / "signing.key"
        dest.write_text("not_hex_at_all_12345\n", encoding="ascii")
        if IS_POSIX:
            dest.chmod(0o600)
        with pytest.raises(KeyLoadError):
            load_private_key_from_file(dest)

    def test_wrong_length_raises_key_load_error(self, tmp_path: Path) -> None:
        dest = tmp_path / "signing.key"
        dest.write_text("deadbeef\n", encoding="ascii")
        if IS_POSIX:
            dest.chmod(0o600)
        with pytest.raises(KeyLoadError, match="64 hex characters"):
            load_private_key_from_file(dest)

    def test_no_key_material_in_exception(self, tmp_path: Path) -> None:
        """Exception messages must never contain private key hex material."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o644 if IS_POSIX else 0o600)
        try:
            load_private_key_from_file(dest)
        except KeyLoadError as exc:
            # The exception must not contain any hex resembling the key
            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

            raw = key.private_bytes(
                encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
            )
            key_hex = raw.hex()
            assert key_hex not in str(exc)
        else:
            pytest.fail("Expected KeyLoadError was not raised")

    @posix_only
    def test_symlink_key_file_is_rejected(self, tmp_path: Path) -> None:
        """Symlink key files must be rejected by O_NOFOLLOW / islink check."""
        key = _gen_key()
        real_key = tmp_path / "real.key"
        write_private_key_atomic(real_key, key)
        symlink_key = tmp_path / "symlink.key"
        symlink_key.symlink_to(real_key)

        with pytest.raises(KeyLoadError, match="symlink"):
            load_private_key_from_file(symlink_key)
        with pytest.raises(KeyPermissionError, match="symlink"):
            check_key_file_permissions(symlink_key)

    @posix_only
    def test_wrong_owner_key_file_is_rejected(self, tmp_path: Path) -> None:
        """Key file owned by a different UID must be rejected."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)

        with patch("os.geteuid", return_value=os.geteuid() + 1000):
            with pytest.raises(KeyLoadError, match="owner UID"):
                load_private_key_from_file(dest)
            with pytest.raises(KeyPermissionError, match="current process UID"):
                check_key_file_permissions(dest)

    def test_non_posix_fails_closed_without_opt_in(self, tmp_path: Path) -> None:
        """On non-POSIX systems, key loading fails closed unless explicitly opted in."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o600)

        with patch("dmint.core.keys._POSIX", False):
            env_clean = {k: v for k, v in os.environ.items() if k != "DMINT_ALLOW_INSECURE_KEY_PERMISSIONS"}
            with patch.dict(os.environ, env_clean, clear=True):
                with pytest.raises(KeyLoadError, match="non-POSIX"):
                    load_private_key_from_file(dest)

    def test_non_posix_succeeds_with_flag(self, tmp_path: Path) -> None:
        """On non-POSIX systems, allow_insecure_permissions=True bypasses the check."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o600)

        with patch("dmint.core.keys._POSIX", False):
            loaded = load_private_key_from_file(dest, allow_insecure_permissions=True)
            assert public_key_hex(loaded.public_key()) == public_key_hex(key.public_key())

    def test_non_posix_succeeds_with_env(self, tmp_path: Path) -> None:
        """On non-POSIX systems, DMINT_ALLOW_INSECURE_KEY_PERMISSIONS=1 bypasses the check."""
        key = _gen_key()
        dest = tmp_path / "signing.key"
        _write_hex_key(dest, key, mode=0o600)

        with patch("dmint.core.keys._POSIX", False):
            with patch.dict(os.environ, {"DMINT_ALLOW_INSECURE_KEY_PERMISSIONS": "1"}, clear=False):
                loaded = load_private_key_from_file(dest)
                assert public_key_hex(loaded.public_key()) == public_key_hex(key.public_key())


# ─── load_private_key (file vs env fallback) ──────────────────────────────────


class TestLoadPrivateKey:
    def test_loads_from_explicit_file(self, tmp_path: Path) -> None:
        key = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key)
        loaded = load_private_key(key_file=dest)
        assert public_key_hex(loaded.public_key()) == public_key_hex(key.public_key())

    def test_env_var_without_opt_in_raises(self) -> None:
        """DMINT_PRIVATE_KEY inline hex without opt-in fails closed."""
        key = _gen_key()
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        raw = key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        env = {k: v for k, v in os.environ.items() if k not in ("DMINT_ALLOW_INLINE_KEY", "DMINT_KEY_FILE")}
        env["DMINT_PRIVATE_KEY"] = raw.hex()
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(KeyLoadError, match="inline private key material"):
                load_private_key()

    def test_env_var_with_opt_in_succeeds_and_warns(self) -> None:
        """DMINT_PRIVATE_KEY inline hex with DMINT_ALLOW_INLINE_KEY=1 succeeds with warning."""
        key = _gen_key()
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        raw = key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        env = {k: v for k, v in os.environ.items() if k != "DMINT_KEY_FILE"}
        env["DMINT_PRIVATE_KEY"] = raw.hex()
        env["DMINT_ALLOW_INLINE_KEY"] = "1"
        with patch.dict(os.environ, env, clear=True):
            with pytest.warns(UserWarning, match="inline private key material"):
                loaded = load_private_key()
        assert public_key_hex(loaded.public_key()) == public_key_hex(key.public_key())

    def test_file_preferred_over_env_var(self, tmp_path: Path) -> None:
        key_file = _gen_key()
        key_env = _gen_key()
        dest = tmp_path / "signing.key"
        write_private_key_atomic(dest, key_file)

        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        raw_env = key_env.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
        )
        with patch.dict(
            os.environ,
            {"DMINT_KEY_FILE": str(dest), "DMINT_PRIVATE_KEY": raw_env.hex()},
            clear=False,
        ):
            loaded = load_private_key()
        # Must have loaded the file key, not the env-var key
        assert public_key_hex(loaded.public_key()) == public_key_hex(key_file.public_key())
        assert public_key_hex(loaded.public_key()) != public_key_hex(key_env.public_key())

    def test_no_source_raises(self) -> None:
        env_clean = {k: v for k, v in os.environ.items() if k not in ("DMINT_PRIVATE_KEY", "DMINT_KEY_FILE")}
        with patch.dict(os.environ, env_clean, clear=True):
            with pytest.raises(KeyLoadError, match="no private key source"):
                load_private_key()


# ─── No key material in repr/str ─────────────────────────────────────────────


class TestLocalAuthorityRepr:
    def test_repr_does_not_contain_key_material(self) -> None:
        from dmint.core.authority import LocalApprovalAuthority
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        key = _gen_key()
        authority = LocalApprovalAuthority(
            issuer_id="test-issuer",
            audience="test-aud",
            private_key=key,
        )
        raw = key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        key_hex = raw.hex()

        assert key_hex not in repr(authority)
        assert key_hex not in str(authority)
        assert "private_key" not in repr(authority).lower()
        assert "test-issuer" in repr(authority)

    def test_repr_format(self) -> None:
        from dmint.core.authority import LocalApprovalAuthority

        key = _gen_key()
        authority = LocalApprovalAuthority(
            issuer_id="my-issuer",
            audience="my-aud",
            private_key=key,
        )
        r = repr(authority)
        assert "LocalApprovalAuthority" in r
        assert "my-issuer" in r
        assert "my-aud" in r


# ─── LocalApprovalAuthority key loading ──────────────────────────────────────


class TestLocalAuthorityKeyLoading:
    def test_fails_closed_when_no_key_source_exists(self) -> None:
        """LocalApprovalAuthority must fail closed when no key source is provided."""
        from dmint.core.authority import LocalApprovalAuthority

        env_clean = {k: v for k, v in os.environ.items() if k not in ("DMINT_PRIVATE_KEY", "DMINT_KEY_FILE")}
        with patch.dict(os.environ, env_clean, clear=True):
            with pytest.raises(KeyLoadError, match="no private key source found"):
                LocalApprovalAuthority(
                    issuer_id="test-issuer",
                    audience="test-aud",
                )

    def test_loads_from_explicit_key_file(self, tmp_path: Path) -> None:
        from dmint.core.authority import LocalApprovalAuthority

        key = _gen_key()
        key_file = tmp_path / "signing.key"
        write_private_key_atomic(key_file, key)

        auth = LocalApprovalAuthority(
            issuer_id="test-issuer",
            audience="test-aud",
            key_file=key_file,
        )
        assert public_key_hex(auth.public_key) == public_key_hex(key.public_key())

    def test_loads_from_dmint_key_file_env(self, tmp_path: Path) -> None:
        from dmint.core.authority import LocalApprovalAuthority

        key = _gen_key()
        key_file = tmp_path / "signing.key"
        write_private_key_atomic(key_file, key)

        with patch.dict(os.environ, {"DMINT_KEY_FILE": str(key_file)}, clear=False):
            auth = LocalApprovalAuthority(
                issuer_id="test-issuer",
                audience="test-aud",
            )
        assert public_key_hex(auth.public_key) == public_key_hex(key.public_key())

    def test_loads_from_dmint_private_key_env_without_opt_in_raises(self) -> None:
        """DMINT_PRIVATE_KEY inline hex without opt-in fails closed."""
        from dmint.core.authority import LocalApprovalAuthority
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        key = _gen_key()
        raw = key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())

        env_clean = {k: v for k, v in os.environ.items() if k not in ("DMINT_KEY_FILE", "DMINT_ALLOW_INLINE_KEY")}
        env_clean["DMINT_PRIVATE_KEY"] = raw.hex()
        with patch.dict(os.environ, env_clean, clear=True):
            with pytest.raises(KeyLoadError, match="inline private keys are disabled"):
                LocalApprovalAuthority(
                    issuer_id="test-issuer",
                    audience="test-aud",
                )

    def test_loads_from_dmint_private_key_env_with_opt_in(self) -> None:
        """DMINT_PRIVATE_KEY inline hex with DMINT_ALLOW_INLINE_KEY=1 succeeds with warning."""
        from dmint.core.authority import LocalApprovalAuthority
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        key = _gen_key()
        raw = key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())

        env_clean = {k: v for k, v in os.environ.items() if k != "DMINT_KEY_FILE"}
        env_clean["DMINT_PRIVATE_KEY"] = raw.hex()
        env_clean["DMINT_ALLOW_INLINE_KEY"] = "1"
        with patch.dict(os.environ, env_clean, clear=True):
            with pytest.warns(UserWarning, match="inline private key material"):
                auth = LocalApprovalAuthority(
                    issuer_id="test-issuer",
                    audience="test-aud",
                )
        assert public_key_hex(auth.public_key) == public_key_hex(key.public_key())

    @posix_only
    def test_refuses_loose_key_file_permissions(self, tmp_path: Path) -> None:
        from dmint.core.authority import LocalApprovalAuthority

        key = _gen_key()
        key_file = tmp_path / "signing.key"
        _write_hex_key(key_file, key, mode=0o644)

        with pytest.raises(KeyLoadError, match="unsafe permissions"):
            LocalApprovalAuthority(
                issuer_id="test-issuer",
                audience="test-aud",
                key_file=key_file,
            )
