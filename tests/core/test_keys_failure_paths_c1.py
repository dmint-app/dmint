"""Real tests for core/keys.py failure paths: symlink, wrong owner, group-readable, parent writable, missing file."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.core.keys import (
    KeyExistsError,
    KeyLoadError,
    KeyPermissionError,
    _check_parent_dir_permissions,
    _parse_integrity_key,
    check_key_file_permissions,
    load_integrity_key_from_file,
    load_integrity_key_source,
    load_private_key,
    load_private_key_from_file,
    public_key_hex,
    write_integrity_key_atomic,
    write_private_key_atomic,
)

TEST_HEX_32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class KeysFailurePathsC1Tests(unittest.TestCase):
    """Test all security failure paths in dmint.core.keys."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        # Ensure base tempdir is 0700
        self.tmp_path.chmod(0o700)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_file_raises_appropriate_error(self) -> None:
        """check_key_file_permissions raises FileNotFoundError, while loaders raise KeyLoadError."""
        nonexistent = self.tmp_path / "nonexistent.key"
        with self.assertRaises(FileNotFoundError):
            check_key_file_permissions(nonexistent)

        with self.assertRaises(KeyLoadError) as ctx1:
            load_private_key_from_file(nonexistent)
        self.assertIn("does not exist", str(ctx1.exception))

        with self.assertRaises(KeyLoadError) as ctx2:
            load_integrity_key_from_file(nonexistent)
        self.assertIn("does not exist", str(ctx2.exception))

    def test_symlink_key_file_rejected(self) -> None:
        """Symlinked key file is rejected for security."""
        real_key = self.tmp_path / "real.key"
        write_integrity_key_atomic(real_key, bytes.fromhex(TEST_HEX_32))
        sym_key = self.tmp_path / "symlink.key"
        sym_key.symlink_to(real_key)

        with self.assertRaises(KeyPermissionError) as ctx:
            check_key_file_permissions(sym_key)
        self.assertIn("symlink", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_private_key_from_file(sym_key)
        self.assertIn("symlink", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_integrity_key_from_file(sym_key)
        self.assertIn("symlink", str(ctx.exception))

    def test_group_readable_key_file_rejected(self) -> None:
        """Group-readable or world-readable key file (mode & 0o077 != 0) is rejected."""
        key_file = self.tmp_path / "shared.key"
        write_integrity_key_atomic(key_file, bytes.fromhex(TEST_HEX_32))
        key_file.chmod(0o644)

        with self.assertRaises(KeyPermissionError) as ctx:
            check_key_file_permissions(key_file)
        self.assertIn("unsafe permissions", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_private_key_from_file(key_file)
        self.assertIn("unsafe permissions", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_integrity_key_from_file(key_file)
        self.assertIn("unsafe permissions", str(ctx.exception))

    def test_directory_as_key_file_rejected(self) -> None:
        """A directory passed as a key file path is rejected."""
        sub_dir = self.tmp_path / "keydir"
        sub_dir.mkdir(mode=0o700)

        with self.assertRaises(KeyPermissionError) as ctx:
            check_key_file_permissions(sub_dir)
        self.assertIn("not a regular file", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_private_key_from_file(sub_dir)
        self.assertIn("not a regular file", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_integrity_key_from_file(sub_dir)
        self.assertIn("not a regular file", str(ctx.exception))

    def test_parent_writable_directory_rejected(self) -> None:
        """Parent directory with group or world write bits (0o022) is rejected."""
        insecure_dir = self.tmp_path / "insecure_parent"
        insecure_dir.mkdir(mode=0o777)
        insecure_dir.chmod(0o777)  # Ensure 0o022 bits are set

        key_file = insecure_dir / "key.pem"
        priv = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_file, priv)

        with self.assertRaises(KeyPermissionError) as ctx:
            check_key_file_permissions(key_file)
        self.assertIn("parent directory has unsafe permissions", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_private_key_from_file(key_file)
        self.assertIn("parent directory has unsafe permissions", str(ctx.exception))

        with self.assertRaises(KeyLoadError) as ctx:
            load_integrity_key_from_file(key_file)
        self.assertIn("parent directory has unsafe permissions", str(ctx.exception))

    def test_parent_dir_wrong_owner_rejected(self) -> None:
        """Parent directory owned by an unrelated UID (neither current euid nor 0) is rejected."""
        key_dir = self.tmp_path / "other_user_dir"
        key_dir.mkdir(mode=0o700)
        key_file = key_dir / "k.key"
        write_integrity_key_atomic(key_file, bytes.fromhex(TEST_HEX_32))

        real_stat = key_dir.stat()
        fake_stat = os.stat_result(
            (
                real_stat.st_mode,
                real_stat.st_ino,
                real_stat.st_dev,
                real_stat.st_nlink,
                99999,  # Unrelated UID
                real_stat.st_gid,
                real_stat.st_size,
                real_stat.st_atime,
                real_stat.st_mtime,
                real_stat.st_ctime,
            )
        )

        with patch("pathlib.Path.stat", return_value=fake_stat):
            with self.assertRaises(KeyPermissionError) as ctx:
                _check_parent_dir_permissions(key_dir)
            self.assertIn("parent directory owner UID", str(ctx.exception))

    def test_key_file_wrong_owner_rejected(self) -> None:
        """Key file owned by an unrelated UID is rejected."""
        key_file = self.tmp_path / "wrong_owner.key"
        write_integrity_key_atomic(key_file, bytes.fromhex(TEST_HEX_32))

        real_stat = os.stat(key_file)
        fake_stat = os.stat_result(
            (
                real_stat.st_mode,
                real_stat.st_ino,
                real_stat.st_dev,
                real_stat.st_nlink,
                real_stat.st_uid + 1000,  # Wrong owner UID
                real_stat.st_gid,
                real_stat.st_size,
                real_stat.st_atime,
                real_stat.st_mtime,
                real_stat.st_ctime,
            )
        )

        with patch("os.fstat", return_value=fake_stat):
            with self.assertRaises(KeyPermissionError) as ctx:
                check_key_file_permissions(key_file)
            self.assertIn("does not match current process UID", str(ctx.exception))

            with self.assertRaises(KeyLoadError) as ctx2:
                load_private_key_from_file(key_file)
            self.assertIn("does not match current process UID", str(ctx2.exception))

            with self.assertRaises(KeyLoadError) as ctx3:
                load_integrity_key_from_file(key_file)
            self.assertIn("does not match current process UID", str(ctx3.exception))

    def test_non_posix_platform_handling(self) -> None:
        """On non-POSIX platforms, fails closed unless DMINT_ALLOW_INSECURE_KEY_PERMISSIONS=1."""
        key_file = self.tmp_path / "win_key.key"
        key_file.write_text(TEST_HEX_32, encoding="ascii")

        with patch("dmint.core.keys._POSIX", False):
            # 1. Without env var -> raises KeyPermissionError / KeyLoadError
            with patch.dict(os.environ, {"DMINT_ALLOW_INSECURE_KEY_PERMISSIONS": "0"}):
                with self.assertRaises(KeyPermissionError):
                    check_key_file_permissions(key_file)
                with self.assertRaises(KeyLoadError):
                    load_integrity_key_from_file(key_file)
                with self.assertRaises(KeyLoadError):
                    load_private_key_from_file(key_file)

            # 2. With env var -> succeeds
            with patch.dict(os.environ, {"DMINT_ALLOW_INSECURE_KEY_PERMISSIONS": "1"}):
                check_key_file_permissions(key_file)
                k_bytes = load_integrity_key_from_file(key_file)
                self.assertEqual(k_bytes, bytes.fromhex(TEST_HEX_32))
                # If file missing on non-posix, raises FileNotFoundError / KeyLoadError
                with self.assertRaises(FileNotFoundError):
                    check_key_file_permissions(self.tmp_path / "win_missing.key")
                with self.assertRaises(KeyLoadError):
                    load_integrity_key_from_file(self.tmp_path / "win_missing.key")

    def test_parse_integrity_key_variations(self) -> None:
        """_parse_integrity_key accepts valid 32 bytes or 64 hex, rejects malformed values."""
        raw_32 = bytes.fromhex(TEST_HEX_32)
        self.assertEqual(_parse_integrity_key(raw_32), raw_32)
        self.assertEqual(_parse_integrity_key(TEST_HEX_32), raw_32)
        self.assertEqual(_parse_integrity_key(TEST_HEX_32.upper()), raw_32)

        # Invalid lengths
        with self.assertRaises(KeyLoadError):
            _parse_integrity_key(b"short")
        with self.assertRaises(KeyLoadError):
            _parse_integrity_key(raw_32 + b"\x00")
        with self.assertRaises(KeyLoadError):
            _parse_integrity_key("deadbeef")
        with self.assertRaises(KeyLoadError):
            _parse_integrity_key("g" * 64)

    def test_write_integrity_key_atomic_file_exists(self) -> None:
        """write_integrity_key_atomic raises KeyExistsError if force is False."""
        p = self.tmp_path / "exist.key"
        write_integrity_key_atomic(p, bytes.fromhex(TEST_HEX_32))
        with self.assertRaises(KeyExistsError):
            write_integrity_key_atomic(p, bytes.fromhex(TEST_HEX_32), force=False)

        # force=True succeeds
        write_integrity_key_atomic(p, bytes.fromhex(TEST_HEX_32), force=True)
        self.assertTrue(p.exists())

    def test_load_integrity_key_source_precedence(self) -> None:
        """Test load_integrity_key_source parameter, env var, and default file resolution."""
        # 1. Direct bytes
        raw = bytes.fromhex(TEST_HEX_32)
        self.assertEqual(load_integrity_key_source(raw), raw)

        # 2. Direct 64 hex string
        self.assertEqual(load_integrity_key_source(TEST_HEX_32), raw)

        # 3. Path to key file
        p = self.tmp_path / "source.key"
        write_integrity_key_atomic(p, raw)
        self.assertEqual(load_integrity_key_source(p), raw)
        self.assertEqual(load_integrity_key_source(str(p)), raw)

        # 4. DMINT_INTEGRITY_KEY_FILE env var
        with patch.dict(os.environ, {"DMINT_INTEGRITY_KEY_FILE": str(p)}):
            self.assertEqual(load_integrity_key_source(None), raw)

        # 5. DMINT_INTEGRITY_KEY env var (raw hex)
        with patch.dict(os.environ, {"DMINT_INTEGRITY_KEY_FILE": "", "DMINT_INTEGRITY_KEY": TEST_HEX_32}):
            self.assertEqual(load_integrity_key_source(None), raw)

        # 6. Default file fallback
        with patch.dict(os.environ, {"DMINT_INTEGRITY_KEY_FILE": "", "DMINT_INTEGRITY_KEY": ""}):
            with patch("dmint.core.keys.DEFAULT_INTEGRITY_KEY_FILE", p):
                self.assertEqual(load_integrity_key_source(None), raw)

        # 7. All sources absent -> KeyLoadError
        with patch.dict(os.environ, {"DMINT_INTEGRITY_KEY_FILE": "", "DMINT_INTEGRITY_KEY": ""}):
            with patch("dmint.core.keys.DEFAULT_INTEGRITY_KEY_FILE", self.tmp_path / "absent.key"):
                with self.assertRaises(KeyLoadError) as ctx:
                    load_integrity_key_source(None)
                self.assertIn("no integrity key source found", str(ctx.exception))

    def test_load_private_key_env_and_file_sources(self) -> None:
        """Test load_private_key from file, DEFAULT_KEY_FILE, and inline env vars."""
        priv = Ed25519PrivateKey.generate()
        key_file = self.tmp_path / "priv.key"
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        raw = priv.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        hex_str = raw.hex()
        key_file.write_text(hex_str + "\n", encoding="ascii")
        key_file.chmod(0o600)

        # 1. Direct file path
        loaded = load_private_key(key_file)
        self.assertEqual(public_key_hex(loaded.public_key()), public_key_hex(priv.public_key()))

        # 2. DMINT_KEY_FILE env var
        with patch.dict(os.environ, {"DMINT_KEY_FILE": str(key_file)}):
            loaded_env = load_private_key(None)
            self.assertEqual(public_key_hex(loaded_env.public_key()), public_key_hex(priv.public_key()))

        # 3. DEFAULT_KEY_FILE fallback
        with patch.dict(os.environ, {"DMINT_KEY_FILE": ""}):
            with patch("dmint.core.keys.DEFAULT_KEY_FILE", key_file):
                loaded_def = load_private_key(None)
                self.assertEqual(public_key_hex(loaded_def.public_key()), public_key_hex(priv.public_key()))

        # 4. DMINT_PRIVATE_KEY inline env var without opt-in -> KeyLoadError
        with patch.dict(
            os.environ, {"DMINT_KEY_FILE": "", "DMINT_PRIVATE_KEY": hex_str, "DMINT_ALLOW_INLINE_KEY": "0"}
        ):
            with patch("dmint.core.keys.DEFAULT_KEY_FILE", self.tmp_path / "absent.key"):
                with self.assertRaises(KeyLoadError) as ctx:
                    load_private_key(None)
                self.assertIn("inline", str(ctx.exception).lower())

        # 5. DMINT_PRIVATE_KEY inline env var WITH opt-in -> succeeds
        with patch.dict(
            os.environ, {"DMINT_KEY_FILE": "", "DMINT_PRIVATE_KEY": hex_str, "DMINT_ALLOW_INLINE_KEY": "1"}
        ):
            with patch("dmint.core.keys.DEFAULT_KEY_FILE", self.tmp_path / "absent.key"):
                with self.assertWarns(UserWarning):
                    loaded_inline = load_private_key(None)
                self.assertEqual(public_key_hex(loaded_inline.public_key()), public_key_hex(priv.public_key()))

        # 6. Missing all sources -> KeyLoadError
        with patch.dict(os.environ, {"DMINT_KEY_FILE": "", "DMINT_PRIVATE_KEY": ""}):
            with patch("dmint.core.keys.DEFAULT_KEY_FILE", self.tmp_path / "absent.key"):
                with self.assertRaises(KeyLoadError):
                    load_private_key(None)

    def test_parse_private_key_hex_invalid_chars(self) -> None:
        """_parse_private_key_hex raises KeyLoadError for 64 chars of non-hex."""
        from dmint.core.keys import _parse_private_key_hex

        with self.assertRaises(KeyLoadError) as ctx:
            _parse_private_key_hex("z" * 64)
        self.assertIn("non-hex", str(ctx.exception))

    def test_write_keys_atomic_non_posix(self) -> None:
        """write_private_key_atomic and write_integrity_key_atomic on non-POSIX platforms."""
        priv = Ed25519PrivateKey.generate()
        p1 = self.tmp_path / "win_priv.key"
        p2 = self.tmp_path / "win_int.key"

        with patch("dmint.core.keys._POSIX", False):
            # 1. Insecure disallowed -> KeyPermissionError
            with patch.dict(os.environ, {"DMINT_ALLOW_INSECURE_KEY_PERMISSIONS": "0"}):
                with self.assertRaises(KeyPermissionError):
                    write_private_key_atomic(p1, priv)
                with self.assertRaises(KeyPermissionError):
                    write_integrity_key_atomic(p2, bytes.fromhex(TEST_HEX_32))

            # 2. Insecure allowed -> succeeds
            with patch.dict(os.environ, {"DMINT_ALLOW_INSECURE_KEY_PERMISSIONS": "1"}):
                write_private_key_atomic(p1, priv)
                self.assertTrue(p1.exists())
                write_integrity_key_atomic(p2, bytes.fromhex(TEST_HEX_32))
                self.assertTrue(p2.exists())

    def test_write_integrity_key_atomic_bad_length(self) -> None:
        """write_integrity_key_atomic raises ValueError if key is not 32 bytes."""
        p = self.tmp_path / "bad_len.key"
        with self.assertRaises(ValueError) as ctx:
            write_integrity_key_atomic(p, b"too_short")
        self.assertIn("exactly 32 bytes", str(ctx.exception))

    def test_load_integrity_key_source_invalid_64_char_fallback(self) -> None:
        """load_integrity_key_source handles 64-char non-hex string by trying path."""
        with self.assertRaises(KeyLoadError):
            load_integrity_key_source("x" * 64)
