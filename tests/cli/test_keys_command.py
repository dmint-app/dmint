"""CLI tests for dmint init-keys and dmint export-public-key."""

from __future__ import annotations

import io
import json
import os
import platform
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.cli.__main__ import main
from dmint.cli.keys import main_export_public_key, main_init_keys
from dmint.core.keys import load_private_key_from_file, public_key_hex, write_private_key_atomic

IS_POSIX = platform.system() != "Windows"
posix_only = pytest.mark.skipif(not IS_POSIX, reason="POSIX-only permission tests")


class TestInitKeysCLI:
    def test_init_keys_generates_file_and_outputs_info(self, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.key"
        stderr_buf = io.StringIO()

        with patch("sys.stderr", stderr_buf):
            ret = main_init_keys(["--key-file", str(key_file), "--issuer-id", "test-auth"])

        assert ret == 0
        assert key_file.exists()
        if IS_POSIX:
            assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

        output = stderr_buf.getvalue()
        assert "generated successfully" in output
        assert "test-auth" in output
        assert "public_key_hex" in output
        assert "-----BEGIN PUBLIC KEY-----" in output

    def test_init_keys_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.key"
        key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_file, key)

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            ret = main_init_keys(["--key-file", str(key_file)])

        assert ret == 1
        output = stderr_buf.getvalue()
        assert "already exists" in output

    def test_init_keys_allows_overwrite_with_force(self, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.key"
        key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_file, key)
        old_hex = public_key_hex(key.public_key())

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            ret = main_init_keys(["--key-file", str(key_file), "--force"])

        assert ret == 0
        new_key = load_private_key_from_file(key_file)
        new_hex = public_key_hex(new_key.public_key())
        assert old_hex != new_hex


class TestExportPublicKeyCLI:
    def test_export_public_key_default_format(self, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.key"
        key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_file, key)
        expected_hex = public_key_hex(key.public_key())

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            ret = main_export_public_key(["--key-file", str(key_file), "--issuer-id", "my-auth"])

        assert ret == 0
        out = stdout_buf.getvalue()
        assert f"issuer_id:      my-auth" in out
        assert f"public_key_hex: {expected_hex}" in out
        assert "-----BEGIN PUBLIC KEY-----" in out

    def test_export_public_key_json_format(self, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.key"
        key = Ed25519PrivateKey.generate()
        write_private_key_atomic(key_file, key)
        expected_hex = public_key_hex(key.public_key())

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            ret = main_export_public_key(["--key-file", str(key_file), "--issuer-id", "my-auth", "--format", "json"])

        assert ret == 0
        parsed = json.loads(stdout_buf.getvalue())
        assert parsed["issuer_id"] == "my-auth"
        assert parsed["public_key_hex"] == expected_hex

    def test_export_public_key_missing_file_fails(self, tmp_path: Path) -> None:
        key_file = tmp_path / "nonexistent.key"
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            ret = main_export_public_key(["--key-file", str(key_file)])

        assert ret == 1
        assert "does not exist" in stderr_buf.getvalue()

    def test_main_dispatch_init_keys_and_export(self, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.key"
        assert main(["init-keys", "--key-file", str(key_file)]) == 0
        assert key_file.exists()
        assert main(["export-public-key", "--key-file", str(key_file), "--format", "hex"]) == 0
