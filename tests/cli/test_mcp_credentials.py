"""Unit and security tests for MCP credential storage (src/dmint_cli/mcp_credentials.py)."""

import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from dmint.cli.errors import CLIError
from dmint.cli.mcp_credentials import CredentialStore, TokenRecord


class MCPCredentialsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.cred_file = self.base_path / "credentials.json"
        # Use file-based storage for deterministic test isolation
        self.store = CredentialStore(storage_path=self.cred_file, use_keyring=False)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_load_credential(self):
        server_id = "https://auth.example.com::postgres"
        tokens = {
            "access_token": "access-secret-token-12345",
            "refresh_token": "refresh-secret-token-67890",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        record = self.store.save(server_id, tokens)
        self.assertEqual(record.server_identity, server_id)
        self.assertEqual(record.access_token, "access-secret-token-12345")
        self.assertEqual(record.refresh_token, "refresh-secret-token-67890")

        loaded = self.store.load(server_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.server_identity, server_id)
        self.assertEqual(loaded.access_token, "access-secret-token-12345")

    def test_expiry_check(self):
        server_id = "https://auth.example.com::expired_test"
        # Expired token
        expired_tokens = {"access_token": "expired-token", "expires_in": -100}
        rec1 = self.store.save(server_id, expired_tokens)
        self.assertTrue(rec1.is_expired)

        # Valid token
        valid_tokens = {"access_token": "valid-token", "expires_in": 3600}
        rec2 = self.store.save(server_id, valid_tokens)
        self.assertFalse(rec2.is_expired)

    def test_delete_and_clear(self):
        s1 = "https://auth1.example.com::srv1"
        s2 = "https://auth2.example.com::srv2"
        self.store.save(s1, {"access_token": "token1"})
        self.store.save(s2, {"access_token": "token2"})

        self.assertIsNotNone(self.store.load(s1))
        self.store.delete(s1)
        self.assertIsNone(self.store.load(s1))
        self.assertIsNotNone(self.store.load(s2))

        self.store.clear()
        self.assertIsNone(self.store.load(s2))
        self.assertFalse(self.cred_file.exists())

    def test_wrong_server_identity_returns_none(self):
        self.store.save("server-A", {"access_token": "tokenA"})
        self.assertIsNone(self.store.load("server-B"))

    def test_file_permissions_strict_0600(self):
        self.store.save("server-perms", {"access_token": "tokenP"})
        self.assertTrue(self.cred_file.exists())
        if hasattr(os, "stat"):
            mode = os.stat(self.cred_file).st_mode & 0o777
            # Check mode is 0600 (owner read/write only, no group or world access)
            self.assertEqual(mode & 0o077, 0)

    def test_no_plaintext_secrets_in_repr(self):
        rec = TokenRecord(
            server_identity="server-secret",
            access_token="secret_access_token_abc",
            refresh_token="secret_refresh_token_xyz",
        )
        repr_str = repr(rec)
        self.assertNotIn("secret_access_token_abc", repr_str)
        self.assertNotIn("secret_refresh_token_xyz", repr_str)
        self.assertIn("<redacted>", repr_str)

    def test_corrupted_credential_entry_handled_safely(self):
        self.cred_file.parent.mkdir(parents=True, exist_ok=True)
        self.cred_file.write_text("CORRUPTED_NOT_JSON", encoding="utf-8")

        # Load on corrupted file returns None without crashing
        loaded = self.store.load("server-A")
        self.assertIsNone(loaded)
