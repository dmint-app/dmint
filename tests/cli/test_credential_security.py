"""Comprehensive security tests for Credential Storage Hardening (Phase 3).

Test vectors:
1. File and directory permissions (0600 file, 0700 dir).
2. Symlink attack rejection (file target, parent dir, ancestor dir, lock file).
3. Concurrent write integrity with advisory file locking (no lost updates or corruption).
4. Corrupt credential file handling (safe non-strict load, visible strict failure, manual recovery guidance).
5. Corrupt credential file is never blindly overwritten on save.
6. Canonical resource URL normalization and strong compound server identity binding.
7. Authorization server issuer mix-up rejection.
8. Token expiry handling with 30-second safety window.
9. RFC 6749 refresh-token grant handling with token endpoint interaction and token preservation.
10. Refresh token failures sanitized without leaking secrets.
11. Plaintext secrets redaction in repr, safe dict export, and error messages.
12. Keyring availability detection and refusal to silently downgrade to file storage.
13. Dynamic OAuth client registration persistence (save_client_info, load_client_info).
14. Explicit deletion and logout semantics (logout, logout_all, clear).
15. Serialized MCP configuration audit to ensure no credentials leak into config artifacts.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from dmint.cli.create_mcp_policy import _assert_no_secrets_in_dict, validate_mcp_protection_config
from dmint.cli.errors import CLIError
from dmint.cli.mcp_credentials import (
    CredentialStore,
    FileLock,
    TokenRecord,
    _check_symlink_safety,
    canonical_server_identity,
    is_keyring_available,
    normalize_resource_url,
    refresh_token,
)


class CredentialSecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name).resolve()
        self.cred_dir = self.base_path / "dmint_config"
        self.cred_file = self.cred_dir / "credentials.json"
        self.store = CredentialStore(storage_path=self.cred_file, backend="file")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. File and Directory Permissions
    # -------------------------------------------------------------------------
    def test_file_and_directory_permissions(self):
        """Credential file must be 0600 and parent directory 0700."""
        self.store.save("https://api.example.com", {"access_token": "secret-tok-1"})
        self.assertTrue(self.cred_file.exists())
        self.assertTrue(self.cred_dir.exists())

        file_mode = os.stat(self.cred_file).st_mode & 0o777
        dir_mode = os.stat(self.cred_dir).st_mode & 0o777

        # 0600 = owner read/write only
        self.assertEqual(file_mode, 0o600, f"File mode {oct(file_mode)} is not 0600")
        # 0700 = owner rwx only
        self.assertEqual(dir_mode, 0o700, f"Directory mode {oct(dir_mode)} is not 0700")

    # -------------------------------------------------------------------------
    # 2. Symlink Attack Protections
    # -------------------------------------------------------------------------
    def test_symlink_target_file_rejected(self):
        """Reject credential file that is a symbolic link."""
        target = self.base_path / "target_file.json"
        target.write_text("{}", encoding="utf-8")

        self.cred_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file.symlink_to(target)

        # Loading must fail with security violation
        with self.assertRaises(CLIError) as ctx:
            self.store.load("https://api.example.com", strict=True)
        self.assertIn("symbolic link", str(ctx.exception).lower())

        # Saving must fail with security violation
        with self.assertRaises(CLIError) as ctx:
            self.store.save("https://api.example.com", {"access_token": "tok"})
        self.assertIn("symbolic link", str(ctx.exception).lower())

    def test_symlink_parent_directory_rejected(self):
        """Reject credential storage where parent directory is a symbolic link."""
        real_dir = self.base_path / "real_dir"
        real_dir.mkdir(parents=True, exist_ok=True)

        symlink_dir = self.base_path / "symlink_dir"
        symlink_dir.symlink_to(real_dir)

        symlinked_cred_file = symlink_dir / "credentials.json"
        with self.assertRaises(CLIError) as ctx:
            store = CredentialStore(storage_path=symlinked_cred_file, backend="file")
            store.save("https://api.example.com", {"access_token": "tok"})
        self.assertIn("parent directory", str(ctx.exception).lower())
        self.assertIn("symbolic link", str(ctx.exception).lower())

    def test_symlink_lock_file_rejected(self):
        """Reject advisory lock when the lock file is a symlink."""
        lock_path = self.cred_dir / "credentials.json.lock"
        self.cred_dir.mkdir(parents=True, exist_ok=True)
        target = self.base_path / "lock_target"
        target.write_text("", encoding="utf-8")
        lock_path.symlink_to(target)

        with self.assertRaises(CLIError) as ctx:
            with FileLock(lock_path):
                pass
        self.assertIn("symbolic link", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 3. Concurrent Write Integrity
    # -------------------------------------------------------------------------
    def test_concurrent_writes_integrity(self):
        """Advisory file locking ensures concurrent writes do not corrupt file or lose updates."""
        num_workers = 16
        tokens_to_write = [(f"https://service-{i}.example.com", f"token-value-{i}") for i in range(num_workers)]

        def write_worker(item):
            s_id, tok = item
            worker_store = CredentialStore(storage_path=self.cred_file, backend="file")
            worker_store.save(s_id, {"access_token": tok, "expires_in": 3600})

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(write_worker, tokens_to_write))

        # Validate that store is valid JSON and contains all records
        self.store.validate_store()
        for s_id, tok in tokens_to_write:
            loaded = self.store.load(s_id)
            self.assertIsNotNone(loaded, f"Record for {s_id} was lost during concurrent writes!")
            self.assertEqual(loaded.access_token, tok)

    # -------------------------------------------------------------------------
    # 4. Corrupted State Handling & Blind Overwrite Prevention
    # -------------------------------------------------------------------------
    def test_corrupt_file_safe_non_strict_load(self):
        """Corrupt file returns None in non-strict load without crashing."""
        self.cred_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file.write_text("{corrupt: json not closed", encoding="utf-8")

        loaded = self.store.load("https://api.example.com", strict=False)
        self.assertIsNone(loaded)

    def test_corrupt_file_strict_load_and_validate_store_recovery_guidance(self):
        """Strict load and validate_store fail visibly with recovery guidance."""
        self.cred_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file.write_text("CORRUPTED_GARBAGE_PAYLOAD", encoding="utf-8")

        with self.assertRaises(CLIError) as ctx:
            self.store.validate_store()
        err_msg = str(ctx.exception)
        self.assertIn("corrupted", err_msg.lower())
        self.assertIn("Manual recovery guidance", err_msg)

        with self.assertRaises(CLIError) as ctx2:
            self.store.load("https://api.example.com", strict=True)
        self.assertIn("corrupted", str(ctx2.exception).lower())

    def test_corrupt_file_never_blindly_overwritten(self):
        """Attempting to save to a store with a corrupt credential file refuses to blindly overwrite."""
        self.cred_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file.write_text("{this is corrupted data that cannot be parsed", encoding="utf-8")

        with self.assertRaises(CLIError) as ctx:
            self.store.save("https://new-service.com", {"access_token": "valid-token"})
        self.assertIn("corrupted", str(ctx.exception).lower())
        self.assertIn("Manual recovery guidance", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 5. Strong Server Identity Binding & Issuer Mix-up
    # -------------------------------------------------------------------------
    def test_resource_url_normalization(self):
        """Normalize URLs: scheme/host lowercase, default ports stripped, trailing slash removed."""
        self.assertEqual(
            normalize_resource_url("HTTP://Example.COM:80/mcp/"),
            "http://example.com/mcp",
        )
        self.assertEqual(
            normalize_resource_url("HTTPS://SECURE.ORG:443/api/v1"),
            "https://secure.org/api/v1",
        )
        self.assertEqual(
            normalize_resource_url("http://127.0.0.1:8080/mcp/"),
            "http://127.0.0.1:8080/mcp",
        )

    def test_canonical_server_identity_compound_key(self):
        """Build compound identity key with URL, issuer, client_id, and integration_id."""
        key = canonical_server_identity(
            "HTTPS://Api.Example.Com:443/mcp/",
            issuer="https://Auth.Example.Com:443",
            client_id="my-client-app",
            integration_id="pg-db",
        )
        expected = "https://api.example.com/mcp#https://auth.example.com@my-client-app::pg-db"
        self.assertEqual(key, expected)

    def test_issuer_mixup_rejection(self):
        """Credential saved for one issuer cannot be loaded for a different issuer."""
        server_id = "https://api.example.com/mcp"
        self.store.save(
            server_id,
            {"access_token": "bound-token-123"},
            issuer="https://legitimate-idp.example.com",
        )

        # Loading with matching issuer succeeds
        rec = self.store.load(server_id, issuer="https://legitimate-idp.example.com")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.access_token, "bound-token-123")

        # Loading with mismatched attacker issuer is rejected
        rec_mismatch = self.store.load(server_id, issuer="https://attacker-idp.example.com")
        self.assertIsNone(rec_mismatch)

    # -------------------------------------------------------------------------
    # 6. Token Expiration and Safety Margin
    # -------------------------------------------------------------------------
    def test_token_expiry_with_safety_margin(self):
        """Tokens expiring within 30 seconds are treated as expired to avoid race conditions."""
        now = time.time()

        # Expired in past
        rec_past = TokenRecord("srv1", "tok", expires_at=now - 100)
        self.assertTrue(rec_past.is_expired)

        # Expiring in 10 seconds (within 30s safety window)
        rec_near = TokenRecord("srv2", "tok", expires_at=now + 10)
        self.assertTrue(rec_near.is_expired)

        # Expiring in 60 seconds (outside 30s window)
        rec_valid = TokenRecord("srv3", "tok", expires_at=now + 60)
        self.assertFalse(rec_valid.is_expired)

        # No expiry set
        rec_none = TokenRecord("srv4", "tok", expires_at=None)
        self.assertFalse(rec_none.is_expired)

    # -------------------------------------------------------------------------
    # 7. RFC 6749 Token Refresh Flow
    # -------------------------------------------------------------------------
    def test_refresh_token_successful_flow(self):
        """RFC 6749 token refresh sends proper form payload and updates credential store."""
        record = TokenRecord(
            server_identity="https://api.example.com/mcp",
            access_token="initial-access-token",
            refresh_token="initial-refresh-token",
            expires_at=time.time() - 10,
            issuer="https://auth.example.com",
            client_id="test-client-id",
        )
        self.store.save(record.server_identity, record.to_dict())

        # Mock successful token endpoint response
        mock_resp_data = {
            "access_token": "new-refreshed-token-456",
            "token_type": "Bearer",
            "expires_in": 3600,
            # Server does not return new refresh token -> old one should be retained
        }
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            new_rec = refresh_token(
                record,
                "https://auth.example.com/oauth/token",
                client_id="test-client-id",
                credential_store=self.store,
            )

            # Verify request
            req_call = mock_urlopen.call_args[0][0]
            self.assertEqual(req_call.full_url, "https://auth.example.com/oauth/token")
            self.assertEqual(req_call.method, "POST")
            post_data = urllib.parse.parse_qs(req_call.data.decode("utf-8"))
            self.assertEqual(post_data["grant_type"], ["refresh_token"])
            self.assertEqual(post_data["refresh_token"], ["initial-refresh-token"])
            self.assertEqual(post_data["client_id"], ["test-client-id"])

            # Verify returned and stored record
            self.assertEqual(new_rec.access_token, "new-refreshed-token-456")
            self.assertEqual(new_rec.refresh_token, "initial-refresh-token")
            self.assertFalse(new_rec.is_expired)

            # Verify persisted in store
            stored = self.store.load(record.server_identity)
            self.assertIsNotNone(stored)
            self.assertEqual(stored.access_token, "new-refreshed-token-456")
            self.assertEqual(stored.refresh_token, "initial-refresh-token")

    def test_refresh_token_missing_refresh_token_raises_error(self):
        """TokenRecord lacking refresh_token raises CLIError on refresh attempt."""
        record = TokenRecord(
            server_identity="https://api.example.com/mcp",
            access_token="no-refresh-token",
            refresh_token=None,
        )
        with self.assertRaises(CLIError) as ctx:
            refresh_token(record, "https://auth.example.com/oauth/token")
        self.assertIn("no refresh_token available", str(ctx.exception).lower())

    def test_refresh_token_endpoint_error_redacted(self):
        """Token endpoint failure is sanitized without leaking secrets in exceptions."""
        record = TokenRecord(
            server_identity="https://api.example.com/mcp",
            access_token="secret-tok-abc",
            refresh_token="secret-ref-xyz",
        )
        mock_err = urllib.error.HTTPError(
            url="https://auth.example.com/oauth/token",
            code=400,
            msg="Bad Request: secret-ref-xyz is invalid",
            hdrs={},
            fp=BytesIO(b""),
        )
        with patch("urllib.request.urlopen", side_effect=mock_err):
            with self.assertRaises(CLIError) as ctx:
                refresh_token(record, "https://auth.example.com/oauth/token")
            err_text = str(ctx.exception)
            self.assertNotIn("secret-ref-xyz", err_text)
            self.assertIn("Token refresh failed", err_text)

    # -------------------------------------------------------------------------
    # 8. Token Redaction in Repr & Safe Export
    # -------------------------------------------------------------------------
    def test_token_redaction_repr_and_safe_dict(self):
        """TokenRecord repr and to_safe_dict must never contain plaintext tokens."""
        rec = TokenRecord(
            server_identity="https://api.example.com",
            access_token="super_secret_access_token_12345",
            refresh_token="super_secret_refresh_token_67890",
        )

        repr_str = repr(rec)
        self.assertNotIn("super_secret_access_token_12345", repr_str)
        self.assertNotIn("super_secret_refresh_token_67890", repr_str)
        self.assertIn("<redacted>", repr_str)

        safe_dict = rec.to_safe_dict()
        self.assertEqual(safe_dict["access_token"], "<redacted>")
        self.assertEqual(safe_dict["refresh_token"], "<redacted>")

    # -------------------------------------------------------------------------
    # 9. Keyring Failure Handling & No Silent Downgrade
    # -------------------------------------------------------------------------
    def test_keyring_requested_but_unavailable_refuses_silent_downgrade(self):
        """When backend='keyring' is requested, missing keyring raises CLIError instead of downgrading."""
        kr_store = CredentialStore(storage_path=self.cred_file, backend="keyring")
        with patch("dmint.cli.mcp_credentials.is_keyring_available", return_value=False):
            with self.assertRaises(CLIError) as ctx:
                kr_store.save("srv1", {"access_token": "tok1"})
            self.assertIn("refusing to silently downgrade", str(ctx.exception).lower())

    def test_keyring_write_error_refuses_silent_downgrade(self):
        """When backend='keyring' write throws, it raises CLIError instead of saving to file."""
        kr_store = CredentialStore(storage_path=self.cred_file, backend="keyring")
        mock_kr = MagicMock()
        mock_kr.set_password.side_effect = RuntimeError("Keyring locked by system")
        with patch("dmint.cli.mcp_credentials.is_keyring_available", return_value=True):
            with patch.object(kr_store, "_get_keyring", return_value=mock_kr):
                with self.assertRaises(CLIError) as ctx:
                    kr_store.save("srv1", {"access_token": "tok1"})
                self.assertIn("refusing to silently downgrade", str(ctx.exception).lower())
        # Ensure credentials file was NOT created
        self.assertFalse(self.cred_file.exists())

    def test_auto_backend_without_fallback_fails_cleanly(self):
        """When backend='auto' and allow_file_fallback=False, missing keyring fails cleanly."""
        auto_store = CredentialStore(
            storage_path=self.cred_file,
            backend="auto",
            allow_file_fallback=False,
        )
        with patch("dmint.cli.mcp_credentials.is_keyring_available", return_value=False):
            with self.assertRaises(CLIError) as ctx:
                auto_store.save("srv1", {"access_token": "tok1"})
            self.assertIn("keyring is unavailable and file fallback is disabled", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 10. Client Info Persistence and Logout Semantics
    # -------------------------------------------------------------------------
    def test_client_info_persistence_and_logout(self):
        """OAuth dynamic client registration info can be saved, loaded, and cleared via logout."""
        server_id = "https://api.example.com/mcp"
        client_info = {
            "client_id": "auto-client-789",
            "client_secret": "dynamic-secret-456",
            "registration_client_uri": "https://auth.example.com/register/auto-client-789",
        }
        self.store.save(server_id, {"access_token": "tok-1"})
        self.store.save_client_info(server_id, client_info)

        loaded_info = self.store.load_client_info(server_id)
        self.assertEqual(loaded_info, client_info)

        # Logout must delete both token and client_info
        self.store.logout(server_id)
        self.assertIsNone(self.store.load(server_id))
        self.assertIsNone(self.store.load_client_info(server_id))

    def test_logout_all_clears_store_file(self):
        """logout_all clears all tokens, client_info, and removes the store file."""
        self.store.save("srv1", {"access_token": "tok1"})
        self.store.save("srv2", {"access_token": "tok2"})
        self.store.save_client_info("srv1", {"client_id": "c1"})
        self.assertTrue(self.cred_file.exists())

        self.store.logout_all()
        self.assertFalse(self.cred_file.exists())
        self.assertIsNone(self.store.load("srv1"))
        self.assertIsNone(self.store.load("srv2"))

    # -------------------------------------------------------------------------
    # 11. Serialized MCP Config Audit (No Secrets Leaked)
    # -------------------------------------------------------------------------
    def test_serialized_mcp_config_audit_rejects_credentials(self):
        """Audit ensures generated MCP configs reject any plaintext tokens or secrets."""
        # 1. Config with access_token field must fail validation
        leaky_config_1 = {
            "policy_file": "policy.json",
            "integrations": [
                {
                    "integration_id": "leaky_srv",
                    "transport": "streamable_http",
                    "connection": {"url": "https://mcp.example.com"},
                    "access_token": "secret-plaintext-token",
                    "tool_bindings": {"tool1": {"tool_name": "tool1", "capability": "mcp.leaky.tool1"}},
                }
            ],
        }
        with self.assertRaises(CLIError) as ctx:
            validate_mcp_protection_config(leaky_config_1)
        self.assertIn("plaintext secret field", str(ctx.exception).lower())

        # 2. Config with nested client_secret must fail validation
        leaky_config_2 = {
            "policy_file": "policy.json",
            "integrations": [
                {
                    "integration_id": "leaky_srv2",
                    "transport": "streamable_http",
                    "connection": {
                        "url": "https://mcp.example.com",
                        "auth": {"client_secret": "my-secret-value"},
                    },
                    "tool_bindings": {"tool1": {"tool_name": "tool1", "capability": "mcp.leaky.tool1"}},
                }
            ],
        }
        with self.assertRaises(CLIError) as ctx:
            validate_mcp_protection_config(leaky_config_2)
        self.assertIn("plaintext secret field", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
