"""Regression tests for Step 3: approvals, Store ABC, key separation, and secrets."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint import (
    ANY_RESOURCE,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalVerifier,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    TrustedContext,
    policy_digest,
    public_key_hex,
)
from dmint.core.storage import SQLiteApprovalStore, ThreadSafeApprovalStore, create_approval_store
from dmint.core.storage.base import ApprovalStore
from dmint.core.storage.factory import resolve_database_url
from dmint.core.storage.sql import SQLAlchemyApprovalStore
from dmint.core.verification import load_trusted_issuers_from_public_sources
from dmint.errors import (
    ApprovalBacklogError,
    ApprovalConsumedError,
    ApprovalRequiredError,
    ApprovalStoreConfigurationError,
    PolicyError,
)


class _ApprovalFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.expires = self.now + timedelta(minutes=10)
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = self.root / "approvals.sqlite"
        self.private_key = Ed25519PrivateKey.generate()
        self.authority = LocalApprovalAuthority(
            issuer_id="authority-1",
            audience="dmint/runtime-1",
            private_key=self.private_key,
        )
        self.approver = ApprovalAuthority._from_trusted_boundary(
            "approval-ui",
            "human-1",
            ApprovalAuthorityKind.HUMAN,
        )
        self.policy_provenance = PolicyProvenance(
            "policy-v1",
            hashlib.sha256(b"policy-v1").hexdigest(),
            self.now,
        )
        self.dmint = Dmint(
            Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),)),
            agent_id="agent-a",
            context=TrustedContext({"environment": "production"}),
        )

        def delete_user(user_id):
            return user_id

        self.dmint.register(
            delete_user,
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        self.delete_user = delete_user

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_record(self, *, user_id: int = 123):
        authorized = self.dmint.authorize(
            self.delete_user,
            user_id,
            capability="database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        from dmint.approvals import ApprovalRecord

        return ApprovalRecord.create(
            request=authorized.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=self.policy_provenance,
            created_at=self.now,
            expires_at=self.expires,
        )

    def open_sqlite(self, path: Path | None = None, *, epoch: str = "epoch-1") -> SQLiteApprovalStore:
        return SQLiteApprovalStore(path or self.database, deployment_epoch=epoch, clock=lambda: self.now)


class TestFindByFingerprint(_ApprovalFixture):
    def test_find_by_fingerprint_is_part_of_the_public_store_abc(self) -> None:
        self.assertIn("find_by_fingerprint", ApprovalStore.__abstractmethods__)
        for store_type in (SQLiteApprovalStore, SQLAlchemyApprovalStore, ThreadSafeApprovalStore):
            self.assertTrue(hasattr(store_type, "find_by_fingerprint"))

    def test_sqlite_find_by_fingerprint_tracks_state_and_exact_scope(self) -> None:
        record = self.make_record()
        with self.open_sqlite() as store:
            store.save_pending(record)
            found = store.find_by_fingerprint(
                request_fingerprint=record.request_fingerprint,
                principal_id=record.request.agent_id,
                integration_id=record.integration_id,
            )
            self.assertIsNotNone(found)
            assert found is not None
            self.assertEqual(found.approval_id, record.approval_id)
            self.assertEqual(found.state.value, "PENDING")

            approved = record.approve(self.approver, now=self.now + timedelta(seconds=1))
            store.save_approved(approved)
            found = store.find_by_fingerprint(
                request_fingerprint=record.request_fingerprint,
                principal_id=record.request.agent_id,
                integration_id=record.integration_id,
            )
            self.assertIsNotNone(found)
            assert found is not None
            self.assertEqual(found.state.value, "APPROVED")

            self.assertIsNone(
                store.find_by_fingerprint(
                    request_fingerprint=record.request_fingerprint,
                    principal_id="someone-else",
                    integration_id=record.integration_id,
                )
            )
            self.assertIsNone(
                store.find_by_fingerprint(
                    request_fingerprint=record.request_fingerprint,
                    principal_id=record.request.agent_id,
                    integration_id="other-integration",
                )
            )

    def test_sqlite_find_by_fingerprint_does_not_cross_deployment_epochs(self) -> None:
        record = self.make_record()
        with self.open_sqlite(epoch="epoch-1") as store:
            store.save_pending(record)
        with self.open_sqlite(epoch="epoch-2") as other_epoch:
            self.assertIsNone(
                other_epoch.find_by_fingerprint(
                    request_fingerprint=record.request_fingerprint,
                    principal_id=record.request.agent_id,
                    integration_id=record.integration_id,
                )
            )

    def test_sqlalchemy_and_thread_safe_stores_share_find_by_fingerprint(self) -> None:
        record = self.make_record()
        sqlalchemy_db = self.root / "sqlalchemy.sqlite"
        sqlalchemy_store = SQLAlchemyApprovalStore(
            f"sqlite:///{sqlalchemy_db}",
            deployment_epoch="epoch-1",
            clock=lambda: self.now,
        )
        try:
            sqlalchemy_store.save_pending(record)
            found = sqlalchemy_store.find_by_fingerprint(
                request_fingerprint=record.request_fingerprint,
                principal_id=record.request.agent_id,
                integration_id=record.integration_id,
            )
            self.assertIsNotNone(found)
            assert found is not None
            self.assertEqual(found.approval_id, record.approval_id)
        finally:
            sqlalchemy_store.close()

        thread_db = self.root / "thread-safe.sqlite"
        thread_store = ThreadSafeApprovalStore(thread_db, deployment_epoch="epoch-1", clock=lambda: self.now)
        try:
            thread_store.save_pending(record)
            found = thread_store.find_by_fingerprint(
                request_fingerprint=record.request_fingerprint,
                principal_id=record.request.agent_id,
                integration_id=record.integration_id,
            )
            self.assertIsNotNone(found)
            assert found is not None
            self.assertEqual(found.approval_id, record.approval_id)
        finally:
            thread_store.close()


class TestBacklogError(_ApprovalFixture):
    def test_sqlite_backlog_uses_dedicated_error_code(self) -> None:
        with self.open_sqlite() as store:
            store._max_pending_per_principal = 1
            store.save_pending(self.make_record(user_id=1))
            with self.assertRaises(ApprovalBacklogError) as raised:
                store.save_pending(self.make_record(user_id=2))
        self.assertEqual(raised.exception.code, "DMT_APPROVAL_BACKLOG")

    def test_sqlalchemy_backlog_uses_dedicated_error_code(self) -> None:
        store = SQLAlchemyApprovalStore(
            f"sqlite:///{self.root / 'sqlalchemy-backlog.sqlite'}",
            deployment_epoch="epoch-1",
            max_pending_per_principal=1,
            clock=lambda: self.now,
        )
        try:
            store.save_pending(self.make_record(user_id=1))
            with self.assertRaises(ApprovalBacklogError) as raised:
                store.save_pending(self.make_record(user_id=2))
        finally:
            store.close()
        self.assertEqual(raised.exception.code, "DMT_APPROVAL_BACKLOG")


class TestRetryStoreLookup(_ApprovalFixture):
    def _build_dmint(self, store: ApprovalStore) -> Dmint:
        policy = Policy((Rule.approval_required("database", "delete", resource=ANY_RESOURCE),))
        return Dmint(
            policy,
            agent_id="agent-a",
            context=TrustedContext({"environment": "production"}),
            integration_id="local-runtime",
            approval_store=store,
            approval_verifier=ApprovalVerifier(
                trusted_issuers={self.authority.issuer_id: self.authority.public_key},
                audience=self.authority.audience,
                clock=lambda: self.now,
            ),
            policy_provenance=PolicyProvenance("policy-v1", policy_digest(policy), self.now),
            approval_ttl=timedelta(minutes=5),
            clock=lambda: self.now,
        )

    def _approve(self, dmint: Dmint, store: ApprovalStore):
        @dmint.protected(
            "database.delete",
            resource=lambda arguments: f"users/{arguments['user_id']}",
        )
        def delete_user(user_id):
            return user_id

        with self.assertRaises(ApprovalRequiredError) as raised:
            delete_user(123)
        pending = store.require_pending(raised.exception.approval_id)
        approved = store.approve_pending(
            pending.approval_id,
            authority=self.authority,
            approved_by="human-1",
            now=self.now,
        )
        matched = store.get_approved_assertion_for_request(
            request_fingerprint=pending.request_fingerprint,
            principal_id=pending.request.agent_id,
            integration_id=pending.integration_id,
        )
        self.assertIsNotNone(matched)
        assert matched is not None
        _, assertion = matched
        return delete_user, approved, assertion

    def test_consumed_replay_probe_uses_store_api_without_private_connection(self) -> None:
        store = ThreadSafeApprovalStore(
            self.root / "retry-thread-safe.sqlite",
            deployment_epoch="epoch-1",
            clock=lambda: self.now,
        )
        try:
            self.assertFalse(hasattr(store, "_connection"))
            dmint = self._build_dmint(store)
            delete_user, _, assertion = self._approve(dmint, store)
            self.assertEqual(dmint.retry(delete_user, 123, approval_credential=assertion), 123)
            with self.assertRaises(ApprovalConsumedError):
                dmint.retry(delete_user, 123)
        finally:
            store.close()

    def test_positional_none_retry_is_deprecated_but_still_executes(self) -> None:
        store = self.open_sqlite()
        try:
            dmint = self._build_dmint(store)
            delete_user, _, _ = self._approve(dmint, store)
            with self.assertWarns(DeprecationWarning):
                self.assertEqual(dmint.retry(delete_user, None, 123), 123)
        finally:
            store.close()


class TestConstructorAndLocalDefaults(_ApprovalFixture):
    def test_constructor_defaults_approval_ttl_when_a_store_is_supplied(self) -> None:
        store = self.open_sqlite()
        try:
            policy = Policy((Rule.allow("database", "read"),))
            dmint = Dmint(
                policy,
                agent_id="agent-a",
                context=TrustedContext({}),
                approval_store=store,
                policy_provenance=PolicyProvenance("policy-v1", policy_digest(policy), self.now),
            )
            self.assertEqual(dmint._approval_ttl, timedelta(minutes=10))
        finally:
            store.close()

        without_store = Dmint(
            Policy((Rule.allow("database", "read"),)),
            agent_id="agent-a",
            context=TrustedContext({}),
        )
        self.assertIsNone(without_store._approval_ttl)

    def test_local_trusts_public_sources_and_never_recreates_a_removed_signing_key(self) -> None:
        dmint_dir = self.root / "zone-a" / ".dmint"
        dmint_dir.mkdir(parents=True)
        external_private_key = Ed25519PrivateKey.generate()
        (dmint_dir / "trusted_issuer.json").write_text(
            json.dumps(
                {
                    "issuer_id": "dmint-authority",
                    "public_key_hex": public_key_hex(external_private_key.public_key()),
                }
            ),
            encoding="utf-8",
        )

        dmint = Dmint.local(
            Policy((Rule.allow("database", "read"),)),
            state_dir=dmint_dir,
            clock=lambda: self.now,
        )
        try:
            self.assertFalse((dmint_dir / "signing.key").exists())
            trusted = dmint._approval_verifier._trusted_issuers["dmint-authority"]
            keys = trusted if isinstance(trusted, tuple) else (trusted,)
            self.assertIn(public_key_hex(external_private_key.public_key()), {public_key_hex(k) for k in keys})
        finally:
            assert dmint._approval_store is not None
            dmint._approval_store.close()

    def test_local_writes_trusted_issuer_file_when_it_generates_a_signing_key(self) -> None:
        dmint_dir = self.root / "zone-b" / ".dmint"
        with patch("dmint.core.verification.load_trusted_issuers_from_public_sources", return_value={}):
            dmint = Dmint.local(
                Policy((Rule.allow("database", "read"),)),
                state_dir=dmint_dir,
                clock=lambda: self.now,
            )
        try:
            self.assertTrue((dmint_dir / "signing.key").exists())
            trusted_path = dmint_dir / "trusted_issuer.json"
            self.assertTrue(trusted_path.exists())
            payload = json.loads(trusted_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["issuer_id"], "dmint-authority")
            self.assertEqual(len(payload["public_key_hex"]), 64)
        finally:
            assert dmint._approval_store is not None
            dmint._approval_store.close()

    def test_local_warns_when_state_directory_permissions_cannot_be_restricted(self) -> None:
        dmint_dir = self.root / "zone-c" / ".dmint"
        dmint_dir.mkdir(parents=True)
        os.chmod(dmint_dir, 0o750)
        real_chmod = os.chmod

        def deny_state_dir_chmod(path, mode, *args, **kwargs):
            if str(path) == str(dmint_dir):
                raise OSError("permission denied")
            return real_chmod(path, mode, *args, **kwargs)

        with (
            patch("dmint.core.verification.load_trusted_issuers_from_public_sources", return_value={}),
            patch("os.chmod", side_effect=deny_state_dir_chmod),
            self.assertWarns(RuntimeWarning),
        ):
            dmint = Dmint.local(
                Policy((Rule.allow("database", "read"),)),
                state_dir=dmint_dir,
                clock=lambda: self.now,
            )
        assert dmint._approval_store is not None
        dmint._approval_store.close()

    def test_local_and_reload_derive_version_id_from_deployment_epoch_and_digest(self) -> None:
        policy_path = self.root / "policy.json"
        policy_path.write_text(Policy((Rule.allow("database", "read"),)).to_json(), encoding="utf-8")
        dmint_dir = self.root / "zone-d" / ".dmint"

        with patch.dict(os.environ, {"DMINT_DEPLOYMENT_EPOCH": "prod-epoch"}, clear=False):
            dmint = Dmint.local(
                policy_path,
                state_dir=dmint_dir,
                clock=lambda: self.now,
            )
            try:
                assert dmint._policy_provenance is not None
                initial_version = dmint._policy_provenance.version_id
                self.assertTrue(initial_version.startswith("prod-epoch-"))
                self.assertEqual(len(initial_version), len("prod-epoch-") + 8)

                policy_path.write_text(
                    Policy(
                        (
                            Rule.allow("database", "read"),
                            Rule.allow("database", "list"),
                        )
                    ).to_json(),
                    encoding="utf-8",
                )
                dmint.reload_policy()
                assert dmint._policy_provenance is not None
                self.assertNotEqual(dmint._policy_provenance.version_id, initial_version)
                self.assertTrue(dmint._policy_provenance.version_id.startswith("prod-epoch-"))
            finally:
                assert dmint._approval_store is not None
                dmint._approval_store.close()

    def test_local_does_not_create_integrity_key_when_environment_supplies_one(self) -> None:
        dmint_dir = self.root / "zone-e" / ".dmint"
        env_key = bytes(range(32)).hex()
        with (
            patch("dmint.core.verification.load_trusted_issuers_from_public_sources", return_value={}),
            patch.dict(os.environ, {"DMINT_INTEGRITY_KEY": env_key}, clear=False),
        ):
            dmint = Dmint.local(
                Policy((Rule.allow("database", "read"),)),
                state_dir=dmint_dir,
                clock=lambda: self.now,
            )
        try:
            self.assertFalse((dmint_dir / "integrity.key").exists())
            assert dmint._approval_store is not None
            self.assertEqual(dmint._approval_store._integrity_key, bytes.fromhex(env_key))
        finally:
            assert dmint._approval_store is not None
            dmint._approval_store.close()


class TestTrustedKeyRotation(_ApprovalFixture):
    def test_environment_accepts_comma_separated_public_keys(self) -> None:
        first = Ed25519PrivateKey.generate().public_key()
        second = Ed25519PrivateKey.generate().public_key()
        with patch.dict(
            os.environ,
            {"DMINT_TRUSTED_PUBLIC_KEY_HEX": f"{public_key_hex(first)},{public_key_hex(second)}"},
            clear=False,
        ):
            trusted = load_trusted_issuers_from_public_sources(self.root)
        value = trusted["dmint-authority"]
        keys = value if isinstance(value, tuple) else (value,)
        self.assertEqual({public_key_hex(k) for k in keys}, {public_key_hex(first), public_key_hex(second)})

    def test_trusted_issuer_json_keys_array_and_verifier_accept_both_rotation_keys(self) -> None:
        first_private = Ed25519PrivateKey.generate()
        second_private = Ed25519PrivateKey.generate()
        dmint_dir = self.root / "rotation" / ".dmint"
        dmint_dir.mkdir(parents=True)
        (dmint_dir / "trusted_issuer.json").write_text(
            json.dumps(
                {
                    "issuer_id": "rotating-authority",
                    "keys": [
                        {"public_key_hex": public_key_hex(first_private.public_key())},
                        {"public_key_hex": public_key_hex(second_private.public_key())},
                    ],
                }
            ),
            encoding="utf-8",
        )

        trusted = load_trusted_issuers_from_public_sources(self.root / "rotation")
        value = trusted["rotating-authority"]
        keys = value if isinstance(value, tuple) else (value,)
        self.assertEqual(
            {public_key_hex(k) for k in keys},
            {public_key_hex(first_private.public_key()), public_key_hex(second_private.public_key())},
        )

        record = self.make_record().approve(self.approver, now=self.now + timedelta(seconds=1))
        verifier = ApprovalVerifier(
            trusted_issuers={"rotating-authority": keys},
            audience=self.authority.audience,
            clock=lambda: self.now,
        )
        for private_key in (first_private, second_private):
            authority = LocalApprovalAuthority(
                issuer_id="rotating-authority",
                audience=self.authority.audience,
                private_key=private_key,
            )
            assertion = authority.issue(record, self.approver, now=self.now)
            verifier.verify(assertion, record, now=self.now)


class TestPolicyFileGuards(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.policy = Policy((Rule.allow("database", "read"),))
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(self.policy.to_json(), encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_symlink_is_rejected_by_flag_and_environment(self) -> None:
        link = self.root / "policy-link.json"
        link.symlink_to(self.policy_path)
        with self.assertRaises(PolicyError):
            Policy.from_file(link, allow_symlinks=False)
        with patch.dict(os.environ, {"DMINT_REJECT_POLICY_SYMLINKS": "1"}, clear=False):
            with self.assertRaises(PolicyError):
                Policy.from_file(link)

    def test_non_regular_file_is_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            Policy.from_file(self.root)

    def test_size_limit_is_enforced_before_parsing(self) -> None:
        with self.assertRaises(PolicyError):
            Policy.from_file(self.policy_path, max_bytes=8)

    def test_regular_file_still_loads(self) -> None:
        loaded = Policy.from_file(self.policy_path)
        self.assertEqual(len(loaded.rules), 1)


class TestSecretFileLoaders(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_database_url_file_is_used_when_direct_url_is_absent(self) -> None:
        database = self.root / "from-file.sqlite"
        url = f"sqlite:///{database}"
        url_file = self.root / "database-url"
        url_file.write_text(url + "\n", encoding="utf-8")
        with patch.dict(
            os.environ,
            {"DMINT_DATABASE_URL_FILE": str(url_file)},
            clear=False,
        ):
            os.environ.pop("DMINT_DATABASE_URL", None)
            self.assertEqual(resolve_database_url(), url)
            store = create_approval_store(deployment_epoch="epoch-1")
            try:
                self.assertIsInstance(store, SQLAlchemyApprovalStore)
            finally:
                store.close()

    def test_missing_database_url_file_fails_loudly(self) -> None:
        with patch.dict(
            os.environ,
            {"DMINT_DATABASE_URL_FILE": str(self.root / "missing")},
            clear=False,
        ):
            os.environ.pop("DMINT_DATABASE_URL", None)
            with self.assertRaises(ApprovalStoreConfigurationError):
                resolve_database_url()

    def test_dashboard_token_file_environment_is_resolved(self) -> None:
        from dmint.dashboard.app import create_app
        from dmint.dashboard.core_client import CoreClient

        token_file = self.root / "dashboard-token"
        token_file.write_text("file-token\n", encoding="utf-8")
        os.chmod(token_file, 0o600)
        store = ThreadSafeApprovalStore(self.root / "dashboard.sqlite", deployment_epoch="epoch-1")
        authority = LocalApprovalAuthority(
            issuer_id="dashboard-authority",
            audience="dmint/dashboard/v1",
            private_key=Ed25519PrivateKey.generate(),
        )
        try:
            client = CoreClient(store=store, authority=authority, approver_id="dashboard-human")
            with patch.dict(
                os.environ,
                {"DMINT_DASHBOARD_TOKEN_FILE": str(token_file)},
                clear=False,
            ):
                os.environ.pop("DMINT_DASHBOARD_TOKEN", None)
                os.environ.pop("DMINT_DASHBOARD_PASSWORD", None)
                app = create_app(client)
            self.assertEqual(app.state.auth_token, "file-token")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
