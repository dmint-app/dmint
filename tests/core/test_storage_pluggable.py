"""Tests for pluggable approval storage: interface, factory, SQLite default, and PostgreSQL."""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dmint import (
    ANY_RESOURCE,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    ApprovalStore,
    ApprovalStoreConfigurationError,
    ApprovalStoreError,
    ApprovalVerifier,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    SQLAlchemyApprovalStore,
    SQLiteApprovalStore,
    TrustedContext,
    create_approval_store,
)
from dmint.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalConsumedError,
    ApprovalNotFoundError,
    ApprovalRequiredError,
)

POSTGRES_TEST_URL = os.environ.get(
    "DMINT_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/dmint_test",
)


def _normalize_pg_url(url: str) -> str:
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        try:
            import psycopg  # noqa: F401
        except ImportError:
            try:
                import psycopg2  # noqa: F401

                url = "postgresql+psycopg2://" + url[len("postgresql://") :]
            except ImportError:
                pass
    return url


def _is_postgres_available(url: str) -> bool:
    try:
        from sqlalchemy import create_engine, text

        eng = create_engine(_normalize_pg_url(url), connect_args={"connect_timeout": 2})
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        eng.dispose()
        return True
    except Exception:
        return False


POSTGRES_AVAILABLE = _is_postgres_available(POSTGRES_TEST_URL)


class StoragePluggableInterfaceTests(unittest.TestCase):
    """Test interface inheritance and factory startup behavior."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "test.db"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_sqlite_inherits_approval_store_interface(self) -> None:
        store = SQLiteApprovalStore(self.db_path, deployment_epoch="ep1")
        self.assertIsInstance(store, ApprovalStore)
        store.close()

    def test_factory_unset_url_defaults_to_sqlite(self) -> None:
        # Guarantee DMINT_DATABASE_URL is not set
        orig = os.environ.pop("DMINT_DATABASE_URL", None)
        try:
            store = create_approval_store(
                default_sqlite_path=self.db_path,
                deployment_epoch="ep1",
            )
            self.assertIsInstance(store, SQLiteApprovalStore)
            self.assertIsInstance(store, ApprovalStore)
            self.assertTrue(self.db_path.exists())
            store.close()
        finally:
            if orig is not None:
                os.environ["DMINT_DATABASE_URL"] = orig

    def test_factory_empty_string_url_defaults_to_sqlite(self) -> None:
        orig = os.environ.get("DMINT_DATABASE_URL")
        os.environ["DMINT_DATABASE_URL"] = "   "
        try:
            store = create_approval_store(
                default_sqlite_path=self.db_path,
                deployment_epoch="ep1",
            )
            self.assertIsInstance(store, SQLiteApprovalStore)
            self.assertIsInstance(store, ApprovalStore)
            store.close()
        finally:
            if orig is not None:
                os.environ["DMINT_DATABASE_URL"] = orig
            else:
                os.environ.pop("DMINT_DATABASE_URL", None)

    def test_factory_invalid_scheme_fails_loud_without_falling_back(self) -> None:
        orig = os.environ.get("DMINT_DATABASE_URL")
        os.environ["DMINT_DATABASE_URL"] = "mysql://user:pass@localhost:3306/db"
        try:
            with self.assertRaises(ApprovalStoreConfigurationError) as ctx:
                create_approval_store(
                    default_sqlite_path=self.db_path,
                    deployment_epoch="ep1",
                )
            self.assertIn("Unsupported database scheme", str(ctx.exception))
            # Verify SQLite DB was NOT created as a silent fallback
            self.assertFalse(self.db_path.exists())
        finally:
            if orig is not None:
                os.environ["DMINT_DATABASE_URL"] = orig
            else:
                os.environ.pop("DMINT_DATABASE_URL", None)

    def test_factory_malformed_url_fails_loud(self) -> None:
        with self.assertRaises(ApprovalStoreConfigurationError):
            create_approval_store(
                database_url="postgresql://",
                deployment_epoch="ep1",
            )
        self.assertFalse(self.db_path.exists())

    def test_factory_unreachable_host_fails_loud_at_startup(self) -> None:
        unreachable = "postgresql://user:pass@localhost:59999/nonexistent_db"
        with self.assertRaises(ApprovalStoreConfigurationError) as ctx:
            create_approval_store(
                database_url=unreachable,
                deployment_epoch="ep1",
            )
        self.assertIn("Failed to connect", str(ctx.exception))
        self.assertFalse(self.db_path.exists())

    def test_factory_sqlite_url_instantiates_sqlalchemy_store(self) -> None:
        sqlite_url = f"sqlite:///{self.db_path}"
        store = create_approval_store(
            database_url=sqlite_url,
            deployment_epoch="ep1",
        )
        self.assertIsInstance(store, SQLAlchemyApprovalStore)
        self.assertIsInstance(store, ApprovalStore)
        store.close()


@unittest.skipUnless(POSTGRES_AVAILABLE, f"PostgreSQL not reachable at {POSTGRES_TEST_URL}")
class PostgreSQLStorageIntegrationTests(unittest.TestCase):
    """Full lifecycle, security guarantees, and concurrency tests against live PostgreSQL."""

    def setUp(self) -> None:
        self.now = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.expires = self.now + timedelta(minutes=15)
        self.epoch = f"pg-epoch-{os.urandom(4).hex()}"
        self.authority = LocalApprovalAuthority(
            issuer_id="authority-pg-test",
            audience="local-runtime",
            clock=lambda: self.now,
        )
        self.verifier = ApprovalVerifier(
            trusted_issuers={self.authority.issuer_id: self.authority.public_key},
            audience=self.authority.audience,
        )
        self.store = SQLAlchemyApprovalStore(
            POSTGRES_TEST_URL,
            deployment_epoch=self.epoch,
            clock=lambda: self.now,
        )

        # Clear tables for test isolation
        from sqlalchemy import delete

        with self.store.engine.begin() as conn:
            conn.execute(delete(self.store._records_table))
            conn.execute(delete(self.store._policy_table))
            conn.execute(delete(self.store._recovery_table))

        self.dmint = Dmint(
            Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),)),
            agent_id="agent-pg",
            context=TrustedContext({"env": "test"}),
        )

        def delete_fn(target_id: int) -> int:
            return target_id

        self.dmint.register(delete_fn, "database.delete", resource=lambda a: f"item/{a['target_id']}")
        self.delete_fn = delete_fn

    def tearDown(self) -> None:
        self.store.close()

    def make_record(self, *, target_id: int = 42) -> ApprovalRecord:
        auth_req = self.dmint.authorize(
            self.delete_fn,
            target_id,
            capability="database.delete",
            resource=lambda a: f"item/{a['target_id']}",
        )
        return ApprovalRecord.create(
            request=auth_req.request,
            integration_id="local-runtime",
            capability_id="database.delete",
            policy_provenance=PolicyProvenance(
                "p-pg-v1",
                hashlib.sha256(b"p-pg-v1").hexdigest(),
                self.now,
            ),
            created_at=self.now,
            expires_at=self.expires,
        )

    def test_save_pending_and_require_pending_roundtrip(self) -> None:
        record = self.make_record()
        saved = self.store.save_pending(record)
        self.assertEqual(saved.approval_id, record.approval_id)

        loaded = self.store.require_pending(record.approval_id)
        self.assertEqual(loaded.approval_id, record.approval_id)
        self.assertEqual(loaded.state, ApprovalState.PENDING)
        self.assertEqual(loaded.request, record.request)
        self.assertEqual(loaded.request_fingerprint, record.request_fingerprint)
        self.assertEqual(loaded.created_at, record.created_at)
        self.assertEqual(loaded.expires_at, record.expires_at)

    def test_authoritative_policy_storage_on_postgres(self) -> None:
        policy = Policy((Rule.allow("storage", "read"),))
        provenance = PolicyProvenance("pol-v1", hashlib.sha256(b"pol-v1").hexdigest(), self.now)

        self.store.set_authoritative_policy(policy, provenance)
        retrieved = self.store.get_authoritative_policy()
        self.assertIsNotNone(retrieved)
        assert retrieved is not None
        p_loaded, prov_loaded = retrieved
        self.assertEqual(prov_loaded.version_id, "pol-v1")
        self.assertEqual(prov_loaded.policy_digest, provenance.policy_digest)

    def test_cleanup_expired_removes_expired_pending_only(self) -> None:
        record = self.make_record()
        self.store.save_pending(record)

        # Before expiration: cleanup returns 0
        cleaned = self.store.cleanup_expired(now=self.now)
        self.assertEqual(cleaned, 0)
        self.assertIsNotNone(self.store.get(record.approval_id))

        # After expiration: cleanup removes row
        cleaned = self.store.cleanup_expired(now=self.expires + timedelta(seconds=1))
        self.assertEqual(cleaned, 1)
        self.assertIsNone(self.store.get(record.approval_id))

    def test_approve_and_single_use_consumption_on_postgres(self) -> None:
        record = self.make_record()
        self.store.save_pending(record)

        # 1. Approve
        approved = self.store.approve_pending(
            record.approval_id,
            authority=self.authority,
            approved_by="sec-admin",
            now=self.now,
        )
        self.assertEqual(approved.state, ApprovalState.APPROVED)
        self.assertEqual(self.store.get(record.approval_id).state, ApprovalState.APPROVED)

        # 2. Issue assertion for consumption
        approver = ApprovalAuthority._from_trusted_boundary(
            self.authority.issuer_id,
            "sec-admin",
            ApprovalAuthorityKind.HUMAN,
        )
        assertion = self.authority.issue(record, approver, now=self.now)

        # 3. Consume
        consumed = self.store.consume_approved(
            approval_id=record.approval_id,
            credential=assertion,
            expected_request=record.request,
            verifier=self.verifier,
            now=self.now + timedelta(seconds=1),
        )
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)

        # 4. Replay fails closed
        with self.assertRaises(ApprovalConsumedError):
            self.store.consume_approved(
                approval_id=record.approval_id,
                credential=assertion,
                expected_request=record.request,
                verifier=self.verifier,
                now=self.now + timedelta(seconds=2),
            )

    def test_reject_pending_on_postgres(self) -> None:
        record = self.make_record()
        self.store.save_pending(record)

        rejected = self.store.reject_pending(
            record.approval_id,
            authority=self.authority,
            rejected_by="sec-auditor",
            reason="Unsafe operation in production",
            now=self.now,
        )
        self.assertEqual(rejected.state, ApprovalState.REJECTED)
        self.assertEqual(rejected.state_reason, "Unsafe operation in production")

    def test_concurrent_consumption_on_postgres_allows_exactly_one_winner(self) -> None:
        """Prove that 8 concurrent consume attempts against Postgres result in 1 success and 7 safe failures."""
        record = self.make_record()
        self.store.save_pending(record)

        approved = self.store.approve_pending(
            record.approval_id,
            authority=self.authority,
            approved_by="sec-admin",
            now=self.now,
        )
        approver = ApprovalAuthority._from_trusted_boundary(
            self.authority.issuer_id,
            "sec-admin",
            ApprovalAuthorityKind.HUMAN,
        )
        assertion = self.authority.issue(record, approver, now=self.now)

        barrier = threading.Barrier(8)

        def worker_attempt(_idx: int) -> str:
            barrier.wait()
            try:
                self.store.consume_approved(
                    approval_id=approved.approval_id,
                    credential=assertion,
                    expected_request=approved.request,
                    verifier=self.verifier,
                    now=self.now + timedelta(seconds=2),
                )
                return "success"
            except (ApprovalConsumedError, ApprovalConcurrentConsumeError) as exc:
                return exc.code
            except Exception as exc:
                return type(exc).__name__

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(worker_attempt, range(8)))

        self.assertEqual(
            results.count("success"),
            1,
            f"Expected exactly 1 success under Postgres concurrency, got {results}",
        )
        failures = [r for r in results if r != "success"]
        self.assertEqual(len(failures), 7)
        for f in failures:
            self.assertIn(f, ("DMT_APPROVAL_CONSUMED", "DMT_APPROVAL_CONCURRENT_CONSUME"))

        # Verify state in DB is CONSUMED
        final_record = self.store.get(approved.approval_id)
        self.assertIsNotNone(final_record)
        self.assertEqual(final_record.state, ApprovalState.CONSUMED)

    def test_concurrent_approve_on_postgres_allows_exactly_one_winner(self) -> None:
        """Prove that 8 concurrent approve attempts against Postgres result in 1 success and 7 safe failures."""
        record = self.make_record()
        self.store.save_pending(record)

        barrier = threading.Barrier(8)

        def worker_attempt(_idx: int) -> str:
            barrier.wait()
            try:
                self.store.approve_pending(
                    record.approval_id,
                    authority=self.authority,
                    approved_by=f"admin-{_idx}",
                    now=self.now,
                )
                return "success"
            except (ApprovalStoreError, Exception) as exc:
                return getattr(exc, "code", type(exc).__name__)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(worker_attempt, range(8)))

        self.assertEqual(
            results.count("success"),
            1,
            f"Expected exactly 1 approve success under Postgres concurrency, got {results}",
        )
        self.assertEqual(len([r for r in results if r != "success"]), 7)

    def test_dmint_engine_retry_with_postgres_storage(self) -> None:
        """Prove that Dmint enforcement engine works seamlessly with PostgreSQL approval store."""
        executed: list[int] = []

        policy = Policy((Rule.approval_required("database", "delete", resource=ANY_RESOURCE),))
        prov = PolicyProvenance("p1", hashlib.sha256(b"p1").hexdigest(), self.now)

        engine_dmint = Dmint(
            policy,
            agent_id="agent-pg-retry",
            context=TrustedContext({"env": "prod"}),
            approval_store=self.store,
            approval_verifier=self.verifier,
            policy_provenance=prov,
            approval_ttl=timedelta(minutes=10),
            clock=lambda: self.now,
        )

        @engine_dmint.protected("database.delete", resource=lambda a: f"item/{a['target_id']}")
        def delete_target(target_id: int) -> int:
            executed.append(target_id)
            return target_id

        # 1. First execution raises APPROVAL_REQUIRED and saves to Postgres
        with self.assertRaises(ApprovalRequiredError) as exc_info:
            delete_target(99)

        approval_id = exc_info.exception.approval_id
        pg_record = self.store.require_pending(approval_id)
        self.assertEqual(pg_record.state, ApprovalState.PENDING)

        # 2. Approve the record
        self.store.approve_pending(
            approval_id,
            authority=self.authority,
            approved_by="human-reviewer",
            now=self.now,
        )
        approver = ApprovalAuthority._from_trusted_boundary(
            self.authority.issuer_id,
            "human-reviewer",
            ApprovalAuthorityKind.HUMAN,
        )
        assertion = self.authority.issue(pg_record, approver, now=self.now)

        # 3. Retry and consume via PostgreSQL
        result = engine_dmint.retry(delete_target, 99, approval_credential=assertion)
        self.assertEqual(result, 99)
        self.assertEqual(executed, [99])

        # 4. Record is now CONSUMED in Postgres
        self.assertEqual(self.store.get(approval_id).state, ApprovalState.CONSUMED)

        # 5. Second retry fails closed with replay protection
        with self.assertRaises(Exception) as replay_exc:
            engine_dmint.retry(delete_target, 99, approval_credential=assertion)
        self.assertIn("consumed", str(replay_exc.exception).lower())

    def test_concurrent_retries_with_postgres_storage_allows_exactly_one_execution(self) -> None:
        """Prove that 8 concurrent retries via Dmint engine against PostgreSQL execute at most once."""
        executed: list[int] = []

        policy = Policy((Rule.approval_required("database", "delete", resource=ANY_RESOURCE),))
        prov = PolicyProvenance("p1", hashlib.sha256(b"p1").hexdigest(), self.now)

        engine_dmint = Dmint(
            policy,
            agent_id="agent-pg-retry",
            context=TrustedContext({"env": "prod"}),
            approval_store=self.store,
            approval_verifier=self.verifier,
            policy_provenance=prov,
            approval_ttl=timedelta(minutes=10),
            clock=lambda: self.now,
        )

        @engine_dmint.protected("database.delete", resource=lambda a: f"item/{a['target_id']}")
        def delete_target(target_id: int) -> int:
            executed.append(target_id)
            return target_id

        # 1. Trigger APPROVAL_REQUIRED
        with self.assertRaises(ApprovalRequiredError) as exc_info:
            delete_target(77)

        approval_id = exc_info.exception.approval_id
        pg_record = self.store.require_pending(approval_id)

        # 2. Approve
        self.store.approve_pending(
            approval_id,
            authority=self.authority,
            approved_by="human-reviewer",
            now=self.now,
        )
        approver = ApprovalAuthority._from_trusted_boundary(
            self.authority.issuer_id,
            "human-reviewer",
            ApprovalAuthorityKind.HUMAN,
        )
        assertion = self.authority.issue(pg_record, approver, now=self.now)

        # 3. 8 concurrent retries race to consume the approval
        barrier = threading.Barrier(8)

        def attempt_retry(_idx: int) -> str:
            barrier.wait()
            try:
                engine_dmint.retry(delete_target, 77, approval_credential=assertion)
                return "success"
            except Exception as exc:
                return getattr(exc, "code", type(exc).__name__)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(attempt_retry, range(8)))

        self.assertEqual(results.count("success"), 1, f"Results: {results}")
        self.assertEqual(len(executed), 1, "Tool callable was executed more than once!")
        failures = [r for r in results if r != "success"]
        self.assertEqual(len(failures), 7)
        for f in failures:
            self.assertIn(f, ("DMT_APPROVAL_CONSUMED", "DMT_APPROVAL_CONCURRENT_CONSUME"))

    def test_multi_epoch_listing_on_postgres_does_not_crash_or_leak(self) -> None:
        """Listing pending or historical records on PostgreSQL filters by deployment_epoch."""
        from dmint.core.storage.sql import SQLAlchemyApprovalStore

        other_epoch = "epoch-other-test"
        other_store = SQLAlchemyApprovalStore(
            self.store.engine,
            deployment_epoch=other_epoch,
            clock=lambda: self.now,
        )

        record_main = self.make_record(target_id=101)
        self.store.save_pending(record_main)

        record_other = self.make_record(target_id=102)
        other_store.save_pending(record_other)

        # self.store (self.epoch) should only see record_main
        main_pending = self.store.list_pending()
        self.assertEqual([r.approval_id for r in main_pending], [record_main.approval_id])

        main_records = self.store.list_records()
        self.assertIn(record_main.approval_id, [r.approval_id for r in main_records])
        self.assertNotIn(record_other.approval_id, [r.approval_id for r in main_records])

        # other_store (other_epoch) should only see record_other
        other_pending = other_store.list_pending()
        self.assertEqual([r.approval_id for r in other_pending], [record_other.approval_id])

        other_records = other_store.list_records()
        self.assertIn(record_other.approval_id, [r.approval_id for r in other_records])
        self.assertNotIn(record_main.approval_id, [r.approval_id for r in other_records])
