"""Shared test fixtures for dmint-dashboard tests."""

from __future__ import annotations

import hashlib
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from dmint import (
    ANY_RESOURCE,
    ApprovalState,
    Dmint,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    SQLiteApprovalStore,
    TrustedContext,
)
from dmint.approvals import ApprovalRecord

from dmint.dashboard.app import create_app
from dmint.dashboard.core_client import CoreClient

# ---------------------------------------------------------------------------
# Shared time references
# ---------------------------------------------------------------------------
NOW = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
EXPIRES = NOW + timedelta(minutes=10)


def make_provenance(now: datetime = NOW) -> PolicyProvenance:
    return PolicyProvenance(
        "test-policy-v1",
        hashlib.sha256(b"test-policy-v1").hexdigest(),
        now,
    )


# ---------------------------------------------------------------------------
# Core object factories
# ---------------------------------------------------------------------------


def delete_user(user_id):
    return user_id


def make_dmint() -> Dmint:
    policy = Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),))
    d = Dmint(policy, agent_id="test-agent", context=TrustedContext({"env": "test"}))
    d.register(
        delete_user,
        "database.delete",
        resource=lambda arguments: f"users/{arguments['user_id']}",
    )
    return d


def make_record(dmint: Dmint, *, user_id: int = 1, now: datetime = NOW) -> ApprovalRecord:
    authorized = dmint.authorize(
        delete_user,
        user_id,
        capability="database.delete",
        resource=lambda arguments: f"users/{arguments['user_id']}",
    )
    return ApprovalRecord.create(
        request=authorized.request,
        integration_id="test-runtime",
        capability_id="database.delete",
        policy_provenance=make_provenance(now),
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmpdir_path(tmp_path):
    return tmp_path


from dmint.dashboard.core_client import CoreClient, ThreadSafeApprovalStore


@pytest.fixture()
def store(tmp_path):
    """Real ThreadSafeApprovalStore backed by a temp file."""
    db = tmp_path / "test.sqlite"
    s = ThreadSafeApprovalStore(db, deployment_epoch="test-epoch", clock=lambda: NOW)
    yield s
    s.close()


@pytest.fixture()
def authority():
    return LocalApprovalAuthority(
        issuer_id="test-dashboard",
        audience="dmint/dashboard/v1",
        clock=lambda: NOW,
    )


@pytest.fixture()
def client_obj(store, authority):
    """CoreClient wrapping the test store."""
    return CoreClient(store=store, authority=authority, approver_id="test-human")


@pytest.fixture()
def dmint_inst():
    return make_dmint()


@pytest.fixture()
def test_client(client_obj):
    """Starlette TestClient for route tests."""
    app = create_app(client_obj)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def pending_record(store, dmint_inst):
    """Save and return one pending record."""
    record = make_record(dmint_inst, user_id=42)
    store.save_pending(record)
    return record
