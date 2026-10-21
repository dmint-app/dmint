"""Dashboard approval races over one shared SQLite connection.

``create_app`` accepts a ``CoreClient`` built on an injected
``SQLiteApprovalStore``.  Simultaneous approve/reject requests through the
dashboard must not produce HTTP 5xx responses or leave records undecided:
the Core store serializes them, exactly one decision wins, and the losing
request receives a typed, user-facing message rather than a 500.
"""

from __future__ import annotations

import threading
import urllib.parse
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from dmint import ApprovalState, LocalApprovalAuthority, SQLiteApprovalStore

from dmint.dashboard.app import create_app
from dmint.dashboard.core_client import CoreClient

from tests.dashboard.conftest import NOW, make_dmint, make_record


def _shared_store(tmp_path: Path) -> SQLiteApprovalStore:
    return SQLiteApprovalStore(tmp_path / "races.sqlite", deployment_epoch="races-epoch", clock=lambda: NOW)


def _build_app(store: SQLiteApprovalStore):
    authority = LocalApprovalAuthority(
        issuer_id="races-dashboard",
        audience="dmint/dashboard/v1",
        private_key=Ed25519PrivateKey.generate(),
        clock=lambda: NOW,
    )
    client = CoreClient(store=store, authority=authority, approver_id="races-human")
    return create_app(
        client,
        auth_token="races-dashboard-token",
        allowed_hosts={"localhost", "127.0.0.1", "[::1]", "testserver"},
    )


def _authenticate(http: TestClient, app, identity: str) -> None:
    http.headers["Origin"] = "http://testserver"
    http.post("/login", data={"token": app.state.auth_token, "identity": identity})
    session_id = http.cookies.get("dmint_session")
    if session_id and session_id in app.state.sessions:
        http.headers["X-CSRF-Token"] = app.state.sessions[session_id]["csrf_token"]


def _two_sessions(app) -> tuple[TestClient, TestClient]:
    first = TestClient(app, raise_server_exceptions=False)
    second = TestClient(app, raise_server_exceptions=False)
    _authenticate(first, app, identity="first-human")
    _authenticate(second, app, identity="second-human")
    return first, second


def _fire_together(*calls: Callable[[], object]) -> list[tuple[int, str]]:
    """Issue every HTTP call from its own thread, released by a shared barrier."""
    barrier = threading.Barrier(len(calls))
    responses: list[tuple[int, str]] = [(-1, "")] * len(calls)

    def runner(index: int, call: Callable[[], object]) -> None:
        barrier.wait(timeout=10)
        response = call()
        responses[index] = (
            response.status_code,  # type: ignore[attr-defined]
            urllib.parse.unquote_plus(response.headers.get("location", "")),  # type: ignore[attr-defined]
        )

    threads = [threading.Thread(target=runner, args=(index, call)) for index, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    return responses


def test_simultaneous_approve_over_one_shared_store(tmp_path: Path) -> None:
    store = _shared_store(tmp_path)
    try:
        app = _build_app(store)
        record = make_record(make_dmint(), user_id=1)
        store.save_pending(record)

        first, second = _two_sessions(app)
        results = _fire_together(
            lambda: first.post(f"/approvals/{record.approval_id}/approve", data={}, follow_redirects=False),
            lambda: second.post(f"/approvals/{record.approval_id}/approve", data={}, follow_redirects=False),
        )

        codes = [code for code, _ in results]
        locations = [location for _, location in results]
        assert all(code < 500 for code in codes), results
        assert sum("Approval granted successfully" in location for location in locations) == 1, results
        assert not any("Internal error" in location for location in locations), results
        loaded = store.get(record.approval_id)
        assert loaded is not None and loaded.state is ApprovalState.APPROVED
    finally:
        store.close()


def test_simultaneous_approve_and_reject_over_one_shared_store(tmp_path: Path) -> None:
    store = _shared_store(tmp_path)
    try:
        app = _build_app(store)
        record = make_record(make_dmint(), user_id=2)
        store.save_pending(record)

        first, second = _two_sessions(app)
        results = _fire_together(
            lambda: first.post(f"/approvals/{record.approval_id}/approve", data={}, follow_redirects=False),
            lambda: second.post(
                f"/approvals/{record.approval_id}/reject", data={"reason": "race"}, follow_redirects=False
            ),
        )

        codes = [code for code, _ in results]
        locations = [location for _, location in results]
        assert all(code < 500 for code in codes), results
        decided = sum(
            "Approval granted successfully" in location or "Approval rejected" in location for location in locations
        )
        assert decided == 1, results
        assert not any("Internal error" in location for location in locations), results
        loaded = store.get(record.approval_id)
        assert loaded is not None and loaded.state in (ApprovalState.APPROVED, ApprovalState.REJECTED)
    finally:
        store.close()
