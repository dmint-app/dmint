"""Security constraint tests.

Verify that the dashboard code enforces the architectural boundary:
  - No SQL
  - No sqlite3 import
  - No private Core member access
  - No table creation
  - No fingerprint calculation
  - No approval logic

Also: a smoke test that verifies the app boots and /health responds.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from dmint import dashboard as dmint_dashboard


_PKG_DIR = Path(dmint_dashboard.__file__).parent
_ALL_PY_FILES = list(_PKG_DIR.rglob("*.py"))


class TestSecurityConstraints:
    """Dashboard code must stay on the correct side of the architectural boundary."""

    def _source_of_all(self) -> list[tuple[Path, str]]:
        return [(f, f.read_text(encoding="utf-8")) for f in _ALL_PY_FILES]

    def test_dashboard_does_not_import_sqlite3(self):
        """Dashboard must not import sqlite3 — Core owns the database."""
        for path, source in self._source_of_all():
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name != "sqlite3", f"sqlite3 directly imported in {path.name}"
                elif isinstance(node, ast.ImportFrom):
                    assert node.module != "sqlite3", f"sqlite3 imported from in {path.name}"

    def test_dashboard_contains_no_raw_sql(self):
        """Dashboard must not contain SQL query strings."""
        sql_patterns = [
            "SELECT ",
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "CREATE TABLE",
            "DROP TABLE",
            "ALTER TABLE",
        ]
        for path, source in self._source_of_all():
            for pattern in sql_patterns:
                assert pattern not in source, f"Raw SQL pattern '{pattern}' found in {path.name}"

    def test_dashboard_does_not_access_private_core_attributes(self):
        """Dashboard must not touch Core private attributes."""
        private_patterns = [
            "._connection",
            "._clock",
            "._deployment_epoch",
            "._recovery_file",
            "._redact_keys",
            "._max_pending_per_principal",
            "._private_key",
            "._trusted_issuers",
        ]
        for path, source in self._source_of_all():
            for pattern in private_patterns:
                assert pattern not in source, f"Private Core attribute '{pattern}' accessed in {path.name}"

    def test_dashboard_does_not_create_tables(self):
        """Dashboard must not define or create database tables."""
        for path, source in self._source_of_all():
            assert "CREATE TABLE" not in source, f"Table creation found in {path.name}"

    def test_dashboard_does_not_calculate_fingerprints(self):
        """Fingerprint calculation belongs to Core only."""
        for path, source in self._source_of_all():
            assert "request_binding_fingerprint" not in source, f"Fingerprint calculation found in {path.name}"

    def test_dashboard_does_not_use_approval_record_private_constructor(self):
        """Dashboard must not construct ApprovalRecord via _RECORD_TOKEN."""
        for path, source in self._source_of_all():
            assert "_RECORD_TOKEN" not in source, f"_RECORD_TOKEN found in {path.name}"
            assert "_from_storage" not in source, f"_from_storage constructor found in {path.name}"

    def test_dashboard_does_not_sign_assertions(self):
        """Cryptographic signing belongs to Core / LocalApprovalAuthority only."""
        for path, source in self._source_of_all():
            assert "Ed25519" not in source, f"Ed25519 signing found in {path.name}"
            assert ".sign(" not in source, f"Direct .sign() call found in {path.name}"

    def test_dashboard_does_not_evaluate_policy(self):
        """Policy evaluation belongs to Core only."""
        for path, source in self._source_of_all():
            assert "Policy(" not in source, f"Policy instantiation found in {path.name}"
            assert "Rule.allow(" not in source, f"Rule.allow() found in {path.name}"
            assert "Rule.deny(" not in source, f"Rule.deny() found in {path.name}"


class TestSmoke:
    """Smoke tests: app boots, health responds, home responds."""

    def test_app_creates_without_error(self):
        import tempfile
        from dmint import LocalApprovalAuthority, SQLiteApprovalStore
        from dmint.dashboard.app import create_app
        from dmint.dashboard.core_client import CoreClient

        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "smoke.sqlite"
            store = SQLiteApprovalStore(db, deployment_epoch="smoke")
            authority = LocalApprovalAuthority(issuer_id="smoke-dashboard", audience="dmint/dashboard/v1")
            client = CoreClient(store=store, authority=authority)
            app = create_app(client)
            assert app is not None
            store.close()

    def test_health_endpoint_returns_ok(self):
        import tempfile
        from dmint import LocalApprovalAuthority, SQLiteApprovalStore
        from dmint.dashboard.app import create_app
        from dmint.dashboard.core_client import CoreClient
        from starlette.testclient import TestClient

        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "smoke_health.sqlite"
            store = SQLiteApprovalStore(db, deployment_epoch="smoke-health")
            authority = LocalApprovalAuthority(issuer_id="smoke-health", audience="dmint/dashboard/v1")
            client = CoreClient(store=store, authority=authority)
            app = create_app(client)
            tc = TestClient(app)
            resp = tc.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"
            store.close()

    def test_home_page_returns_200(self):
        import tempfile
        from dmint import LocalApprovalAuthority, SQLiteApprovalStore
        from dmint.dashboard.app import create_app
        from dmint.dashboard.core_client import CoreClient
        from starlette.testclient import TestClient

        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "smoke_home.sqlite"
            store = SQLiteApprovalStore(db, deployment_epoch="smoke-home")
            authority = LocalApprovalAuthority(issuer_id="smoke-home", audience="dmint/dashboard/v1")
            client = CoreClient(store=store, authority=authority)
            app = create_app(client)
            tc = TestClient(app)
            resp = tc.get("/")
            assert resp.status_code == 200
            assert b"Dmint" in resp.content
            store.close()

    def test_audit_page_returns_200(self):
        import tempfile
        from dmint import LocalApprovalAuthority, SQLiteApprovalStore
        from dmint.dashboard.app import create_app
        from dmint.dashboard.core_client import CoreClient
        from starlette.testclient import TestClient

        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "smoke_audit.sqlite"
            store = SQLiteApprovalStore(db, deployment_epoch="smoke-audit")
            authority = LocalApprovalAuthority(issuer_id="smoke-audit", audience="dmint/dashboard/v1")
            client = CoreClient(store=store, authority=authority)
            app = create_app(client)
            tc = TestClient(app)
            resp = tc.get("/audit")
            assert resp.status_code == 200
            assert b"Audit" in resp.content
            store.close()
