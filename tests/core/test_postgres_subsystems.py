"""Tests confirming DMINT_DATABASE_URL governs all subsystems (Core, MCP, Dashboard).

Validates that:
1. ThreadSafeApprovalStore is the single canonical implementation exported across subsystems.
2. Setting DMINT_DATABASE_URL makes MCPGateway instantiate a PostgreSQL-backed store.
3. Setting DMINT_DATABASE_URL makes Dashboard CoreClient instantiate a PostgreSQL-backed store.
4. Passing database_url explicitly to CoreClient instantiates a PostgreSQL-backed store.
5. Misconfigured/unreachable PostgreSQL URLs fail loud (ApprovalStoreConfigurationError)
   without silently falling back to SQLite in either MCP Gateway or Dashboard.
6. End-to-end integration: MCPGateway persists pending approval to PostgreSQL, and
   Dashboard CoreClient reads and approves it from PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import unittest

import mcp.types as types
from sqlalchemy import create_engine, delete

from dmint import (
    ApprovalRequiredError,
    ApprovalState,
    ApprovalStore,
    LocalApprovalAuthority,
    Policy,
    PolicyProvenance,
    Rule,
    ThreadSafeApprovalStore,
)
from dmint.core.errors import ApprovalStoreConfigurationError
from dmint.core.storage.sql import SQLAlchemyApprovalStore
from dmint.core.storage.sqlite import SQLiteApprovalStore
from dmint.dashboard.core_client import (
    CoreClient,
    ThreadSafeApprovalStore as DashThreadSafeApprovalStore,
)
from dmint.mcp import (
    DisclosureMode,
    DiscoveryMode,
    DownstreamMCPClient,
    MCPGateway,
    MCPGatewayConfig,
    MCPIntegrationConfig,
    MCPToolBinding,
)
from dmint.mcp.gateway import (
    ThreadSafeApprovalStore as MCPThreadSafeApprovalStore,
)
from dmint.policy import policy_digest
from dmint.models import AnyResource

POSTGRES_TEST_URL = os.environ.get(
    "DMINT_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/dmint_test",
)


class MockDownstreamClient(DownstreamMCPClient):
    """Mock downstream client for MCP testing."""

    def __init__(self, config: MCPIntegrationConfig, tools: list[types.Tool] | None = None) -> None:
        super().__init__(config)
        self._tools = tools or []
        self.call_log: list[tuple[str, dict]] = []

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def list_tools(self) -> list[types.Tool]:
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict | None = None) -> types.CallToolResult:
        self.call_log.append((name, arguments or {}))
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"executed {name}")])


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


def _clean_postgres(url: str) -> None:
    """Wipe test tables for test isolation."""
    engine = create_engine(_normalize_pg_url(url))
    with engine.begin() as conn:
        for tbl in ("dmint_approval_records", "dmint_policy_state", "dmint_recovery_epochs"):
            try:
                conn.execute(delete(SQLAlchemyApprovalStore._metadata.tables[tbl]))
            except Exception:
                pass
    engine.dispose()


class TestCanonicalStorageExports(unittest.TestCase):
    """Confirm ThreadSafeApprovalStore is canonical across subsystems."""

    def test_canonical_export_identity(self) -> None:
        self.assertIs(MCPThreadSafeApprovalStore, ThreadSafeApprovalStore)
        self.assertIs(DashThreadSafeApprovalStore, ThreadSafeApprovalStore)

        from dmint.core.storage import ThreadSafeApprovalStore as CoreStore
        from dmint.storage import ThreadSafeApprovalStore as StorageStore

        self.assertIs(CoreStore, ThreadSafeApprovalStore)
        self.assertIs(StorageStore, ThreadSafeApprovalStore)


class TestMCPGatewayPostgresSupport(unittest.TestCase):
    """Confirm MCP Gateway respects DMINT_DATABASE_URL and does not default to SQLite."""

    def setUp(self) -> None:
        self.orig_env = os.environ.get("DMINT_DATABASE_URL")
        self.addCleanup(self._restore_env)
        self.policy = Policy(rules=(Rule.allow("mcp", "test"),))
        self.provenance = PolicyProvenance("p1", policy_digest(self.policy), datetime.now(timezone.utc))
        self.integration = MCPIntegrationConfig(
            integration_id="test-svc",
            command="dummy",
            tool_bindings=[MCPToolBinding("test", "mcp.test", discovery=DiscoveryMode.EXPOSED)],
        )
        self.config = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.provenance,
            integrations=[self.integration],
            agent_id="test-agent",
        )

    def _restore_env(self) -> None:
        if self.orig_env is not None:
            os.environ["DMINT_DATABASE_URL"] = self.orig_env
        else:
            os.environ.pop("DMINT_DATABASE_URL", None)

    def tearDown(self) -> None:
        self._restore_env()

    def test_mcp_gateway_uses_postgres_when_env_var_set(self) -> None:
        os.environ["DMINT_DATABASE_URL"] = POSTGRES_TEST_URL

        gateway = MCPGateway(self.config)
        self.assertIsNotNone(gateway._approval_store)
        self.assertIsInstance(gateway._approval_store, ThreadSafeApprovalStore)

        underlying = gateway._approval_store.underlying_store
        self.assertIsInstance(underlying, SQLAlchemyApprovalStore)
        self.assertNotIsInstance(underlying, SQLiteApprovalStore)

    def test_mcp_gateway_fails_loud_on_invalid_postgres_url(self) -> None:
        os.environ["DMINT_DATABASE_URL"] = "postgresql://bad_user:bad_pass@127.0.0.1:59999/bad_db"

        with self.assertRaises(ApprovalStoreConfigurationError):
            MCPGateway(self.config)


class TestDashboardCoreClientPostgresSupport(unittest.TestCase):
    """Confirm Dashboard CoreClient respects DMINT_DATABASE_URL and does not default to SQLite."""

    def setUp(self) -> None:
        self.orig_env = os.environ.get("DMINT_DATABASE_URL")
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self.orig_env is not None:
            os.environ["DMINT_DATABASE_URL"] = self.orig_env
        else:
            os.environ.pop("DMINT_DATABASE_URL", None)

    def tearDown(self) -> None:
        self._restore_env()

    def test_dashboard_uses_postgres_when_env_var_set(self) -> None:
        os.environ["DMINT_DATABASE_URL"] = POSTGRES_TEST_URL

        client = CoreClient()
        self.assertIsInstance(client.store, ThreadSafeApprovalStore)

        underlying = client.store.underlying_store
        self.assertIsInstance(underlying, SQLAlchemyApprovalStore)
        self.assertNotIsInstance(underlying, SQLiteApprovalStore)

    def test_dashboard_uses_postgres_when_passed_as_argument(self) -> None:
        os.environ.pop("DMINT_DATABASE_URL", None)

        client = CoreClient(database_url=POSTGRES_TEST_URL)
        underlying = client.store.underlying_store
        self.assertIsInstance(underlying, SQLAlchemyApprovalStore)
        self.assertNotIsInstance(underlying, SQLiteApprovalStore)

    def test_dashboard_fails_loud_on_invalid_postgres_url(self) -> None:
        os.environ["DMINT_DATABASE_URL"] = "postgresql://bad_user:bad_pass@127.0.0.1:59999/bad_db"

        with self.assertRaises(ApprovalStoreConfigurationError):
            CoreClient()


class TestSubsystemsCrossIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end integration across MCP Gateway and Dashboard over PostgreSQL."""

    async def asyncSetUp(self) -> None:
        self.orig_env = os.environ.get("DMINT_DATABASE_URL")
        self.addCleanup(self._restore_env)
        os.environ["DMINT_DATABASE_URL"] = POSTGRES_TEST_URL
        _clean_postgres(POSTGRES_TEST_URL)

        self.authority = LocalApprovalAuthority(
            issuer_id="dash-human",
            audience="gateway_epoch",
        )

        self.policy = Policy(rules=(Rule.approval_required("mcp", "deploy", resource=AnyResource()),))
        self.provenance = PolicyProvenance("p1", policy_digest(self.policy), datetime.now(timezone.utc))

        self.integ_cfg = MCPIntegrationConfig(
            integration_id="infra",
            command="dummy",
            tool_bindings=[
                MCPToolBinding("deploy", "mcp.deploy", discovery=DiscoveryMode.EXPOSED),
            ],
        )

        self.gateway_config = MCPGatewayConfig(
            policy=self.policy,
            policy_provenance=self.provenance,
            integrations=[self.integ_cfg],
            approval_ttl=timedelta(hours=1),
            disclosure_mode=DisclosureMode.DOG,
            agent_id="deployer-agent",
        )

        def mock_factory(cfg: MCPIntegrationConfig) -> DownstreamMCPClient:
            return MockDownstreamClient(
                cfg,
                tools=[types.Tool(name="deploy", description="deploy tool", inputSchema={})],
            )

        self.gateway = MCPGateway(self.gateway_config, client_factory=mock_factory)
        self.dashboard_client = CoreClient(
            authority=self.authority,
            approver_id="dash-human",
            deployment_epoch="gateway_epoch",
        )

    def _restore_env(self) -> None:
        if self.orig_env is not None:
            os.environ["DMINT_DATABASE_URL"] = self.orig_env
        else:
            os.environ.pop("DMINT_DATABASE_URL", None)

    async def asyncTearDown(self) -> None:
        if hasattr(self, "gateway") and self.gateway.is_connected:
            await self.gateway.disconnect()
        self._restore_env()

    async def test_mcp_gateway_persists_to_postgres_and_dashboard_approves(self) -> None:
        """MCPGateway generates pending approval in Postgres; Dashboard reads and approves it."""
        # 1. MCPGateway handles tool call requiring approval -> raises ApprovalRequiredError
        approval_id: str | None = None
        with self.assertRaises(ApprovalRequiredError) as exc_info:
            await self.gateway.route_call("deploy", {"target": "production"})
        approval_id = exc_info.exception.approval_id
        self.assertIsNotNone(approval_id)

        # 2. Dashboard CoreClient queries pending approvals from PostgreSQL
        pending_list = self.dashboard_client.list_pending()
        self.assertTrue(any(p.approval_id == approval_id for p in pending_list))
        record = self.dashboard_client.get_approval(approval_id)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.state, ApprovalState.PENDING)
        self.assertEqual(record.request.tool, "mcp")
        self.assertEqual(record.request.action, "deploy")
        self.assertEqual(record.request.agent_id, "deployer-agent")

        # 3. Dashboard CoreClient approves the request in PostgreSQL
        approved = self.dashboard_client.approve(approval_id, reason="Approved by SRE lead")
        self.assertEqual(approved.state, ApprovalState.APPROVED)
        self.assertEqual(approved.approval_id, approval_id)

        # 4. Verify in PostgreSQL that state is APPROVED
        refreshed = self.dashboard_client.get_approval(approval_id)
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        self.assertEqual(refreshed.state, ApprovalState.APPROVED)
        self.assertIsNotNone(refreshed.decision_authority)
        assert refreshed.decision_authority is not None
        self.assertEqual(refreshed.decision_authority.subject_id, "dash-human")
        self.assertEqual(refreshed.state_reason, "Approved by SRE lead")
