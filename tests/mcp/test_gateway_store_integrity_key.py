"""Regression: gateway store re-wrap must propagate an explicit integrity key (SRC-06).

The gateway wraps a passed ``SQLiteApprovalStore`` in ``ThreadSafeApprovalStore``. If the
explicit key is not forwarded, the wrapper silently resolves the ambient key instead:
its writes produce records the original store cannot verify, and reads fail the integrity
check (fail closed).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from dmint.core.approvals import ApprovalRecord, PolicyProvenance
from dmint.core.enforcement import Dmint
from dmint.core.models import ANY_RESOURCE, TrustedContext
from dmint.core.policy import Policy, Rule
from dmint.core.storage import SQLiteApprovalStore, ThreadSafeApprovalStore
from dmint.mcp.config_loader import MCPGatewayConfig
from dmint.mcp.gateway import MCPGateway


def test_gateway_store_rewrap_propagates_explicit_integrity_key(tmp_path: Any, monkeypatch: Any) -> None:
    ambient_key = b"\xaa" * 32
    explicit_key = b"\xbb" * 32

    # Pin ambient key resolution to a known different key (env key file takes precedence).
    ambient_key_file = tmp_path / "ambient.key"
    ambient_key_file.write_text(ambient_key.hex(), encoding="utf-8")
    ambient_key_file.chmod(0o600)
    monkeypatch.setenv("DMINT_INTEGRITY_KEY_FILE", str(ambient_key_file))
    monkeypatch.setenv("DMINT_INTEGRITY_KEY", ambient_key.hex())

    now = datetime(2026, 2, 1, tzinfo=timezone.utc)
    dmint = Dmint(
        Policy((Rule.allow("database", "delete", resource=ANY_RESOURCE),)),
        agent_id="agent-a",
        context=TrustedContext({"environment": "test"}),
    )

    def delete_user(user_id: int) -> int:
        return user_id

    dmint.register(delete_user, "database.delete", resource=lambda arguments: f"users/{arguments['user_id']}")
    authorized = dmint.authorize(
        delete_user,
        7,
        capability="database.delete",
        resource=lambda arguments: f"users/{arguments['user_id']}",
    )
    record = ApprovalRecord.create(
        request=authorized.request,
        integration_id="local-runtime",
        capability_id="database.delete",
        policy_provenance=PolicyProvenance("policy-v1", hashlib.sha256(b"policy-v1").hexdigest(), now),
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )

    db_file = tmp_path / "gateway-approvals.sqlite"
    source_store = SQLiteApprovalStore(db_file, deployment_epoch="epoch-1", integrity_key=explicit_key)
    gateway: MCPGateway | None = None
    try:
        config = MCPGatewayConfig(
            policy=Policy((Rule.allow("integ1.tool1", "run"),)),
            policy_provenance=PolicyProvenance("v1", hashlib.sha256(b"pol").hexdigest(), now),
            integrations=(),
            agent_id="test-agent",
        )
        gateway = MCPGateway(config=config, approval_store=source_store)

        wrapped = gateway.approval_store
        assert isinstance(wrapped, ThreadSafeApprovalStore)
        # The wrapped store must adopt the explicit key, never the ambient one.
        assert wrapped.underlying_store._integrity_key == explicit_key
        assert wrapped.underlying_store._integrity_key != ambient_key

        # Behavioral proof: records written through the wrapped store must verify with
        # the original store (same key) when read back.
        wrapped.save_pending(record)
        loaded = source_store.require_pending(record.approval_id)
        assert loaded.approval_id == record.approval_id
    finally:
        if gateway is not None and gateway.approval_store is not None:
            gateway.approval_store.close()
        source_store.close()
