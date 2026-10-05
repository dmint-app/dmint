"""Subprocess entrypoint that runs a DmintMCPProxy as an agent-facing MCP server."""

from datetime import datetime, timedelta, timezone
import asyncio
import os
from pathlib import Path
import sys

_src_dir = str(Path(__file__).resolve().parent.parent.parent / "src")
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from dmint.approvals import PolicyProvenance
from dmint.mcp import DmintMCPProxy, DiscoveryMode, MCPIntegrationConfig, MCPToolBinding
from dmint.policy import Policy, Rule, policy_digest, AnyResource
from dmint.storage import SQLiteApprovalStore


async def main():
    tool_bindings = {
        "echo": MCPToolBinding(
            tool_name="echo",
            capability="test.echo",
            discovery=DiscoveryMode.EXPOSED,
        ),
        "delete_database": MCPToolBinding(
            tool_name="delete_database",
            capability="test.delete_database",
            resource_key="target",
            discovery=DiscoveryMode.EXPOSED,
        ),
    }
    integration_config = MCPIntegrationConfig(
        integration_id=os.environ["DMINT_INTEGRATION_ID"],
        command=os.environ["DMINT_DOWNSTREAM_COMMAND"],
        args=tuple(os.environ["DMINT_DOWNSTREAM_ARGS"].split("\x1f")),
        tool_bindings=tool_bindings,
        default_discovery=DiscoveryMode.HIDDEN,
    )

    db_path = os.environ.get("DMINT_APPROVAL_DB")
    approval_store = None
    policy_provenance = None
    approval_ttl = None

    if db_path:
        approval_store = SQLiteApprovalStore(db_path, deployment_epoch="ep_1")
        approval_ttl = timedelta(hours=1)
        policy = Policy(
            rules=(
                Rule.allow("test", "echo", resource=AnyResource()),
                Rule.approval_required("test", "delete_database", resource=AnyResource()),
            )
        )
        policy_provenance = PolicyProvenance("v1", policy_digest(policy), datetime.now(timezone.utc))
    else:
        policy = Policy(
            rules=(
                Rule.allow("test", "echo", resource=AnyResource()),
                Rule.allow("test", "delete_database", resource=AnyResource()),
            )
        )

    proxy = DmintMCPProxy(
        integration_config,
        policy=policy,
        approval_store=approval_store,
        policy_provenance=policy_provenance,
        approval_ttl=approval_ttl,
    )
    await proxy.serve_stdio()


if __name__ == "__main__":
    asyncio.run(main())
