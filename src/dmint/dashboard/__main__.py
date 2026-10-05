"""CLI entrypoint: ``python -m dmint_dashboard`` or ``dmint-dashboard``."""

from __future__ import annotations

import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("dmint_dashboard")


def main(argv: list[str] | None = None, prog: str | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog=prog or "dmint-dashboard",
        description="Dmint local human approval dashboard (no authentication — local/demo only)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("DMINT_DASHBOARD_HOST", "127.0.0.1"),
        help="Bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("DMINT_DASHBOARD_PORT", "8080")),
        help="Bind port (default: 8080)",
    )
    parser.add_argument(
        "--db-path",
        default=os.environ.get("DMINT_DB_PATH"),
        help="Path to Core-owned SQLite database (or set DMINT_DB_PATH)",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DMINT_DATABASE_URL"),
        help="Database connection URL (PostgreSQL or SQLite, or set DMINT_DATABASE_URL)",
    )
    parser.add_argument(
        "--deployment-epoch",
        default=os.environ.get("DMINT_DEPLOYMENT_EPOCH", "default"),
        help="Core deployment epoch (must match the running Core instance)",
    )
    parser.add_argument(
        "--authority-issuer",
        default=os.environ.get("DMINT_AUTHORITY_ISSUER", "dmint-dashboard"),
        help="Issuer ID for the dashboard LocalApprovalAuthority",
    )
    parser.add_argument(
        "--approver-id",
        default=os.environ.get("DMINT_APPROVER_ID", "dashboard-human"),
        help="Human subject ID recorded in Core when approving/rejecting",
    )
    args = parser.parse_args(argv)

    if not args.db_path and not args.database_url:
        parser.error(
            "DMINT_DB_PATH / DMINT_DATABASE_URL environment variable or --db-path / --database-url argument is required.\n"
            "  Example: dmint-dashboard --db-path /var/dmint/approvals.sqlite3 "
            "--deployment-epoch my-deployment"
        )

    # Import Core here so startup errors are surfaced clearly.
    try:
        from dmint import LocalApprovalAuthority
        from .app import create_app
        from .core_client import CoreClient, ThreadSafeApprovalStore
    except ImportError as exc:
        sys.exit(
            f"Could not import dmint or dmint.dashboard: {exc}\n"
            "Install dashboard dependencies with: pip install 'dmint[dashboard]'"
        )

    target = args.database_url or args.db_path
    log.info("Connecting to Core approval store at %s (epoch: %s)", target, args.deployment_epoch)
    store = ThreadSafeApprovalStore(
        database=args.db_path,
        database_url=args.database_url,
        deployment_epoch=args.deployment_epoch,
    )
    authority = LocalApprovalAuthority(
        issuer_id=args.authority_issuer,
        audience="dmint/dashboard/v1",
    )
    client = CoreClient(store=store, authority=authority, approver_id=args.approver_id)
    app = create_app(client)

    log.info(
        "\n"
        "  ╔══════════════════════════════════════════════════════╗\n"
        "  ║           Dmint Dashboard V1                         ║\n"
        "  ║                                                      ║\n"
        "  ║  WARNING: No authentication — local/demo use only.  ║\n"
        "  ╚══════════════════════════════════════════════════════╝\n"
        "\n"
        "  Dashboard: http://%s:%d/\n"
        "  Health:    http://%s:%d/health\n",
        args.host,
        args.port,
        args.host,
        args.port,
    )

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
