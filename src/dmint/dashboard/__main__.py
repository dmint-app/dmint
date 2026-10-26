"""CLI entrypoint: ``python -m dmint_dashboard`` or ``dmint-dashboard``."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("dmint_dashboard")


def main(argv: list[str] | None = None, prog: str | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog=prog or "dmint-dashboard",
        description="Dmint local human approval dashboard (authenticated & CSRF protected)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("DMINT_DASHBOARD_HOST", "127.0.0.1"),
        help="Bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--allow-public-bind",
        action="store_true",
        default=os.environ.get("DMINT_DASHBOARD_ALLOW_PUBLIC_BIND", "").lower() in ("1", "true", "yes"),
        help="Explicitly permit binding to 0.0.0.0 / all interfaces (insecure without network controls)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("DMINT_DASHBOARD_PORT", "8080")),
        help="Bind port (default: 8080)",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("DMINT_DASHBOARD_TOKEN") or os.environ.get("DMINT_DASHBOARD_PASSWORD"),
        help="Dashboard authentication token / password (or set DMINT_DASHBOARD_TOKEN)",
    )
    parser.add_argument(
        "--token-file",
        default=os.environ.get("DMINT_DASHBOARD_TOKEN_FILE"),
        help="Path to file containing auth token (enforces 0600 permissions, or set DMINT_DASHBOARD_TOKEN_FILE)",
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
        "--key-file",
        default=os.environ.get("DMINT_KEY_FILE"),
        help="Path to signing key file (or set DMINT_KEY_FILE)",
    )
    parser.add_argument(
        "--approver-id",
        default=os.environ.get("DMINT_APPROVER_ID"),
        help="Configured approver ID recorded in Core when approving/rejecting (or set DMINT_APPROVER_ID)",
    )
    parser.add_argument(
        "--trusted-proxy",
        action="store_true",
        default=os.environ.get("DMINT_DASHBOARD_TRUSTED_PROXY", "").lower() in ("1", "true", "yes"),
        help="Trust X-Forwarded-Proto header from reverse proxy (default: off)",
    )
    args = parser.parse_args(argv)

    # Security check: refuse ANY non-loopback bind without explicit permission flag
    import ipaddress

    def _is_loopback_host(host_str: str) -> bool:
        clean = host_str.strip().lower()
        if clean == "localhost":
            return True
        try:
            ip = ipaddress.ip_address(clean)
            return ip.is_loopback
        except ValueError:
            return False

    if not _is_loopback_host(args.host) and not args.allow_public_bind:
        parser.error(
            f"Binding to non-loopback interface '{args.host}' is refused by default to prevent unauthorized network exposure. "
            "Pass --allow-public-bind flag explicitly if exposing the dashboard to the network."
        )

    from pathlib import Path

    if not args.db_path and not args.database_url:
        if Path(".dmint/approvals.sqlite3").is_file():
            args.db_path = ".dmint/approvals.sqlite3"
        elif Path("approvals.sqlite3").is_file():
            args.db_path = "approvals.sqlite3"
        else:
            parser.error(
                "DMINT_DB_PATH / DMINT_DATABASE_URL environment variable or --db-path / --database-url argument is required.\n"
                "  Example: dmint-dashboard --db-path /var/dmint/approvals.sqlite3 "
                "--deployment-epoch my-deployment"
            )

    approver_id = args.approver_id or os.environ.get("DMINT_APPROVER_ID")
    if not approver_id:
        if args.db_path and (Path(args.db_path).resolve().parent / "signing.key").is_file():
            import getpass

            try:
                approver_id = getpass.getuser() or "dashboard-admin"
            except Exception:
                approver_id = "dashboard-admin"
        else:
            parser.error(
                "Configured approver ID is required. Pass --approver-id <id> or set DMINT_APPROVER_ID environment variable."
            )

    if not args.key_file and args.db_path:
        sibling_skey = Path(args.db_path).resolve().parent / "signing.key"
        if sibling_skey.is_file():
            args.key_file = str(sibling_skey)

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
    from dmint.core.redaction import redact_database_url

    safe_target = redact_database_url(str(target)) if args.database_url else target
    log.info("Connecting to Core approval store at %s (epoch: %s)", safe_target, args.deployment_epoch)
    store = ThreadSafeApprovalStore(
        database=args.db_path,
        database_url=args.database_url,
        deployment_epoch=args.deployment_epoch,
    )
    authority = LocalApprovalAuthority(
        issuer_id=args.authority_issuer,
        audience="dmint/dashboard/v1",
        key_file=args.key_file,
    )
    client = CoreClient(store=store, authority=authority, approver_id=approver_id)

    # Authentication Token setup
    token = args.auth_token
    token_file = args.token_file
    token_was_generated = False
    if not token and not token_file and not os.environ.get("DMINT_DASHBOARD_TOKEN_FILE"):
        token = secrets.token_urlsafe(32)
        token_was_generated = True

    app = create_app(
        client,
        auth_token=token,
        token_file=token_file,
        allowed_hosts=[args.host],
        approver_id=approver_id,
        trusted_proxy=args.trusted_proxy,
    )

    token_banner = (
        f"  🔑 One-Time Login Token: {token}\n"
        if token_was_generated
        else "  🔑 Authentication: Enabled (configured via DMINT_DASHBOARD_TOKEN / flag)\n"
    )

    log.info(
        "\n"
        "  ╔══════════════════════════════════════════════════════════════╗\n"
        "  ║                   Dmint Security Dashboard                   ║\n"
        "  ║                                                              ║\n"
        "  ║  Deterministic authorization for AI agent tool calls.        ║\n"
        "  ╚══════════════════════════════════════════════════════════════╝\n"
        "\n"
        "%s"
        "  Dashboard URL: http://%s:%d/\n"
        "  Health Check:  http://%s:%d/health\n",
        token_banner,
        args.host,
        args.port,
        args.host,
        args.port,
    )

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
