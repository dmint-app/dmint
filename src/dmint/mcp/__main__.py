"""CLI entrypoint for Dmint MCP Multi-Server Gateway."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import sys

from .config_loader import load_protection_config
from .errors import MCPConfigurationError
from .ssrf import is_loopback_host


def main(argv: list[str] | None = None) -> None:
    """Main CLI entrypoint for running the Dmint MCP Gateway."""
    parser = argparse.ArgumentParser(
        prog="dmint-mcp",
        description="Dmint MCP multi-server enforcement gateway.",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="run",
        choices=["run"],
        help="Action to execute (default: run)",
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        default="mcp_protection.json",
        help="Path to mcp_protection.json (default: mcp_protection.json)",
    )
    parser.add_argument(
        "--transport",
        dest="transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Agent-facing transport to expose (default: stdio)",
    )
    parser.add_argument(
        "--host",
        dest="host",
        default="127.0.0.1",
        help="Host address to bind for HTTP transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        default=8000,
        help="Port to bind for HTTP transport (default: 8000)",
    )
    parser.add_argument(
        "--auth-token",
        dest="auth_token",
        default=None,
        help="Bearer token or token mapping for agent transport auth (or DMINT_AUTH_TOKEN env)",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Logging level for HTTP server (default: info)",
    )

    args = parser.parse_args(argv)

    config_path = Path(args.config_path).resolve()
    if not config_path.is_file():
        sys.stderr.write(f"Error: configuration file not found at '{config_path}'\n")
        sys.exit(1)
        return

    try:
        config = load_protection_config(config_path)
    except MCPConfigurationError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        sys.exit(1)
        return
    except Exception as exc:
        sys.stderr.write(f"Failed to load protection configuration: {exc}\n")
        sys.exit(1)
        return

    auth_token = args.auth_token or os.environ.get("DMINT_AUTH_TOKEN")

    if args.transport == "http":
        is_loopback = is_loopback_host(args.host)
        if not is_loopback and not auth_token:
            sys.stderr.write(
                f"Configuration error: Cannot bind public host '{args.host}' without transport authentication configured\n"
            )
            sys.exit(1)
            return

    try:
        from .gateway import MCPGateway
    except ImportError as exc:
        sys.stderr.write(
            f'Error: dmint-mcp requires additional dependencies: {exc}\nPlease install with: pip install "dmint[mcp]"\n'
        )
        sys.exit(1)
        return

    gateway = MCPGateway(config)

    try:
        if args.transport == "http":
            asyncio.run(
                gateway.serve_http(
                    host=args.host,
                    port=args.port,
                    auth_token=auth_token,
                    log_level=args.log_level,
                )
            )
        else:
            asyncio.run(gateway.serve_stdio())
    except KeyboardInterrupt:
        sys.exit(0)
        return
    except MCPConfigurationError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        sys.exit(1)
        return
    except Exception as exc:
        sys.stderr.write(f"Runtime error: {exc}\n")
        sys.exit(1)
        return


if __name__ == "__main__":
    main()
