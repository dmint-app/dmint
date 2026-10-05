"""Dashboard launcher for dmint CLI."""

from __future__ import annotations

import sys


def main_dashboard(args: list[str] | None = None) -> int:
    """Launch the Dmint local human approval dashboard."""
    try:
        from dmint.dashboard import main as dashboard_main
    except ImportError as exc:
        print(
            f"Error: dmint-dashboard is required for this command: {exc}\n"
            f"Install it with: pip install 'dmint[dashboard]'",
            file=sys.stderr,
        )
        return 1

    try:
        dashboard_main(argv=args, prog="dmint dashboard")
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except Exception as exc:
        print(f"Error starting dashboard: {exc}", file=sys.stderr)
        return 1
