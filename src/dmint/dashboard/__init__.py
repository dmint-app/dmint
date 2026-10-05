from dmint.version import __version__
from .core_client import CoreClient, ThreadSafeApprovalStore


def main(argv: list[str] | None = None, prog: str | None = None) -> None:
    """Run the public Dashboard CLI entrypoint."""
    from .__main__ import main as _main

    return _main(argv=argv, prog=prog)


__all__ = ["CoreClient", "ThreadSafeApprovalStore", "main", "__version__"]
