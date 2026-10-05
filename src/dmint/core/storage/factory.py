"""Factory for instantiating the configured ApprovalStore."""

from __future__ import annotations

import os
import urllib.parse
from collections.abc import Callable, Collection
from datetime import datetime
from pathlib import Path

from ..errors import ApprovalStoreConfigurationError
from .base import ApprovalStore
from .sql import SQLAlchemyApprovalStore
from .sqlite import SQLiteApprovalStore

_VALID_SCHEMES = {
    "sqlite",
    "postgresql",
    "postgres",
    "postgresql+psycopg2",
    "postgresql+psycopg",
    "postgresql+pg8000",
    "postgresql+asyncpg",
}


def create_approval_store(
    database_url: str | None = None,
    *,
    deployment_epoch: str,
    default_sqlite_path: str | Path = "dmint.db",
    recovery_epoch_file: str | Path | None = None,
    redact_keys: Collection[str] | None = None,
    max_pending_per_principal: int = 100,
    clock: Callable[[], datetime] | None = None,
) -> ApprovalStore:
    """Create and return an ApprovalStore based on DMINT_DATABASE_URL or explicit argument.

    Behaviors:
    1. Unset or empty DMINT_DATABASE_URL (and database_url is None) ->
       defaults to a local SQLite file (SQLiteApprovalStore).
       Zero external dependencies; standard OSS/local/dev path.
    2. Set to a postgresql://... URL ->
       connects to PostgreSQL via SQLAlchemyApprovalStore.
    3. Set to a sqlite:///... URL ->
       connects via SQLAlchemyApprovalStore.
    4. Set but invalid (malformed URL, unsupported scheme, unreachable host, auth failure) ->
       raises ApprovalStoreConfigurationError and refuses to start.
       Never falls back to SQLite silently.
    """
    raw_url = database_url if database_url is not None else os.environ.get("DMINT_DATABASE_URL")

    # 1. Unset -> local SQLite default (OSS/dev path)
    if raw_url is None or not raw_url.strip():
        return SQLiteApprovalStore(
            default_sqlite_path,
            deployment_epoch=deployment_epoch,
            recovery_epoch_file=recovery_epoch_file,
            redact_keys=redact_keys,
            max_pending_per_principal=max_pending_per_principal,
            clock=clock,
        )

    url_str = raw_url.strip()

    # 2. Parse and validate URL
    try:
        parsed = urllib.parse.urlparse(url_str)
    except Exception as exc:
        raise ApprovalStoreConfigurationError(
            f"Invalid DMINT_DATABASE_URL: could not parse URL '{url_str}': {exc}"
        ) from exc

    if not parsed.scheme or parsed.scheme.lower() not in _VALID_SCHEMES:
        raise ApprovalStoreConfigurationError(
            f"Unsupported database scheme '{parsed.scheme}' in DMINT_DATABASE_URL. "
            "Supported schemes: postgresql://, postgres://, sqlite://"
        )

    scheme = parsed.scheme.lower()
    if scheme in ("postgresql", "postgres") or scheme.startswith("postgresql+"):
        if not parsed.netloc and not parsed.hostname:
            raise ApprovalStoreConfigurationError(
                f"Malformed PostgreSQL DMINT_DATABASE_URL: missing host in '{url_str}'"
            )

    # 3. Instantiate SQLAlchemyApprovalStore (validates connection during init, fails loud on failure)
    return SQLAlchemyApprovalStore(
        url_str,
        deployment_epoch=deployment_epoch,
        recovery_epoch_file=recovery_epoch_file,
        redact_keys=redact_keys,
        max_pending_per_principal=max_pending_per_principal,
        clock=clock,
    )
