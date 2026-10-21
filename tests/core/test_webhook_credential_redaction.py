"""Credential redaction for outgoing webhook payloads.

Resource strings may embed credentials (``postgres://app:secret@host/db``).
Every webhook field passes through :func:`sanitize_webhook_field`, which must
remove URL userinfo before the value is placed in any Slack, Discord, Teams,
or denial payload.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from dmint.approvals import ApprovalRecord, PolicyProvenance, new_request_id
from dmint.core.models import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.core.webhooks import (
    build_denial_payload,
    build_discord_payload,
    build_slack_payload,
    build_teams_payload,
    sanitize_webhook_field,
)

SECRET = "supersecretpw"
CREDENTIAL_RESOURCE = f"postgres://app:{SECRET}@db.internal/prod"


def _record(
    *, tool: str = "database", action: str = "connect", resource: str | None = CREDENTIAL_RESOURCE
) -> ApprovalRecord:
    now = datetime.now(timezone.utc)
    request = ToolRequest(
        request_id=new_request_id(),
        agent_id="agent-42",
        tool=tool,
        action=action,
        resource=resource if resource is not None else NO_RESOURCE,
        arguments={"password": "argument-secret-not-forwarded"},
        context=TrustedContext({"env": "test"}),
    )
    provenance = PolicyProvenance("pol-v1", "0" * 64, now)
    return ApprovalRecord.create(
        request=request,
        integration_id="local-runtime",
        capability_id=f"{tool}.{action}",
        policy_provenance=provenance,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


BUILDERS: dict[str, Callable[..., dict[str, Any]]] = {
    "slack": lambda record: build_slack_payload(record),
    "discord": lambda record: build_discord_payload(record),
    "teams": lambda record: build_teams_payload(record),
    "denial": lambda record: build_denial_payload(record.request),
}


@pytest.mark.parametrize("kind", sorted(BUILDERS))
def test_payload_builders_redact_resource_credentials(kind: str) -> None:
    blob = json.dumps(BUILDERS[kind](_record()))
    assert SECRET not in blob, f"{kind} payload leaked resource credentials: {blob}"
    assert "[redacted]@" in blob


@pytest.mark.parametrize("kind", sorted(BUILDERS))
def test_payload_builders_redact_credentials_in_action_string(kind: str) -> None:
    action = "connect https://svc:hunter2secret@api.internal/run"
    blob = json.dumps(BUILDERS[kind](_record(action=action)))
    assert "hunter2secret" not in blob
    assert "[redacted]@" in blob


def test_sanitize_webhook_field_redacts_url_userinfo() -> None:
    sanitized = sanitize_webhook_field("https://user:pw@example.com/path?x=1")
    assert sanitized == "https://[redacted]@example.com/path?x=1"


def test_sanitize_webhook_field_redacts_last_authority_separator() -> None:
    # Everything up to the last "@" of the authority is credentials.
    assert sanitize_webhook_field("https://u:p@ss@h/x") == "https://[redacted]@h/x"
    # Percent-encoded userinfo is covered as well.
    assert sanitize_webhook_field("postgres://user%40name:pw@host:5432/db") == "postgres://[redacted]@host:5432/db"


def test_sanitize_webhook_field_leaves_at_signs_outside_authority() -> None:
    # "@" in the path (not userinfo) is preserved.
    assert sanitize_webhook_field("https://example.com/users/@me") == "https://example.com/users/@me"
    assert sanitize_webhook_field("mailto:user@example.com") == "mailto:user@example.com"


def test_sanitize_webhook_field_redacts_before_truncation() -> None:
    long_username = "u" * 300
    sanitized = sanitize_webhook_field(f"https://{long_username}:pw@h/x")
    assert sanitized == "https://[redacted]@h/x"


def test_sanitize_webhook_field_redacts_multiple_credentials() -> None:
    raw = "https://a:one@h1/x and postgres://b:two@h2/y"
    sanitized = sanitize_webhook_field(raw)
    assert "one" not in sanitized and "two" not in sanitized
    assert sanitized == "https://[redacted]@h1/x and postgres://[redacted]@h2/y"
