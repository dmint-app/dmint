"""Outgoing webhook notifications for Dmint approval events (Slack, Discord, MS Teams).

This module provides fire-and-forget notification dispatch to configured incoming
webhooks whenever an APPROVAL_REQUIRED event occurs.

CRITICAL SECURITY & RELIABILITY INVARIANT:
Webhook failures (timeouts, 4xx/5xx responses, network disconnects, malformed URLs)
must NEVER alter or disrupt the authorization decision path, degrade the fail-closed
default, or raise an unhandled exception up into the enforcement gate. Webhook
dispatch is strictly an asynchronous notification side-effect.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dmint.version import get_user_agent
from .approvals import ApprovalRecord
from .models import ToolRequest

logger = logging.getLogger(__name__)

DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 3.0


def _format_resource(resource: Any) -> str:
    if isinstance(resource, str):
        return resource
    return "(none)"


def _format_approve_cmd(
    approval_id: str,
    *,
    database_url: str | None = None,
    deployment_epoch: str | None = None,
) -> str:
    cmd_parts = ["dmint", "approve", approval_id]
    if deployment_epoch and deployment_epoch != "default":
        cmd_parts.extend(["--deployment-epoch", deployment_epoch])
    if database_url:
        cmd_parts.extend(["--database-url", database_url])
    return " ".join(cmd_parts)


def build_slack_payload(
    record: ApprovalRecord,
    *,
    database_url: str | None = None,
    deployment_epoch: str | None = None,
) -> dict[str, Any]:
    """Format an ApprovalRecord as a Slack incoming webhook payload with Block Kit."""
    tool_action = f"{record.request.tool}.{record.request.action}"
    resource = _format_resource(record.request.resource)
    approve_cmd = _format_approve_cmd(
        record.approval_id,
        database_url=database_url,
        deployment_epoch=deployment_epoch,
    )
    agent_id = record.request.agent_id

    return {
        "text": f"🛡️ Dmint Approval Required: {tool_action} by {agent_id}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ Dmint Approval Required",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Approval ID:*\n`{record.approval_id}`"},
                    {"type": "mrkdwn", "text": f"*Agent / Principal:*\n`{agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Tool / Action:*\n`{tool_action}`"},
                    {"type": "mrkdwn", "text": f"*Resource / Target:*\n`{resource}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*To approve, run:*\n```{approve_cmd}```",
                },
            },
        ],
    }


def build_discord_payload(
    record: ApprovalRecord,
    *,
    database_url: str | None = None,
    deployment_epoch: str | None = None,
) -> dict[str, Any]:
    """Format an ApprovalRecord as a Discord incoming webhook payload with Embeds."""
    tool_action = f"{record.request.tool}.{record.request.action}"
    resource = _format_resource(record.request.resource)
    approve_cmd = _format_approve_cmd(
        record.approval_id,
        database_url=database_url,
        deployment_epoch=deployment_epoch,
    )
    agent_id = record.request.agent_id

    return {
        "content": "🛡️ **Dmint Approval Required**",
        "embeds": [
            {
                "title": f"Approval Required: {tool_action}",
                "color": 15105570,  # Warning amber / orange #E67E22
                "fields": [
                    {"name": "Approval ID", "value": f"`{record.approval_id}`", "inline": False},
                    {"name": "Agent / Principal", "value": agent_id, "inline": True},
                    {"name": "Tool / Action", "value": tool_action, "inline": True},
                    {"name": "Resource / Target", "value": resource, "inline": False},
                    {
                        "name": "Action Command",
                        "value": f"```bash\n{approve_cmd}\n```",
                        "inline": False,
                    },
                ],
            }
        ],
    }


def build_teams_payload(
    record: ApprovalRecord,
    *,
    database_url: str | None = None,
    deployment_epoch: str | None = None,
) -> dict[str, Any]:
    """Format an ApprovalRecord as a Microsoft Teams MessageCard webhook payload."""
    tool_action = f"{record.request.tool}.{record.request.action}"
    resource = _format_resource(record.request.resource)
    approve_cmd = _format_approve_cmd(
        record.approval_id,
        database_url=database_url,
        deployment_epoch=deployment_epoch,
    )
    agent_id = record.request.agent_id

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "E67E22",
        "summary": f"Dmint Approval Required: {tool_action}",
        "title": "🛡️ Dmint Approval Required",
        "sections": [
            {
                "facts": [
                    {"name": "Approval ID:", "value": record.approval_id},
                    {"name": "Agent / Principal:", "value": agent_id},
                    {"name": "Tool / Action:", "value": tool_action},
                    {"name": "Resource / Target:", "value": resource},
                ],
                "text": f"**To approve, run:**\n\n`{approve_cmd}`",
            }
        ],
    }


def build_denial_payload(request: ToolRequest) -> dict[str, Any]:
    """Format an explicit policy DENY event for outgoing webhooks."""
    tool_action = f"{request.tool}.{request.action}"
    resource = _format_resource(request.resource)
    return {
        "text": f"🚫 Dmint Policy Denied: {tool_action} by {request.agent_id}",
        "request_id": request.request_id,
        "tool_action": tool_action,
        "resource": resource,
        "agent_id": request.agent_id,
    }


def _post_json(url: str, payload: dict[str, Any], *, timeout: float = DEFAULT_WEBHOOK_TIMEOUT_SECONDS) -> None:
    """Send an HTTP POST request with a JSON payload using the standard library."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": get_user_agent("webhook"),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        if status and status >= 400:
            raise urllib.error.HTTPError(url, status, f"HTTP Error {status}", resp.headers, None)


@dataclass(frozen=True)
class WebhookConfig:
    """Configuration for outgoing approval webhook destinations."""

    slack_url: str | None = None
    discord_url: str | None = None
    teams_url: str | None = None
    timeout: float = DEFAULT_WEBHOOK_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> WebhookConfig:
        target_env = os.environ if env is None else env
        slack = target_env.get("DMINT_SLACK_WEBHOOK_URL", "").strip() or None
        discord = target_env.get("DMINT_DISCORD_WEBHOOK_URL", "").strip() or None
        teams = (
            target_env.get("DMINT_TEAMS_WEBHOOK_URL", "").strip()
            or target_env.get("DMINT_MSTEAMS_WEBHOOK_URL", "").strip()
            or None
        )

        timeout = DEFAULT_WEBHOOK_TIMEOUT_SECONDS
        raw_timeout = target_env.get("DMINT_WEBHOOK_TIMEOUT", "").strip()
        if raw_timeout:
            try:
                parsed_timeout = float(raw_timeout)
                if parsed_timeout > 0:
                    timeout = parsed_timeout
            except ValueError:
                pass

        return cls(
            slack_url=slack,
            discord_url=discord,
            teams_url=teams,
            timeout=timeout,
        )


class WebhookNotifier:
    """Dispatches outgoing webhook notifications on approval events.

    Guarantees isolation: exceptions are logged and suppressed so enforcement
    and authorization are never interrupted.
    """

    def __init__(
        self,
        config: WebhookConfig | None = None,
        *,
        database_url: str | None = None,
        deployment_epoch: str | None = None,
    ) -> None:
        self._config = config if config is not None else WebhookConfig.from_env()
        self._database_url = database_url
        self._deployment_epoch = deployment_epoch

    @property
    def config(self) -> WebhookConfig:
        return self._config

    @property
    def is_configured(self) -> bool:
        return bool(self._config.slack_url or self._config.discord_url or self._config.teams_url)

    def send_approval_required(self, record: ApprovalRecord) -> None:
        """Dispatch approval-required notifications to all configured webhook endpoints."""
        if not self.is_configured:
            return

        if self._config.slack_url:
            self._dispatch_safe(
                self._config.slack_url,
                build_slack_payload(
                    record,
                    database_url=self._database_url,
                    deployment_epoch=self._deployment_epoch,
                ),
                "Slack",
            )

        if self._config.discord_url:
            self._dispatch_safe(
                self._config.discord_url,
                build_discord_payload(
                    record,
                    database_url=self._database_url,
                    deployment_epoch=self._deployment_epoch,
                ),
                "Discord",
            )

        if self._config.teams_url:
            self._dispatch_safe(
                self._config.teams_url,
                build_teams_payload(
                    record,
                    database_url=self._database_url,
                    deployment_epoch=self._deployment_epoch,
                ),
                "Microsoft Teams",
            )

    def send_policy_denied(self, request: ToolRequest) -> None:
        """Dispatch policy denial notifications to all configured webhook endpoints."""
        if not self.is_configured:
            return

        payload = build_denial_payload(request)

        if self._config.slack_url:
            self._dispatch_safe(self._config.slack_url, payload, "Slack")

        if self._config.discord_url:
            discord_payload = {
                "content": payload["text"],
                "embeds": [
                    {
                        "title": f"🚫 Policy Denied: {payload['tool_action']}",
                        "color": 15158332,  # Danger Red #E74C3C
                        "fields": [
                            {"name": "Agent / Principal", "value": payload["agent_id"], "inline": True},
                            {"name": "Tool / Action", "value": payload["tool_action"], "inline": True},
                            {"name": "Resource / Target", "value": payload["resource"], "inline": False},
                            {"name": "Request ID", "value": f"`{payload['request_id']}`", "inline": False},
                        ],
                    }
                ],
            }
            self._dispatch_safe(self._config.discord_url, discord_payload, "Discord")

        if self._config.teams_url:
            self._dispatch_safe(self._config.teams_url, payload, "Microsoft Teams")

    def _dispatch_safe(self, url: str, payload: dict[str, Any], platform: str) -> None:
        try:
            _post_json(url, payload, timeout=self._config.timeout)
        except Exception as exc:
            logger.warning("Failed to dispatch %s webhook to %s: %s", platform, url, exc)


def dispatch_approval_webhook(
    record: ApprovalRecord,
    *,
    config: WebhookConfig | None = None,
    database_url: str | None = None,
    deployment_epoch: str | None = None,
) -> None:
    """Safe standalone function to dispatch an approval record notification.

    Catches all exceptions, ensuring zero propagation to caller.
    """
    try:
        notifier = WebhookNotifier(
            config=config,
            database_url=database_url,
            deployment_epoch=deployment_epoch,
        )
        notifier.send_approval_required(record)
    except Exception as exc:
        logger.warning("Unexpected error during approval webhook dispatch: %s", exc)


def dispatch_denial_webhook(
    request: ToolRequest,
    *,
    config: WebhookConfig | None = None,
) -> None:
    """Safe standalone function to dispatch a policy denial notification.

    Catches all exceptions, ensuring zero propagation to caller.
    """
    try:
        notifier = WebhookNotifier(config=config)
        notifier.send_policy_denied(request)
    except Exception as exc:
        logger.warning("Unexpected error during policy denial webhook dispatch: %s", exc)
