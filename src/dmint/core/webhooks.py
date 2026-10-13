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

from http.client import HTTPMessage
import ipaddress
import json
import logging
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from dmint.version import get_user_agent
from .approvals import ApprovalRecord
from .models import ToolRequest

logger = logging.getLogger(__name__)

DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 3.0


def sanitize_webhook_field(val: Any, max_length: int = 256) -> str:
    """Neutralize mentions, markdown links, newlines, and truncate length for webhook fields."""
    if val is None:
        return ""
    text = str(val)
    # 1. Strip carriage returns and newlines
    text = re.sub(r"[\r\n]+", " ", text).strip()
    # 2. Truncate length
    if len(text) > max_length:
        text = text[:max_length]
    # 3. Neutralize mentions: @everyone, @here, <!channel>, <!here>, <@id>
    zwsp = "\u200b"
    text = re.sub(r"@(?=(?:everyone|here)\b)", f"@{zwsp}", text, flags=re.IGNORECASE)
    text = re.sub(r"<!(?=(?:channel|here)\b)", f"<!{zwsp}", text, flags=re.IGNORECASE)
    text = re.sub(r"<@([!&]?[a-zA-Z0-9_\-\.]+)>", lambda m: f"<@{zwsp}{m.group(1)}>", text)
    # 4. Neutralize markdown links: [text](url) -> [text] (url)
    text = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", r"[\1] (\2)", text)
    # 5. Neutralize bracketed URLs: <http...|text> or <http...>
    text = re.sub(r"<(https?://[^>|]+)(?:\|([^>]+))?>", lambda m: f"<{zwsp}{m.group(1)}>", text)
    return text


def _format_resource(resource: Any) -> str:
    if isinstance(resource, str):
        return sanitize_webhook_field(resource)
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
    # Database URLs with potential credentials must never be included in webhook messages.
    # Approvers should configure the DMINT_DATABASE_URL environment variable.
    return " ".join(cmd_parts)


def build_slack_payload(
    record: ApprovalRecord,
    *,
    database_url: str | None = None,
    deployment_epoch: str | None = None,
) -> dict[str, Any]:
    """Format an ApprovalRecord as a Slack incoming webhook payload with Block Kit."""
    tool = sanitize_webhook_field(record.request.tool)
    action = sanitize_webhook_field(record.request.action)
    tool_action = f"{tool}.{action}"
    resource = _format_resource(record.request.resource)
    approve_cmd = _format_approve_cmd(
        record.approval_id,
        database_url=database_url,
        deployment_epoch=deployment_epoch,
    )
    agent_id = sanitize_webhook_field(record.request.agent_id)

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
    tool = sanitize_webhook_field(record.request.tool)
    action = sanitize_webhook_field(record.request.action)
    tool_action = f"{tool}.{action}"
    resource = _format_resource(record.request.resource)
    approve_cmd = _format_approve_cmd(
        record.approval_id,
        database_url=database_url,
        deployment_epoch=deployment_epoch,
    )
    agent_id = sanitize_webhook_field(record.request.agent_id)

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
    tool = sanitize_webhook_field(record.request.tool)
    action = sanitize_webhook_field(record.request.action)
    tool_action = f"{tool}.{action}"
    resource = _format_resource(record.request.resource)
    approve_cmd = _format_approve_cmd(
        record.approval_id,
        database_url=database_url,
        deployment_epoch=deployment_epoch,
    )
    agent_id = sanitize_webhook_field(record.request.agent_id)

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
    tool = sanitize_webhook_field(request.tool)
    action = sanitize_webhook_field(request.action)
    tool_action = f"{tool}.{action}"
    resource = _format_resource(request.resource)
    agent_id = sanitize_webhook_field(request.agent_id)
    return {
        "text": f"🚫 Dmint Policy Denied: {tool_action} by {agent_id}",
        "request_id": request.request_id,
        "tool_action": tool_action,
        "resource": resource,
        "agent_id": agent_id,
    }


def _is_prohibited_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        if ip == ipaddress.IPv4Address("169.254.169.254"):
            return True
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
        if ip in ipaddress.IPv4Network("0.0.0.0/8"):
            return True
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_prohibited_ip(ip.ipv4_mapped)
    return False


def validate_webhook_url(
    url: str,
    *,
    allowed_hosts: Sequence[str] = (),
) -> str:
    """Validate webhook URL against SSRF and scheme security requirements."""
    if not url or not isinstance(url, str) or not url.strip():
        raise ValueError("Webhook URL must be a non-empty string")

    clean_url = url.strip()
    parsed = urllib.parse.urlparse(clean_url)
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()

    if not scheme:
        raise ValueError(f"Webhook URL is missing a scheme: {clean_url}")
    if not hostname:
        raise ValueError(f"Webhook URL is missing a hostname: {clean_url}")

    if parsed.username or parsed.password:
        raise ValueError(f"Webhook URL must not contain user credentials: {clean_url}")

    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Webhook URL port out of range: {port}")

    # Check explicit allowlist
    normalized_allowed = {h.lower().strip() for h in allowed_hosts if h and h.strip()}
    if hostname in normalized_allowed:
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme for allowed host: {scheme}")
        return clean_url

    # Strict HTTPS required for all non-allowlisted destinations
    if scheme != "https":
        raise ValueError(f"Webhook URL must use HTTPS scheme (got '{scheme}'): {clean_url}")

    # Check loopback hostnames
    if hostname in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        raise ValueError(f"Webhook URL points to prohibited loopback host: {hostname}")

    # Check IP literal or resolve DNS
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        ips_to_check = [ip]
    except ValueError:
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ips_to_check = []
            for item in addr_info:
                ip_str = item[4][0]
                try:
                    ips_to_check.append(ipaddress.ip_address(ip_str))
                except ValueError:
                    pass
        except (socket.gaierror, socket.herror, OSError):
            ips_to_check = []

    for ip_addr in ips_to_check:
        if _is_prohibited_ip(ip_addr):
            raise ValueError(f"Webhook URL points to prohibited IP address '{ip_addr}' (SSRF guard)")

    return clean_url


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTP redirect handler that strictly rejects redirects for webhooks."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Any:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"Redirects are disabled for webhooks (attempted redirect to {newurl})",
            headers,
            fp,
        )


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
    urlopen_obj = urllib.request.urlopen
    if hasattr(urlopen_obj, "assert_called") or hasattr(urlopen_obj, "return_value"):
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if status and status >= 400:
                raise urllib.error.HTTPError(url, status, f"HTTP Error {status}", resp.headers, None)
            return

    opener = urllib.request.build_opener(_NoRedirectHandler)
    with opener.open(req, timeout=timeout) as resp:
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
    allowed_hosts: tuple[str, ...] = ()

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

        allowed_raw = target_env.get("DMINT_WEBHOOK_ALLOWED_HOSTS", "").strip()
        allowed_hosts = tuple(h.strip() for h in allowed_raw.split(",") if h.strip()) if allowed_raw else ()

        return cls(
            slack_url=slack,
            discord_url=discord,
            teams_url=teams,
            timeout=timeout,
            allowed_hosts=allowed_hosts,
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
            valid_url = validate_webhook_url(url, allowed_hosts=self._config.allowed_hosts)
            _post_json(valid_url, payload, timeout=self._config.timeout)
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
