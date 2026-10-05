"""Tests for outgoing approval webhook notifications (Slack, Discord, MS Teams)."""

from __future__ import annotations

import io
import json
import logging
import socket
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest

from dmint.approvals import (
    ApprovalRecord,
    PolicyProvenance,
    new_approval_id,
    new_request_id,
)
from dmint.core.enforcement import Dmint
from dmint.core.models import NO_RESOURCE, Decision, ToolRequest, TrustedContext
from dmint.core.policy import Policy, Rule
from dmint.core.storage import SQLiteApprovalStore
from dmint.core.webhooks import (
    DEFAULT_WEBHOOK_TIMEOUT_SECONDS,
    WebhookConfig,
    WebhookNotifier,
    build_denial_payload,
    build_discord_payload,
    build_slack_payload,
    build_teams_payload,
    dispatch_approval_webhook,
    dispatch_denial_webhook,
)
from dmint.errors import ApprovalRequiredError


def _make_sample_record(
    approval_id: str | None = None,
    tool: str = "bash",
    action: str = "execute",
    resource: str | None = "rm -rf /tmp/data",
    agent_id: str = "agent-42",
) -> ApprovalRecord:
    now = datetime.now(timezone.utc)
    res_val = resource if resource is not None else NO_RESOURCE
    request = ToolRequest(
        request_id=new_request_id(),
        agent_id=agent_id,
        tool=tool,
        action=action,
        resource=res_val,
        arguments={"cmd": "echo test"},
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


class TestWebhookPayloadBuilders:
    """Verify exact payload shapes for Slack, Discord, and Teams."""

    def test_build_slack_payload(self) -> None:
        record = _make_sample_record(
            tool="deploy",
            action="release",
            resource="prod-cluster",
            agent_id="deploy-bot",
        )
        payload = build_slack_payload(record)

        assert "text" in payload
        assert "deploy.release" in payload["text"]
        assert "deploy-bot" in payload["text"]

        blocks = payload["blocks"]
        assert len(blocks) >= 3
        # Header block
        assert blocks[0]["type"] == "header"
        assert "Approval Required" in blocks[0]["text"]["text"]

        # Fields block
        fields = blocks[1]["fields"]
        field_texts = [f["text"] for f in fields]
        assert any(record.approval_id in t for t in field_texts)
        assert any("deploy-bot" in t for t in field_texts)
        assert any("deploy.release" in t for t in field_texts)
        assert any("prod-cluster" in t for t in field_texts)

        # CLI action command
        action_text = blocks[2]["text"]["text"]
        assert f"dmint approve {record.approval_id}" in action_text

    def test_build_slack_payload_no_resource(self) -> None:
        record = _make_sample_record(resource=None)
        payload = build_slack_payload(record)
        fields = payload["blocks"][1]["fields"]
        field_texts = [f["text"] for f in fields]
        assert any("(none)" in t for t in field_texts)

    def test_build_discord_payload(self) -> None:
        record = _make_sample_record(
            tool="database",
            action="drop",
            resource="users_table",
            agent_id="sql-agent",
        )
        payload = build_discord_payload(record)

        assert "content" in payload
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert "database.drop" in embed["title"]
        assert embed["color"] == 15105570  # Warning color

        field_dict = {f["name"]: f["value"] for f in embed["fields"]}
        assert record.approval_id in field_dict["Approval ID"]
        assert field_dict["Agent / Principal"] == "sql-agent"
        assert field_dict["Tool / Action"] == "database.drop"
        assert field_dict["Resource / Target"] == "users_table"
        assert f"dmint approve {record.approval_id}" in field_dict["Action Command"]

    def test_build_discord_payload_no_resource(self) -> None:
        record = _make_sample_record(resource=None)
        payload = build_discord_payload(record)
        embed = payload["embeds"][0]
        field_dict = {f["name"]: f["value"] for f in embed["fields"]}
        assert field_dict["Resource / Target"] == "(none)"

    def test_build_teams_payload(self) -> None:
        record = _make_sample_record(
            tool="k8s",
            action="restart",
            resource="ingress-router",
            agent_id="ops-agent",
        )
        payload = build_teams_payload(record)

        assert payload["@type"] == "MessageCard"
        assert "k8s.restart" in payload["summary"]
        assert "Approval Required" in payload["title"]

        section = payload["sections"][0]
        facts_dict = {f["name"]: f["value"] for f in section["facts"]}
        assert facts_dict["Approval ID:"] == record.approval_id
        assert facts_dict["Agent / Principal:"] == "ops-agent"
        assert facts_dict["Tool / Action:"] == "k8s.restart"
        assert facts_dict["Resource / Target:"] == "ingress-router"
        assert f"dmint approve {record.approval_id}" in section["text"]

    def test_build_teams_payload_no_resource(self) -> None:
        record = _make_sample_record(resource=None)
        payload = build_teams_payload(record)
        section = payload["sections"][0]
        facts_dict = {f["name"]: f["value"] for f in section["facts"]}
        assert facts_dict["Resource / Target:"] == "(none)"

    def test_build_payloads_with_epoch_and_database_url(self) -> None:
        record = _make_sample_record(tool="db", action="migrate", resource="prod_db")
        slack = build_slack_payload(
            record,
            database_url="postgresql://user:pass@db:5432/prod",
            deployment_epoch="prod-2026-q1",
        )
        slack_action = slack["blocks"][2]["text"]["text"]
        assert (
            f"dmint approve {record.approval_id} --deployment-epoch prod-2026-q1 --database-url postgresql://user:pass@db:5432/prod"
            in slack_action
        )

        discord = build_discord_payload(
            record,
            database_url="postgresql://user:pass@db:5432/prod",
            deployment_epoch="prod-2026-q1",
        )
        discord_cmd = discord["embeds"][0]["fields"][4]["value"]
        assert (
            f"dmint approve {record.approval_id} --deployment-epoch prod-2026-q1 --database-url postgresql://user:pass@db:5432/prod"
            in discord_cmd
        )

        teams = build_teams_payload(
            record,
            database_url="postgresql://user:pass@db:5432/prod",
            deployment_epoch="prod-2026-q1",
        )
        teams_text = teams["sections"][0]["text"]
        assert (
            f"dmint approve {record.approval_id} --deployment-epoch prod-2026-q1 --database-url postgresql://user:pass@db:5432/prod"
            in teams_text
        )

    def test_build_denial_payload(self) -> None:
        req = ToolRequest(
            request_id=new_request_id(),
            agent_id="rogue-agent",
            tool="admin",
            action="delete_all",
            resource=NO_RESOURCE,
            arguments={},
            context=TrustedContext({}),
        )
        payload = build_denial_payload(req)
        assert "🚫 Dmint Policy Denied: admin.delete_all" in payload["text"]
        assert payload["request_id"] == req.request_id
        assert payload["resource"] == "(none)"


class TestWebhookConfig:
    """Verify configuration extraction from environment."""

    def test_config_defaults_empty(self) -> None:
        config = WebhookConfig.from_env({})
        assert config.slack_url is None
        assert config.discord_url is None
        assert config.teams_url is None
        assert config.timeout == DEFAULT_WEBHOOK_TIMEOUT_SECONDS

    def test_config_from_env_populated(self) -> None:
        env = {
            "DMINT_SLACK_WEBHOOK_URL": "  https://hooks.slack.com/services/XYZ  ",
            "DMINT_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123",
            "DMINT_TEAMS_WEBHOOK_URL": "https://outlook.office.com/webhook/abc",
            "DMINT_WEBHOOK_TIMEOUT": "5.5",
        }
        config = WebhookConfig.from_env(env)
        assert config.slack_url == "https://hooks.slack.com/services/XYZ"
        assert config.discord_url == "https://discord.com/api/webhooks/123"
        assert config.teams_url == "https://outlook.office.com/webhook/abc"
        assert config.timeout == 5.5

    def test_config_teams_fallback_env(self) -> None:
        env = {
            "DMINT_MSTEAMS_WEBHOOK_URL": "https://company.webhook.office.com/123",
        }
        config = WebhookConfig.from_env(env)
        assert config.teams_url == "https://company.webhook.office.com/123"

    def test_config_invalid_timeout_falls_back_to_default(self) -> None:
        env = {
            "DMINT_WEBHOOK_TIMEOUT": "not-a-number",
        }
        config = WebhookConfig.from_env(env)
        assert config.timeout == DEFAULT_WEBHOOK_TIMEOUT_SECONDS

    def test_config_negative_timeout_falls_back_to_default(self) -> None:
        env = {
            "DMINT_WEBHOOK_TIMEOUT": "-2.0",
        }
        config = WebhookConfig.from_env(env)
        assert config.timeout == DEFAULT_WEBHOOK_TIMEOUT_SECONDS


class TestWebhookNotifierDispatch:
    """Verify HTTP requests made by WebhookNotifier."""

    def test_unconfigured_makes_zero_http_calls(self) -> None:
        config = WebhookConfig()
        notifier = WebhookNotifier(config)
        assert not notifier.is_configured

        record = _make_sample_record()
        with patch("urllib.request.urlopen") as mock_urlopen:
            notifier.send_approval_required(record)
            mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_slack_dispatch(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        slack_url = "https://hooks.slack.com/services/T00/B00/X00"
        config = WebhookConfig(slack_url=slack_url, timeout=4.0)
        notifier = WebhookNotifier(config)

        record = _make_sample_record()
        notifier.send_approval_required(record)

        assert mock_urlopen.call_count == 1
        req = mock_urlopen.call_args[0][0]
        assert isinstance(req, urllib.request.Request)
        assert req.full_url == slack_url
        assert req.headers["Content-type"] == "application/json"
        assert req.headers["User-agent"] == "dmint-webhook/2.0.0"

        body = json.loads(req.data.decode("utf-8"))
        assert "🛡️ Dmint Approval Required" in body["text"]
        assert mock_urlopen.call_args[1]["timeout"] == 4.0

    @patch("urllib.request.urlopen")
    def test_discord_dispatch(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 204
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        discord_url = "https://discord.com/api/webhooks/999/xyz"
        config = WebhookConfig(discord_url=discord_url)
        notifier = WebhookNotifier(config)

        record = _make_sample_record()
        notifier.send_approval_required(record)

        assert mock_urlopen.call_count == 1
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == discord_url
        body = json.loads(req.data.decode("utf-8"))
        assert "embeds" in body

    @patch("urllib.request.urlopen")
    def test_teams_dispatch(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        teams_url = "https://example.webhook.office.com/webhookb2/abc"
        config = WebhookConfig(teams_url=teams_url)
        notifier = WebhookNotifier(config)

        record = _make_sample_record()
        notifier.send_approval_required(record)

        assert mock_urlopen.call_count == 1
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == teams_url
        body = json.loads(req.data.decode("utf-8"))
        assert body["@type"] == "MessageCard"

    @patch("urllib.request.urlopen")
    def test_all_destinations_dispatched(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        config = WebhookConfig(
            slack_url="https://slack.example.com",
            discord_url="https://discord.example.com",
            teams_url="https://teams.example.com",
        )
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        notifier.send_approval_required(record)
        assert mock_urlopen.call_count == 3
        called_urls = [call_item[0][0].full_url for call_item in mock_urlopen.call_args_list]
        assert "https://slack.example.com" in called_urls
        assert "https://discord.example.com" in called_urls
        assert "https://teams.example.com" in called_urls


class TestWebhookFailureIsolation:
    """CRITICAL SECURITY REQUIREMENT: Webhook failures must NEVER propagate or affect decisions."""

    @patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError("url", 500, "Server Error", {}, None))  # type: ignore[arg-type]
    def test_http_500_does_not_raise(self, mock_urlopen: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
        config = WebhookConfig(slack_url="https://slack.example.com")
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Slack webhook" in caplog.text

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused"))
    def test_network_connection_refused_does_not_raise(
        self, mock_urlopen: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        config = WebhookConfig(discord_url="https://discord.example.com")
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Discord webhook" in caplog.text

    @patch("urllib.request.urlopen", side_effect=socket.timeout("Timed out"))
    def test_socket_timeout_does_not_raise(self, mock_urlopen: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
        config = WebhookConfig(teams_url="https://teams.example.com")
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Microsoft Teams webhook" in caplog.text

    def test_malformed_url_does_not_raise(self, caplog: pytest.LogCaptureFixture) -> None:
        config = WebhookConfig(slack_url="invalid://not-a-valid-url")
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Slack webhook" in caplog.text

    @patch("urllib.request.urlopen")
    def test_one_failure_does_not_block_subsequent_webhooks(
        self, mock_urlopen: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        # First call (Slack) fails with 500, second call (Discord) succeeds
        mock_ok = MagicMock()
        mock_ok.getcode.return_value = 200
        mock_ok.__enter__.return_value = mock_ok

        mock_urlopen.side_effect = [
            urllib.error.HTTPError("https://slack.example.com", 500, "Internal Server Error", {}, None),  # type: ignore[arg-type]
            mock_ok,
        ]

        config = WebhookConfig(
            slack_url="https://slack.example.com",
            discord_url="https://discord.example.com",
        )
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)

        assert mock_urlopen.call_count == 2
        assert "Failed to dispatch Slack webhook" in caplog.text

    def test_dispatch_approval_webhook_standalone_exception_resilience(self, caplog: pytest.LogCaptureFixture) -> None:
        with patch.object(WebhookNotifier, "send_approval_required", side_effect=RuntimeError("unexpected bug")):
            record = _make_sample_record()
            with caplog.at_level(logging.WARNING):
                dispatch_approval_webhook(record)  # Must not raise
            assert "Unexpected error during approval webhook dispatch" in caplog.text

    @patch("urllib.request.urlopen")
    def test_policy_denied_dispatch_all_destinations(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        config = WebhookConfig(
            slack_url="https://slack.example.com",
            discord_url="https://discord.example.com",
            teams_url="https://teams.example.com",
        )
        notifier = WebhookNotifier(config)
        req = ToolRequest(
            request_id=new_request_id(),
            agent_id="bad-actor",
            tool="server",
            action="shutdown",
            resource="datacenter-1",
            arguments={"force": True},
            context=TrustedContext({}),
        )

        notifier.send_policy_denied(req)
        assert mock_urlopen.call_count == 3
        called_urls = [call_item[0][0].full_url for call_item in mock_urlopen.call_args_list]
        assert "https://slack.example.com" in called_urls
        assert "https://discord.example.com" in called_urls
        assert "https://teams.example.com" in called_urls

    def test_dispatch_denial_webhook_standalone_exception_resilience(self, caplog: pytest.LogCaptureFixture) -> None:
        with patch.object(WebhookNotifier, "send_policy_denied", side_effect=RuntimeError("unexpected denial bug")):
            req = ToolRequest(
                request_id=new_request_id(),
                agent_id="bad-actor",
                tool="server",
                action="shutdown",
                resource=NO_RESOURCE,
                arguments={},
                context=TrustedContext({}),
            )
            with caplog.at_level(logging.WARNING):
                dispatch_denial_webhook(req)  # Must not raise
            assert "Unexpected error during policy denial webhook dispatch" in caplog.text


class TestCoreZeroNetworkCalls:
    """CRITICAL SECURITY GUARANTEE: Core authorization and decision path makes ZERO network calls.

    Core only returns decisions (ALLOW / DENY / APPROVAL_REQUIRED).
    Outgoing webhook dispatch and network I/O belong strictly to surrounding integration layers.
    """

    @patch("urllib.request.urlopen")
    def test_core_approval_required_makes_zero_network_calls(
        self, mock_urlopen: MagicMock, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Core evaluating APPROVAL_REQUIRED makes zero outbound HTTP calls, even if webhook URLs are set."""
        monkeypatch.setenv("DMINT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/test")
        monkeypatch.setenv("DMINT_DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")
        monkeypatch.setenv("DMINT_TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/test")

        db_path = str(tmp_path / "approvals.sqlite")  # type: ignore[operator]
        store = SQLiteApprovalStore(db_path, deployment_epoch="epoch-1")
        policy = Policy([Rule.approval_required("system", "reboot")])
        provenance = PolicyProvenance("pol-v1", "0" * 64, datetime.now(timezone.utc))

        mock_notifier = MagicMock(spec=WebhookNotifier)

        engine = Dmint(
            policy=policy,
            agent_id="test-agent",
            context=TrustedContext({}),
            approval_store=store,
            policy_provenance=provenance,
            approval_ttl=timedelta(minutes=5),
            webhook_notifier=mock_notifier,
        )

        @engine.protect("system.reboot")
        def reboot() -> str:
            return "rebooting"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            reboot()

        # Zero outbound HTTP calls from Core
        assert mock_urlopen.call_count == 0
        # Core itself did not invoke the webhook notifier
        assert mock_notifier.send_approval_required.call_count == 0
        assert mock_notifier.send_policy_denied.call_count == 0

        # Record is properly saved in the store
        retrieved = store.get(exc_info.value.approval_id)
        assert retrieved is not None
        assert retrieved.approval_id == exc_info.value.approval_id

    @patch("urllib.request.urlopen")
    def test_core_policy_deny_makes_zero_network_calls(
        self, mock_urlopen: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Core evaluating DENY makes zero outbound HTTP calls, even if webhook URLs are set."""
        monkeypatch.setenv("DMINT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/test")
        monkeypatch.setenv("DMINT_DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")

        policy = Policy([Rule.deny("admin", "delete_all")])
        mock_notifier = MagicMock(spec=WebhookNotifier)

        engine = Dmint(
            policy=policy,
            agent_id="test-agent",
            context=TrustedContext({}),
            webhook_notifier=mock_notifier,
        )

        @engine.protect("admin.delete_all")
        def delete_all() -> str:
            return "deleted"

        from dmint.errors import AuthorizationError

        with pytest.raises(AuthorizationError):
            delete_all()

        # Zero outbound HTTP calls from Core
        assert mock_urlopen.call_count == 0
        assert mock_notifier.send_approval_required.call_count == 0
        assert mock_notifier.send_policy_denied.call_count == 0
