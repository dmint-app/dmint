"""Tests for outgoing approval webhook notifications (Slack, Discord, MS Teams)."""

from __future__ import annotations

import io
import json
import logging
import socket
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any
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


def _public_getaddrinfo(*_args: Any, **_kwargs: Any) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    """Return a fixed public IP for any hostname.

    Dispatch tests must not depend on the host resolver: DNS64/NAT64 networks
    synthesize ``64:ff9b::/96`` addresses (reserved, rejected by the SSRF guard)
    and some hostnames fail to resolve at all.
    """
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


@pytest.fixture
def _hermetic_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin DNS resolution to a fixed public address for dispatch tests."""
    monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", _public_getaddrinfo)


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
        secret_url = "postgresql://user:secret_pass_123@db:5432/prod"
        slack = build_slack_payload(
            record,
            database_url=secret_url,
            deployment_epoch="prod-2026-q1",
        )
        slack_action = slack["blocks"][2]["text"]["text"]
        # Secret credentials must never appear in payload
        assert "secret_pass_123" not in slack_action
        assert "--database-url" not in slack_action
        assert f"dmint approve {record.approval_id} --deployment-epoch prod-2026-q1" in slack_action

        discord = build_discord_payload(
            record,
            database_url=secret_url,
            deployment_epoch="prod-2026-q1",
        )
        discord_cmd = discord["embeds"][0]["fields"][4]["value"]
        assert "secret_pass_123" not in discord_cmd
        assert "--database-url" not in discord_cmd
        assert f"dmint approve {record.approval_id} --deployment-epoch prod-2026-q1" in discord_cmd

        teams = build_teams_payload(
            record,
            database_url=secret_url,
            deployment_epoch="prod-2026-q1",
        )
        teams_text = teams["sections"][0]["text"]
        assert "secret_pass_123" not in teams_text
        assert "--database-url" not in teams_text
        assert f"dmint approve {record.approval_id} --deployment-epoch prod-2026-q1" in teams_text

    def test_database_url_redaction_and_leak_prevention(self) -> None:
        """Verify that credentials in database URLs are strictly redacted across all supported formats."""
        from dmint.core.redaction import redact_database_url

        # 1. Standard user:pass@host
        url_with_pass = "postgresql://admin:super_secret_pw@db.internal:5432/dmint"
        redacted = redact_database_url(url_with_pass)
        assert "super_secret_pw" not in redacted
        assert "postgresql://admin:[REDACTED]@db.internal:5432/dmint" == redacted

        # 2. No password
        url_without_pass = "sqlite:////var/data/dmint.sqlite"
        assert redact_database_url(url_without_pass) == url_without_pass

        # 3. IPv6 host parsing
        url_ipv6 = "postgresql://admin:secret_pass@[::1]:5432/dmint"
        redacted_ipv6 = redact_database_url(url_ipv6)
        assert "secret_pass" not in redacted_ipv6
        assert "postgresql://admin:[REDACTED]@[::1]:5432/dmint" == redacted_ipv6

        # 4. URLs with no username but a password (:secret@host)
        url_no_user = "postgresql://:only_secret_pass@db.internal:5432/dmint"
        redacted_no_user = redact_database_url(url_no_user)
        assert "only_secret_pass" not in redacted_no_user
        assert "postgresql://:[REDACTED]@db.internal:5432/dmint" == redacted_no_user

        # 5. Passwords in query strings (?password=..., sslpassword=..., sslkey=...)
        url_query = (
            "postgresql://db.internal:5432/dmint?sslmode=require&password=query_secret&sslpassword=ssl_pw&sslkey=my_key"
        )
        redacted_query = redact_database_url(url_query)
        assert "query_secret" not in redacted_query
        assert "ssl_pw" not in redacted_query
        assert "my_key" not in redacted_query
        assert "password=%5BREDACTED%5D" in redacted_query or "password=[REDACTED]" in redacted_query
        assert "sslpassword=%5BREDACTED%5D" in redacted_query or "sslpassword=[REDACTED]" in redacted_query
        assert "sslkey=%5BREDACTED%5D" in redacted_query or "sslkey=[REDACTED]" in redacted_query

        # 6. libpq key-value connection strings (host=... password=...)
        libpq_kv = "host=db.internal port=5432 dbname=dmint user=admin password=super_kv_secret sslpassword='sec_ssl'"
        redacted_libpq = redact_database_url(libpq_kv)
        assert "super_kv_secret" not in redacted_libpq
        assert "sec_ssl" not in redacted_libpq
        assert "password=[REDACTED]" in redacted_libpq
        assert "sslpassword=[REDACTED]" in redacted_libpq

        # 7. DSN embedded inside free-text driver error message (with percent-encoded password containing @ and /)
        driver_err_percent = (
            "sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not connect to server at "
            "postgresql://admin:p%40ss%2Fword@db.internal:5432/dmint: Connection refused"
        )
        redacted_driver_percent = redact_database_url(driver_err_percent)
        assert "p%40ss%2Fword" not in redacted_driver_percent
        assert "p@ss/word" not in redacted_driver_percent
        assert "postgresql://admin:[REDACTED]@db.internal:5432/dmint: Connection refused" in redacted_driver_percent

        # 8. Password containing literal '@' or '/' (in raw connection URI or libpq string)
        raw_at_slash_uri = "postgresql://user:p@ss/word@db.internal:5432/dmint"
        redacted_raw = redact_database_url(raw_at_slash_uri)
        assert "p@ss/word" not in redacted_raw
        assert "postgresql://user:[REDACTED]@db.internal:5432/dmint" == redacted_raw

        from dmint.core.redaction import _redact_query_params

        raw_at_slash_with_query = (
            "postgresql://user:p@ss/word@db.internal:5432/dmint?sslmode=require&api_key=query_secret&auth=ssl_pw"
        )
        redacted_raw_query = redact_database_url(raw_at_slash_with_query)
        assert "p@ss/word" not in redacted_raw_query
        assert "query_secret" not in redacted_raw_query
        assert "ssl_pw" not in redacted_raw_query
        assert "api_key=%5BREDACTED%5D" in redacted_raw_query or "api_key=[REDACTED]" in redacted_raw_query
        assert "auth=%5BREDACTED%5D" in redacted_raw_query or "auth=[REDACTED]" in redacted_raw_query

        # Direct verification of query param helper
        direct_qp = _redact_query_params("host/db?api_key=secret_token&auth=oauth_bearer")
        assert "secret_token" not in direct_qp
        assert "oauth_bearer" not in direct_qp
        assert "api_key=%5BREDACTED%5D" in direct_qp or "api_key=[REDACTED]" in direct_qp

        # Free-text driver error with raw @ and /
        driver_err_raw = "OperationalError: failed connecting to postgresql://user:p@ss/word@db.internal:5432/dmint: connection refused"
        redacted_driver_raw = redact_database_url(driver_err_raw)
        assert "p@ss/word" not in redacted_driver_raw
        assert "postgresql://user:[REDACTED]@db.internal:5432/dmint: connection refused" in redacted_driver_raw

        # Free-text driver error with libpq containing @ and /
        driver_err_libpq = "psycopg2.OperationalError: connection to server at host=db.internal user=admin password=p@ss/word dbname=dmint failed: FATAL: auth failed"
        redacted_driver_libpq = redact_database_url(driver_err_libpq)
        assert "p@ss/word" not in redacted_driver_libpq
        assert "password=[REDACTED]" in redacted_driver_libpq

    def test_factory_exceptions_do_not_leak_database_url_password(self) -> None:
        """Factory exception messages must never contain raw passwords, including across chained exceptions."""
        from dmint.core.storage.factory import create_approval_store, ApprovalStoreConfigurationError

        unreachable_url = "postgresql://user:secret_hunter2_pass@unreachable.invalid.domain:5432/db"
        with pytest.raises(ApprovalStoreConfigurationError) as exc_info:
            create_approval_store(
                database_url=unreachable_url,
                deployment_epoch="test",
            )
        exc_str = str(exc_info.value)
        assert "secret_hunter2_pass" not in exc_str
        # Check __cause__ exception suppression
        assert exc_info.value.__cause__ is None or "secret_hunter2_pass" not in str(exc_info.value.__cause__)

    def test_dashboard_log_does_not_leak_database_url_password(self, caplog: pytest.LogCaptureFixture) -> None:
        """Dashboard startup logs must redact database credentials."""
        from dmint.core.redaction import redact_database_url

        target_url = "postgresql://db_user:confidential_pw_999@localhost:5432/dmint"
        safe = redact_database_url(target_url)
        assert "confidential_pw_999" not in safe
        assert "postgresql://db_user:[REDACTED]@localhost:5432/dmint" == safe

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


@pytest.mark.usefixtures("_hermetic_dns")
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
        assert req.headers["User-agent"] == "dmint-webhook/2.0.3"

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
        assert set(called_urls) == {
            "https://slack.example.com",
            "https://discord.example.com",
            "https://teams.example.com",
        }


@pytest.mark.usefixtures("_hermetic_dns")
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

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused"))
    def test_dispatch_failure_log_redacts_webhook_url_and_secret_path(
        self, mock_urlopen: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Network failure: the log must contain only the platform and host, never the token path."""
        secret_url = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24
        config = WebhookConfig(slack_url=secret_url)
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Slack webhook" in caplog.text
        assert caplog.records
        log_args = caplog.records[-1].args
        assert isinstance(log_args, tuple)
        assert log_args[:2] == ("Slack", "hooks.slack.com")
        assert secret_url not in caplog.text
        assert "XXXXXXXXXXXXXXXXXXXXXXXX" not in caplog.text
        assert "/services/" not in caplog.text

    def test_validation_failure_log_redacts_webhook_url_in_exception(self, caplog: pytest.LogCaptureFixture) -> None:
        """Validation errors echo the URL; the log must redact the URL in both the line and the error text."""
        secret_url = "http://hooks.slack.com/services/T00000000/B00000000/SEKRITPATHVALUE"
        config = WebhookConfig(slack_url=secret_url)
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Slack webhook" in caplog.text
        assert secret_url not in caplog.text
        assert "SEKRITPATHVALUE" not in caplog.text

    def test_validation_failure_log_redacts_webhook_userinfo(self, caplog: pytest.LogCaptureFixture) -> None:
        """Userinfo credentials embedded in a webhook URL must never reach the log."""
        secret_url = "https://user:sup3rs3cret@hooks.slack.com/services/T0/B0/USERINFOTOKEN"
        config = WebhookConfig(slack_url=secret_url)
        notifier = WebhookNotifier(config)
        record = _make_sample_record()

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(record)  # Must not raise

        assert "Failed to dispatch Slack webhook" in caplog.text
        assert secret_url not in caplog.text
        assert "sup3rs3cret" not in caplog.text
        assert "USERINFOTOKEN" not in caplog.text

    @patch("urllib.request.urlopen")
    def test_unresolvable_hostname_is_refused_before_http(
        self, mock_urlopen: MagicMock, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A webhook hostname that fails DNS resolution must be refused before any HTTP call (SRC-11)."""

        def _fail_resolution(*_args: Any, **_kwargs: Any) -> Any:
            raise socket.gaierror("Name or service not known")

        # Override the class-level hermetic DNS: this hostname must not resolve.
        monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", _fail_resolution)

        config = WebhookConfig(slack_url="https://unresolvable-host.invalid/services/T0/B0/SEKRIT")
        notifier = WebhookNotifier(config)

        with caplog.at_level(logging.WARNING):
            notifier.send_approval_required(_make_sample_record())  # Must not raise

        # Fail closed: no HTTP attempt was made, and the secret path stays out of logs.
        assert mock_urlopen.call_count == 0
        assert "Failed to dispatch Slack webhook" in caplog.text
        assert "SEKRIT" not in caplog.text

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
        assert set(called_urls) == {
            "https://slack.example.com",
            "https://discord.example.com",
            "https://teams.example.com",
        }

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

        with pytest.warns(DeprecationWarning, match="webhook_notifier"):
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

        with pytest.warns(DeprecationWarning, match="webhook_notifier"):
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


class TestWebhookSanitizationAndSSRF:
    """Security tests for webhook mention neutralization, link stripping, length bounds, SSRF, and redirects."""

    def test_sanitize_webhook_field_mentions(self) -> None:
        from dmint.core.webhooks import sanitize_webhook_field

        # @everyone and @here must have a zero-width space inserted to prevent channel notifications
        sanitized_everyone = sanitize_webhook_field("deploy @everyone immediately")
        assert "@everyone" not in sanitized_everyone
        assert "@\u200beveryone" in sanitized_everyone

        sanitized_here = sanitize_webhook_field("status @here please check")
        assert "@here" not in sanitized_here
        assert "@\u200bhere" in sanitized_here

        # Slack <!channel> and <!here>
        sanitized_channel = sanitize_webhook_field("ping <!channel> wake up")
        assert "<!channel>" not in sanitized_channel
        assert "<!\u200bchannel>" in sanitized_channel

        sanitized_slack_here = sanitize_webhook_field("ping <!here> wake up")
        assert "<!here>" not in sanitized_slack_here
        assert "<!\u200bhere>" in sanitized_slack_here

        # User and role mentions <@U123456>, <@12345>
        sanitized_user = sanitize_webhook_field("assigned to <@U12345678>")
        assert "<@U12345678>" not in sanitized_user
        assert "<@\u200bU12345678>" in sanitized_user

        sanitized_discord_user = sanitize_webhook_field("assigned to <@987654321>")
        assert "<@987654321>" not in sanitized_discord_user
        assert "<@\u200b987654321>" in sanitized_discord_user

    def test_sanitize_webhook_field_markdown_links(self) -> None:
        from dmint.core.webhooks import sanitize_webhook_field

        # Markdown link syntax [text](url) neutralized so clients do not render clickable links
        link_input = "check out [evil payload](https://evil.attacker.com/steal)"
        sanitized = sanitize_webhook_field(link_input)
        assert "[evil payload](https://evil.attacker.com/steal)" not in sanitized
        assert "[evil payload] (https://evil.attacker.com/steal)" in sanitized

        # Slack bracket links <url|text>
        slack_link = "see <https://malicious.site|click me>"
        sanitized_slack = sanitize_webhook_field(slack_link)
        assert "<https://malicious.site" not in sanitized_slack
        assert "<\u200bhttps://malicious.site" in sanitized_slack

    def test_sanitize_webhook_field_newlines_and_truncation(self) -> None:
        from dmint.core.webhooks import sanitize_webhook_field

        # Newlines and carriage returns stripped to single spaces
        multiline = "line1\nline2\r\nline3\rline4"
        sanitized = sanitize_webhook_field(multiline)
        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert sanitized == "line1 line2 line3 line4"

        # Truncation to 256 characters
        long_str = "x" * 500
        truncated = sanitize_webhook_field(long_str)
        assert len(truncated) == 256
        assert truncated == "x" * 256

    def test_payload_builders_hostile_values(self) -> None:
        from dmint.core.webhooks import (
            build_slack_payload,
            build_discord_payload,
            build_teams_payload,
            build_denial_payload,
        )

        hostile_agent = "agent-x @everyone\n[click](http://evil.com)"
        hostile_tool = "tool\r\n<!channel>"
        hostile_action = "action\n<@U999>"
        hostile_resource = "res\n<!here> " + ("A" * 300)

        record = _make_sample_record(
            tool=hostile_tool,
            action=hostile_action,
            resource=hostile_resource,
            agent_id=hostile_agent,
        )

        # 1. Slack
        slack = build_slack_payload(record)
        slack_json = json.dumps(slack)
        assert "@everyone" not in slack_json
        assert "<!channel>" not in slack_json
        assert "<!here>" not in slack_json
        assert "<@U999>" not in slack_json
        assert "[click](http://evil.com)" not in slack_json

        # 2. Discord
        discord = build_discord_payload(record)
        discord_json = json.dumps(discord)
        assert "@everyone" not in discord_json
        assert "<!channel>" not in discord_json
        assert "<!here>" not in discord_json
        assert "<@U999>" not in discord_json
        assert "[click](http://evil.com)" not in discord_json

        # 3. Teams
        teams = build_teams_payload(record)
        teams_json = json.dumps(teams)
        assert "@everyone" not in teams_json
        assert "<!channel>" not in teams_json
        assert "<!here>" not in teams_json
        assert "<@U999>" not in teams_json
        assert "[click](http://evil.com)" not in teams_json

        # 4. Denial
        req = ToolRequest(
            request_id=new_request_id(),
            agent_id=hostile_agent,
            tool=hostile_tool,
            action=hostile_action,
            resource=hostile_resource,
            arguments={},
            context=TrustedContext({}),
        )
        denial = build_denial_payload(req)
        denial_json = json.dumps(denial)
        assert "@everyone" not in denial_json
        assert "<!channel>" not in denial_json
        assert "<!here>" not in denial_json
        assert "<@U999>" not in denial_json
        assert "[click](http://evil.com)" not in denial_json

    def test_ssrf_guard_enforcement(self) -> None:
        from dmint.core.webhooks import validate_webhook_url

        # Plain HTTP rejected without explicit allowlist
        with pytest.raises(ValueError, match="must use HTTPS"):
            validate_webhook_url("http://hooks.slack.com/services/test")

        # Prohibited loopback hostnames
        with pytest.raises(ValueError, match="loopback"):
            validate_webhook_url("https://localhost/webhook")
        with pytest.raises(ValueError, match="loopback"):
            validate_webhook_url("https://localhost.localdomain/webhook")

        # Prohibited private IP literals
        with pytest.raises(ValueError, match="prohibited IP"):
            validate_webhook_url("https://127.0.0.1/webhook")
        with pytest.raises(ValueError, match="prohibited IP"):
            validate_webhook_url("https://10.0.0.1/webhook")
        with pytest.raises(ValueError, match="prohibited IP"):
            validate_webhook_url("https://192.168.1.1/webhook")
        with pytest.raises(ValueError, match="prohibited IP"):
            validate_webhook_url("https://172.16.0.1/webhook")
        with pytest.raises(ValueError, match="prohibited IP"):
            validate_webhook_url("https://169.254.169.254/webhook")

        # Embedded user credentials rejected
        with pytest.raises(ValueError, match="user credentials"):
            validate_webhook_url("https://admin:pass@hooks.slack.com/services/test")

        # Explicit allowlist allows target host (including HTTP for local receiver)
        allowed = validate_webhook_url("http://127.0.0.1:9999/webhook", allowed_hosts=("127.0.0.1",))
        assert allowed == "http://127.0.0.1:9999/webhook"

    def test_ssrf_guard_refuses_unresolvable_hostnames(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DNS resolution failure must fail closed: unresolvable hosts are refused (SRC-11)."""
        from dmint.core.webhooks import validate_webhook_url

        def _fail_resolution(*_args: Any, **_kwargs: Any) -> Any:
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", _fail_resolution)
        with pytest.raises(ValueError, match="resolve"):
            validate_webhook_url("https://nonexistent-audit-probe.invalid/hook")

        # Resolution succeeding but yielding no usable addresses is equally untrusted.
        monkeypatch.setattr("dmint.core.webhooks.socket.getaddrinfo", lambda *_args, **_kwargs: [])
        with pytest.raises(ValueError, match="resolve"):
            validate_webhook_url("https://no-addresses.invalid/hook")

    def test_local_fake_http_receiver_hostile_values_and_redirects(self) -> None:
        """Run a local fake HTTP server to verify live transmission with hostile values and redirect prevention."""
        import http.server
        import threading
        from dmint.core.webhooks import WebhookConfig, WebhookNotifier, _post_json, validate_webhook_url

        received_requests: list[dict[str, Any]] = []

        class FakeReceiverHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/stolen_secret")
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                received_requests.append(
                    {
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": json.loads(body.decode("utf-8")),
                    }
                )
                self.send_response(200)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress server access logs

        server = http.server.HTTPServer(("127.0.0.1", 0), FakeReceiverHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # 1. Live dispatch with hostile values to fake receiver
            url = f"http://127.0.0.1:{port}/webhook"
            config = WebhookConfig(
                slack_url=url,
                allowed_hosts=("127.0.0.1",),
                timeout=3.0,
            )
            notifier = WebhookNotifier(config)

            record = _make_sample_record(
                tool="hostile_tool @everyone",
                action="hostile_action <!channel>",
                resource="hostile_res [phish](http://phish.com)",
                agent_id="hostile_agent <@U12345>\nnewline",
            )
            notifier.send_approval_required(record)

            assert len(received_requests) == 1
            rec = received_requests[0]
            rec_body_str = json.dumps(rec["body"])

            # Verify hostile strings are completely neutralized on the wire
            assert "@everyone" not in rec_body_str
            assert "<!channel>" not in rec_body_str
            assert "<@U12345>" not in rec_body_str
            assert "[phish](http://phish.com)" not in rec_body_str
            assert "newline" in rec_body_str
            assert "\\nnewline" not in rec_body_str

            # 2. Redirect prevention: ensure redirects are rejected and never followed
            redirect_url = f"http://127.0.0.1:{port}/redirect"
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                _post_json(
                    validate_webhook_url(redirect_url, allowed_hosts=("127.0.0.1",)),
                    {"test": "data"},
                    timeout=2.0,
                )
            assert exc_info.value.code == 302
            assert "Redirects are disabled" in str(exc_info.value.reason)
        finally:
            server.shutdown()
            server.server_close()
