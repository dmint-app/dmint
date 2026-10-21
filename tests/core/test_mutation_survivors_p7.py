"""Regression tests killing the Phase-7 mutation survivors (TEST-MUTATION-SURVIVORS).

The Phase-7 campaign generated 68 mutants across 11 security modules; 17 were
behavioural survivors that passed both the targeted subsets and the full suite.
Each test below targets one survivor (campaign ids in the docstrings) so a
re-run of the campaign reports zero behavioural survivors. The two
docstring-only mutants (P7-015, P7-062) are equivalent and need no test.
"""

from __future__ import annotations

import dataclasses
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.approvals import ApprovalRecord, PolicyProvenance, new_request_id
from dmint.core.authority import LocalApprovalAuthority
from dmint.core.constraints import validate_constraints_schema, validate_pattern_safety
from dmint.core.enforcement import Dmint, _validate_function
from dmint.core.errors import PolicyError, RequestValidationError
from dmint.core.models import NO_RESOURCE, ToolRequest, TrustedContext
from dmint.core.policy import Decision, Policy, Rule
from dmint.core.redaction import _redact_query_params, _redact_single_uri
from dmint.core.webhooks import WebhookConfig, build_discord_payload, build_slack_payload

_NOW = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)


def _record() -> ApprovalRecord:
    request = ToolRequest(
        request_id=new_request_id(),
        agent_id="agent-7",
        tool="db",
        action="query",
        resource="prod_users",
        arguments={"table": "prod_users"},
        context=TrustedContext({}),
    )
    return ApprovalRecord.create(
        request=request,
        integration_id="mcp.db",
        capability_id="db.query",
        policy_provenance=PolicyProvenance(
            version_id="policy-v1",
            policy_digest=hashlib.sha256(b"mutation-policy").hexdigest(),
            evaluated_at=_NOW,
        ),
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=15),
    )


def _request_for(agent_id: str, arguments: dict) -> ToolRequest:
    return ToolRequest(
        request_id=new_request_id(),
        agent_id=agent_id,
        tool="db",
        action="query",
        resource=NO_RESOURCE,
        arguments=arguments,
        context=TrustedContext({}),
    )


# ---------------------------------------------------------------------------
# policy.py — optional-field gates in Policy.to_dict (P7-008 .. P7-011)
# ---------------------------------------------------------------------------


def test_policy_to_dict_includes_optional_rule_fields_only_when_set() -> None:
    """P7-008..P7-011: optional rule fields must serialize iff they are set."""
    rich = Rule(
        Decision.ALLOW,
        "db",
        "query",
        agent_id="agent-7",
        resource="/var/log/*",
        resource_kind="path",
        constraints={"properties": {"limit": {"type": "integer", "maximum": 100}}},
        schema_hash="schema-abc123",
    )
    plain = Rule(Decision.ALLOW, "db", "query")
    rich_dict, plain_dict = Policy((rich, plain)).to_dict()["rules"]

    assert rich_dict["agent_id"] == "agent-7"
    assert rich_dict["resource_kind"] == "path"
    assert rich_dict["constraints"] == {"properties": {"limit": {"type": "integer", "maximum": 100}}}
    assert rich_dict["schema_hash"] == "schema-abc123"
    for key in ("agent_id", "resource_kind", "constraints", "schema_hash"):
        assert key not in plain_dict


def test_optional_rule_fields_participate_in_decision_paths() -> None:
    """P7-008..P7-011 companion: agent and constraint gates change decisions."""
    policy = Policy(
        (
            Rule(Decision.ALLOW, "db", "query", agent_id="agent-7"),
            Rule(
                Decision.ALLOW, "db", "query", constraints={"properties": {"limit": {"type": "integer", "maximum": 10}}}
            ),
        )
    )
    assert policy.evaluate(_request_for("agent-7", {})) is Decision.ALLOW
    assert policy.evaluate(_request_for("agent-9", {"limit": 5})) is Decision.ALLOW
    assert policy.evaluate(_request_for("agent-9", {"limit": 50})) is Decision.DENY


# ---------------------------------------------------------------------------
# constraints.py — character-class bracket scanning (P7-013, P7-021, P7-022)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r"[^]]",  # negated class containing a literal `]`
        r"[]]",  # class containing a single literal `]`
        r"[.]",
        r"[a]b",
        r"[\\]",  # escaped backslash inside a class
        r"[\^]",
        r"[\[]",  # escaped `[` inside a class
        r"[a-z\]]",  # escaped `]` inside a class
        r"[]a]",
        r"[^abc]",
    ],
)
def test_character_class_bracket_scanning_accepts_valid_patterns(pattern: str) -> None:
    """P7-013, P7-021, P7-022: `^` handling and literal/escaped `]` must parse."""
    validate_pattern_safety(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"[\]",  # the `]` is escaped: the class is genuinely unterminated
        r"[^\]",
        r"[]\]",
        r"x[\]y",
        r"[abc",
    ],
)
def test_character_class_bracket_scanning_rejects_malformed_patterns(pattern: str) -> None:
    """P7-013, P7-022: escaped `]` must not be treated as the class terminator."""
    with pytest.raises(PolicyError, match="unterminated character class"):
        validate_pattern_safety(pattern)


def test_constraints_schema_pattern_gate_uses_bracket_scanning() -> None:
    """P7-013/021/022 end-to-end: the policy-load path applies the same scanning."""
    validate_constraints_schema({"properties": {"code": {"type": "string", "pattern": r"[^]]"}}})
    with pytest.raises(PolicyError, match="unterminated character class"):
        validate_constraints_schema({"properties": {"code": {"type": "string", "pattern": r"[\]"}}})


# ---------------------------------------------------------------------------
# enforcement.py — unwrap guard and registered-binding guard (P7-024, P7-032)
# ---------------------------------------------------------------------------


def test_validate_function_accepts_descriptor_targets_before_callability_check() -> None:
    """P7-024: classmethod/staticmethod descriptors must be unwrapped and validated."""

    def method(cls) -> str:
        return "ok"

    def function() -> str:
        return "ok"

    class_method = classmethod(method)
    static_method = staticmethod(function)
    assert _validate_function(class_method) is class_method
    assert _validate_function(static_method) is static_method


def test_validate_function_rejects_descriptor_without_wrapped_function() -> None:
    """P7-024 other direction: a classmethod without a wrapped function fails closed."""
    with pytest.raises(RequestValidationError, match="must be callable"):
        _validate_function(classmethod(None))


def test_protected_wrapper_binding_survives_attribute_loss_via_registry() -> None:
    """P7-032: the guarded wrapper must also resolve its binding via the registry."""
    engine = Dmint(
        policy=Policy((Rule(Decision.ALLOW, "tool", "action"),)),
        agent_id="agent-1",
        context=TrustedContext({}),
    )

    @engine.protect("tool.action")
    def guarded(value):
        return value

    assert engine._registered.get(guarded) is not None
    guarded.__dmint_binding__ = None  # simulate attribute loss (copy/wrap boundary)
    authorized = engine.authorize(guarded, 7, capability="tool.action")
    assert engine.execute(authorized) == 7


# ---------------------------------------------------------------------------
# authority.py — sealing invariants (P7-043, P7-044)
# ---------------------------------------------------------------------------


def test_authority_blocks_post_construction_mutation() -> None:
    """P7-043: construction must seal the authority before it becomes usable."""
    authority = LocalApprovalAuthority(
        issuer_id="issuer-1",
        audience="dmint-approvals",
        private_key=Ed25519PrivateKey.generate(),
    )
    with pytest.raises(AttributeError, match="immutable"):
        authority._issuer_id = "attacker"  # noqa: SLF001


def test_authority_sealing_guard_defaults_to_unsealed_before_init() -> None:
    """P7-044: the sealing default must be `not yet sealed`, not `sealed`."""
    unsealed = LocalApprovalAuthority.__new__(LocalApprovalAuthority)
    unsealed._sealed = True
    with pytest.raises(AttributeError, match="immutable"):
        unsealed._issuer_id = "attacker"  # noqa: SLF001


# ---------------------------------------------------------------------------
# webhooks.py — payload formatting and frozen config (P7-063 .. P7-066)
# ---------------------------------------------------------------------------


def test_slack_payload_header_keeps_emoji_flag() -> None:
    """P7-063: the Slack header plain_text must keep `"emoji": True`."""
    payload = build_slack_payload(_record())
    assert payload["blocks"][0]["text"] == {
        "type": "plain_text",
        "text": "🛡️ Dmint Approval Required",
        "emoji": True,
    }


def test_discord_embed_marks_agent_and_tool_fields_inline() -> None:
    """P7-064, P7-065: Discord embed fields must keep exact names/values/inline flags."""
    payload = build_discord_payload(_record())
    fields = {field["name"]: field for field in payload["embeds"][0]["fields"]}
    assert fields["Agent / Principal"] == {"name": "Agent / Principal", "value": "agent-7", "inline": True}
    assert fields["Tool / Action"] == {"name": "Tool / Action", "value": "db.query", "inline": True}


def test_webhook_config_is_frozen() -> None:
    """P7-066: WebhookConfig must remain a frozen dataclass."""
    config = WebhookConfig(slack_url="https://hooks.example.net/services/x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.slack_url = "https://attacker.example.net/hook"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# redaction.py — blank/duplicate query params (P7-067, P7-068)
# ---------------------------------------------------------------------------


def test_blank_query_param_is_still_redacted_for_schemeless_uri() -> None:
    """P7-067: parse_qsl must keep blank values so `?token=` is sanitized."""
    assert _redact_query_params("host/path?token=") == "host/path?token=%5BREDACTED%5D"


def test_blank_query_param_still_triggers_uri_redaction() -> None:
    """P7-067, P7-068: blank sensitive params must not bypass URI sanitization."""
    assert _redact_single_uri("https://h/p?token=&x=1") == "https://h/p?token=%5BREDACTED%5D&x=1"


def test_duplicate_query_params_are_all_redacted() -> None:
    """P7-067, P7-068 companion: repeated sensitive params are all redacted."""
    assert _redact_single_uri("https://h/p?token=a&token=b") == (
        "https://h/p?token=%5BREDACTED%5D&token=%5BREDACTED%5D"
    )
