"""Branch-coverage edges for RFC 8785 request binding (SRC-18).

The Phase-6 branch report flagged `dmint.core.request_binding` below the
production branch-coverage gate. These tests cover the resource-representation
switch, the binding identity guards, and the typed canonicalization failure
path so malformed bindings keep failing closed.
"""

from __future__ import annotations

import pytest

from dmint.approvals import new_request_id
from dmint.core.errors import CanonicalizationError, MalformedApprovalError
from dmint.core.models import ANY_RESOURCE, NO_RESOURCE, ToolRequest, TrustedContext
from dmint.core.request_binding import canonical_request_binding, request_binding_envelope


def _request(**overrides) -> ToolRequest:
    fields: dict = {
        "request_id": new_request_id(),
        "agent_id": "agent-1",
        "tool": "db",
        "action": "query",
        "resource": NO_RESOURCE,
        "arguments": {},
        "context": TrustedContext({}),
    }
    fields.update(overrides)
    return ToolRequest(**fields)


def _envelope(request: ToolRequest) -> dict:
    return request_binding_envelope(request, integration_id="mcp.db", capability_id="db.query")


def test_resource_representation_covers_none_value_and_any() -> None:
    assert _envelope(_request())["resource"] == {"kind": "none"}
    assert _envelope(_request(resource="logs/x"))["resource"] == {"kind": "value", "value": "logs/x"}

    request = _request()
    object.__setattr__(request, "resource", ANY_RESOURCE)
    assert _envelope(request)["resource"] == {"kind": "any"}


def test_unknown_resource_representation_fails_closed() -> None:
    request = _request()
    object.__setattr__(request, "resource", 12345)
    with pytest.raises(MalformedApprovalError, match="invalid request resource representation"):
        _envelope(request)


def test_envelope_requires_a_tool_request() -> None:
    with pytest.raises(MalformedApprovalError, match="request binding requires a ToolRequest"):
        request_binding_envelope(object(), integration_id="mcp.db", capability_id="db.query")


def test_envelope_wraps_invalid_binding_identity() -> None:
    with pytest.raises(MalformedApprovalError, match="invalid request binding identity"):
        request_binding_envelope(_request(), integration_id="", capability_id="db.query")


def test_canonicalization_failure_surfaces_as_typed_error(monkeypatch) -> None:
    def _boom(_envelope: dict) -> bytes:
        raise RuntimeError("canonicalizer offline")

    monkeypatch.setattr("dmint.core.request_binding.canonicalize_bytes", _boom)
    with pytest.raises(CanonicalizationError, match="request binding cannot be JCS canonicalized"):
        canonical_request_binding(_request(), integration_id="mcp.db", capability_id="db.query")
