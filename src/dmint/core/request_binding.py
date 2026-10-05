"""RFC 8785 request binding and semantic fingerprint construction."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from .canonicalize import thaw_json
from .errors import CanonicalizationError, MalformedApprovalError, UnknownApprovalVersionError
from .models import AnyResource, NoResource, ToolRequest, validate_text
from .versions import CANONICALIZATION_PROFILE, REQUEST_BINDING_VERSION

_FINGERPRINT_DOMAIN = b"dmint/request-fingerprint/v1\x00"


def _resource_value(request: ToolRequest) -> dict[str, Any]:
    if type(request.resource) is NoResource:
        return {"kind": "none"}
    if type(request.resource) is AnyResource:
        return {"kind": "any"}
    if type(request.resource) is str:
        return {"kind": "value", "value": request.resource}
    raise MalformedApprovalError("invalid request resource representation")


def request_binding_envelope(
    request: ToolRequest,
    *,
    integration_id: str,
    capability_id: str,
    binding_version: str = REQUEST_BINDING_VERSION,
    canonicalization_profile: str = CANONICALIZATION_PROFILE,
) -> dict[str, Any]:
    """Build the semantic request envelope, excluding workflow metadata."""

    if type(request) is not ToolRequest:
        raise MalformedApprovalError("request binding requires a ToolRequest")
    if binding_version != REQUEST_BINDING_VERSION:
        raise UnknownApprovalVersionError("unknown request binding version")
    if canonicalization_profile != CANONICALIZATION_PROFILE:
        raise UnknownApprovalVersionError("unknown canonicalization profile")
    try:
        integration_id = validate_text(integration_id, "integration_id")
        capability_id = validate_text(capability_id, "capability_id")
    except Exception as exc:
        raise MalformedApprovalError("invalid request binding identity") from exc
    return {
        "action": request.action,
        "arguments": thaw_json(request.arguments),
        "binding_version": binding_version,
        "canonicalization_profile": canonicalization_profile,
        "capability_id": capability_id,
        "integration_id": integration_id,
        "principal_id": request.agent_id,
        "resource": _resource_value(request),
        "tool": request.tool,
        "trusted_context": thaw_json(request.context.values),
    }


def canonical_request_binding(
    request: ToolRequest,
    *,
    integration_id: str,
    capability_id: str,
    binding_version: str = REQUEST_BINDING_VERSION,
    canonicalization_profile: str = CANONICALIZATION_PROFILE,
) -> bytes:
    """Return the RFC 8785 bytes for the exact semantic request envelope."""

    envelope = request_binding_envelope(
        request,
        integration_id=integration_id,
        capability_id=capability_id,
        binding_version=binding_version,
        canonicalization_profile=canonicalization_profile,
    )
    try:
        return rfc8785.dumps(envelope)
    except (TypeError, ValueError, OverflowError) as exc:
        raise CanonicalizationError("request binding cannot be JCS canonicalized") from exc


def request_binding_fingerprint(
    request: ToolRequest,
    *,
    integration_id: str,
    capability_id: str,
    binding_version: str = REQUEST_BINDING_VERSION,
    canonicalization_profile: str = CANONICALIZATION_PROFILE,
) -> str:
    """Return the domain-separated SHA-256 semantic request fingerprint."""

    canonical = canonical_request_binding(
        request,
        integration_id=integration_id,
        capability_id=capability_id,
        binding_version=binding_version,
        canonicalization_profile=canonicalization_profile,
    )
    return hashlib.sha256(_FINGERPRINT_DOMAIN + canonical).hexdigest()
