"""Validated immutable request and resource models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .canonicalize import canonicalize_frozen, freeze_json
from .errors import RequestValidationError
from .versions import MAX_REQUEST_BYTES


class Decision(str, Enum):
    """Phase 1 runtime decisions."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

    def __bool__(self) -> bool:
        raise TypeError("compare Decision explicitly; it is not a boolean authorization result")


def validate_text(value: Any, field: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise RequestValidationError(f"invalid {field}")
    return value


@dataclass(frozen=True)
class NoResource:
    """A request that intentionally has no resource target."""


NO_RESOURCE = NoResource()


@dataclass(frozen=True)
class AnyResource:
    """An explicit policy wildcard matching any request resource."""


ANY_RESOURCE = AnyResource()


def validate_request_resource(value: Any) -> str | NoResource:
    if type(value) is NoResource:
        return value
    if type(value) is str:
        return validate_text(value, "resource")
    raise RequestValidationError("request resource must be a string or NO_RESOURCE")


@dataclass(frozen=True)
class TrustedContext:
    """Host-supplied context; model output is not a trusted source."""

    values: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.values) is not dict:
            raise RequestValidationError("trusted context must be a JSON object")
        object.__setattr__(self, "values", freeze_json(self.values, "context"))

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "TrustedContext":
        return cls(values)


@dataclass(frozen=True)
class ToolRequest:
    """The immutable security-relevant request evaluated by Dmint."""

    request_id: str
    agent_id: str
    tool: str
    action: str
    resource: str | NoResource
    arguments: Mapping[str, Any]
    context: TrustedContext

    def __post_init__(self) -> None:
        validate_text(self.request_id, "request_id")
        validate_text(self.agent_id, "agent_id")
        validate_text(self.tool, "tool")
        validate_text(self.action, "action")
        validate_request_resource(self.resource)
        if type(self.arguments) is not dict:
            raise RequestValidationError("arguments must be a JSON object")
        if type(self.context) is not TrustedContext:
            raise RequestValidationError("context must be TrustedContext")
        frozen_args = freeze_json(self.arguments, "arguments")
        json_args = canonicalize_frozen(frozen_args)
        json_ctx = canonicalize_frozen(self.context.values)
        if len(json_args.encode("utf-8")) + len(json_ctx.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise RequestValidationError("request payload size exceeds maximum allowed limit")
        object.__setattr__(self, "arguments", frozen_args)
