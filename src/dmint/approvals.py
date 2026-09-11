"""In-memory approval domain model and state machine for Stage 2A."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from .errors import (
    ApprovalExpiredError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
    UnknownApprovalStateError,
    UnknownApprovalVersionError,
)
from .models import ToolRequest
from .request_binding import request_binding_fingerprint
from .versions import (
    APPROVAL_RECORD_SCHEMA_VERSION,
    CANONICALIZATION_PROFILE,
    REQUEST_BINDING_VERSION,
)

_SUPPORTED_SCHEMA_VERSIONS = frozenset({APPROVAL_RECORD_SCHEMA_VERSION})
_SUPPORTED_BINDING_VERSIONS = frozenset({REQUEST_BINDING_VERSION})
_SUPPORTED_CANONICALIZATION_PROFILES = frozenset({CANONICALIZATION_PROFILE})
_SECURE_ID_PATTERN = re.compile(r"^(?:req|apr)_[A-Za-z0-9_-]{43}$")
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RECORD_TOKEN = object()
_AUTHORITY_TOKEN = object()


class ApprovalState(str, Enum):
    """Persistent approval states supported by Stage 2A."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    POLICY_INVALIDATED = "POLICY_INVALIDATED"
    CONSUMED = "CONSUMED"


class ApprovalAuthorityKind(str, Enum):
    """Authority categories; agent and LLM identities are intentionally absent."""

    HUMAN = "HUMAN"
    AUTHENTICATED_APPLICATION = "AUTHENTICATED_APPLICATION"


def new_request_id() -> str:
    """Create a non-sequential workflow identifier."""

    return f"req_{secrets.token_urlsafe(32)}"


def new_approval_id() -> str:
    """Create a non-sequential approval-record identifier."""

    return f"apr_{secrets.token_urlsafe(32)}"


def parse_approval_state(value: Any) -> ApprovalState:
    """Parse a state without allowing unknown values to fail open."""

    if type(value) is not str:
        raise UnknownApprovalStateError("approval state must be a string")
    try:
        return ApprovalState(value)
    except ValueError as exc:
        raise UnknownApprovalStateError("unknown approval state") from exc


def _require_text(value: Any, field: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise MalformedApprovalError(f"invalid approval {field}")
    return value


def _require_utc(value: Any, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise MalformedApprovalError(f"approval {field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate_secure_id(value: Any, prefix: str, field: str) -> str:
    if type(value) is not str or not _SECURE_ID_PATTERN.fullmatch(value) or not value.startswith(prefix):
        raise MalformedApprovalError(f"invalid approval {field}")
    return value


def _validate_fingerprint(value: Any) -> str:
    if type(value) is not str or not _FINGERPRINT_PATTERN.fullmatch(value):
        raise MalformedApprovalError("invalid request fingerprint")
    return value


def _validate_version(value: Any, supported: frozenset[str], field: str) -> str:
    value = _require_text(value, field)
    if value not in supported:
        raise UnknownApprovalVersionError(f"unknown approval {field}")
    return value


@dataclass(frozen=True)
class PolicyProvenance:
    """Policy evaluation metadata, separate from semantic request identity."""

    version_id: str
    policy_digest: str
    evaluated_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.version_id, "policy version")
        _validate_fingerprint(self.policy_digest)
        object.__setattr__(self, "evaluated_at", _require_utc(self.evaluated_at, "policy evaluation time"))


@dataclass(frozen=True, init=False)
class ApprovalAuthority:
    """An identity claim supplied by a trusted approval boundary.

    This value does not authenticate the subject. The future approval adapter
    must authenticate the human/application before constructing it. There is
    deliberately no agent or LLM authority kind.
    """

    authority_id: str
    subject_id: str
    kind: ApprovalAuthorityKind

    def __init__(
        self,
        token: object,
        authority_id: str,
        subject_id: str,
        kind: ApprovalAuthorityKind,
    ) -> None:
        if token is not _AUTHORITY_TOKEN:
            raise TypeError("ApprovalAuthority values require a trusted approval boundary")
        _require_text(authority_id, "authority_id")
        _require_text(subject_id, "approver subject")
        if type(kind) is not ApprovalAuthorityKind:
            raise MalformedApprovalError("invalid approval authority kind")
        object.__setattr__(self, "authority_id", authority_id)
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "kind", kind)

    @classmethod
    def _from_trusted_boundary(
        cls,
        authority_id: str,
        subject_id: str,
        kind: ApprovalAuthorityKind,
    ) -> "ApprovalAuthority":
        return cls(_AUTHORITY_TOKEN, authority_id, subject_id, kind)

    @classmethod
    def _from_recorded_metadata(
        cls,
        authority_id: str,
        subject_id: str,
        kind: ApprovalAuthorityKind,
    ) -> "ApprovalAuthority":
        """Rebuild signed/recorded metadata; this does not authenticate it."""

        return cls(_AUTHORITY_TOKEN, authority_id, subject_id, kind)


class ApprovalRecord:
    """Immutable approval metadata; it is not an execution permission."""

    __slots__ = (
        "_schema_version",
        "_approval_id",
        "_request",
        "_request_fingerprint",
        "_binding_version",
        "_canonicalization_profile",
        "_integration_id",
        "_capability_id",
        "_policy_provenance",
        "_created_at",
        "_expires_at",
        "_state",
        "_decision_authority",
        "_decision_at",
        "_state_at",
        "_state_reason",
        "_consumed_at",
    )

    def __init__(
        self,
        token: object,
        *,
        schema_version: str,
        approval_id: str,
        request: ToolRequest,
        request_fingerprint: str,
        binding_version: str,
        canonicalization_profile: str,
        integration_id: str,
        capability_id: str,
        policy_provenance: PolicyProvenance,
        created_at: datetime,
        expires_at: datetime,
        state: ApprovalState,
        decision_authority: ApprovalAuthority | None,
        decision_at: datetime | None,
        state_at: datetime,
        state_reason: str | None,
        consumed_at: datetime | None,
    ) -> None:
        if token is not _RECORD_TOKEN:
            raise TypeError("ApprovalRecord instances are created by the approval domain")
        self._validate(
            schema_version,
            approval_id,
            request,
            request_fingerprint,
            binding_version,
            canonicalization_profile,
            integration_id,
            capability_id,
            policy_provenance,
            created_at,
            expires_at,
            state,
            decision_authority,
            decision_at,
            state_at,
            state_reason,
            consumed_at,
        )
        object.__setattr__(self, "_schema_version", schema_version)
        object.__setattr__(self, "_approval_id", approval_id)
        object.__setattr__(self, "_request", request)
        object.__setattr__(self, "_request_fingerprint", request_fingerprint)
        object.__setattr__(self, "_binding_version", binding_version)
        object.__setattr__(self, "_canonicalization_profile", canonicalization_profile)
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_capability_id", capability_id)
        object.__setattr__(self, "_policy_provenance", policy_provenance)
        object.__setattr__(self, "_created_at", _require_utc(created_at, "creation time"))
        object.__setattr__(self, "_expires_at", _require_utc(expires_at, "expiration time"))
        object.__setattr__(self, "_state", state)
        object.__setattr__(self, "_decision_authority", decision_authority)
        object.__setattr__(self, "_decision_at", _optional_utc(decision_at, "decision time"))
        object.__setattr__(self, "_state_at", _require_utc(state_at, "state time"))
        object.__setattr__(self, "_state_reason", state_reason)
        object.__setattr__(self, "_consumed_at", _optional_utc(consumed_at, "consumption time"))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ApprovalRecord is immutable")

    @classmethod
    def create(
        cls,
        *,
        request: ToolRequest,
        integration_id: str,
        capability_id: str,
        policy_provenance: PolicyProvenance,
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
        binding_version: str = REQUEST_BINDING_VERSION,
        canonicalization_profile: str = CANONICALIZATION_PROFILE,
        schema_version: str = APPROVAL_RECORD_SCHEMA_VERSION,
    ) -> "ApprovalRecord":
        created_at = _require_utc(created_at or datetime.now(timezone.utc), "creation time")
        expires_at = _require_utc(expires_at or (created_at + timedelta(minutes=5)), "expiration time")
        if expires_at <= created_at:
            raise MalformedApprovalError("approval expiration must be after creation")
        request_fingerprint = request_binding_fingerprint(
            request,
            integration_id=integration_id,
            capability_id=capability_id,
            binding_version=binding_version,
            canonicalization_profile=canonicalization_profile,
        )
        return cls(
            _RECORD_TOKEN,
            schema_version=schema_version,
            approval_id=new_approval_id(),
            request=request,
            request_fingerprint=request_fingerprint,
            binding_version=binding_version,
            canonicalization_profile=canonicalization_profile,
            integration_id=integration_id,
            capability_id=capability_id,
            policy_provenance=policy_provenance,
            created_at=created_at,
            expires_at=expires_at,
            state=ApprovalState.PENDING,
            decision_authority=None,
            decision_at=None,
            state_at=created_at,
            state_reason=None,
            consumed_at=None,
        )

    @classmethod
    def _from_storage(
        cls,
        *,
        schema_version: str,
        approval_id: str,
        request: ToolRequest,
        request_fingerprint: str,
        binding_version: str,
        canonicalization_profile: str,
        integration_id: str,
        capability_id: str,
        policy_provenance: PolicyProvenance,
        created_at: datetime,
        expires_at: datetime,
        state: ApprovalState,
        state_at: datetime,
        decision_authority: ApprovalAuthority | None = None,
        decision_at: datetime | None = None,
        state_reason: str | None = None,
        consumed_at: datetime | None = None,
    ) -> "ApprovalRecord":
        expected_fingerprint = request_binding_fingerprint(
            request,
            integration_id=integration_id,
            capability_id=capability_id,
            binding_version=binding_version,
            canonicalization_profile=canonicalization_profile,
        )
        if request_fingerprint != expected_fingerprint:
            raise MalformedApprovalError("stored request fingerprint does not match request")
        return cls(
            _RECORD_TOKEN,
            schema_version=schema_version,
            approval_id=approval_id,
            request=request,
            request_fingerprint=request_fingerprint,
            binding_version=binding_version,
            canonicalization_profile=canonicalization_profile,
            integration_id=integration_id,
            capability_id=capability_id,
            policy_provenance=policy_provenance,
            created_at=created_at,
            expires_at=expires_at,
            state=state,
            decision_authority=decision_authority,
            decision_at=decision_at,
            state_at=state_at,
            state_reason=state_reason,
            consumed_at=consumed_at,
        )

    @staticmethod
    def _validate(
        schema_version: str,
        approval_id: str,
        request: ToolRequest,
        request_fingerprint: str,
        binding_version: str,
        canonicalization_profile: str,
        integration_id: str,
        capability_id: str,
        policy_provenance: PolicyProvenance,
        created_at: datetime,
        expires_at: datetime,
        state: ApprovalState,
        decision_authority: ApprovalAuthority | None,
        decision_at: datetime | None,
        state_at: datetime,
        state_reason: str | None,
        consumed_at: datetime | None,
    ) -> None:
        _validate_version(schema_version, _SUPPORTED_SCHEMA_VERSIONS, "schema version")
        _validate_secure_id(approval_id, "apr_", "approval_id")
        if type(request) is not ToolRequest:
            raise MalformedApprovalError("approval request must be a ToolRequest")
        _validate_secure_id(request.request_id, "req_", "request_id")
        _validate_fingerprint(request_fingerprint)
        _validate_version(binding_version, _SUPPORTED_BINDING_VERSIONS, "binding version")
        _validate_version(
            canonicalization_profile,
            _SUPPORTED_CANONICALIZATION_PROFILES,
            "canonicalization profile",
        )
        _require_text(integration_id, "integration_id")
        _require_text(capability_id, "capability_id")
        if type(policy_provenance) is not PolicyProvenance:
            raise MalformedApprovalError("invalid policy provenance")
        created_at = _require_utc(created_at, "creation time")
        expires_at = _require_utc(expires_at, "expiration time")
        state_at = _require_utc(state_at, "state time")
        if expires_at <= created_at:
            raise MalformedApprovalError("approval expiration must be after creation")
        if type(state) is not ApprovalState:
            raise UnknownApprovalStateError("invalid approval state")
        if decision_authority is not None and type(decision_authority) is not ApprovalAuthority:
            raise MalformedApprovalError("invalid approval authority")
        if state_reason is not None:
            _require_text(state_reason, "state reason")
        if state in {ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.CONSUMED}:
            if decision_authority is None or decision_at is None:
                raise MalformedApprovalError("decision metadata is required for this state")
        if state is ApprovalState.PENDING and (decision_authority is not None or decision_at is not None):
            raise MalformedApprovalError("pending approval cannot have decision metadata")
        if state is ApprovalState.CONSUMED and consumed_at is None:
            raise MalformedApprovalError("consumed approval requires consumption time")
        if state is not ApprovalState.CONSUMED and consumed_at is not None:
            raise MalformedApprovalError("only consumed approval can have consumption time")

    def _next(
        self,
        *,
        state: ApprovalState,
        state_at: datetime,
        decision_authority: ApprovalAuthority | None = None,
        decision_at: datetime | None = None,
        state_reason: str | None = None,
        consumed_at: datetime | None = None,
    ) -> "ApprovalRecord":
        return ApprovalRecord(
            _RECORD_TOKEN,
            schema_version=self._schema_version,
            approval_id=self._approval_id,
            request=self._request,
            request_fingerprint=self._request_fingerprint,
            binding_version=self._binding_version,
            canonicalization_profile=self._canonicalization_profile,
            integration_id=self._integration_id,
            capability_id=self._capability_id,
            policy_provenance=self._policy_provenance,
            created_at=self._created_at,
            expires_at=self._expires_at,
            state=state,
            decision_authority=decision_authority,
            decision_at=decision_at,
            state_at=state_at,
            state_reason=state_reason,
            consumed_at=consumed_at,
        )

    def _require_not_expired(self, now: datetime | None = None) -> datetime:
        now = _require_utc(now or datetime.now(timezone.utc), "transition time")
        if now >= self._expires_at:
            raise ApprovalExpiredError("approval has expired")
        return now

    def _require_state(self, *allowed: ApprovalState) -> None:
        if self._state not in allowed:
            raise IllegalApprovalTransitionError(
                f"cannot transition approval from {self._state.value}"
            )

    def approve(self, authority: ApprovalAuthority, *, now: datetime | None = None) -> "ApprovalRecord":
        self._require_state(ApprovalState.PENDING)
        now = self._require_not_expired(now)
        if type(authority) is not ApprovalAuthority:
            raise MalformedApprovalError("approval requires a trusted authority value")
        return self._next(
            state=ApprovalState.APPROVED,
            state_at=now,
            decision_authority=authority,
            decision_at=now,
        )

    def reject(
        self,
        authority: ApprovalAuthority,
        *,
        now: datetime | None = None,
        reason: str | None = None,
    ) -> "ApprovalRecord":
        self._require_state(ApprovalState.PENDING)
        now = self._require_not_expired(now)
        if type(authority) is not ApprovalAuthority:
            raise MalformedApprovalError("rejection requires a trusted authority value")
        return self._next(
            state=ApprovalState.REJECTED,
            state_at=now,
            decision_authority=authority,
            decision_at=now,
            state_reason=reason,
        )

    def cancel(self, *, now: datetime | None = None, reason: str | None = None) -> "ApprovalRecord":
        self._require_state(ApprovalState.PENDING, ApprovalState.APPROVED)
        now = self._require_not_expired(now)
        return self._next(
            state=ApprovalState.CANCELLED,
            state_at=now,
            state_reason=reason,
            decision_authority=self._decision_authority,
            decision_at=self._decision_at,
        )

    def expire(self, *, now: datetime | None = None) -> "ApprovalRecord":
        self._require_state(ApprovalState.PENDING, ApprovalState.APPROVED)
        now = _require_utc(now or datetime.now(timezone.utc), "transition time")
        if now < self._expires_at:
            raise IllegalApprovalTransitionError("approval has not expired")
        return self._next(
            state=ApprovalState.EXPIRED,
            state_at=now,
            decision_authority=self._decision_authority,
            decision_at=self._decision_at,
        )

    def invalidate_policy(self, *, now: datetime | None = None, reason: str = "policy changed") -> "ApprovalRecord":
        self._require_state(ApprovalState.PENDING, ApprovalState.APPROVED)
        now = self._require_not_expired(now)
        return self._next(
            state=ApprovalState.POLICY_INVALIDATED,
            state_at=now,
            state_reason=reason,
            decision_authority=self._decision_authority,
            decision_at=self._decision_at,
        )

    def consume(self, *, now: datetime | None = None) -> "ApprovalRecord":
        self._require_state(ApprovalState.APPROVED)
        now = self._require_not_expired(now)
        return self._next(
            state=ApprovalState.CONSUMED,
            state_at=now,
            decision_authority=self._decision_authority,
            decision_at=self._decision_at,
            consumed_at=now,
        )

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def approval_id(self) -> str:
        return self._approval_id

    @property
    def request_id(self) -> str:
        return self._request.request_id

    @property
    def request(self) -> ToolRequest:
        return self._request

    @property
    def request_fingerprint(self) -> str:
        return self._request_fingerprint

    @property
    def binding_version(self) -> str:
        return self._binding_version

    @property
    def canonicalization_profile(self) -> str:
        return self._canonicalization_profile

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def capability_id(self) -> str:
        return self._capability_id

    @property
    def policy_provenance(self) -> PolicyProvenance:
        return self._policy_provenance

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def state(self) -> ApprovalState:
        return self._state

    @property
    def decision_authority(self) -> ApprovalAuthority | None:
        return self._decision_authority

    @property
    def decision_at(self) -> datetime | None:
        return self._decision_at

    @property
    def state_at(self) -> datetime:
        return self._state_at

    @property
    def state_reason(self) -> str | None:
        return self._state_reason

    @property
    def consumed_at(self) -> datetime | None:
        return self._consumed_at


def _optional_utc(value: datetime | None, field: str) -> datetime | None:
    if value is None:
        return None
    return _require_utc(value, field)
