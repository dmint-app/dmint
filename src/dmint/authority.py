"""Trusted approval authority and exact-request assertion verification."""

from __future__ import annotations

import base64
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .approvals import ApprovalAuthority, ApprovalAuthorityKind, ApprovalRecord, ApprovalState
from .errors import (
    ApprovalAlgorithmUnsupportedError,
    ApprovalAudienceInvalidError,
    ApprovalExpiredError,
    ApprovalIntegrationMismatchError,
    ApprovalInvalidError,
    ApprovalIssuerInvalidError,
    ApprovalMalformedError,
    ApprovalPrincipalMismatchError,
    ApprovalSignatureInvalidError,
    ApprovalVersionUnsupportedError,
)
from .versions import APPROVAL_CREDENTIAL_VERSION, APPROVAL_SIGNATURE_ALGORITHM

_ASSERTION_TOKEN = object()
_ID_PATTERN = re.compile(r"^(?:req|apr)_[A-Za-z0-9_-]{43}$")
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_APPROVER_KINDS = frozenset(item.value for item in ApprovalAuthorityKind)
_OUTER_FIELDS = frozenset({"algorithm", "credential_version", "payload", "signature"})
_PAYLOAD_FIELDS = frozenset(
    {
        "approval_id",
        "approver_authority_id",
        "approver_kind",
        "approver_subject_id",
        "audience",
        "decision",
        "expires_at",
        "integration_id",
        "issued_at",
        "issuer",
        "nonce",
        "policy_digest",
        "policy_evaluated_at",
        "policy_version_id",
        "principal_id",
        "request_fingerprint",
        "request_id",
    }
)
_APPROVAL_DECISION = "APPROVE"


def _text(value: Any, field: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ApprovalMalformedError(f"invalid assertion {field}")
    return value


def _id(value: Any, prefix: str, field: str) -> str:
    value = _text(value, field)
    if not _ID_PATTERN.fullmatch(value) or not value.startswith(prefix):
        raise ApprovalMalformedError(f"invalid assertion {field}")
    return value


def _fingerprint(value: Any) -> str:
    value = _text(value, "request_fingerprint")
    if not _FINGERPRINT_PATTERN.fullmatch(value):
        raise ApprovalMalformedError("invalid assertion request_fingerprint")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ApprovalMalformedError(f"assertion {field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: Any, field: str) -> datetime:
    value = _text(value, field)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ApprovalMalformedError(f"invalid assertion {field}") from exc
    normalized = _timestamp(parsed, field)
    if normalized.isoformat() != value:
        raise ApprovalMalformedError(f"assertion {field} is not canonical UTC")
    return normalized


def _timestamp_text(value: datetime, field: str) -> str:
    return _timestamp(value, field).isoformat()


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: Any, field: str, expected_length: int) -> bytes:
    if type(value) is not str or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ApprovalMalformedError(f"invalid assertion {field}")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ApprovalMalformedError(f"invalid assertion {field}") from exc
    if len(decoded) != expected_length or _b64_encode(decoded) != value:
        raise ApprovalMalformedError(f"invalid assertion {field}")
    return decoded


def _canonical_envelope(envelope: Mapping[str, Any]) -> bytes:
    try:
        return rfc8785.dumps(dict(envelope))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ApprovalMalformedError("assertion is not canonicalizable") from exc


class ApprovalAssertion:
    """Immutable signed approval assertion bound to one exact request."""

    __slots__ = (
        "_credential_version",
        "_algorithm",
        "_approval_id",
        "_request_id",
        "_request_fingerprint",
        "_principal_id",
        "_integration_id",
        "_audience",
        "_issuer",
        "_issued_at",
        "_expires_at",
        "_policy_version_id",
        "_policy_digest",
        "_policy_evaluated_at",
        "_decision",
        "_nonce",
        "_approver_authority_id",
        "_approver_subject_id",
        "_approver_kind",
        "_signature",
    )

    def __init__(self, token: object, **values: Any) -> None:
        if token is not _ASSERTION_TOKEN:
            raise TypeError("ApprovalAssertion instances are created by an authority or parser")
        self._validate(values)
        for name, value in values.items():
            object.__setattr__(self, f"_{name}", value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ApprovalAssertion is immutable")

    @classmethod
    def _signed(cls, values: dict[str, Any], signature: bytes) -> "ApprovalAssertion":
        values = dict(values)
        values["signature"] = signature
        return cls(_ASSERTION_TOKEN, **values)

    @staticmethod
    def _unsigned_values(values: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "algorithm": values["algorithm"],
            "credential_version": values["credential_version"],
            "payload": {
                key: (
                    value.isoformat()
                    if key in {"issued_at", "expires_at", "policy_evaluated_at"}
                    else value
                )
                for key, value in values.items()
                if key not in {"algorithm", "credential_version"}
            },
        }

    @classmethod
    def from_bytes(cls, serialized: bytes) -> "ApprovalAssertion":
        if type(serialized) is not bytes:
            raise ApprovalMalformedError("assertion must be UTF-8 JSON bytes")
        try:
            document = json.loads(
                serialized.decode("utf-8"),
                object_pairs_hook=_strict_pairs,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ApprovalMalformedError("assertion is malformed JSON") from exc
        if type(document) is not dict or set(document) != _OUTER_FIELDS:
            raise ApprovalMalformedError("assertion has invalid fields")
        try:
            if rfc8785.dumps(document) != serialized:
                raise ApprovalMalformedError("assertion is not canonical JCS")
        except (TypeError, ValueError, OverflowError) as exc:
            raise ApprovalMalformedError("assertion is not canonicalizable") from exc
        payload = document["payload"]
        if type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS:
            raise ApprovalMalformedError("assertion payload has invalid fields")
        signature = _b64_decode(document["signature"], "signature", 64)
        payload = dict(payload)
        payload["issued_at"] = _parse_timestamp(payload["issued_at"], "issued_at")
        payload["expires_at"] = _parse_timestamp(payload["expires_at"], "expires_at")
        payload["policy_evaluated_at"] = _parse_timestamp(
            payload["policy_evaluated_at"],
            "policy_evaluated_at",
        )
        return cls(
            _ASSERTION_TOKEN,
            credential_version=document["credential_version"],
            algorithm=document["algorithm"],
            signature=signature,
            **payload,
        )

    def _payload(self) -> dict[str, Any]:
        return {
            "approval_id": self._approval_id,
            "approver_authority_id": self._approver_authority_id,
            "approver_kind": self._approver_kind,
            "approver_subject_id": self._approver_subject_id,
            "audience": self._audience,
            "decision": self._decision,
            "expires_at": self._expires_at.isoformat(),
            "integration_id": self._integration_id,
            "issued_at": self._issued_at.isoformat(),
            "issuer": self._issuer,
            "nonce": self._nonce,
            "policy_digest": self._policy_digest,
            "policy_evaluated_at": self._policy_evaluated_at.isoformat(),
            "policy_version_id": self._policy_version_id,
            "principal_id": self._principal_id,
            "request_fingerprint": self._request_fingerprint,
            "request_id": self._request_id,
        }

    def _unsigned_envelope(self) -> dict[str, Any]:
        return {
            "algorithm": self._algorithm,
            "credential_version": self._credential_version,
            "payload": self._payload(),
        }

    def signing_bytes(self) -> bytes:
        return _canonical_envelope(self._unsigned_envelope())

    def to_bytes(self) -> bytes:
        document = dict(self._unsigned_envelope())
        document["signature"] = _b64_encode(self._signature)
        return _canonical_envelope(document)

    @staticmethod
    def _validate(values: Mapping[str, Any]) -> None:
        if values.get("credential_version") != APPROVAL_CREDENTIAL_VERSION:
            raise ApprovalVersionUnsupportedError("unsupported approval credential version")
        if values.get("algorithm") != APPROVAL_SIGNATURE_ALGORITHM:
            raise ApprovalAlgorithmUnsupportedError("unsupported approval signature algorithm")
        _id(values.get("approval_id"), "apr_", "approval_id")
        _id(values.get("request_id"), "req_", "request_id")
        _fingerprint(values.get("request_fingerprint"))
        _text(values.get("principal_id"), "principal_id")
        _text(values.get("integration_id"), "integration_id")
        _text(values.get("audience"), "audience")
        _text(values.get("issuer"), "issuer")
        if values.get("decision") != _APPROVAL_DECISION:
            raise ApprovalInvalidError("assertion decision is not APPROVE")
        _text(values.get("policy_version_id"), "policy_version_id")
        _fingerprint(values.get("policy_digest"))
        issued_at = values.get("issued_at")
        expires_at = values.get("expires_at")
        policy_evaluated_at = values.get("policy_evaluated_at")
        if type(issued_at) is not datetime or type(expires_at) is not datetime:
            raise ApprovalMalformedError("assertion timestamps are invalid")
        if type(policy_evaluated_at) is not datetime:
            raise ApprovalMalformedError("assertion policy timestamp is invalid")
        issued_at = _timestamp(issued_at, "issued_at")
        expires_at = _timestamp(expires_at, "expires_at")
        if expires_at <= issued_at:
            raise ApprovalMalformedError("assertion expiration must be after issuance")
        _timestamp(policy_evaluated_at, "policy_evaluated_at")
        nonce = _text(values.get("nonce"), "nonce")
        if not _NONCE_PATTERN.fullmatch(nonce):
            raise ApprovalMalformedError("invalid assertion nonce")
        _text(values.get("approver_authority_id"), "approver_authority_id")
        _text(values.get("approver_subject_id"), "approver_subject_id")
        if values.get("approver_kind") not in _APPROVER_KINDS:
            raise ApprovalMalformedError("invalid assertion approver kind")
        signature = values.get("signature")
        if type(signature) is not bytes or len(signature) != 64:
            raise ApprovalMalformedError("invalid assertion signature")

    @property
    def credential_version(self) -> str:
        return self._credential_version

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def approval_id(self) -> str:
        return self._approval_id

    @property
    def request_id(self) -> str:
        return self._request_id

    @property
    def request_fingerprint(self) -> str:
        return self._request_fingerprint

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def issued_at(self) -> datetime:
        return self._issued_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def policy_version_id(self) -> str:
        return self._policy_version_id

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def policy_evaluated_at(self) -> datetime:
        return self._policy_evaluated_at

    @property
    def decision(self) -> str:
        return self._decision

    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def approver_authority_id(self) -> str:
        return self._approver_authority_id

    @property
    def approver_subject_id(self) -> str:
        return self._approver_subject_id

    @property
    def approver_kind(self) -> str:
        return self._approver_kind

    @property
    def signature(self) -> bytes:
        return self._signature


class LocalApprovalAuthority:
    """Local trusted signer; the host must protect this object and its key."""

    __slots__ = ("_issuer_id", "_audience", "_private_key", "_clock", "_sealed")

    def __init__(
        self,
        *,
        issuer_id: str,
        audience: str,
        private_key: Ed25519PrivateKey | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _text(issuer_id, "issuer_id")
        _text(audience, "audience")
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        object.__setattr__(self, "_issuer_id", issuer_id)
        object.__setattr__(self, "_audience", audience)
        object.__setattr__(self, "_private_key", private_key)
        object.__setattr__(
            self,
            "_clock",
            clock or (lambda: datetime.now(timezone.utc)),
        )
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("approval authority is immutable")
        object.__setattr__(self, name, value)

    @property
    def issuer_id(self) -> str:
        return self._issuer_id

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def issue(
        self,
        record: ApprovalRecord,
        approver: ApprovalAuthority,
        *,
        now: datetime | None = None,
    ) -> ApprovalAssertion:
        if type(record) is not ApprovalRecord or record.state not in (
            ApprovalState.PENDING,
            ApprovalState.APPROVED,
        ):
            raise ApprovalInvalidError("approval assertion requires a consumable record")
        if type(approver) is not ApprovalAuthority:
            raise ApprovalMalformedError("approval assertion requires an authority identity")
        now = _timestamp(now or self._clock(), "issued_at")
        if now >= record.expires_at:
            raise ApprovalExpiredError("approval record has expired")
        values = {
            "credential_version": APPROVAL_CREDENTIAL_VERSION,
            "algorithm": APPROVAL_SIGNATURE_ALGORITHM,
            "approval_id": record.approval_id,
            "request_id": record.request_id,
            "request_fingerprint": record.request_fingerprint,
            "principal_id": record.request.agent_id,
            "integration_id": record.integration_id,
            "audience": self._audience,
            "issuer": self._issuer_id,
            "issued_at": now,
            "expires_at": record.expires_at,
            "policy_version_id": record.policy_provenance.version_id,
            "policy_digest": record.policy_provenance.policy_digest,
            "policy_evaluated_at": record.policy_provenance.evaluated_at,
            "decision": _APPROVAL_DECISION,
            "nonce": secrets.token_urlsafe(32),
            "approver_authority_id": approver.authority_id,
            "approver_subject_id": approver.subject_id,
            "approver_kind": approver.kind.value,
        }
        unsigned = ApprovalAssertion._unsigned_values(values)
        signature = self._private_key.sign(_canonical_envelope(unsigned))
        return ApprovalAssertion._signed(values, signature)


@dataclass(frozen=True)
class VerifiedApproval:
    """Verification result, not an execution permission or retry capability."""

    assertion: ApprovalAssertion
    record: ApprovalRecord


class ApprovalVerifier:
    """Verify assertions against trusted issuer keys and one exact record."""

    __slots__ = ("_trusted_issuers", "_audience", "_clock", "_sealed")

    def __init__(
        self,
        *,
        trusted_issuers: Mapping[str, Ed25519PublicKey],
        audience: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _text(audience, "audience")
        if not isinstance(trusted_issuers, Mapping) or not trusted_issuers:
            raise ValueError("trusted_issuers must be a non-empty mapping")
        trusted: dict[str, Ed25519PublicKey] = {}
        for issuer, key in trusted_issuers.items():
            _text(issuer, "issuer_id")
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError("trusted issuer keys must be Ed25519 public keys")
            trusted[issuer] = key
        object.__setattr__(self, "_trusted_issuers", MappingProxyType(trusted))
        object.__setattr__(self, "_audience", audience)
        object.__setattr__(
            self,
            "_clock",
            clock or (lambda: datetime.now(timezone.utc)),
        )
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("approval verifier is immutable")
        object.__setattr__(self, name, value)

    def verify(
        self,
        assertion: ApprovalAssertion | bytes,
        record: ApprovalRecord,
        *,
        now: datetime | None = None,
    ) -> VerifiedApproval:
        if type(assertion) is bytes:
            assertion = ApprovalAssertion.from_bytes(assertion)
        if type(assertion) is not ApprovalAssertion:
            raise ApprovalMalformedError("invalid approval assertion")
        if type(record) is not ApprovalRecord or record.state not in (
            ApprovalState.PENDING,
            ApprovalState.APPROVED,
        ):
            raise ApprovalInvalidError("approval record is not consumable")
        if assertion.audience != self._audience:
            raise ApprovalAudienceInvalidError("approval audience mismatch")
        key = self._trusted_issuers.get(assertion.issuer)
        if key is None:
            raise ApprovalIssuerInvalidError("approval issuer is not trusted")
        try:
            key.verify(assertion.signature, assertion.signing_bytes())
        except InvalidSignature as exc:
            raise ApprovalSignatureInvalidError("approval signature is invalid") from exc
        now = _timestamp(now or self._clock(), "verification time")
        if now < assertion.issued_at:
            raise ApprovalInvalidError("approval is not yet valid")
        if now >= assertion.expires_at:
            raise ApprovalExpiredError("approval assertion has expired")
        if assertion.expires_at != record.expires_at:
            raise ApprovalInvalidError("approval expiration does not match request record")
        if assertion.approval_id != record.approval_id or assertion.request_id != record.request_id:
            raise ApprovalInvalidError("approval workflow identity mismatch")
        if assertion.request_fingerprint != record.request_fingerprint:
            raise ApprovalInvalidError("approval request fingerprint mismatch")
        if assertion.principal_id != record.request.agent_id:
            raise ApprovalPrincipalMismatchError("approval principal mismatch")
        if assertion.integration_id != record.integration_id:
            raise ApprovalIntegrationMismatchError("approval integration mismatch")
        if (
            assertion.policy_version_id != record.policy_provenance.version_id
            or assertion.policy_digest != record.policy_provenance.policy_digest
            or assertion.policy_evaluated_at != record.policy_provenance.evaluated_at
        ):
            raise ApprovalInvalidError("approval policy provenance mismatch")
        return VerifiedApproval(assertion, record)
