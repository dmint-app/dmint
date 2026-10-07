"""Verify-only module for approval assertions, verification, and public keys.

This module contains ZERO private-key loading, storage, or signing code.
It is safe for agent-facing and gateway components to import.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from .approvals import ApprovalAuthorityKind, ApprovalRecord, ApprovalState
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

__all__ = [
    "ApprovalAssertion",
    "VerifiedApproval",
    "ApprovalVerifier",
    "public_key_hex",
    "public_key_pem",
    "public_key_from_hex",
    "public_key_from_pem",
]

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
    except (ValueError, binascii.Error) as exc:
        raise ApprovalMalformedError(f"invalid assertion {field}") from exc
    if len(decoded) != expected_length or _b64_encode(decoded) != value:
        raise ApprovalMalformedError(f"invalid assertion {field}")
    return decoded


def _canonical_envelope(envelope: Mapping[str, Any]) -> bytes:
    try:
        return rfc8785.dumps(dict(envelope))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ApprovalMalformedError("assertion is not canonicalizable") from exc


# ─── Public-Key Helpers ────────────────────────────────────────────────────────


def public_key_hex(public_key: Ed25519PublicKey) -> str:
    """Return the raw 32-byte Ed25519 public key as a lowercase hex string (64 chars)."""
    raw = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return raw.hex()


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    """Return the public key as a PEM-encoded SubjectPublicKeyInfo string."""
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    """Load an Ed25519PublicKey from a 64-char lowercase hex string.

    Raises ValueError on invalid input.
    """
    if not isinstance(hex_str, str) or len(hex_str) != 64:
        raise ValueError("public_key_hex must be a 64-character hex string")
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("public_key_hex contains non-hex characters") from exc
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_from_pem(pem_str: str) -> Ed25519PublicKey:
    """Load an Ed25519PublicKey from a PEM string.

    Raises ValueError on invalid input.
    """
    try:
        key = load_pem_public_key(pem_str.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("PEM key is not an Ed25519 public key")
    return key


# ─── Assertion Model ───────────────────────────────────────────────────────────


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

    _credential_version: str
    _algorithm: str
    _approval_id: str
    _request_id: str
    _request_fingerprint: str
    _principal_id: str
    _integration_id: str
    _audience: str
    _issuer: str
    _issued_at: datetime
    _expires_at: datetime
    _policy_version_id: str
    _policy_digest: str
    _policy_evaluated_at: datetime
    _decision: str
    _nonce: str
    _approver_authority_id: str
    _approver_subject_id: str
    _approver_kind: str
    _signature: bytes

    def __init__(self, token: object, **values: Any) -> None:
        if token is not _ASSERTION_TOKEN:
            raise TypeError("ApprovalAssertion instances are created by an authority or parser")
        self._validate(values)
        for name, value in values.items():
            object.__setattr__(self, f"_{name}", value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("approval assertion is immutable")

    @classmethod
    def _signed(cls, values: Mapping[str, Any], signature: bytes) -> ApprovalAssertion:
        all_values = dict(values)
        all_values["signature"] = signature
        return cls(_ASSERTION_TOKEN, **all_values)

    @classmethod
    def _unsigned_values(cls, values: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "credential_version": values["credential_version"],
            "algorithm": values["algorithm"],
            "payload": {
                "approval_id": values["approval_id"],
                "request_id": values["request_id"],
                "request_fingerprint": values["request_fingerprint"],
                "principal_id": values["principal_id"],
                "integration_id": values["integration_id"],
                "audience": values["audience"],
                "issuer": values["issuer"],
                "issued_at": _timestamp_text(values["issued_at"], "issued_at"),
                "expires_at": _timestamp_text(values["expires_at"], "expires_at"),
                "policy_version_id": values["policy_version_id"],
                "policy_digest": values["policy_digest"],
                "policy_evaluated_at": _timestamp_text(values["policy_evaluated_at"], "policy_evaluated_at"),
                "decision": values["decision"],
                "nonce": values["nonce"],
                "approver_authority_id": values["approver_authority_id"],
                "approver_subject_id": values["approver_subject_id"],
                "approver_kind": values["approver_kind"],
            },
        }

    def _validate(self, values: Mapping[str, Any]) -> None:
        if set(values) != _PAYLOAD_FIELDS | {"algorithm", "credential_version", "signature"}:
            raise ApprovalMalformedError("invalid assertion fields")
        if values["credential_version"] != APPROVAL_CREDENTIAL_VERSION:
            raise ApprovalVersionUnsupportedError("unsupported approval assertion credential version")
        if values["algorithm"] != APPROVAL_SIGNATURE_ALGORITHM:
            raise ApprovalAlgorithmUnsupportedError("unsupported approval assertion algorithm")
        _id(values["approval_id"], "apr_", "approval_id")
        _id(values["request_id"], "req_", "request_id")
        _fingerprint(values["request_fingerprint"])
        _text(values["principal_id"], "principal_id")
        _text(values["integration_id"], "integration_id")
        _text(values["audience"], "audience")
        _text(values["issuer"], "issuer")
        issued_at = _timestamp(values["issued_at"], "issued_at")
        expires_at = _timestamp(values["expires_at"], "expires_at")
        policy_eval = _timestamp(values["policy_evaluated_at"], "policy_evaluated_at")
        if issued_at >= expires_at:
            raise ApprovalMalformedError("assertion issued_at must precede expires_at")
        if policy_eval > issued_at:
            raise ApprovalMalformedError("assertion policy evaluation must precede issuance")
        _text(values["policy_version_id"], "policy_version_id")
        _fingerprint(values["policy_digest"])
        if values["decision"] != _APPROVAL_DECISION:
            raise ApprovalMalformedError("invalid assertion decision")
        nonce = _text(values["nonce"], "nonce")
        if not _NONCE_PATTERN.fullmatch(nonce):
            raise ApprovalMalformedError("invalid assertion nonce")
        _text(values["approver_authority_id"], "approver_authority_id")
        _text(values["approver_subject_id"], "approver_subject_id")
        if values["approver_kind"] not in _APPROVER_KINDS:
            raise ApprovalMalformedError("invalid assertion approver_kind")
        sig = values["signature"]
        if type(sig) is not bytes or len(sig) != 64:
            raise ApprovalMalformedError("invalid assertion signature")

    def to_envelope(self) -> dict[str, Any]:
        envelope = self._unsigned_values(
            {name[1:]: getattr(self, name) for name in self.__slots__ if name != "_signature"}
        )
        envelope["signature"] = _b64_encode(self._signature)
        return envelope

    def signing_bytes(self) -> bytes:
        return _canonical_envelope(
            self._unsigned_values({name[1:]: getattr(self, name) for name in self.__slots__ if name != "_signature"})
        )

    def to_bytes(self) -> bytes:
        return _canonical_envelope(self.to_envelope())

    @classmethod
    def from_bytes(cls, raw: bytes) -> ApprovalAssertion:
        if type(raw) is not bytes:
            raise ApprovalMalformedError("assertion bytes must be raw bytes")
        try:
            parsed = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_pairs,
                parse_constant=_reject_constant,
            )
        except Exception as exc:
            raise ApprovalMalformedError("assertion is not canonical JSON") from exc
        if type(parsed) is not dict or set(parsed) != _OUTER_FIELDS:
            raise ApprovalMalformedError("invalid assertion envelope")
        if parsed["credential_version"] != APPROVAL_CREDENTIAL_VERSION:
            raise ApprovalVersionUnsupportedError("unsupported approval assertion credential version")
        if parsed["algorithm"] != APPROVAL_SIGNATURE_ALGORITHM:
            raise ApprovalAlgorithmUnsupportedError("unsupported approval assertion algorithm")
        payload = parsed["payload"]
        if type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS:
            raise ApprovalMalformedError("invalid assertion payload")
        signature = _b64_decode(parsed["signature"], "signature", 64)
        values = {
            "credential_version": parsed["credential_version"],
            "algorithm": parsed["algorithm"],
            "approval_id": payload["approval_id"],
            "request_id": payload["request_id"],
            "request_fingerprint": payload["request_fingerprint"],
            "principal_id": payload["principal_id"],
            "integration_id": payload["integration_id"],
            "audience": payload["audience"],
            "issuer": payload["issuer"],
            "issued_at": _parse_timestamp(payload["issued_at"], "issued_at"),
            "expires_at": _parse_timestamp(payload["expires_at"], "expires_at"),
            "policy_version_id": payload["policy_version_id"],
            "policy_digest": payload["policy_digest"],
            "policy_evaluated_at": _parse_timestamp(payload["policy_evaluated_at"], "policy_evaluated_at"),
            "decision": payload["decision"],
            "nonce": payload["nonce"],
            "approver_authority_id": payload["approver_authority_id"],
            "approver_subject_id": payload["approver_subject_id"],
            "approver_kind": payload["approver_kind"],
            "signature": signature,
        }
        return cls(_ASSERTION_TOKEN, **values)

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


@dataclass(frozen=True)
class VerifiedApproval:
    """Verification result, not an execution permission or retry capability."""

    assertion: ApprovalAssertion
    record: ApprovalRecord


class ApprovalVerifier:
    """Verify assertions against trusted issuer keys and one exact record.

    Contains only verification logic. Operates strictly with public keys.
    """

    __slots__ = ("_trusted_issuers", "_audience", "_clock", "_sealed")

    _trusted_issuers: MappingProxyType[str, Ed25519PublicKey]
    _audience: str
    _clock: Callable[[], datetime]
    _sealed: bool

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
