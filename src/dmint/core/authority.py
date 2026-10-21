"""Trusted approval authority for signing exact-request assertions."""

from __future__ import annotations

import os
import secrets
import warnings
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
)
from .errors import (
    ApprovalExpiredError,
    ApprovalInvalidError,
    ApprovalMalformedError,
)
from .keys import (
    DEFAULT_KEY_FILE,
    KeyLoadError,
    _parse_private_key_hex,
    load_private_key_from_file,
)
from .verification import (
    _canonical_envelope,
    _text,
    _timestamp,
    ApprovalAssertion,
    ApprovalVerifier,
    VerifiedApproval,
)
from .versions import APPROVAL_CREDENTIAL_VERSION, APPROVAL_SIGNATURE_ALGORITHM

__all__ = [
    "ApprovalAuthority",
    "ApprovalAuthorityKind",
    "ApprovalAssertion",
    "VerifiedApproval",
    "ApprovalVerifier",
    "LocalApprovalAuthority",
]

_APPROVAL_DECISION = "APPROVE"


class LocalApprovalAuthority:
    """Local trusted signer; the host must protect this object and its key."""

    __slots__ = ("_issuer_id", "_audience", "_private_key", "_clock", "_sealed")

    _issuer_id: str
    _audience: str
    _private_key: Ed25519PrivateKey
    _clock: Callable[[], datetime]
    _sealed: bool

    def __init__(
        self,
        *,
        issuer_id: str,
        audience: str,
        private_key: Ed25519PrivateKey | None = None,
        key_file: Path | str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _text(issuer_id, "issuer_id")
        _text(audience, "audience")

        if private_key is None:
            if key_file is not None:
                private_key = load_private_key_from_file(key_file)
            elif os.environ.get("DMINT_KEY_FILE", "").strip():
                private_key = load_private_key_from_file(os.environ["DMINT_KEY_FILE"].strip())
            elif DEFAULT_KEY_FILE.exists():
                private_key = load_private_key_from_file(DEFAULT_KEY_FILE)
            elif os.environ.get("DMINT_PRIVATE_KEY", "").strip():
                if os.environ.get("DMINT_ALLOW_INLINE_KEY", "").lower() not in ("1", "true", "yes"):
                    raise KeyLoadError(
                        "DMINT_PRIVATE_KEY is set but inline private keys are disabled by default for security; "
                        "set DMINT_ALLOW_INLINE_KEY=1 to opt-in."
                    )
                warnings.warn(
                    "DMINT_PRIVATE_KEY contains inline private key material visible in process environment. "
                    "Use a restricted key file (mode 0600) instead.",
                    UserWarning,
                    stacklevel=2,
                )
                private_key = _parse_private_key_hex(os.environ["DMINT_PRIVATE_KEY"].strip())
            else:
                # Invariant: NEVER silently generate an ephemeral key in production or runtime.
                # Callers must provide an explicit key_file, DMINT_KEY_FILE, or private_key.
                raise KeyLoadError(
                    "no private key source found; an Ed25519 signing key must be provided via key_file, "
                    "DMINT_KEY_FILE, or explicit private_key. Generate one with 'dmint init-keys'."
                )

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

    def __repr__(self) -> str:
        """Never include private key material in repr."""
        issuer = getattr(self, "_issuer_id", "<uninitialized>")
        audience = getattr(self, "_audience", "<uninitialized>")
        return f"LocalApprovalAuthority(issuer_id={issuer!r}, audience={audience!r})"

    def __str__(self) -> str:
        """Never include private key material in str."""
        return self.__repr__()

    @property
    def issuer_id(self) -> str:
        return self._issuer_id

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def issue_for_human(
        self,
        record: ApprovalRecord,
        *,
        subject_id: str,
        now: datetime | None = None,
    ) -> ApprovalAssertion:
        """Issue an assertion recording a HUMAN approver identity.

        This is the supported dashboard/host handoff entry point: the caller
        supplies only the authenticated (or explicitly self-asserted) subject
        label; the authority constructs the trusted boundary object itself.
        """
        _text(subject_id, "approver subject")
        approver = ApprovalAuthority._from_trusted_boundary(
            self._issuer_id,
            subject_id,
            ApprovalAuthorityKind.HUMAN,
        )
        return self.issue(record, approver, now=now)

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
