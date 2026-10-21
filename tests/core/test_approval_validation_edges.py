"""Branch-coverage edges for approval-record validators (SRC-18).

The Phase-6 branch report flagged `dmint.core.approvals` below the production
branch-coverage gate. These tests exercise the malformed-input guard branches of
the record validators: each must fail closed with a typed error instead of
accepting the value.
"""

from __future__ import annotations

import datetime as dt

import pytest

from dmint.core.approvals import (
    _require_text,
    _require_utc,
    _validate_fingerprint,
    _validate_secure_id,
    parse_approval_state,
)
from dmint.core.errors import MalformedApprovalError, UnknownApprovalStateError


def test_parse_approval_state_rejects_non_string() -> None:
    with pytest.raises(UnknownApprovalStateError):
        parse_approval_state(123)


def test_require_text_rejects_non_string_empty_and_untrimmed() -> None:
    for bad in (None, b"bytes", "", " padded"):
        with pytest.raises(MalformedApprovalError):
            _require_text(bad, "request_id")


def test_require_utc_rejects_non_datetime_and_naive() -> None:
    with pytest.raises(MalformedApprovalError):
        _require_utc("2026-01-01T00:00:00Z", "expires_at")
    with pytest.raises(MalformedApprovalError):
        _require_utc(dt.datetime(2026, 1, 1), "expires_at")


def test_validate_secure_id_rejects_bad_prefix_and_pattern() -> None:
    with pytest.raises(MalformedApprovalError):
        _validate_secure_id("apr_", "apr_", "approval_id")  # empty suffix
    with pytest.raises(MalformedApprovalError):
        _validate_secure_id("zzz_" + "a" * 40, "apr_", "approval_id")  # wrong prefix


def test_validate_fingerprint_rejects_non_string_and_bad_pattern() -> None:
    with pytest.raises(MalformedApprovalError):
        _validate_fingerprint(42)
    with pytest.raises(MalformedApprovalError):
        _validate_fingerprint("sha256:not-hex")
