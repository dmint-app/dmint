"""Branch-coverage edges for `dmint.core` lazy exports (SRC-18).

`dmint.core.__getattr__` lazily exposes the approval authority and key helpers.
The Phase-6 branch report flagged the module below the production branch-coverage
gate; these tests cover each lazy-export branch and the unknown-name fallthrough.
"""

from __future__ import annotations

import pytest

import dmint.core as core


def test_lazy_local_approval_authority_export() -> None:
    assert core.LocalApprovalAuthority is not None


def test_lazy_key_helper_exports() -> None:
    assert callable(core.load_private_key)
    assert callable(core.load_private_key_from_file)
    assert callable(core.write_private_key_atomic)


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError):
        core.definitely_not_an_export  # type: ignore[attr-defined]  # noqa: B018
