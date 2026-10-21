"""Regression tests for DOC-QUICKSTART-KEY.

The README Python SDK quickstart must bootstrap the storage-integrity key:
without it, ``SQLiteApprovalStore`` raises ``KeyLoadError`` on a fresh machine
(no env vars, no ``~/.config/dmint`` key files).
"""

from __future__ import annotations

import io
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from dmint.cli.keys import main_init_keys
from dmint.core import keys as keys_module
from dmint.core.keys import KeyLoadError
from dmint.core.storage import SQLiteApprovalStore

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _sdk_quickstart_section() -> str:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Quickstart: Python SDK")
    rest = readme[start:]
    next_heading = rest.find("\n## ", 1)
    return rest if next_heading == -1 else rest[:next_heading]


def test_readme_quickstart_documents_integrity_key_bootstrap() -> None:
    section = _sdk_quickstart_section()
    assert "dmint init-keys" in section or "DMINT_INTEGRITY_KEY" in section, (
        "README Python SDK quickstart must document the integrity-key bootstrap "
        "(dmint init-keys or DMINT_INTEGRITY_KEY / DMINT_INTEGRITY_KEY_FILE); "
        "otherwise a fresh install fails with KeyLoadError when constructing SQLiteApprovalStore"
    )


def test_init_keys_bootstrap_makes_store_construction_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DMINT_INTEGRITY_KEY", raising=False)
    monkeypatch.delenv("DMINT_INTEGRITY_KEY_FILE", raising=False)
    monkeypatch.setattr(keys_module, "DEFAULT_INTEGRITY_KEY_FILE", tmp_path / "integrity.key")

    # Fresh machine, before the documented bootstrap: fail closed.
    with pytest.raises(KeyLoadError):
        SQLiteApprovalStore(str(tmp_path / "approvals.sqlite3"), deployment_epoch="qs")

    # Run the exact bootstrap step the quickstart documents.
    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        assert main_init_keys(["--key-file", str(tmp_path / "signing.key")]) == 0

    integrity_file = tmp_path / "integrity.key"
    assert integrity_file.exists(), "dmint init-keys must create the default integrity key file"
    assert stat.S_IMODE(integrity_file.stat().st_mode) == 0o600

    # The same store construction now succeeds.
    store = SQLiteApprovalStore(str(tmp_path / "approvals.sqlite3"), deployment_epoch="qs")
    assert store is not None
