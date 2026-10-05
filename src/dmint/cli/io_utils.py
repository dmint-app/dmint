"""Shared I/O helpers for atomic writing and prompt loading."""

from __future__ import annotations

import importlib.resources
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dmint.cli.errors import OutputWriteError

if TYPE_CHECKING:
    from dmint.policy import Policy


def load_system_prompt() -> str:
    """Load system prompt from bundled resource file policy_skill.md."""
    try:
        return importlib.resources.files("dmint.cli.prompts").joinpath("policy_skill.md").read_text(encoding="utf-8")
    except Exception:
        prompt_path = Path(__file__).parent / "prompts" / "policy_skill.md"
        return prompt_path.read_text(encoding="utf-8")


def _deterministic_json(data: Any) -> str:
    """Return deterministic, canonical JSON representation (sorted keys, no trailing whitespace).

    Uses sort_keys=True so that tool ordering and key ordering are byte-stable
    regardless of dict insertion order.
    """
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)


def atomic_write_json(output_path: Path, data: dict[str, Any]) -> None:
    """Atomically write deterministic JSON to destination.

    - Serialization: sort_keys=True ensures byte-equivalent output for equal inputs.
    - Temp file + fsync + os.replace ensures no partial writes survive.
    - chmod 0600 restricts access to owner only (policy files are security artefacts).
    """
    temp_path: str | None = None
    temp_fd: int | None = None
    try:
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(dir=output_path.parent, prefix=".policy_tmp_")
        if hasattr(os, "fchmod"):
            os.fchmod(temp_fd, stat.S_IRUSR | stat.S_IWUSR)
        else:
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
        with open(temp_fd, "w", encoding="utf-8") as f:
            temp_fd = None  # open() took ownership of descriptor
            f.write(_deterministic_json(data))
            f.write("\n")  # POSIX EOF newline
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, output_path)
    except Exception as exc:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise OutputWriteError(f"failed to write output policy file: {exc}") from exc


def atomic_write_policy_json(output_path: Path, policy: "Policy") -> None:
    """Serialize a validated Policy object to disk using its canonical to_dict() representation.

    This is the ONLY correct way to persist a policy file:
    - Uses Policy.to_dict() — the official Dmint serialization path — not raw LLM output.
    - Deterministic: same Policy instance → byte-equivalent file.
    - Atomic, fsync'd, chmod 0600.
    """
    canonical = policy.to_dict()
    atomic_write_json(output_path, canonical)
