"""Dmint Policy Manager Skill loader and workflow definitions."""

from __future__ import annotations

import importlib.resources
from pathlib import Path
import re

POLICY_MANAGER_SKILL_NAME = "dmint-policy-manager"
SKILL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


def get_skill_path(skill_name: str = POLICY_MANAGER_SKILL_NAME) -> Path:
    """Return the filesystem Path to a skill's SKILL.md (defaults to dmint-policy-manager)."""
    if not skill_name or not SKILL_NAME_PATTERN.match(skill_name):
        raise ValueError(
            f"Invalid skill name '{skill_name}'. Must contain only alphanumeric characters, dashes, or underscores."
        )

    # First attempt: package data inside src/dmint/skills/skills/<skill_name>/SKILL.md
    pkg_skill = Path(__file__).resolve().parent / "skills" / skill_name / "SKILL.md"
    if pkg_skill.exists():
        return pkg_skill

    # Second attempt: repository root .agents/skills/<skill_name>/SKILL.md
    repo_skill = Path(__file__).resolve().parent.parent.parent.parent / ".agents" / "skills" / skill_name / "SKILL.md"
    if repo_skill.exists():
        return repo_skill

    return pkg_skill


def load_policy_manager_skill() -> str:
    """Load and return the markdown content of the dmint-policy-manager skill."""
    skill_path = get_skill_path()
    if skill_path.exists():
        return skill_path.read_text(encoding="utf-8")

    # Fallback to importlib.resources if packaged
    try:
        traversable = (
            importlib.resources.files("dmint.skills")
            .joinpath("skills")
            .joinpath("dmint-policy-manager")
            .joinpath("SKILL.md")
        )
        return traversable.read_text(encoding="utf-8")
    except Exception:
        try:
            traversable = (
                importlib.resources.files("dmint_skills")
                .joinpath("skills")
                .joinpath("dmint-policy-manager")
                .joinpath("SKILL.md")
            )
            return traversable.read_text(encoding="utf-8")
        except Exception as exc:
            raise FileNotFoundError(f"Could not locate dmint-policy-manager skill file at {skill_path}: {exc}") from exc


DMINT_POLICY_MANAGER_SKILL = load_policy_manager_skill()
