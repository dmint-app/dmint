"""CLI command to install Dmint AI coding agent skills into workspace or global configs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys

from dmint.cli.errors import CLIError
from dmint.cli.version import __version__

SKILL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
DEFAULT_SKILL_NAME = "dmint-policy-manager"
DEFAULT_WORKSPACE_SKILL_DIR = ".agents/skills"
ALT_WORKSPACE_SKILL_DIR = ".agent/skills"
GEMINI_GLOBAL_SKILL_DIR = Path.home() / ".gemini" / "config" / "skills"
CLAUDE_GLOBAL_SKILL_DIR = Path.home() / ".claude" / "skills"


def resolve_skill_content(skill_name: str = DEFAULT_SKILL_NAME) -> tuple[str, str]:
    """Resolve skill markdown content and provenance source.

    Returns:
        tuple[str, str]: (skill_markdown_text, source_description)
    """
    # 1. Check if dmint_skills package is installed and provides the skill
    try:
        from dmint import skills as dmint_skills

        if skill_name == DEFAULT_SKILL_NAME and hasattr(dmint_skills, "load_policy_manager_skill"):
            content = dmint_skills.load_policy_manager_skill()
            return content, "dmint_skills package"
        if hasattr(dmint_skills, "get_skill_path"):
            skill_p = dmint_skills.get_skill_path(skill_name)
            if skill_p.exists():
                return skill_p.read_text(encoding="utf-8"), f"dmint_skills ({skill_p})"
    except ImportError:
        pass
    except Exception:
        pass

    # 2. Check bundled asset in canonical dmint.skills location
    canonical_path = Path(__file__).resolve().parent.parent / "skills" / "skills" / skill_name / "SKILL.md"
    if canonical_path.exists():
        return canonical_path.read_text(encoding="utf-8"), f"bundled asset ({canonical_path.name})"

    # 3. Check workspace .agents/skills/ relative to dmint monorepo root
    repo_path = Path(__file__).resolve().parent.parent.parent.parent / ".agents" / "skills" / skill_name / "SKILL.md"
    if repo_path.exists():
        return repo_path.read_text(encoding="utf-8"), f"workspace asset ({repo_path})"

    raise FileNotFoundError(f"Could not locate skill '{skill_name}'. Ensure dmint is installed or the skill exists.")


def determine_default_destination(cwd: Path | None = None) -> Path:
    """Determine the most appropriate default destination in the workspace.

    If .agent/skills already exists in the workspace, prefer .agent/skills/.
    Otherwise, default to standard .agents/skills/.
    """
    base_dir = cwd or Path.cwd()
    alt_dir = base_dir / ALT_WORKSPACE_SKILL_DIR
    if alt_dir.is_dir():
        return alt_dir
    return base_dir / DEFAULT_WORKSPACE_SKILL_DIR


def resolve_target_file_path(dest_path: Path | str, skill_name: str) -> Path:
    """Resolve the final SKILL.md file path given a destination directory or file path."""
    if not skill_name or not SKILL_NAME_PATTERN.match(skill_name):
        raise CLIError(
            f"Security error: Invalid skill name '{skill_name}'. "
            "Skill name must contain only alphanumeric characters, dashes, or underscores."
        )

    target = Path(dest_path).expanduser().resolve()

    # If the user explicitly pointed to a file ending in .md
    if target.suffix.lower() == ".md":
        return target

    # If target is already named after the skill (e.g. .agents/skills/dmint-policy-manager or .agent/dmint-skill)
    if target.name.lower() in (skill_name.lower(), f"{skill_name}-skill", "dmint-skill", "skill"):
        return target / "SKILL.md"

    # Standard convention: <dest>/<skill_name>/SKILL.md
    return target / skill_name / "SKILL.md"


def install_skill_file(
    dest: Path | str,
    skill_name: str = DEFAULT_SKILL_NAME,
    force: bool = False,
    interactive: bool = False,
) -> Path:
    """Install the specified skill into the target destination.

    Args:
        dest: Destination directory or file path.
        skill_name: Name of skill to install (default: dmint-policy-manager).
        force: Overwrite existing file without prompting.
        interactive: Allow interactive confirmation if file exists.

    Returns:
        Path: The absolute path to the installed SKILL.md file.
    """
    if not skill_name or not SKILL_NAME_PATTERN.match(skill_name):
        raise CLIError(
            f"Security error: Invalid skill name '{skill_name}'. "
            "Skill name must contain only alphanumeric characters, dashes, or underscores."
        )

    content, source_desc = resolve_skill_content(skill_name)
    target_file = resolve_target_file_path(dest, skill_name)

    if target_file.exists() and not force:
        if interactive:
            try:
                reply = input(f"Skill already exists at '{target_file}'. Overwrite? [y/N]: ").strip().lower()
                if reply not in ("y", "yes"):
                    print("Installation cancelled by user.")
                    return target_file
            except (EOFError, KeyboardInterrupt):
                print("\nInstallation cancelled.")
                return target_file
        else:
            print(f"Skill already exists at '{target_file}'. Use --force to overwrite.")
            return target_file

    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(content, encoding="utf-8")
    return target_file


def interactive_destination_prompt(default_dest: Path) -> Path:
    """Prompt the user interactively to select or type an installation destination."""
    print("=" * 60)
    print(" Dmint AI Agent Skill Installation")
    print("=" * 60)
    print("Select where to install the Dmint skill for your AI coding agents:")
    print("  [1] .agents/skills/ (Default - recommended for Antigravity, Gemini, Cursor)")
    print("  [2] .agent/skills/  (Alternative project workspace folder)")
    print("  [3] ~/.gemini/config/skills/ (Global user config for Gemini & Antigravity)")
    print("  [4] ~/.claude/skills/        (Global user config for Claude Code)")
    print("  [5] Type custom directory path")
    print()

    try:
        choice = input(f"Enter selection [1-5] or type destination path [{default_dest}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nUsing default destination.")
        return default_dest

    if not choice or choice == "1":
        return default_dest
    elif choice == "2":
        return Path.cwd() / ALT_WORKSPACE_SKILL_DIR
    elif choice == "3":
        return GEMINI_GLOBAL_SKILL_DIR
    elif choice == "4":
        return CLAUDE_GLOBAL_SKILL_DIR
    elif choice == "5":
        try:
            custom = input("Enter custom directory path: ").strip()
            if custom:
                return Path(custom).expanduser()
        except (EOFError, KeyboardInterrupt):
            pass
        return default_dest
    else:
        # If the user typed an actual path directly into the first prompt
        return Path(choice).expanduser()


def build_parser() -> argparse.ArgumentParser:
    """Construct argument parser for dmint install-skill."""
    parser = argparse.ArgumentParser(
        prog="dmint install-skill",
        description="Install the Dmint AI agent skill into your project workspace or global agent configuration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  dmint install-skill                         # Interactive wizard or installs to .agents/skills/
  dmint install-skill -y                      # Non-interactive, installs to default .agents/skills/
  dmint install-skill --dest .agent/skills    # Installs to specific directory
  dmint install-skill --target ./my-skills    # Installs to custom target folder
  dmint install-skill --global                # Installs to global ~/.gemini/config/skills/
  dmint install-skill --claude                # Installs to global ~/.claude/skills/
""",
    )
    parser.add_argument(
        "--dest",
        "--target",
        dest="target",
        type=str,
        default=None,
        help="Target directory or file path for skill installation (default: .agents/skills/)",
    )
    parser.add_argument(
        "--global",
        dest="global_install",
        action="store_true",
        help="Install into global user agent directory (~/.gemini/config/skills/)",
    )
    parser.add_argument(
        "--claude",
        dest="claude_install",
        action="store_true",
        help="Install into global Claude Code directory (~/.claude/skills/)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        "--non-interactive",
        dest="non_interactive",
        action="store_true",
        help="Run without interactive confirmation, accepting defaults",
    )
    parser.add_argument(
        "-f",
        "--force",
        dest="force",
        action="store_true",
        help="Overwrite existing skill files without prompting",
    )
    parser.add_argument(
        "--skill",
        dest="skill_name",
        type=str,
        default=DEFAULT_SKILL_NAME,
        help=f"Skill name to install (default: {DEFAULT_SKILL_NAME})",
    )
    parser.add_argument(
        "--list",
        dest="list_skills",
        action="store_true",
        help="List available skills and exit",
    )
    return parser


def main_install_skill(argv: list[str] | None = None) -> int:
    """Main entry point for dmint install-skill subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_skills:
        print("Available Dmint Agent Skills:")
        print(f"  - {DEFAULT_SKILL_NAME} (Primary: natural language policy authoring & verification)")
        return 0

    # Determine destination
    default_dest = determine_default_destination()

    if args.global_install:
        destination = GEMINI_GLOBAL_SKILL_DIR
    elif args.claude_install:
        destination = CLAUDE_GLOBAL_SKILL_DIR
    elif args.target:
        destination = Path(args.target).expanduser()
    elif args.non_interactive:
        destination = default_dest
    else:
        # Prompt user (interactive TTY, piped input, or fallback on EOF)
        destination = interactive_destination_prompt(default_dest)

    try:
        target_file = install_skill_file(
            dest=destination,
            skill_name=args.skill_name,
            force=args.force,
            interactive=not args.non_interactive,
        )
    except Exception as exc:
        print(f"Error installing skill: {exc}", file=sys.stderr)
        return 1

    print("\n✓ Dmint skill successfully installed!")
    print(f"  Skill:     {args.skill_name}")
    print(f"  Location:  {target_file.resolve()}")
    print("\nAI coding agents (Antigravity, Gemini CLI, Claude Code, Cursor) will now automatically")
    print("discover this skill when working in this project.")
    print("\nYou can now ask your AI agent:")
    print('  - "Protect my GitHub MCP server with read-only access"')
    print('  - "I have a Figma MCP server. I want safe permissions"')
    print('  - "Verify my security policy and check for issues"')
    print('  - "Allow the agent to create issues but not delete them"')

    return 0
