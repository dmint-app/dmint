"""Tests for dmint install-skill CLI command and interactive destination selection."""

from __future__ import annotations

import io
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from dmint.cli.__main__ import main
from dmint.cli.install_skill import (
    DEFAULT_SKILL_NAME,
    determine_default_destination,
    install_skill_file,
    main_install_skill,
    resolve_skill_content,
    resolve_target_file_path,
)


class TestInstallSkill(unittest.TestCase):
    """Test suite for skill installation in workspaces and custom destinations."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="dmint_skill_test_"))

    def tearDown(self) -> None:
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_resolve_skill_content(self) -> None:
        """resolve_skill_content must load valid markdown containing frontmatter and proxy invariant."""
        content, source = resolve_skill_content(DEFAULT_SKILL_NAME)
        self.assertTrue(len(content) > 1000)
        self.assertIn("name: dmint-policy-manager", content)
        self.assertIn("Dmint does not secure an MCP server if the agent can bypass", content)
        self.assertTrue(len(source) > 0)

    def test_resolve_target_file_path_directory(self) -> None:
        """Target path given a directory resolves to <dir>/<skill_name>/SKILL.md."""
        dest = self.temp_dir / ".agents" / "skills"
        resolved = resolve_target_file_path(dest, DEFAULT_SKILL_NAME)
        self.assertEqual(resolved, dest / DEFAULT_SKILL_NAME / "SKILL.md")

    def test_resolve_target_file_path_explicit_md(self) -> None:
        """Target path given a specific .md file resolves to that file."""
        explicit_file = self.temp_dir / "my_custom_skill.md"
        resolved = resolve_target_file_path(explicit_file, DEFAULT_SKILL_NAME)
        self.assertEqual(resolved, explicit_file)

    def test_determine_default_destination_prefers_existing_agent(self) -> None:
        """If .agent/skills exists in workspace, determine_default_destination prefers it."""
        alt_skills = self.temp_dir / ".agent" / "skills"
        alt_skills.mkdir(parents=True)
        default_dest = determine_default_destination(self.temp_dir)
        self.assertEqual(default_dest, alt_skills)

    def test_install_skill_file_creates_file(self) -> None:
        """install_skill_file writes SKILL.md and returns the resolved path."""
        target_dest = self.temp_dir / "test_workspace" / ".agents" / "skills"
        installed_path = install_skill_file(dest=target_dest, skill_name=DEFAULT_SKILL_NAME, force=True)
        self.assertTrue(installed_path.exists())
        self.assertEqual(installed_path.name, "SKILL.md")
        self.assertIn("dmint-policy-manager", installed_path.read_text(encoding="utf-8"))

    def test_install_skill_cli_non_interactive_target(self) -> None:
        """dmint install-skill --target <dir> -y installs without prompt."""
        target_dest = self.temp_dir / "custom_skills"
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = main(["install-skill", "--target", str(target_dest), "-y"])

        self.assertEqual(exit_code, 0)
        expected_file = target_dest / DEFAULT_SKILL_NAME / "SKILL.md"
        self.assertTrue(expected_file.exists())
        self.assertIn("Dmint skill successfully installed!", stdout_buf.getvalue())

    def test_install_skill_cli_interactive_choice_1(self) -> None:
        """Selecting choice '1' defaults to .agents/skills."""
        workspace = self.temp_dir / "app"
        workspace.mkdir(parents=True)

        with patch("pathlib.Path.cwd", return_value=workspace):
            with patch("builtins.input", return_value="1"):
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    exit_code = main(["install-skill"])

        self.assertEqual(exit_code, 0)
        expected_file = workspace / ".agents" / "skills" / DEFAULT_SKILL_NAME / "SKILL.md"
        self.assertTrue(expected_file.exists())

    def test_install_skill_cli_interactive_choice_2(self) -> None:
        """Selecting choice '2' installs to .agent/skills."""
        workspace = self.temp_dir / "app_v2"
        workspace.mkdir(parents=True)

        with patch("pathlib.Path.cwd", return_value=workspace):
            with patch("builtins.input", return_value="2"):
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    exit_code = main(["install-skill"])

        self.assertEqual(exit_code, 0)
        expected_file = workspace / ".agent" / "skills" / DEFAULT_SKILL_NAME / "SKILL.md"
        self.assertTrue(expected_file.exists())

    def test_install_skill_cli_interactive_typed_custom_path(self) -> None:
        """Typing a custom path directly at the prompt installs to that custom path."""
        workspace = self.temp_dir / "app_custom"
        workspace.mkdir(parents=True)
        custom_typed = self.temp_dir / "typed_dest"

        with patch("pathlib.Path.cwd", return_value=workspace):
            with patch("builtins.input", return_value=str(custom_typed)):
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    exit_code = main(["install-skill"])

        self.assertEqual(exit_code, 0)
        expected_file = custom_typed / DEFAULT_SKILL_NAME / "SKILL.md"
        self.assertTrue(expected_file.exists())

    def test_install_skill_cli_interactive_choice_5(self) -> None:
        """Selecting choice '5' prompts for a custom path and installs there."""
        workspace = self.temp_dir / "app_c5"
        workspace.mkdir(parents=True)
        custom_dest = self.temp_dir / "custom_c5_dest"

        # First prompt: "5", Second prompt: custom path
        inputs = ["5", str(custom_dest)]
        with patch("pathlib.Path.cwd", return_value=workspace):
            with patch("builtins.input", side_effect=inputs):
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    exit_code = main(["install-skill"])

        self.assertEqual(exit_code, 0)
        expected_file = custom_dest / DEFAULT_SKILL_NAME / "SKILL.md"
        self.assertTrue(expected_file.exists())

    def test_install_skill_cli_command_aliases(self) -> None:
        """All variations ('install skill', 'install-skills', 'install') normalize to install-skill."""
        for cmd_args in [
            ["install", "skill", "--list"],
            ["install", "skills", "--list"],
            ["install-skills", "--list"],
            ["install", "--list"],
        ]:
            with self.subTest(cmd_args=cmd_args):
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    exit_code = main(cmd_args)
                self.assertEqual(exit_code, 0)
                self.assertIn("Available Dmint Agent Skills", stdout_buf.getvalue())

    def test_install_skill_force_flag_overwrites(self) -> None:
        """--force flag overwrites existing file cleanly."""
        target_dest = self.temp_dir / "existing_skills"
        skill_file = target_dest / DEFAULT_SKILL_NAME / "SKILL.md"
        skill_file.parent.mkdir(parents=True)
        skill_file.write_text("OLD_STALE_CONTENT", encoding="utf-8")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            exit_code = main(["install-skill", "--target", str(target_dest), "--force", "-y"])

        self.assertEqual(exit_code, 0)
        new_content = skill_file.read_text(encoding="utf-8")
        self.assertNotIn("OLD_STALE_CONTENT", new_content)
        self.assertIn("name: dmint-policy-manager", new_content)


if __name__ == "__main__":
    unittest.main()
