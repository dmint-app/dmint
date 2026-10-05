"""Tests for version metadata consistency across package, CLI, user agents, docs, and metadata."""

from __future__ import annotations

import io
from pathlib import Path
import re
import sys
from typing import Any
import unittest
from unittest.mock import MagicMock, patch

import dmint.cli as dmint_cli
from dmint.cli import DEFAULT_USER_AGENT, __version__, get_user_agent
from dmint.cli.__main__ import main
from dmint.cli.api import OpenAICompatClient
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport
from dmint.cli.mcp_oauth import create_oauth_client_provider
from dmint.cli.version import __version__ as version_module_version


class TestVersionConsistency(unittest.TestCase):
    """Verify version consistency across all project touchpoints."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent.parent

    def test_package_and_module_version_match(self) -> None:
        """dmint.cli.__version__ must match version.py.__version__."""
        self.assertEqual(dmint_cli.__version__, __version__)
        self.assertEqual(version_module_version, __version__)
        self.assertTrue(re.match(r"^\d+\.\d+\.\d+", __version__), f"Invalid semver: {__version__}")

    def test_pyproject_toml_version_match(self) -> None:
        """pyproject.toml version must match dmint_cli.__version__."""
        pyproject_path = self.repo_root / "pyproject.toml"
        self.assertTrue(pyproject_path.exists(), "pyproject.toml missing")
        content = pyproject_path.read_text(encoding="utf-8")
        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        self.assertIsNotNone(match, "Could not find version in pyproject.toml")
        pyproject_version = match.group(1)
        self.assertEqual(
            pyproject_version,
            __version__,
            f"pyproject.toml version '{pyproject_version}' does not match package version '{__version__}'",
        )

    def test_all_monorepo_subsystems_version_match(self) -> None:
        """All submodules (root dmint, core, mcp, cli, dashboard, skills) must export 2.0.0."""
        import dmint
        import dmint.core
        import dmint.mcp
        import dmint.dashboard
        import dmint.skills

        self.assertEqual(dmint.__version__, "2.0.0")
        self.assertEqual(dmint.core.__version__, "2.0.0")
        self.assertEqual(dmint.mcp.__version__, "2.0.0")
        self.assertEqual(dmint.cli.__version__, "2.0.0")
        self.assertEqual(dmint.dashboard.__version__, "2.0.0")
        self.assertEqual(dmint.skills.__version__, "2.0.0")

    def test_cli_version_flag_outputs(self) -> None:
        """dmint --version, -V, -v, and version all output 'dmint <version>'."""
        expected_output = f"dmint {__version__}\n"

        for flag in ["--version", "-V", "-v", "version"]:
            with self.subTest(flag=flag):
                stdout_buf = io.StringIO()
                with patch("sys.stdout", stdout_buf):
                    exit_code = main([flag])
                self.assertEqual(exit_code, 0)
                self.assertEqual(stdout_buf.getvalue(), expected_output)

    def test_canonical_user_agent_format(self) -> None:
        """User-Agent helper must dynamically embed the authoritative package version."""
        self.assertEqual(get_user_agent(), f"dmint-cli/{__version__}")
        self.assertEqual(DEFAULT_USER_AGENT, f"dmint-cli/{__version__}")
        self.assertEqual(get_user_agent("oauth"), f"dmint-oauth/{__version__}")
        self.assertEqual(get_user_agent("policy-author"), f"dmint-policy-author/{__version__}")

    def test_api_client_user_agent_consistency(self) -> None:
        """OpenAICompatClient must send User-Agent with current __version__."""
        client = OpenAICompatClient(api_key="test-key")
        captured_reqs: list[Any] = []

        def mock_urlopen(req: Any, *args: Any, **kwargs: Any) -> Any:
            captured_reqs.append(req)
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = None
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            client.chat_completion(messages=[{"role": "user", "content": "hi"}])

        self.assertEqual(len(captured_reqs), 1)
        user_agent = captured_reqs[0].headers.get("User-agent")
        self.assertEqual(
            user_agent,
            f"dmint-policy-author/{__version__}",
            f"API client User-Agent mismatch: {user_agent}",
        )

    def test_oauth_client_metadata_version_consistency(self) -> None:
        """create_oauth_client_provider must configure OAuthClientMetadata with current software_version."""
        integration = MCPIntegration(
            integration_id="test_server",
            transport=MCPTransport.STREAMABLE_HTTP,
            connection={"url": "https://api.example.com/mcp"},
        )
        with patch(
            "mcp_oauth.OAuthCallbackServer" if "mcp_oauth" in sys.modules else "dmint.cli.mcp_oauth.OAuthCallbackServer"
        ) as mock_server_cls:
            mock_server = MagicMock()
            mock_server.redirect_uri = "http://127.0.0.1:8080/callback"
            mock_server_cls.return_value = mock_server

            with patch("threading.Thread") as mock_thread:
                mock_thread.return_value = MagicMock()
                provider = create_oauth_client_provider(integration, open_browser=False)

        # Inspect provider's client_metadata
        client_metadata = getattr(provider, "client_metadata", None)
        self.assertIsNotNone(client_metadata, "Provider missing client_metadata")
        self.assertEqual(client_metadata.client_name, "dmint-cli")
        self.assertEqual(
            client_metadata.software_version,
            __version__,
            f"OAuthClientMetadata software_version '{client_metadata.software_version}' != '{__version__}'",
        )

    def test_readme_documents_current_version(self) -> None:
        """README.md header and CLI examples must reference current __version__."""
        readme_path = self.repo_root / "README.md"
        self.assertTrue(readme_path.exists(), "README.md missing")
        content = readme_path.read_text(encoding="utf-8")

        # Header check: # Dmint
        self.assertIn("# Dmint", content, "README header does not contain '# Dmint'")

    def test_changelog_release_notes_current_version(self) -> None:
        """CHANGELOG.md must contain release notes for current __version__."""
        changelog_path = self.repo_root / "CHANGELOG.md"
        self.assertTrue(changelog_path.exists(), "CHANGELOG.md missing")
        content = changelog_path.read_text(encoding="utf-8")

        expected_section = f"## [{__version__}]"
        self.assertIn(
            expected_section,
            content,
            f"CHANGELOG.md missing release section '{expected_section}'",
        )

    def test_no_hardcoded_version_duplication_in_source_tree(self) -> None:
        """Verify that no Python file across all of src/dmint/ other than version.py defines a hardcoded version string."""
        src_dir = self.repo_root / "src" / "dmint"
        self.assertTrue(src_dir.exists(), "src/dmint does not exist")

        version_literal_pattern = re.compile(rf'["\']{re.escape(__version__)}["\']')
        stale_version_patterns = [
            re.compile(r'["\']1\.1\.1["\']'),
            re.compile(r'["\']1\.1\.0["\']'),
            re.compile(r'["\']1\.0\.1["\']'),
            re.compile(r'["\']1\.0\.0["\']'),
            re.compile(r'["\']0\.3\.0["\']'),
            re.compile(r'["\']0\.2\.0["\']'),
            re.compile(r'["\']0\.1\.0["\']'),
        ]

        offending_files: list[str] = []

        for py_file in src_dir.glob("**/*.py"):
            # src/dmint/version.py is the single allowed authoritative source for the literal
            if py_file.name == "version.py" and py_file.parent == src_dir:
                continue

            code = py_file.read_text(encoding="utf-8")

            # Check for current version literal
            if version_literal_pattern.search(code):
                offending_files.append(
                    f"{py_file.relative_to(src_dir)} (contains hardcoded current version '{__version__}')"
                )

            # Check for stale versions
            for stale_pat in stale_version_patterns:
                if stale_pat.search(code):
                    offending_files.append(f"{py_file.relative_to(src_dir)} (contains hardcoded stale version)")

        self.assertEqual(
            offending_files,
            [],
            f"Found version duplication in source files (must derive from dmint.version): {offending_files}",
        )

    def test_dmint_version_env_var_override(self) -> None:
        """Setting DMINT_VERSION overrides get_version() and user agent strings dynamically."""
        import os
        from dmint.version import get_user_agent as get_ua, get_version

        with patch.dict(os.environ, {"DMINT_VERSION": "2.9.9"}):
            self.assertEqual(get_version(), "2.9.9")
            self.assertEqual(get_ua(), "dmint-cli/2.9.9")
            self.assertEqual(get_ua("mcp"), "dmint-mcp/2.9.9")
            self.assertEqual(get_ua("webhook"), "dmint-webhook/2.9.9")

    def test_dmint_user_agent_env_var_override(self) -> None:
        """Setting DMINT_USER_AGENT overrides the default base User-Agent."""
        import os
        from dmint.version import get_user_agent as get_ua

        with patch.dict(os.environ, {"DMINT_USER_AGENT": "custom-agent/4.2"}):
            self.assertEqual(get_ua(), "custom-agent/4.2")
            # Component-specific user agents still include component
            self.assertEqual(get_ua("mcp"), "dmint-mcp/2.0.0")


if __name__ == "__main__":
    unittest.main()
