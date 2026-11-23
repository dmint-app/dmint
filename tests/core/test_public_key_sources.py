"""Public-key-only trusted issuer discovery for 3-Zone approval verification."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.core.verification import load_trusted_issuers_from_public_sources, public_key_hex


class TestPublicKeySources(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp_dir.name) / "workspace"
        self.dmint_dir = self.workspace / ".dmint"
        self.dmint_dir.mkdir(parents=True)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key_hex = public_key_hex(self.private_key.public_key())

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def _write_trusted_issuer(self, payload: object) -> Path:
        path = self.dmint_dir / "trusted_issuer.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_workspace_trusted_issuer_loads_public_key_and_aliases(self) -> None:
        self._write_trusted_issuer(
            {
                "issuer_id": "prod-secops-authority",
                "public_key_hex": self.public_key_hex,
            }
        )

        trusted = load_trusted_issuers_from_public_sources(
            self.workspace,
            extra_issuer_ids=("hook-claude-code",),
        )

        for issuer in (
            "prod-secops-authority",
            "dmint-cli",
            "dmint-authority",
            "dmint-dashboard",
            "local-authority",
            "hook-claude-code",
        ):
            self.assertIn(issuer, trusted)
            self.assertEqual(public_key_hex(trusted[issuer]), self.public_key_hex)

    def test_trusted_issuers_list_and_mapping_formats(self) -> None:
        self._write_trusted_issuer(
            {
                "trusted_issuers": [
                    {"issuer_id": "authority-one", "public_key_hex": self.public_key_hex},
                ]
            }
        )
        trusted = load_trusted_issuers_from_public_sources(self.workspace)
        self.assertEqual(public_key_hex(trusted["authority-one"]), self.public_key_hex)

        self._write_trusted_issuer({"authority-two": self.public_key_hex})
        trusted = load_trusted_issuers_from_public_sources(self.workspace)
        self.assertEqual(public_key_hex(trusted["authority-two"]), self.public_key_hex)

    def test_environment_public_key_uses_configured_issuer_id(self) -> None:
        with patch.dict(
            os.environ,
            {
                "DMINT_TRUSTED_PUBLIC_KEY_HEX": self.public_key_hex,
                "DMINT_TRUSTED_ISSUER_ID": "env-authority",
            },
            clear=False,
        ):
            trusted = load_trusted_issuers_from_public_sources(self.workspace)

        self.assertIn("env-authority", trusted)
        self.assertEqual(public_key_hex(trusted["env-authority"]), self.public_key_hex)

    def test_malformed_configured_keys_do_not_create_trusted_issuers(self) -> None:
        self._write_trusted_issuer({"issuer_id": "bad-file-authority", "public_key_hex": "not-hex"})
        with patch.dict(
            os.environ,
            {
                "DMINT_TRUSTED_PUBLIC_KEY_HEX": "also-not-hex",
                "DMINT_TRUSTED_ISSUER_ID": "bad-env-authority",
            },
            clear=False,
        ):
            trusted = load_trusted_issuers_from_public_sources(self.workspace)

        self.assertNotIn("bad-file-authority", trusted)
        self.assertNotIn("bad-env-authority", trusted)

    def test_signing_key_file_is_not_used_as_a_public_key_source(self) -> None:
        # A private key in the enforcement zone must not be read or converted into
        # a trusted issuer. Only explicit public-key sources are considered.
        (self.dmint_dir / "signing.key").write_text("00" * 32, encoding="utf-8")
        workspace_prefix = str(self.workspace)

        def only_workspace_files(path: Path) -> bool:
            return str(path).startswith(workspace_prefix) and path.name == "signing.key"

        with patch.object(Path, "is_file", autospec=True, side_effect=only_workspace_files):
            trusted = load_trusted_issuers_from_public_sources(self.workspace)

        self.assertEqual(trusted, {})


if __name__ == "__main__":
    unittest.main()
