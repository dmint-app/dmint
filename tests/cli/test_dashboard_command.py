"""Integration tests for 'dmint dashboard' command."""

from __future__ import annotations

import io
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from dmint import SQLiteApprovalStore
from dmint.cli.__main__ import main
from dmint.cli.dashboard import main_dashboard


def get_free_port() -> int:
    """Find an available TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DashboardCommandTests(unittest.TestCase):
    def test_dashboard_help_flag(self) -> None:
        """'dmint dashboard --help' displays usage and exits 0."""
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = main(["dashboard", "--help"])
        self.assertEqual(code, 0)
        output = stdout_buf.getvalue()
        self.assertIn("usage: dmint dashboard", output)
        self.assertIn("--db-path", output)
        self.assertIn("--host", output)
        self.assertIn("--port", output)

    def test_dashboard_missing_db_path_error(self) -> None:
        """'dmint dashboard' without --db-path or DMINT_DB_PATH fails with exit code 2."""
        stderr_buf = io.StringIO()
        with patch.dict("os.environ", {}, clear=True), patch("sys.stderr", stderr_buf):
            code = main(["dashboard"])
        self.assertEqual(code, 2)
        error_output = stderr_buf.getvalue()
        self.assertIn("DMINT_DB_PATH", error_output)
        self.assertIn("--db-path", error_output)

    def test_dashboard_missing_dependency_error(self) -> None:
        """If dmint-dashboard is not importable, displays clear instruction and exits 1."""
        stderr_buf = io.StringIO()
        with (
            patch.dict(
                "sys.modules", {"dmint.dashboard": None, "dmint_dashboard": None, "dmint_dashboard.__main__": None}
            ),
            patch("sys.stderr", stderr_buf),
        ):
            code = main_dashboard(["--db-path", "/tmp/nonexistent.db"])
        self.assertEqual(code, 1)
        error_output = stderr_buf.getvalue()
        self.assertTrue("dmint dashboard" in error_output or "dmint-dashboard" in error_output)
        self.assertIn("pip install", error_output)

    def test_dashboard_live_subprocess_health_and_api(self) -> None:
        """Launch 'dmint dashboard' as real subprocess and query /health and /api/dashboard."""
        import urllib.request
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_approvals.sqlite3"
            # Initialize Core-owned SQLite store
            store = SQLiteApprovalStore(str(db_path), deployment_epoch="cli-dashboard-test")
            store.close()

            key_file = Path(tmpdir) / "signing.key"
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from dmint.core.keys import write_private_key_atomic

            write_private_key_atomic(key_file, Ed25519PrivateKey.generate())

            port = get_free_port()
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "dmint.cli",
                    "dashboard",
                    "--db-path",
                    str(db_path),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--auth-token",
                    "cli-test-token",
                    "--approver-id",
                    "cli-test-approver",
                    "--key-file",
                    str(key_file),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                # Poll /health until server is up (up to 10 seconds)
                health_url = f"http://127.0.0.1:{port}/health"
                dashboard_api_url = f"http://127.0.0.1:{port}/api/dashboard"
                ready = False
                for _ in range(50):
                    try:
                        with urllib.request.urlopen(health_url, timeout=0.5) as resp:
                            if resp.status == 200:
                                data = json.loads(resp.read().decode("utf-8"))
                                self.assertEqual(data.get("status"), "ok")
                                ready = True
                                break
                    except Exception:
                        time.sleep(0.1)

                self.assertTrue(ready, "Dashboard server did not become healthy within 5 seconds")

                # Verify unauthenticated request to /api/dashboard is rejected with HTTP 401
                import urllib.error

                req_unauth = urllib.request.Request(dashboard_api_url)
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req_unauth, timeout=1.0)
                self.assertEqual(ctx.exception.code, 401)

                # Verify authenticated request to /api/dashboard succeeds with 200
                req_auth = urllib.request.Request(
                    dashboard_api_url,
                    headers={"Authorization": "Bearer cli-test-token"},
                )
                with urllib.request.urlopen(req_auth, timeout=1.0) as resp:
                    self.assertEqual(resp.status, 200)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("pending", data)
                    self.assertIn("pending_count", data)
                    self.assertIn("approved_count", data)
                    self.assertIn("rejected_count", data)
                    self.assertEqual(data["pending"], [])
                    self.assertEqual(data["pending_count"], 0)

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    unittest.main()
