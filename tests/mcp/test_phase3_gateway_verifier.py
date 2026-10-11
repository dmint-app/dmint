"""Phase 3 gateway verifier tests.

Tests:
- Gateway module is importable without private-key loader code in its namespace.
- Gateway verifies a real assertion using only a public key (no private key on disk/env).
- Unknown issuer, wrong audience, wrong key, tampered assertion — all fail closed.
- Approval signed by key A is rejected when gateway trusts only key B.
- E2E: request → APPROVAL_REQUIRED → approve with persisted key → simulate authority
  restart (new instance, same key file) → retry through gateway → executes once →
  second retry rejected.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmint.approvals import (
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
)
from dmint.authority import ApprovalAssertion, ApprovalVerifier, LocalApprovalAuthority
from dmint.core.keys import (
    public_key_from_hex,
    public_key_hex,
    write_private_key_atomic,
    load_private_key_from_file,
)
from dmint.errors import (
    ApprovalAudienceInvalidError,
    ApprovalConsumedError,
    ApprovalIssuerInvalidError,
    ApprovalSignatureInvalidError,
    ApprovalRequiredError,
)
from dmint.mcp import (
    DiscoveryMode,
    DisclosureMode,
    DmintMCPProxy,
    DownstreamMCPClient,
    EnforcementGate,
    MCPIntegrationConfig,
    MCPToolBinding,
)
from dmint.mcp.config_loader import MCPGatewayConfig, TrustedIssuerConfig, parse_protection_config
from dmint.models import AnyResource, TrustedContext
from dmint.policy import Policy, Rule, policy_digest
from dmint.storage import SQLiteApprovalStore

AGENT_ID = "test-agent"
ISSUER = "test-authority"
AUDIENCE = "github-prod"  # matches integration_id as audience per retry test pattern


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _gen_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _make_policy() -> Policy:
    return Policy(rules=[Rule.approval_required("github", "merge", resource=AnyResource())])


def _make_integration_config() -> MCPIntegrationConfig:
    return MCPIntegrationConfig(
        integration_id="github-prod",
        command="python3",
        args=["-c", "pass"],
        tool_bindings={
            "merge_pr": MCPToolBinding(
                tool_name="merge_pr",
                capability="github.merge",
                resource_key="pr_id",
                discovery=DiscoveryMode.EXPOSED,
            ),
        },
    )


class SpyDownstreamClient(DownstreamMCPClient):
    def __init__(self, config: MCPIntegrationConfig) -> None:
        super().__init__(config)
        self.call_count = 0

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def call_tool(self, name: str, arguments: dict | None = None):
        self.call_count += 1
        return f"executed:{name}"


def _make_approver() -> ApprovalAuthority:
    return ApprovalAuthority._from_trusted_boundary("ui", "alice", ApprovalAuthorityKind.HUMAN)


def _make_proxy(
    config: MCPIntegrationConfig,
    spy_client: SpyDownstreamClient,
    store: SQLiteApprovalStore,
    policy: Policy,
    verifier: ApprovalVerifier,
) -> DmintMCPProxy:
    provenance = PolicyProvenance("v1", policy_digest(policy), datetime.now(timezone.utc))
    proxy = DmintMCPProxy(
        config,
        policy=policy,
        agent_id=AGENT_ID,
        context=TrustedContext({}),
        approval_store=store,
        approval_verifier=verifier,
        policy_provenance=provenance,
        approval_ttl=timedelta(hours=1),
    )
    proxy._gate = EnforcementGate(
        spy_client,
        config,
        policy=policy,
        agent_id=AGENT_ID,
        context=TrustedContext({}),
        approval_store=store,
        approval_verifier=verifier,
        policy_provenance=provenance,
        approval_ttl=timedelta(hours=1),
    )
    return proxy


# ─── Test: gateway does NOT expose private-key loader in its namespace ─────────


class TestGatewayDoesNotExposePrivateKeyLoader:
    """The gateway module must be importable without exposing private-key loading code."""

    def test_gateway_module_does_not_expose_load_private_key_from_file(self) -> None:
        import dmint.mcp.gateway as gw

        assert not hasattr(gw, "load_private_key_from_file"), (
            "gateway module must not expose load_private_key_from_file"
        )

    def test_gateway_module_does_not_expose_write_private_key_atomic(self) -> None:
        import dmint.mcp.gateway as gw

        assert not hasattr(gw, "write_private_key_atomic"), "gateway module must not expose write_private_key_atomic"

    def test_gateway_module_does_not_expose_load_private_key(self) -> None:
        import dmint.mcp.gateway as gw

        assert not hasattr(gw, "load_private_key"), "gateway module must not expose load_private_key"

    def test_gateway_module_does_not_expose_local_approval_authority(self) -> None:
        import dmint.mcp.gateway as gw

        assert not hasattr(gw, "LocalApprovalAuthority"), "gateway module must not expose LocalApprovalAuthority"

    def test_gateway_does_not_import_signing_or_private_key_code(self) -> None:
        """Isolated process test: importing dmint.mcp modules must NOT import signing or private-key modules."""
        import subprocess
        import sys

        code = (
            "import sys\n"
            "import dmint.mcp.gateway as gw\n"
            "import dmint.mcp.__main__ as main_mod\n"
            "import dmint.mcp.config_loader as cfg_mod\n"
            "# 1. Neither signing nor private-key loader modules may be in sys.modules\n"
            "banned_modules = {'dmint.core.authority', 'dmint.core.keys'}\n"
            "loaded_banned = banned_modules & set(sys.modules.keys())\n"
            "assert not loaded_banned, f'Banned modules loaded by gateway: {loaded_banned}'\n"
            "# 2. No module in sys.modules imported by gateway may expose private-key loaders or signer\n"
            "banned_symbols = {'load_private_key', 'load_private_key_from_file', 'write_private_key_atomic', 'LocalApprovalAuthority'}\n"
            "for mod_name, mod in list(sys.modules.items()):\n"
            "    if mod_name.startswith('dmint.mcp'):\n"
            "        for sym in banned_symbols:\n"
            "            assert not hasattr(mod, sym), f'{mod_name} exposes banned symbol {sym}'\n"
        )
        src_dir = str(Path(__file__).resolve().parents[2] / "src")
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": src_dir},
        )
        assert proc.returncode == 0, f"Subprocess failed:\n{proc.stderr}\n{proc.stdout}"

    def test_canonicalize_rfc8785_byte_for_byte_equivalence(self) -> None:
        """Prove that Dmint's canonicalize_bytes produces identical bytes to external rfc8785.dumps."""
        import rfc8785
        from dmint.core.canonicalize import canonicalize_bytes

        test_payloads = [
            {"tool": "db", "action": "read", "resource": "/users/1"},
            {"numbers": [0, -0.0, 1.5, 1e20, -1e-5, 9007199254740991]},
            {"unicode": "hello \u2028 \u2029 \u007f \U0001f600", "escapes": '\b\f\n\r\t"\\'},
            {"nested": {"a": [True, False, None], "b": {"c": 123}}},
            {"sorted_keys": {"\u00e9": 1, "e\u0301": 2, "z": 3, "a": 4}},
        ]
        for payload in test_payloads:
            external_bytes = rfc8785.dumps(payload)
            dmint_bytes = canonicalize_bytes(payload)
            assert dmint_bytes == external_bytes, (
                f"Mismatch for payload {payload}: {dmint_bytes!r} vs {external_bytes!r}"
            )

    def test_gateway_importable_without_private_key_on_disk_or_in_env(self) -> None:
        """Importing the gateway module must not fail when no private key is present."""
        from unittest.mock import patch

        env_clean = {k: v for k, v in os.environ.items() if k not in ("DMINT_PRIVATE_KEY", "DMINT_KEY_FILE")}
        with patch.dict(os.environ, env_clean, clear=True):
            import importlib
            import dmint.mcp.gateway

            importlib.reload(dmint.mcp.gateway)  # must not raise


# ─── Test: verify real assertion with only public key ─────────────────────────


class TestGatewayVerifiesWithPublicKeyOnly(unittest.IsolatedAsyncioTestCase):
    """ApprovalVerifier constructed with ONLY a public key can verify a valid assertion."""

    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_path = str(self.tmp_path / "approvals.db")
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="ep1")

        self.key = _gen_key()
        # Authority has private key; verifier has ONLY the public key.
        self.authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE, private_key=self.key)
        self.verifier = ApprovalVerifier(trusted_issuers={ISSUER: self.key.public_key()}, audience=AUDIENCE)
        self.policy = _make_policy()
        self.config = _make_integration_config()
        self.client = SpyDownstreamClient(self.config)

    async def asyncTearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    async def test_verifier_with_public_key_only_accepts_valid_assertion(self) -> None:
        """Verifier constructed with ONLY a public key accepts a valid signed assertion."""
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, self.verifier)
        args = {"pr_id": "42"}

        # First call → APPROVAL_REQUIRED
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)
        approval_id = ctx.exception.approval_id

        # Load the pending record and approve with the authority (has private key).
        record = self.store.get(approval_id)
        approver = _make_approver()
        assertion = self.authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        # Retry — verifier uses ONLY the public key to verify.
        result = await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        self.assertIn("executed", result)
        self.assertEqual(self.client.call_count, 1)


# ─── Test: fail-closed cases ──────────────────────────────────────────────────


class TestVerifierFailsClosed(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_path = str(self.tmp_path / "approvals.db")
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="ep1")
        self.key = _gen_key()
        self.authority = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE, private_key=self.key)
        self.verifier = ApprovalVerifier(trusted_issuers={ISSUER: self.key.public_key()}, audience=AUDIENCE)
        self.policy = _make_policy()
        self.config = _make_integration_config()
        self.client = SpyDownstreamClient(self.config)

    async def asyncTearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    async def _do_route_and_get_record(self, proxy: DmintMCPProxy, args: dict) -> ApprovalRecord:
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)
        return self.store.get(ctx.exception.approval_id)

    async def test_unknown_issuer_fails_closed(self) -> None:
        """Assertion from an unknown issuer must be rejected."""
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, self.verifier)
        args = {"pr_id": "42"}
        record = await self._do_route_and_get_record(proxy, args)

        # Sign with our authority (known issuer), but configure verifier with different issuer name
        approver = _make_approver()
        assertion = self.authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        # Build proxy that trusts a DIFFERENT issuer name
        verifier_wrong_issuer = ApprovalVerifier(
            trusted_issuers={"other-issuer": self.key.public_key()}, audience=AUDIENCE
        )
        proxy_wrong = _make_proxy(self.config, self.client, self.store, self.policy, verifier_wrong_issuer)

        with self.assertRaises((ApprovalIssuerInvalidError, Exception)):
            await proxy_wrong.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        self.assertEqual(self.client.call_count, 0)

    async def test_wrong_audience_fails_closed(self) -> None:
        """Assertion for a different audience must be rejected."""
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, self.verifier)
        args = {"pr_id": "42"}
        record = await self._do_route_and_get_record(proxy, args)

        # Sign with an authority targeting wrong audience
        wrong_audience_authority = LocalApprovalAuthority(
            issuer_id=ISSUER, audience="wrong-audience", private_key=self.key
        )
        approver = _make_approver()
        assertion = wrong_audience_authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        with self.assertRaises(Exception):
            await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        self.assertEqual(self.client.call_count, 0)

    async def test_wrong_key_fails_closed(self) -> None:
        """Assertion signed by key A must be rejected by verifier trusting key B."""
        key_b = _gen_key()
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, self.verifier)
        args = {"pr_id": "42"}
        record = await self._do_route_and_get_record(proxy, args)

        # Sign with key A
        approver = _make_approver()
        assertion = self.authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        # Verifier trusts key B only
        verifier_key_b = ApprovalVerifier(trusted_issuers={ISSUER: key_b.public_key()}, audience=AUDIENCE)
        proxy_b = _make_proxy(self.config, self.client, self.store, self.policy, verifier_key_b)

        with self.assertRaises(Exception):
            await proxy_b.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        self.assertEqual(self.client.call_count, 0)

    async def test_tampered_assertion_bytes_fail_closed(self) -> None:
        """Modifying serialized assertion bytes must cause rejection."""
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, self.verifier)
        args = {"pr_id": "42"}
        record = await self._do_route_and_get_record(proxy, args)

        approver = _make_approver()
        assertion = self.authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        # Tamper with the serialized bytes
        good_bytes = assertion.to_bytes()
        # Flip a byte in the middle of the payload
        mid = len(good_bytes) // 2
        tampered = bytearray(good_bytes)
        tampered[mid] ^= 0xFF
        tampered_bytes = bytes(tampered)

        with self.assertRaises(Exception):
            await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=tampered_bytes)
        self.assertEqual(self.client.call_count, 0)

    async def test_key_a_signed_rejected_when_gateway_trusts_only_key_b(self) -> None:
        """E2E: assertion from key A is rejected when gateway trusts only key B."""
        key_a = self.key
        key_b = _gen_key()

        # Gateway trusts ONLY key B
        verifier_only_b = ApprovalVerifier(trusted_issuers={ISSUER: key_b.public_key()}, audience=AUDIENCE)
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, verifier_only_b)
        args = {"pr_id": "42"}
        record = await self._do_route_and_get_record(proxy, args)

        # Sign with key A
        authority_a = LocalApprovalAuthority(issuer_id=ISSUER, audience=AUDIENCE, private_key=key_a)
        approver = _make_approver()
        assertion_a = authority_a.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        with self.assertRaises(Exception):
            await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion_a)
        self.assertEqual(self.client.call_count, 0)


# ─── Test: config_loader trusted_issuers parsing ──────────────────────────────


class TestConfigLoaderTrustedIssuers:
    def _base_config(self) -> dict:
        return {
            "policy": {
                "rules": [
                    {
                        "effect": "allow",
                        "tool": "github",
                        "action": "merge",
                        "resource": "*",
                        "conditions": [],
                    }
                ]
            },
            "integrations": [
                {
                    "integration_id": "test",
                    "transport": "stdio",
                    "connection": {"command": "echo"},
                    "tool_bindings": {"merge_pr": "github.merge"},
                }
            ],
        }

    def test_no_trusted_issuers_defaults_to_empty(self) -> None:
        config = parse_protection_config(self._base_config())
        assert config.trusted_issuers == ()

    def test_parses_single_trusted_issuer(self) -> None:
        key = _gen_key()
        hex_str = public_key_hex(key.public_key())
        data = self._base_config()
        data["trusted_issuers"] = [{"issuer_id": "test-auth", "public_key_hex": hex_str}]
        config = parse_protection_config(data)
        assert len(config.trusted_issuers) == 1
        assert config.trusted_issuers[0].issuer_id == "test-auth"
        assert config.trusted_issuers[0].public_key_hex == hex_str

    def test_parses_multiple_trusted_issuers(self) -> None:
        key1 = _gen_key()
        key2 = _gen_key()
        data = self._base_config()
        data["trusted_issuers"] = [
            {"issuer_id": "auth-v1", "public_key_hex": public_key_hex(key1.public_key())},
            {"issuer_id": "auth-v2", "public_key_hex": public_key_hex(key2.public_key())},
        ]
        config = parse_protection_config(data)
        assert len(config.trusted_issuers) == 2

    def test_duplicate_issuer_id_raises(self) -> None:
        from dmint.mcp.errors import MCPConfigurationError

        key = _gen_key()
        hex_str = public_key_hex(key.public_key())
        data = self._base_config()
        data["trusted_issuers"] = [
            {"issuer_id": "auth", "public_key_hex": hex_str},
            {"issuer_id": "auth", "public_key_hex": hex_str},
        ]
        with pytest.raises(MCPConfigurationError, match="duplicate issuer_id"):
            parse_protection_config(data)

    def test_invalid_hex_raises(self) -> None:
        from dmint.mcp.errors import MCPConfigurationError

        data = self._base_config()
        data["trusted_issuers"] = [{"issuer_id": "auth", "public_key_hex": "not_hex" + "a" * 57}]
        with pytest.raises(MCPConfigurationError):
            parse_protection_config(data)

    def test_wrong_hex_length_raises(self) -> None:
        from dmint.mcp.errors import MCPConfigurationError

        data = self._base_config()
        data["trusted_issuers"] = [{"issuer_id": "auth", "public_key_hex": "abcd"}]
        with pytest.raises(MCPConfigurationError, match="64 hex characters"):
            parse_protection_config(data)

    def test_custom_approval_audience_is_preserved(self) -> None:
        data = self._base_config()
        data["approval_audience"] = "my-custom-audience"
        config = parse_protection_config(data)
        assert config.approval_audience == "my-custom-audience"

    def test_default_approval_audience(self) -> None:
        config = parse_protection_config(self._base_config())
        assert config.approval_audience == "dmint/dashboard/v1"

    def test_gateway_builds_verifier_from_trusted_issuers(self) -> None:
        """MCPGateway constructs ApprovalVerifier from trusted_issuers in config."""
        from dmint.mcp.gateway import MCPGateway
        from dmint.mcp.config_loader import parse_protection_config

        key = _gen_key()
        hex_str = public_key_hex(key.public_key())
        data = self._base_config()
        data["trusted_issuers"] = [{"issuer_id": "test-auth", "public_key_hex": hex_str}]
        data["approval_audience"] = "dmint/dashboard/v1"
        config = parse_protection_config(data)

        gw = MCPGateway(config)
        # The verifier should be built and not None
        assert gw._approval_verifier is not None
        assert isinstance(gw._approval_verifier, ApprovalVerifier)


# ─── E2E Test: persisted key + authority restart + single-use retry ───────────


class TestE2EPersistedKeyRestartAndSingleUse(unittest.IsolatedAsyncioTestCase):
    """
    Full E2E scenario:
      1. Generate & persist key to file (authority "process 1").
      2. Request → APPROVAL_REQUIRED.
      3. Simulate authority restart: load key from SAME file (new LocalApprovalAuthority).
      4. Approve using the new instance with the same persisted key.
      5. Retry through gateway → executes once.
      6. Second retry with the SAME assertion → rejected (consumed).
    """

    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_path = str(self.tmp_path / "approvals.db")
        self.store = SQLiteApprovalStore(self.db_path, deployment_epoch="ep1")
        self.issuer_id = "persistent-authority"
        self.key_file = self.tmp_path / "signing.key"

        # Generate & persist the key (authority "process 1").
        self.original_key = _gen_key()
        write_private_key_atomic(self.key_file, self.original_key)

        # Build verifier with ONLY the public key.
        self.verifier = ApprovalVerifier(
            trusted_issuers={self.issuer_id: self.original_key.public_key()},
            audience=AUDIENCE,
        )

        self.policy = _make_policy()
        self.config = _make_integration_config()
        self.client = SpyDownstreamClient(self.config)

    async def asyncTearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    async def test_e2e_persisted_key_restart_execute_once_second_retry_rejected(self) -> None:
        """The big E2E test for Phase 3."""
        proxy = _make_proxy(self.config, self.client, self.store, self.policy, self.verifier)
        args = {"pr_id": "42"}

        # Step 1: Request → APPROVAL_REQUIRED
        with self.assertRaises(ApprovalRequiredError) as ctx:
            await proxy.gate.route_call(integration_id="github-prod", tool_name="merge_pr", arguments=args)
        approval_id = ctx.exception.approval_id

        # Step 2: Load the pending record.
        record = self.store.get(approval_id)
        self.assertEqual(record.state, ApprovalState.PENDING)

        # Step 3: Simulate authority RESTART — new LocalApprovalAuthority instance
        # created by loading the key from the SAME file.
        restarted_key = load_private_key_from_file(self.key_file)
        restarted_authority = LocalApprovalAuthority(
            issuer_id=self.issuer_id,
            audience=AUDIENCE,
            private_key=restarted_key,
        )
        # Public key must match — it's the same underlying key on disk.
        self.assertEqual(
            public_key_hex(restarted_key.public_key()),
            public_key_hex(self.original_key.public_key()),
        )

        # Step 4: Approve with the restarted authority instance.
        approver = _make_approver()
        assertion = restarted_authority.issue(record, approver)
        self.store.save_approved(record.approve(approver))

        # Step 5: Retry → gateway verifies with public key, executes once.
        result = await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        self.assertIn("executed", result)
        self.assertEqual(self.client.call_count, 1, "Tool must be called exactly once")

        # Verify record is now CONSUMED.
        consumed = self.store.get(approval_id)
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)

        # Step 6: Second retry with the SAME assertion → must fail (single-use).
        with self.assertRaises(ApprovalConsumedError):
            await proxy.retry_call(tool_name="merge_pr", arguments=args, approval_credential=assertion)
        # Must NOT have called the downstream tool a second time.
        self.assertEqual(self.client.call_count, 1, "Tool was called more than once — single-use not enforced!")


# ─── Subprocess E2E Test ──────────────────────────────────────────────────────


class TestSubprocessE2E(unittest.IsolatedAsyncioTestCase):
    """Subprocess-based E2E test verifying the complete operational flow across process boundaries:
    1. Run `dmint init-keys` in a subprocess to generate the signing key.
    2. Run `dmint export-public-key` in a subprocess to extract the public key.
    3. Start gateway in test with ONLY the exported public key (no private key in memory/env).
    4. Agent calls protected tool → APPROVAL_REQUIRED.
    5. Run `dmint approve` in a separate subprocess with the key file and --output-assertion.
    6. Retry through gateway with the assertion → executes once.
    7. Second retry with the same assertion → rejected with ApprovalConsumedError.
    """

    async def test_full_subprocess_e2e_flow(self) -> None:
        import json
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            key_file = tmp_path / "signing.key"
            db_path = tmp_path / "approvals.db"
            assertion_file = tmp_path / "assertion.bin"
            issuer_id = "subprocess-authority"
            audience = "github-prod"

            src_dir = str(Path(__file__).resolve().parents[2] / "src")
            env = {
                **os.environ,
                "PYTHONPATH": src_dir,
                "DMINT_DB_PATH": str(db_path),
            }

            # 1. Run `dmint init-keys` in subprocess
            init_res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "dmint.cli.__main__",
                    "init-keys",
                    "--key-file",
                    str(key_file),
                    "--issuer-id",
                    issuer_id,
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(init_res.returncode, 0, f"init-keys failed: {init_res.stderr}")
            self.assertTrue(key_file.exists(), "Key file was not created")

            # 2. Run `dmint export-public-key` in subprocess
            export_res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "dmint.cli.__main__",
                    "export-public-key",
                    "--key-file",
                    str(key_file),
                    "--issuer-id",
                    issuer_id,
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(export_res.returncode, 0, f"export-public-key failed: {export_res.stderr}")
            exported_data = json.loads(export_res.stdout)
            pubkey_hex = exported_data["public_key_hex"]
            self.assertEqual(len(pubkey_hex), 64)

            # 3. Gateway configured with public key ONLY
            # (No private key anywhere in this process or memory)
            pubkey = public_key_from_hex(pubkey_hex)
            verifier = ApprovalVerifier(
                trusted_issuers={issuer_id: pubkey},
                audience=audience,
            )
            store = SQLiteApprovalStore(str(db_path), deployment_epoch="default")
            policy = _make_policy()
            config = _make_integration_config()
            client = SpyDownstreamClient(config)
            proxy = _make_proxy(config, client, store, policy, verifier)

            # 4. Request tool -> APPROVAL_REQUIRED
            args = {"pr_id": "42"}
            with self.assertRaises(ApprovalRequiredError) as ctx:
                await proxy.gate.route_call(
                    integration_id="github-prod",
                    tool_name="merge_pr",
                    arguments=args,
                )
            approval_id = ctx.exception.approval_id

            # 5. `dmint approve` in a separate process
            approve_res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "dmint.cli.__main__",
                    "approve",
                    approval_id,
                    "--db-path",
                    str(db_path),
                    "--key-file",
                    str(key_file),
                    "--authority-issuer",
                    issuer_id,
                    "--audience",
                    audience,
                    "--approver-id",
                    "operator-alice",
                    "--output-assertion",
                    str(assertion_file),
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(
                approve_res.returncode,
                0,
                f"approve failed:\nstdout={approve_res.stdout}\nstderr={approve_res.stderr}",
            )
            self.assertTrue(assertion_file.exists(), "Assertion file was not written")
            assertion_bytes = assertion_file.read_bytes()

            # 6. Retry through gateway -> executes once
            result = await proxy.retry_call(
                tool_name="merge_pr",
                arguments=args,
                approval_credential=assertion_bytes,
            )
            self.assertIn("executed", result)
            self.assertEqual(client.call_count, 1)

            # 7. Replay rejected with ApprovalConsumedError
            with self.assertRaises(ApprovalConsumedError):
                await proxy.retry_call(
                    tool_name="merge_pr",
                    arguments=args,
                    approval_credential=assertion_bytes,
                )
            self.assertEqual(client.call_count, 1, "Downstream tool called more than once on replay")
            store.close()
