# Dmint v2.0.4 — Production Proof & Zero-Trust Security Hardening Guide

**How to deploy Dmint in production so that no AI agent—even under full prompt injection, jailbreak, or arbitrary code execution inside its workspace—can bypass policies, forge approvals, steal credentials, or tamper with hooks.**

---

## Table of Contents

1. [The Core Production Principle: Why Process & Key Separation Matters](#1-the-core-production-principle-why-process--key-separation-matters)
2. [Complete Cryptographic Key & Digest Architecture (What Every Key Does & Where It Lives)](#2-complete-cryptographic-key--digest-architecture-what-every-key-does--where-it-lives)
3. [Production Blueprint A: Locking Down AI Coding Agents (Claude Code, Codex, OpenCode, Cursor, Windsurf, Cline)](#3-production-blueprint-a-locking-down-ai-coding-agents-claude-code-codex-opencode-cursor-windsurf-cline)
4. [Production Blueprint B: 3-Zone Docker Compose & Kubernetes Architecture (`dmint-mcp` Gateway + PostgreSQL)](#4-production-blueprint-b-3-zone-docker-compose--kubernetes-architecture-dmint-mcp-gateway--postgresql)
5. [Production Blueprint C: Python SDK in Production Workers (FastAPI, LangGraph, CrewAI, Celery)](#5-production-blueprint-c-python-sdk-in-production-workers-fastapi-langgraph-crewai-celery)
6. [How Every Attack Vector Is Defeated (Mathematical & Systems Proof)](#6-how-every-attack-vector-is-defeated-mathematical--systems-proof)
7. [Production Go-Live Verification Script & Checklist](#7-production-go-live-verification-script--checklist)

---

## 1. The Core Production Principle: Why Process & Key Separation Matters

Dmint enforces deterministic authorization at the tool and protocol boundary. However, **software cryptography alone cannot stop an AI agent if the agent runs under the exact same OS user (`UID`) and container filesystem as the human approver's private key (`signing.key`) and writable `policy.json`.**

If an AI agent has a `Bash` or `Python` tool and runs as the same OS user that owns `signing.key` and `policy.json`, a jailbroken agent could attempt to:
1. Read `signing.key` from disk and self-sign its own `APPROVAL_REQUIRED` requests.
2. Edit `policy.json` or `.dmint/policies/<harness>.policy.json` to change `"deny"` to `"allow"`.
3. Edit `.claude/settings.json` or `.codex/hooks.json` to remove the `dmint hook run` pre-tool hook.
4. Read downstream API keys (`STRIPE_SECRET_KEY`, `DATABASE_URL`) from `/proc/self/environ`.

To make Dmint **100% unbreakable in production**, you enforce **Three Isolated Trust Zones**:

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║ ZONE 1: UNTRUSTED AI AGENT SANDBOX (OS User: ai-agent / Container A)         ║
║                                                                              ║
║  • Runs Claude Code, Codex, OpenCode, Cursor, or LangChain/CrewAI agent      ║
║  • Holds ZERO private keys (no signing.key)                                  ║
║  • Holds ZERO downstream API secrets (no raw DB passwords or Stripe keys)    ║
║  • Cannot write to policy.json, .dmint/policies/*.json, or hook configs      ║
║    (enforced via root ownership + chmod 0444 + chattr +i or Docker :ro)      ║
╚══════════════════════════════════════╦═══════════════════════════════════════╝
                                       │
                                       │ Tool Call (PreToolUse Hook / MCP RPC)
                                       ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║ ZONE 2: DMINT ENFORCEMENT GATE (OS User: dmint-gate / Container B)           ║
║                                                                              ║
║  • Evaluates immutable policy.json (pinned via DMINT_EXPECTED_POLICY_DIGEST) ║
║  • Verifies MCP tool schemas (pinned via SHA-256 schema_hash)                ║
║  • Holds ONLY the Ed25519 PUBLIC Key (public_key_hex in trusted_issuers)     ║
║    -> Can VERIFY human approvals, but can NEVER SIGN or FORGE an approval!   ║
║  • Holds HMAC-SHA256 integrity.key (0400) + Downstream MCP credentials       ║
╚══════════════════════════════════════╦═══════════════════════════════════════╝
                                       │
                                       │ Writes PENDING / Consumes APPROVED
                                       ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║ ZONE 3: HUMAN APPROVAL AUTHORITY (OS User: dmint-approver / Container C)     ║
║                                                                              ║
║  • Runs `dmint approve <id>` or `dmint dashboard` (bound to 127.0.0.1/VPN)   ║
║  • Sole holder of Ed25519 PRIVATE Signing Key (`signing.key`, mode 0400)     ║
║  • Re-verifies request against authoritative policy before signing           ║
║  • Signs single-use Ed25519 assertion bound to RFC 8785 argument_hash        ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 2. Complete Cryptographic Key & Digest Architecture (What Every Key Does & Where It Lives)

When you run `dmint init-keys` (or `dmint init`), Dmint generates two distinct cryptographic keys and uses several SHA-256 integrity mechanisms. Here is the exact role, algorithm, and production placement of each:

| Artifact | Cryptographic Primitive | What It Does | Who Needs It | Who Must NEVER Have It | Production Location & Permissions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Private Signing Key** (`signing.key`) | **Ed25519** Private Seed (RFC 8032, 32 bytes / 64 hex chars) | Cryptographically signs `ApprovalAssertion` tokens when a human runs `dmint approve <id>` or clicks **Approve** in `dmint dashboard`. | **Zone 3 Only** (Human Approver CLI / Approval Dashboard service) | **AI Agent (Zone 1)** and **Enforcement Gate / MCP Proxy (Zone 2)** | `/etc/dmint/authority/signing.key` or Approver laptop `~/.config/dmint/signing.key` (`chown dmint-approver`, `chmod 0400`, parent dir `0700`) |
| **2. Public Verification Key** (`public_key_hex` / `PEM`) | **Ed25519** Public Key (32 bytes / 64 hex chars) | Verifies that an `APPROVED` assertion was signed by the holder of `signing.key` over the exact `(request_id, argument_hash, policy_digest, capability_id, deployment_epoch, expires_at, nonce)`. | **Zone 2** (Dmint Enforcement Gate, `dmint-mcp`, `dmint hook run`, Python SDK `ApprovalVerifier`) | Safe to be public (cannot be used to sign or forge anything) | Exported via `dmint export-public-key --json` and passed to `trusted_issuers` or stored in `/etc/dmint/gate/public.key` (`0444`) |
| **3. Store Integrity Key** (`integrity.key`) | **HMAC-SHA256** Secret Key (32 bytes / 64 hex chars, domain `dmint/approval-record-integrity/v2\x00`) | Computes `row_mac` over every row in SQLite/PostgreSQL (`approvals` table) so nobody can tamper with pending request parameters, timestamps, or state columns in the database. | **Zone 2** (Enforcement Gate) & **Zone 3** (Approval Authority) | **AI Agent (Zone 1)** | `/etc/dmint/shared/integrity.key` (`chmod 0400`, owned by service group) or `DMINT_INTEGRITY_KEY_FILE` |
| **4. Policy File Digest** (`policy_digest`) | **SHA-256** (domain `dmint/policy-digest/v1\x00` + raw file SHA-256) | Ensures `policy.json` has not been modified on disk since deployment, and invalidates any previously signed approval if the policy changes. | **Zone 2** (`DMINT_EXPECTED_POLICY_DIGEST`) & **Zone 3** | Read-only | Computed via `dmint policy-digest policy.json` and injected as `DMINT_EXPECTED_POLICY_DIGEST` |
| **5. MCP Tool Schema Hash** (`schema_hash`) | **SHA-256** over RFC 8785 JCS `{"description": ..., "inputSchema": ...}` | Pins the exact tool definition of every downstream MCP tool so a compromised MCP server cannot silently alter tool descriptions or parameters ("rug-pull attack"). | **Zone 2** (`dmint-mcp` Gateway) | Read-only inside `policy.json` | Automatically pinned inside `policy.json` (`tool_schemas`) by `dmint create-mcp-policy` |
| **6. Audit Log Hash Chain** (`audit.jsonl`) | **SHA-256** chain with domain separation (`dmint/audit-log/v1\x00`) | Links every structured audit entry to its predecessor via `prev_hash` and `entry_hash`, so insertion, reordering, mid-chain deletion, or payload edits are detectable. | **Zone 2** (Gate) & **Zone 3** (Approver) | **AI Agent (Zone 1)** | `.dmint/audit.jsonl` (`0600`, append-only, rotated); verify with `dmint logs --verify` |

### Why Separating `signing.key` from `public_key_hex` Is the Ultimate Game-Changer

Even if an attacker or a rogue AI agent compromises the SQLite/PostgreSQL database AND steals `integrity.key` to write `state = 'APPROVED'` with a valid `row_mac`:
- When the agent retries the tool call, `Dmint.consume_approved()` loads the `ApprovalAssertion` and runs **Ed25519 signature verification** using `public_key_hex`.
- Because `signing.key` is **not on the agent host/container**, the attacker cannot produce a valid 64-byte Ed25519 signature over the canonical payload:
  ```text
  b"dmint/approval-assertion/v1\x00" + JCS({
    "approval_id": "apr_...",
    "request_fingerprint": "<sha256_of_canonical_tool_action_resource_args>",
    "argument_hash": "<sha256_of_rfc8785_arguments>",
    "policy_digest": "<sha256_of_policy>",
    "capability_id": "postgres.drop_table",
    "deployment_epoch": "prod-2026",
    "issuer_id": "dmint-authority",
    "audience": "dmint-enforcement-gateway",
    "approver_principal": "secops@company.com",
    "issued_at": "2026-10-25T19:00:00Z",
    "expires_at": "2026-10-25T19:15:00Z",
    "nonce": "<128-bit-random-hex>"
  })
  ```
- Verification fails immediately with `DMT_APPROVAL_SIGNATURE_INVALID` and execution is blocked (`DENY`).

---

## 3. Production Blueprint A: Locking Down AI Coding Agents (Claude Code, Codex, OpenCode, Cursor, Windsurf, Cline)

When running AI coding agents on a developer workstation, remote cloud devbox, or CI runner, follow these **5 exact steps** so the coding agent cannot edit its own policy, disable its hooks, or read `signing.key`:

### Step 1: Create Separate OS Users for the Agent and the Approver

```bash
# Run as root / sudo on Linux:
sudo useradd -m -s /bin/bash dmint-approver
sudo useradd -m -s /bin/bash ai-agent
```

### Step 2: Generate Keys in the Approver's Protected Vault & Export the Public Key

```bash
# 1. Generate signing.key and integrity.key inside /etc/dmint (never inside the agent's writable workspace)
sudo mkdir -p /etc/dmint/authority /etc/dmint/shared
sudo chmod 0700 /etc/dmint/authority
sudo chmod 0750 /etc/dmint/shared

sudo dmint init-keys \
  --key-file /etc/dmint/authority/signing.key \
  --integrity-key-file /etc/dmint/shared/integrity.key \
  --issuer-id "prod-secops-authority"

# 2. Lock signing.key strictly to dmint-approver (the AI agent cannot read /etc/dmint/authority)
sudo chown -R dmint-approver:dmint-approver /etc/dmint/authority
sudo chmod 0400 /etc/dmint/authority/signing.key

# 3. Export the Ed25519 public key so the hook runner can verify approvals WITHOUT needing signing.key
sudo -u dmint-approver dmint export-public-key \
  --key-file /etc/dmint/authority/signing.key \
  --json | sudo tee /etc/dmint/shared/trusted_issuer.json
sudo chmod 0444 /etc/dmint/shared/trusted_issuer.json
```

### Step 3: Initialize Per-Harness Policies & Hooks in the Project Workspace

```bash
cd /srv/workspace/my-project

# Initialize all 6 harness hooks and dedicated per-harness policies (.dmint/policies/<harness>.policy.json)
sudo dmint init --harness all --templates shell,filesystem,postgres,github --dir /srv/workspace/my-project

# Remove the workspace-local signing.key so the private key ONLY exists in /etc/dmint/authority/signing.key
sudo rm -f /srv/workspace/my-project/.dmint/signing.key
```

### Step 4: Make Policies and Hook Configurations Read-Only & Kernel-Immutable (`chattr +i`)

Even if the AI agent attempts `rm -f .claude/settings.json` or `python3 -c 'open("policy.json", "w")'`, the OS kernel will reject the write with `Operation not permitted`:

```bash
cd /srv/workspace/my-project

# 1. Set root ownership and read-only permissions (0444) on all policies and hook files
sudo chown -R root:root \
  policy.json \
  .dmint/policies \
  .claude \
  .codex \
  .opencode \
  .cursor \
  .windsurf \
  .clinerules \
  .cline

sudo chmod 0444 policy.json .dmint/policies/*.policy.json
sudo chmod 0444 .claude/settings.json .codex/hooks.json .cursor/hooks.json .windsurf/hooks.json .clinerules/hooks.json
sudo chmod 0555 .codex/dmint-hook.sh .clinerules/hooks/PreToolUse .cline/hooks/PreToolUse.sh

# 2. On Linux (ext4/xfs/btrfs), set the kernel immutable bit (+i) so even root-equivalent file writes fail until unset:
sudo chattr +i policy.json
sudo chattr +i .dmint/policies/*.policy.json
sudo chattr +i .claude/settings.json .codex/hooks.json .codex/dmint-hook.sh
sudo chattr +i .opencode/plugins/dmint-guard.ts .opencode/plugin/dmint-guard.ts
sudo chattr +i .cursor/hooks.json .windsurf/hooks.json
sudo chattr +i .clinerules/hooks/PreToolUse .cline/hooks/PreToolUse.sh .clinerules/hooks.json

# (On macOS, use `sudo chflags schg <file>` instead of `chattr +i`)
```

### Step 5: Pin the Expected Policy Digest & Approve from the Approver Account

```bash
# Compute the canonical SHA-256 digest of your policy file:
export DMINT_EXPECTED_POLICY_DIGEST=$(dmint policy-digest /srv/workspace/my-project/policy.json)

# When the AI agent triggers APPROVAL_REQUIRED (e.g., `git push origin main`),
# the human operator approves from the isolated `dmint-approver` user:
sudo -u dmint-approver dmint approve apr_... \
  --key-file /etc/dmint/authority/signing.key \
  --db /srv/workspace/my-project/.dmint/approvals.sqlite3 \
  --by "alice@company.com" \
  --reason "Approved release push"
```

---

## 4. Production Blueprint B: 3-Zone Docker Compose & Kubernetes Architecture (`dmint-mcp` Gateway + PostgreSQL)

For production autonomous agents or remote IDE integrations using Model Context Protocol (MCP), **never run MCP servers inside the agent container**. Instead, run `dmint-mcp` in an isolated gateway container:

- **The AI Agent Container (`agent-worker`)** has **zero** database credentials, **zero** cloud API keys, **zero** `signing.key`, and **zero** `integrity.key`. It can only send HTTP requests to `http://dmint-mcp-gateway:8000/mcp` using its `DMINT_AUTH_TOKEN`.
- **The Dmint Gateway Container (`dmint-mcp-gateway`)** mounts `policy.json` and `mcp_protection.json` as read-only (`:ro`), pins `DMINT_EXPECTED_POLICY_DIGEST`, holds `integrity.key` (`:ro`), and holds only the **Public Key** (`DMINT_TRUSTED_PUBLIC_KEY_HEX`). It has **no `signing.key`**.
- **The Approval Dashboard / Authority Container (`dmint-dashboard`)** is the **only** container with `signing.key` (`:ro`), accessible only to human operators over an internal VPN / Tailscale / mTLS reverse proxy.

### Complete `docker-compose.prod.yml`

```yaml
version: "3.9"

services:
  postgres-approvals:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_USER: dmint_store
      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password
      POSTGRES_DB: dmint_approvals
    volumes:
      - pg_approvals_data:/var/lib/postgresql/data
    secrets:
      - pg_password
    networks:
      - dmint_backend_net

  dmint-mcp-gateway:
    image: dmint:2.0.4
    command:
      - dmint-mcp
      - run
      - --config
      - /etc/dmint/mcp_protection.json
      - --transport
      - http
      - --host
      - 0.0.0.0
      - --port
      - "8000"
      - --expected-policy-digest
      - "${DMINT_EXPECTED_POLICY_DIGEST}"
    user: "10001:10001"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      DMINT_DATABASE_URL: "postgresql://dmint_store:${PG_PASSWORD}@postgres-approvals:5432/dmint_approvals"
      DMINT_DEPLOYMENT_EPOCH: "prod-2026-v1"
      DMINT_INTEGRITY_KEY_FILE: "/run/secrets/dmint_integrity_key"
      DMINT_AUTH_TOKEN: "${AGENT_GATEWAY_BEARER_TOKEN}"
      DMINT_SLACK_WEBHOOK_URL: "${DMINT_SLACK_WEBHOOK_URL}"
      # Downstream tool secrets live ONLY in the gateway, NEVER in the agent container:
      PROD_POSTGRES_URL: "${PROD_POSTGRES_URL}"
      STRIPE_SECRET_KEY: "${STRIPE_SECRET_KEY}"
    volumes:
      - ./config/policy.json:/etc/dmint/policy.json:ro
      - ./config/mcp_protection.json:/etc/dmint/mcp_protection.json:ro
    secrets:
      - source: dmint_integrity_key
        target: dmint_integrity_key
        uid: "10001"
        gid: "10001"
        mode: 0400
    depends_on:
      - postgres-approvals
    networks:
      - dmint_agent_net
      - dmint_backend_net

  dmint-dashboard:
    image: dmint:2.0.4
    command:
      - dmint
      - dashboard
      - --host
      - 127.0.0.1
      - --port
      - "8080"
      - --deployment-epoch
      - "prod-2026-v1"
      - --key-file
      - /run/secrets/dmint_signing_key
      - --token-file
      - /run/secrets/dmint_dashboard_token
      - --authority-issuer
      - "prod-secops-authority"
      - --approver-id
      - "secops-team@company.com"
    user: "10002:10002"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      DMINT_DATABASE_URL: "postgresql://dmint_store:${PG_PASSWORD}@postgres-approvals:5432/dmint_approvals"
      DMINT_INTEGRITY_KEY_FILE: "/run/secrets/dmint_integrity_key"
    volumes:
      - ./config/policy.json:/app/policy.json:ro
    secrets:
      - source: dmint_signing_key
        target: dmint_signing_key
        uid: "10002"
        gid: "10002"
        mode: 0400
      - source: dmint_integrity_key
        target: dmint_integrity_key
        uid: "10002"
        gid: "10002"
        mode: 0400
      - source: dmint_dashboard_token
        target: dmint_dashboard_token
        uid: "10002"
        gid: "10002"
        mode: 0400
    ports:
      - "127.0.0.1:8080:8080"
    depends_on:
      - postgres-approvals
    networks:
      - dmint_backend_net

  agent-worker:
    image: my-ai-agent:latest
    user: "10003:10003"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      # The agent ONLY knows the gateway URL and its gateway bearer token.
      # It has NO access to postgres-approvals, signing.key, integrity.key, or downstream DB/Stripe keys!
      MCP_SERVER_URL: "http://dmint-mcp-gateway:8000/mcp"
      MCP_BEARER_TOKEN: "${AGENT_GATEWAY_BEARER_TOKEN}"
    networks:
      - dmint_agent_net

networks:
  dmint_agent_net:
    internal: true
  dmint_backend_net:
    internal: true

volumes:
  pg_approvals_data:

secrets:
  pg_password:
    file: ./secrets/pg_password.txt
  dmint_signing_key:
    file: ./secrets/signing.key
  dmint_integrity_key:
    file: ./secrets/integrity.key
  dmint_dashboard_token:
    file: ./secrets/dashboard.token
```

---

## 5. Production Blueprint C: Python SDK in Production Workers (FastAPI, LangGraph, CrewAI, Celery)

When embedding `@dmint.protect` directly inside a Python agent worker process, configure `Dmint` with an **`ApprovalVerifier` initialized ONLY with the public key (`trusted_issuers`)** and pin `expected_policy_digest`:

```python
import os
from datetime import datetime, timedelta, timezone
from dmint import (
    ApprovalRequiredError,
    ApprovalVerifier,
    AuthorizationError,
    Dmint,
    Policy,
    PolicyProvenance,
    TrustedContext,
    create_approval_store,
    policy_digest,
    public_key_from_hex,
)

# 1. Load policy from read-only mount and verify its exact SHA-256 file digest
POLICY_PATH = "/etc/dmint/policy.json"
EXPECTED_DIGEST = os.environ["DMINT_EXPECTED_POLICY_DIGEST"]  # From `dmint policy-digest policy.json`

policy = Policy.from_file(POLICY_PATH, expected_policy_digest=EXPECTED_DIGEST)

# 2. Configure PostgreSQL approval store (reads DMINT_DATABASE_URL & DMINT_INTEGRITY_KEY_FILE)
store = create_approval_store(deployment_epoch="prod-2026-v1")

# 3. Configure PUBLIC-KEY ONLY verifier (this worker process NEVER loads signing.key!)
verifier = ApprovalVerifier(
    trusted_issuers={
        # Output of `dmint export-public-key --json` from the Approver Vault:
        "prod-secops-authority": public_key_from_hex(os.environ["DMINT_AUTHORITY_PUBLIC_KEY_HEX"]),
    },
    audience="dmint-enforcement-gateway",
)

provenance = PolicyProvenance(
    version_id="prod-2026-v1",
    policy_digest=policy_digest(policy),
    evaluated_at=datetime.now(timezone.utc),
)

# 4. Initialize fail-closed Dmint engine
dmint = Dmint(
    policy=policy,
    agent_id="billing-agent-prod",
    context=TrustedContext({"environment": "production", "region": "ap-south-1"}),
    approval_store=store,
    approval_verifier=verifier,
    policy_provenance=provenance,
    expected_policy_digest=EXPECTED_DIGEST,
    approval_ttl=timedelta(minutes=15),
)


@dmint.protect("stripe.issue_refund", resource_param="account_id")
def issue_refund(account_id: str, amount_cents: int, reason: str) -> dict:
    return {"status": "refunded", "account_id": account_id, "amount_cents": amount_cents}
```

---

## 6. How Every Attack Vector Is Defeated (Mathematical & Systems Proof)

| # | Attack Vector Attempted by Jailbroken AI Agent | How Dmint + Production Isolation Defeats It (`100% Fail-Closed`) | Error Code Returned |
| :--- | :--- | :--- | :--- |
| **1** | **Self-Signing / Forging an Approval**: Agent tries to sign its own `ApprovalAssertion` or flip `state='APPROVED'` in SQLite/PostgreSQL. | `signing.key` (Ed25519 private key) is stored exclusively in Zone 3 (`dmint-approver`). Zone 2 only holds `public_key_hex`. Any forged or unsigned DB row fails Ed25519 verification + `row_mac` HMAC-SHA256 verification. | `DMT_APPROVAL_SIGNATURE_INVALID` / `DMT_APPROVAL_CORRUPT` |
| **2** | **Argument Tampering After Human Approval**: Agent requests approval for `git push origin staging`, human approves, and agent retries with `git push origin main --force`. | Approval signature binds `argument_hash` (SHA-256 over RFC 8785 JCS canonical arguments) and `request_fingerprint`. Changing 1 byte produces a different hash and refuses consumption of the original approval. | `DMT_APPROVAL_REQUEST_MISMATCH` |
| **3** | **Replay Attack**: Agent receives a valid human approval for `issue_refund("acct_1", 5000)` and calls the function 10 times in a parallel loop. | `consume_approved()` uses serialized transactions (`BEGIN IMMEDIATE` in SQLite / `SELECT ... FOR UPDATE` in PostgreSQL) to transition `APPROVED -> CONSUMED` atomically once, plus an in-memory replay cache. Calls 2..10 fail closed. | `DMT_APPROVAL_CONSUMED` |
| **4** | **Compound Shell Command Smuggling**: Agent runs `git status && cat .env`, `ls; rm -rf /`, `echo $(cat ~/.ssh/id_rsa)`, or `find . -exec sh -c "..."`. | `split_compound_shell_command()` in `hooks.py` decomposes `&&`, `||`, `;`, `|`, `&`, newlines, and detects `$()`, backticks, `eval`, and `-exec`. Every sub-command is evaluated independently; strictest decision (`DENY`) wins. | `DMT_POLICY_DENIED` |
| **5** | **Symlink & Path Traversal Escape**: Agent creates `ln -s /etc/shadow ./safe_notes.txt` or passes `../../.env` or `%2e%2e%2f.env` to `Read` / `Write`. | `hooks.py` resolves `Path.resolve()` against symlink targets before policy evaluation, and `resources.py` rejects `..`, `%2e%2e`, `%2f`, backslashes, and NUL bytes. Symlinks pointing outside workspace or to `.env`/`*.key` match `DENY`. | `DMT_POLICY_DENIED` / `DMT_RESOURCE_INVALID` |
| **6** | **Batch Patch Smuggling (`apply_patch` / `read_files`)**: Agent hides `*** Update File: .claude/settings.json` or `.env` inside a 20-file `apply_patch` call. | `extract_hook_invocations()` extracts every `*** Add/Update/Delete File:` header and every batch item, evaluating each against the harness policy and enforcing `DENY > APPROVAL_REQUIRED > ALLOW`. | `DMT_POLICY_DENIED` |
| **7** | **Downstream MCP Tool Rug-Pull & SSRF**: Compromised remote MCP server changes a tool's schema after policy creation or redirects to `http://169.254.169.254/latest/meta-data/`. | `dmint-mcp` verifies `compute_tool_schema_hash()` against the SHA-256 `schema_hash` pinned in `policy.json` on every call, and `ssrf.py` blocks loopback, RFC 1918, link-local, cloud metadata IPs, and pins resolved DNS socket IPs against TOCTOU rebinding. | `DMT_MCP_SCHEMA_MISMATCH` / `DMT_MCP_CONFIG_ERROR` |

---

## 7. Production Go-Live Verification Script & Checklist

Before launching your agent in production, run `dmint doctor` and verify every item in this checklist:

```bash
# 1. Verify cryptographic engine, keys, policies, hooks, and run the 7-scenario red-team proof:
dmint doctor
dmint demo

# 2. Inspect and cryptographically verify the tamper-evident SHA-256 audit log chain:
dmint logs --level WARNING
dmint logs --verify

# 3. Verify all policy files offline (zero network, zero LLM):
dmint verify-policy policy.json
for p in .dmint/policies/*.policy.json; do dmint verify-policy "$p"; done

# 4. Compute and export your pinned policy digest:
export DMINT_EXPECTED_POLICY_DIGEST=$(dmint policy-digest policy.json)
echo "Pinned Digest: $DMINT_EXPECTED_POLICY_DIGEST"
```

### Final Pre-Launch Checklist

- [ ] **Private Key Isolation**: `signing.key` is **not** readable by the AI agent UID (`chmod 0400`, owned by `dmint-approver`, or mounted only in the `dmint-dashboard` container).
- [ ] **Public Key Verification**: Gateway / SDK worker is configured with `trusted_issuers` from `dmint export-public-key --json`.
- [ ] **Policy & Hook Immutability**: `policy.json`, `.dmint/policies/*.policy.json`, and harness hook files (`.claude/settings.json`, `.codex/hooks.json`, etc.) are owned by `root`, mode `0444`, and mounted `:ro` or locked with `chattr +i`.
- [ ] **Policy Digest Pinning**: `DMINT_EXPECTED_POLICY_DIGEST` is set in the runtime environment.
- [ ] **Audit Chain Verified**: `dmint logs --verify` reports a valid SHA-256 chain to the current head.
- [ ] **Downstream Secret Isolation**: Database URLs and third-party API keys are injected into `dmint-mcp`, never into the AI agent's environment.
- [ ] **Automated Self-Test**: `dmint doctor` exits with code `0` (`ALL CHECKS PASSED`).
