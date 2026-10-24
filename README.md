<div align="center">

<img src="assets/logo.svg" alt="Dmint Logo" width="100" height="100" />

# Dmint

**Deterministic authorization and security enforcement for AI-agent tool execution.**

[![PyPI Version](https://img.shields.io/pypi/v/dmint.svg?color=blue)](https://pypi.org/project/dmint/)
[![Python Version](https://img.shields.io/pypi/pyversions/dmint.svg?color=blue)](https://pypi.org/project/dmint/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Type Checked](https://img.shields.io/badge/types-Mypy%20Strict-blue.svg)](pyproject.toml)
[![Code Style](https://img.shields.io/badge/code%20style-Ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](.pre-commit-config.yaml)

</div>

---

Dmint places a strict, tamper-evident security boundary between AI agents and the sensitive tools, databases, APIs, and file systems they control. Every tool invocation is intercepted, canonicalized via **RFC 8785**, and evaluated against declarative policies before execution—ensuring that agents cannot execute unauthorized or destructive commands even when subject to prompt injection or jailbreak attacks.

---

## Why Dmint?

Modern AI agents (Claude Code, Cursor, Antigravity, AutoGPT, custom LangChain/LlamaIndex agents) are frequently granted access to high-privilege execution environments: databases, cloud infrastructure, file systems, and command shells.

- **Prompt-based guardrails fail:** Instructing an LLM *"Do not run DELETE without asking"* is unreliable against adversarial prompt injection, jailbreaks, and hallucinations.
- **Dmint is deterministic:** There is **zero LLM evaluation** in the authorization decision path. Policies are evaluated as pure, deterministic boolean logic.
- **Fail-closed by default:** Any unrecognized tool, unknown action, missing credential, or unauthenticated request is rejected immediately with `DENY`.

---

## Architecture Overview

```
                                  [ AI Agent / LLM ]
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │         Dmint Enforcement Gate          │
                     │  1. Parameter Canonicalization (JCS)   │
                     │  2. SHA-256 Request Fingerprinting      │
                     │  3. Deterministic Policy Evaluation     │
                     └────────────────────┬────────────────────┘
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
            [   ALLOW   ]        [ APPROVAL_REQUIRED ]       [    DENY   ]
                  │                       │                       │
                  ▼                       ▼                       ▼
          Executes Tool           Generates Ed25519       Execution Blocked
        (Local / Downstream)      Pending Assertion      (AuthorizationError)
                                          │
                                          ▼
                               [ Human Review UI / CLI ]
                                          │
                                          ▼
                               Atomic Store Consume &
                                   Approved Retry
```

---

## Key Capabilities

- **Deterministic Evaluation Engine**: Evaluates `ALLOW`, `DENY`, and `APPROVAL_REQUIRED` rules in order of strict precedence (deny-overrides, default deny).
- **RFC 8785 Canonical Request Binding**: Normalizes all tool arguments into JSON Canonicalization Scheme (JCS) hashes to guarantee byte-for-byte immutability.
- **Human-in-the-Loop Approvals**: High-risk actions trigger cryptographic approval records stored in SQLite/PostgreSQL and reviewable via a local dashboard or CLI.
- **Outgoing Webhook Notifications**: Real-time alerts dispatched to Slack, Discord, and Microsoft Teams the moment an approval is required, eliminating manual polling.
- **Single-Use Replay Protection**: Approvals transition atomically (`PENDING` $\to$ `APPROVED` $\to$ `CONSUMED`) preventing token re-use or race conditions.
- **Model Context Protocol (MCP) Gateway**: Seamless stdio and Streamable-HTTP proxy with SSRF defense, RFC 1918 private IP blocking, and DNS rebinding protections.
- **Developer & Agent Tooling**: Full CLI for compiling natural language access requirements (`access.md`) into verified policies (`policy.json`) and bundled skills for Cursor, Claude Code, and Antigravity.

---

## Subsystems

`dmint` v2.0.3 is organized as a unified monorepo providing modular packages under a single distribution:

| Module | Description | Primary Exports / Entrypoint |
| :--- | :--- | :--- |
| **`dmint.core`** | Deterministic policy engine, RFC 8785 canonicalizer, SQLite approval store | `from dmint import Dmint, Policy, Rule` |
| **`dmint.cli`** | Developer CLI for authoring, compiling, validating, and managing policies | `dmint` command |
| **`dmint.mcp`** | Transparent security proxy for Model Context Protocol (stdio & Streamable HTTP) | `dmint-mcp` command |
| **`dmint.dashboard`** | Local web dashboard for human review and Ed25519 approval signing | `dmint dashboard` or `dmint-dashboard` |
| **`dmint.skills`** | Packaged AI agent skills (`dmint-policy-manager`) for self-authoring policies | `dmint install-skill` |

---

## Installation

### Core Package & CLI
```bash
pip install dmint
```

### With MCP Protection Gateway
```bash
pip install "dmint[mcp]"
```

### With Human Approval Dashboard
```bash
pip install "dmint[dashboard]"
```

### With PostgreSQL Storage
```bash
pip install "dmint[postgres]"
```

### Complete Installation (Everything Included)
```bash
pip install "dmint[all]"
```

---

## 60-Second Quickstart: Coding Agents (Claude Code, Codex, OpenCode, Cursor)

Protect built-in shell commands (`Bash`, `exec_command`), file edits (`Read`, `Write`, `Edit`), and MCP tools across all major AI coding harnesses with one command:

```bash
pip install dmint

# Generates .dmint/ keys (0600), starter policy.json (shell + filesystem), and pre-tool hooks:
dmint init --harness all
```

Supported harnesses out of the box (`--harness all` or comma-separated):
- **Claude Code** (`.claude/settings.json` `PreToolUse` hook)
- **OpenAI Codex CLI** (`.codex/hooks.json` & `.codex/dmint-hook.sh`)
- **OpenCode** (`.opencode/plugin/dmint-guard.ts` `tool.execute.before` plugin)
- **Cursor** (`.cursor/hooks.json`), **Windsurf** (`.windsurf/hooks.json`), **Cline / Roo Code** (`.clinerules/hooks.json`)

Test how your `policy.json` evaluates any command right from the terminal:

```bash
dmint check -t shell.execute -r "git status"           # -> ALLOW (exit 0)
dmint check -t shell.execute -r "git push origin main" # -> APPROVAL_REQUIRED (exit 1)
dmint check -t shell.execute -r "rm -rf /"             # -> DENY (exit 2)
```

When an agent hits an `APPROVAL_REQUIRED` rule (like `git push origin main`), approve it once from your terminal and ask the agent to retry:

```bash
dmint pending
dmint approve apr_... --by alice@company.com
```

The next retry automatically verifies the Ed25519 signature against the exact RFC 8785 canonicalized arguments and consumes the approval atomically (`APPROVED -> CONSUMED`). Editing any argument or replaying the call a second time is refused.

---

## Quickstart: Python SDK

### Option A: Zero-Config Local Setup (`Dmint.local`)

For local agents and quick evaluation, `Dmint.local()` automatically creates `.dmint/signing.key`, `.dmint/integrity.key`, and `.dmint/approvals.sqlite3`:

```python
from dmint import ApprovalRequiredError, Dmint, Policy, Rule

policy = Policy([
    Rule.allow("database", "select"),
    Rule.approval_required("database", "update"),
    Rule.deny("database", "drop"),
])
dmint = Dmint.local(policy)

@dmint.protect("database.update")
def update_user_role(user_id: int, role: str) -> str:
    return f"Updated user {user_id} to {role}"

try:
    update_user_role(1, "admin")
except ApprovalRequiredError as exc:
    print(f"Paused for human sign-off: dmint approve {exc.approval_id}")
    # After running `dmint approve <id>`, retry without manually passing the credential bytes:
    # dmint.retry(update_user_role, 1, "admin")
```

### Option B: Explicit Production Configuration

Dmint's approval store is tamper-evident: pending records are HMAC-signed with a local integrity key, and approvals are signed with an Ed25519 key. Generate both once before running the example:

```bash
dmint init-keys
```

This writes `~/.config/dmint/signing.key` and `~/.config/dmint/integrity.key` (mode `0600`). In CI or containers, provide the integrity key with `DMINT_INTEGRITY_KEY` (64 hex characters) or `DMINT_INTEGRITY_KEY_FILE` (path to a `0600` key file) instead.

Protecting local Python functions and agent tools with Dmint:

```python
from datetime import datetime, timezone, timedelta
from dmint import (
    Dmint,
    Policy,
    Rule,
    Condition,
    TrustedContext,
    SQLiteApprovalStore,
    PolicyProvenance,
    policy_digest,
    ApprovalRequiredError,
    AuthorizationError,
)

# 1. Define deterministic policy rules
policy = Policy(
    [
        Rule.allow("database", "select"),
        Rule.approval_required("database", "update"),
        Rule.deny("database", "drop"),
    ]
)

# 2. Configure persistent approval store & provenance
store = SQLiteApprovalStore("./approvals.sqlite3", deployment_epoch="prod-v1")
provenance = PolicyProvenance("prod-v1", policy_digest(policy), datetime.now(timezone.utc))

# 3. Initialize Dmint enforcement engine
dmint = Dmint(
    policy=policy,
    agent_id="data-analyst-agent",
    context=TrustedContext({"environment": "production"}),
    approval_store=store,
    policy_provenance=provenance,
    approval_ttl=timedelta(minutes=30),
)


# 4. Protect your tool callables with decorators
@dmint.protect("database.select")
def select_users(query: str) -> list[dict]:
    return [{"id": 1, "username": "alice"}]


@dmint.protect("database.update")
def update_user_role(user_id: int, role: str) -> str:
    return f"Updated user {user_id} to {role}"


@dmint.protect("database.drop")
def drop_table(table_name: str) -> str:
    return f"Dropped {table_name}"


# --- EXECUTION ---

# ALLOW: Executes immediately
result = select_users("SELECT * FROM users")
print(f"[✓] Query result: {result}")

# DENY: Immediately blocked with AuthorizationError
try:
    drop_table("users")
except AuthorizationError as exc:
    print(f"[✗] Security blocked forbidden call: {exc}")

# APPROVAL_REQUIRED: Halts and writes pending record to SQLite
try:
    update_user_role(1, "admin")
except ApprovalRequiredError as exc:
    print(f"[!] Action paused for approval. ID: {exc.approval_id}")
    print(f"    Request Fingerprint: {exc.request_fingerprint}")
```

> [!NOTE]
> **Supported callable types**: `@dmint.protect` supports synchronous functions (`def`), asynchronous functions (`async def`), instance methods, class methods (`@classmethod`), and static methods (`@staticmethod`). Generator and async-generator functions are not supported.
>
> **Measured Performance**: In-memory policy evaluation runs in ~3 µs; persistent storage operations (SQLite/PostgreSQL approval lifecycle) take ~2-5 ms.

### Pluggable Storage: SQLite & Production PostgreSQL

Dmint provides a pluggable approval persistence interface (`ApprovalStore`) driven by SQLAlchemy Core.

- **Local / Dev / Testing (SQLite)**: By default (or when `DMINT_DATABASE_URL` is unset), Dmint uses local SQLite storage with zero external dependencies.
- **Production (PostgreSQL)**: Set the `DMINT_DATABASE_URL` environment variable to a PostgreSQL connection string to persist pending approvals with row-level locking (`SELECT ... FOR UPDATE`), atomic single-use consumption, and enterprise concurrency guarantees.

```python
from dmint import create_approval_store

# Automatically reads DMINT_DATABASE_URL from environment (or defaults to SQLite)
store = create_approval_store(deployment_epoch="prod-v1")
```

#### Production: Postgres

To configure PostgreSQL in production:

1. Install Dmint with PostgreSQL driver support:
   ```bash
   pip install "dmint[postgres]"
   ```
2. Set the environment variable:
   ```bash
   export DMINT_DATABASE_URL="postgresql://dmint_user:secure_password@postgres-host:5432/dmint_prod"
   ```
3. If `DMINT_DATABASE_URL` is set but invalid (unreachable host, authentication failure, or malformed URL), Dmint **fails loud at startup** and refuses to run—preventing silent fallback to ephemeral or unbacked local storage.

---

## Quickstart: MCP Gateway

Secure any Model Context Protocol (MCP) server (Postgres, Filesystem, GitHub, custom tools) without changing a line of code:

### 1. Define `mcp_protection.json`
```json
{
  "policy_file": "policy.json",
  "approval_db": "./approvals.sqlite3",
  "approval_ttl": 300,
  "integrations": [
    {
      "integration_id": "postgres-prod",
      "transport": "stdio",
      "connection": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"]
      },
      "tool_bindings": {
        "query": {
          "tool_name": "query",
          "capability": "postgres.query",
          "discovery": "exposed"
        }
      }
    }
  ]
}
```

### 2. Run the Gateway
```bash
dmint-mcp run --config mcp_protection.json
```

### 3. Connect Your AI Assistant (Cursor, Claude Code, Antigravity)
Add Dmint MCP as a stdio server in your client configuration (e.g. `.cursor/mcp.json` or Claude Code settings):

```json
{
  "mcpServers": {
    "protected-db": {
      "command": "dmint-mcp",
      "args": ["run", "--config", "/path/to/mcp_protection.json"]
    }
  }
}
```

---

## CLI Reference

`dmint` includes a full-featured CLI for authoring, compiling, and validating policies:

| Command | Usage | Description |
| :--- | :--- | :--- |
| `dmint init` | `dmint init --harness all` | One-command setup: generates `.dmint/` keys, starter `policy.json`, and coding-agent hooks. |
| `dmint check` | `dmint check -t shell.execute -r "git status"` | Simulates a tool call against `policy.json` (`ALLOW` / `APPROVAL_REQUIRED` / `DENY`). |
| `dmint hook` | `dmint hook <install\|run\|status\|uninstall>` | Manages and runs pre-tool hooks for Claude Code, Codex, OpenCode, Cursor, Windsurf, and Cline. |
| `dmint create-policy` | `dmint create-policy -f access.md -o policy.json` | Interactive LLM wizard that converts markdown access requirements into validated policies. |
| `dmint create-mcp-policy` | `dmint create-mcp-policy --url https://api.example.com/mcp` | Discovers live MCP server tools and generates `policy.json` and `mcp_protection.json`. |
| `dmint protect-mcp` | `dmint protect-mcp --url https://api.example.com/mcp` | Compatibility alias for `dmint create-mcp-policy` (identical options). |
| `dmint verify-policy` | `dmint verify-policy policy.json` | 100% offline schema and capability validation. Zero network, zero LLM. |
| `dmint policy-digest` | `dmint policy-digest policy.json` | Computes the SHA-256 digest of the exact policy file bytes (for `DMINT_EXPECTED_POLICY_DIGEST`). |
| `dmint compile-policy` | `dmint compile-policy -f access.md -o policy.json` | [Compatibility] Legacy LLM wizard delegating to `create-policy` non-interactive mode. |
| `dmint pending` | `dmint pending` | Lists all approval requests currently in `PENDING` state across SQLite or PostgreSQL. |
| `dmint approve` | `dmint approve <id> [--reason "..."]` | Signs and approves a pending request via Core Ed25519 primitives after policy re-verification. |
| `dmint reject` | `dmint reject <id> [--reason "..."]` | Marks a pending request as `REJECTED` with an optional audit reason. |
| `dmint dashboard` | `dmint dashboard --db-path ./approvals.sqlite3` | Launches the local human approval web dashboard (FastAPI). |
| `dmint install-skill` | `dmint install-skill -y` | Installs the `dmint-policy-manager` skill into `.agents/skills/` for AI coding assistants. |
| `dmint init-keys` | `dmint init-keys` | Generates and persists Ed25519 signing and HMAC integrity keys (`0600`, atomic). |
| `dmint export-public-key` | `dmint export-public-key --format json` | Prints the public key (hex + PEM) and issuer ID for gateway `trusted_issuers`. |

---

## Real-Time Notifications (Outgoing Webhooks)

When an agent triggers an `APPROVAL_REQUIRED` policy rule, Dmint can notify your team immediately on **Slack**, **Discord**, or **Microsoft Teams** with the exact approval ID, tool, resource, and copy-paste CLI approval command:

```bash
# Configure any or all webhook destinations via environment variables
export DMINT_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export DMINT_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export DMINT_TEAMS_WEBHOOK_URL="https://example.webhook.office.com/webhookb2/..."
```

- **Fail-Safe & Isolated**: Webhook errors or timeouts never block, weaken, or compromise runtime authorization decisions.
- **Zero-Config Default**: Webhook dispatch is a pure no-op when URLs are unset.

> [!NOTE]
> **TODO (Approver Environment)**: Because `--database-url` credentials are strictly stripped from outgoing webhook notifications to prevent credential leakage in chat channels, approvers executing `dmint approve <id>` must ensure the `DMINT_DATABASE_URL` environment variable is configured in their execution environment if using a remote PostgreSQL store.


---

## When to Use Dmint (and When to Pick Something Else)

| If you... | Use | Why |
| :--- | :--- | :--- |
| **Need self-hosted, Ed25519-signed, single-use human sign-off on high-risk actions in Python, MCP, or coding-agent hooks** | **Dmint** | Approvals are cryptographically bound to exact RFC 8785 arguments, usable once (`PENDING -> APPROVED -> CONSUMED`), and voided if `policy.json` changes. |
| Run entirely on AWS Bedrock AgentCore | AWS AgentCore Policy | Managed Cedar policy enforcement at the AWS gateway with zero infrastructure to host. |
| Need broad multi-language governance across Go, .NET, Java, and Rust | Microsoft Agent Governance Toolkit / Cerbos | Multi-language SDKs and centralized policy decision points (PDPs). |
| Need prompt-injection classification, toxicity filtering, or PII redaction | LLM Guardrails (Llama Guard, NeMo) | Dmint is a deterministic capability and argument gate—never a text classifier. |

---

## Security Invariants

Dmint enforces five fundamental invariants across all modules:

1. **Deterministic Enforcement**: Decisions are made solely through deterministic mathematical matching. LLMs draft policies, but never decide authorization at runtime.
2. **Fail-Closed Default**: Any request not explicitly allowed by a matching rule evaluates to `DENY`.
3. **Exact Request Binding**: Requests are canonicalized using RFC 8785 and fingerprinted with SHA-256 domain separation. Mismatched arguments invalidate approval tokens.
4. **Single-Use Approvals**: Approvals transition atomically in SQLite (`PENDING` $\to$ `APPROVED` $\to$ `CONSUMED`) to prevent race conditions and replay attacks.
5. **SSRF & Network Hardening**: Remote MCP transports reject loopback, link-local, private RFC 1918 addresses, cloud instance metadata endpoints (`169.254.169.254`), and DNS-rebinding attempts via connection-level IP pinning.

For complete vulnerability reporting guidelines and threat boundaries, see [SECURITY.md](SECURITY.md).

---

## What Dmint Does NOT Protect Against

> [!CAUTION]
> **CRITICAL OS USER & PROCESS ISOLATION REQUIREMENT**
>
> Dmint is an application- and protocol-level authorization gate. It **does NOT protect against an agent executing under the same OS user account**:
>
> In adversarial attack matrix testing, a same-OS-user agent succeeded in all five host attack vectors:
> 1. **Signing Key Theft**: Reading the private Ed25519 signing key (`signing.key`) from disk to self-sign approvals.
> 2. **Policy File Tampering**: Directly editing `policy.json` to insert unrestricted `ALLOW` rules.
> 3. **Database Modification**: Directly rewriting rows or checksums in the SQLite approvals database.
> 4. **Dashboard Token Theft**: Reading the dashboard token from configuration files or `/proc/<pid>/environ`.
> 5. **Client Configuration Replacement**: Overwriting `.cursor/mcp.json` or client settings to bypass `dmint-mcp` entirely and talk to unprotected tools directly.
>
> **Protection Guarantee**: Dmint's cryptographic security boundary holds **strictly when the AI agent process runs under a different OS user or in an isolated container** with no filesystem access to Dmint keys, policies, or stores. See [docs/deployment-model.md](docs/deployment-model.md).

---

---

## Local Development & Testing

Whether you are a human developer or an AI coding assistant, follow these instructions to develop, build, install, test, and preview Dmint locally.

### 1. Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/dmint-app/dmint.git
cd dmint

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with all development tools and subsystem extras
pip install -e ".[all,dev]"

# Install git pre-commit hooks (if git repo is initialized)
pre-commit install --hook-type pre-commit --hook-type commit-msg
```

### 2. Run Verification & Tests (The 6-Step Loop)

Before proposing any changes or commits, run the mandatory verification flow:

```bash
# 1. Format code deterministically
ruff format .

# 2. Lint and check for syntax / rule errors
ruff check .

# 3. Type check all 79 source files
mypy src/

# 4. Run targeted tests for what you changed
pytest tests/<subsystem>/ -v   # e.g., tests/core/, tests/cli/, tests/mcp/, tests/dashboard/

# 5. Run full test suite (baseline: 1525 passed, 0 skipped, 0 failed)
pytest tests/ -q

# 6. Run pre-commit checks across all files
pre-commit run --all-files
```

**Full-suite prerequisites:** PostgreSQL-backed suites require a reachable server (`DMINT_TEST_DATABASE_URL`; default `postgresql://postgres:postgres@localhost:5432/dmint_test`) and fail loudly — never skip — when it is unreachable. RFC 8785 cross-checks and node-parity fuzzing require Node.js plus `npm ci` inside `tests/fixtures/`.

For detailed checklists per subsystem, see [`FLOW.md`](FLOW.md).

### 3. Local Editable Installation for Development (`pip install -e`)

For active local development where code changes in `src/` should take effect immediately without rebuilding wheels:

```bash
# Option A: In a clean virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[all,dev]"

# Option B: Direct install or older pip environments (e.g. Ubuntu 22.04 LTS pip 22.0.2)
pip install --no-build-isolation -e ".[all,dev]"
```

> **Note on PEP 660 / Build Isolation**: Older versions of `pip` (< 22.3) have known build-isolation limitations when resolving editable wheels under PEP 660. The monorepo provides a `setup.py` compatibility shim and requires `setuptools>=64`. Using `--no-build-isolation` or upgrading `pip` (`pip install --upgrade pip`) ensures seamless editable builds across all environments.

### 4. Build & Locally Install the Package

To test the package exactly as end users will receive it from PyPI:

```bash
# 1. Build the distribution archives (.whl and .tar.gz)
python3 -m build --no-isolation

# 2. Validate package metadata with twine
twine check dist/*
# Expected: PASSED for both artifacts

# 3. Test install the wheel in a fresh, isolated virtual environment
python3 -m venv /tmp/dmint-test-env
source /tmp/dmint-test-env/bin/activate

# Install the wheel with all extras
pip install "dist/dmint-2.0.3-py3-none-any.whl[all]"

# 4. Verify all installed CLI entrypoints
dmint --version        # Expected: dmint 2.0.3
dmint --help           # Policy wizards and verification commands
dmint-mcp --help       # MCP multi-server gateway
dmint-dashboard --help # Approval web review console

# 5. Verify Python API import
python -c "import dmint; print('Installed Dmint version:', dmint.__version__)"

# 6. Cleanup test environment when done
deactivate
rm -rf /tmp/dmint-test-env
```

---

## Reading & Running Documentation Locally

The complete technical documentation, architecture specifications, and interactive guides live in [`docs/`](docs/). The site is built with **Holocron** and **Vite 8** with React 19 SSR.

### Live Development Preview (Hot-Reloading)

```bash
cd docs

# Install documentation dependencies
npm install

# Start the local development server
npm run dev
```

- Open **[http://localhost:3334](http://localhost:3334)** in your web browser.
- All 28 pages (Quickstart, Core Concepts, Guides, Architecture, and API Reference) are fully browsable with live search and code highlighting.
- Changes to any `.mdx` file or `docs.json` update instantly via Vite HMR.

### Production Preview (Build & Serve)

To preview the compiled production bundle exactly as deployed to Cloudflare Workers:

```bash
cd docs

# Compile client bundles and RSC SSR engine
npm run build

# Start the production Node.js preview server
npm start
```

---

## Developer & AI Agent Resources

- [`FLOW.md`](FLOW.md) — Mandatory step-by-step verification checklist and pre-commit flow.
- [`AGENTS.md`](AGENTS.md) — Authoritative monorepo guidance, invariants, and operational rules for AI agents.
- [`PLAIN.md`](PLAIN.md) — Deep architectural specification, state machine proofs, and 15-section security review checklist.
- [`.agents/skills/`](.agents/skills/) — AI coding agent skills for security reviews, policy authoring, and adversarial testing.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Community contribution guidelines, Conventional Commits format, and PR process.
- [`SECURITY.md`](SECURITY.md) — Security policy, threat boundary definitions, and vulnerability reporting.

---

## Versioning & Push-Time Release Gate

Dmint adheres strictly to **[Semantic Versioning 2.0.0](https://semver.org/)** and uses a push-time release gate:

| Change severity | SemVer bump | Typical changes |
|---|---|---|
| **High / Major** | `2.0.3` &rarr; `3.0.0` | Incompatible API changes, breaking policy schema modifications, removed public methods. |
| **Medium / Minor** | `2.0.3` &rarr; `2.1.0` | Backwards-compatible features, new CLI flags, new integrations. |
| **Low / Patch** | `2.0.3` &rarr; `2.0.4` | Bug fixes, security hardening, documentation updates, test additions, non-breaking refactors. |

Every push must include the appropriate version decision and bump. A push carrying any Major change is Major; otherwise any Minor change makes it Minor; otherwise it is Patch. When severity is ambiguous, choose the higher severity and ask before a Major bump.

The bump and its required updates are made in the same push: `pyproject.toml`, `src/dmint/version.py`, `CHANGELOG.md`, `PLAIN.md`, current-version documentation, and any version-pinned tests. The full verification flow in [`FLOW.md`](FLOW.md) must pass before pushing.

After CI succeeds for a push to `main`, the **Publish to PyPI** workflow publishes the new version automatically. Manual dispatch and GitHub release publication remain fallback paths. The workflow rejects a version that already exists on PyPI; bump the version instead of retrying the same one.

---

## License

Dmint is licensed under the [Apache License, Version 2.0](LICENSE).
