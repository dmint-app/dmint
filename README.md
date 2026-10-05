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

`dmint` v2.0.0 is organized as a unified monorepo providing modular packages under a single distribution:

| Module | Description | Primary Exports / Entrypoint |
| :--- | :--- | :--- |
| **`dmint.core`** | Deterministic policy engine, RFC 8785 canonicalizer, SQLite approval store | `from dmint import Dmint, Policy, Rule` |
| **`dmint.cli`** | Developer CLI for authoring, compiling, validating, and managing policies | `dmint` command |
| **`dmint.mcp`** | Transparent security proxy for Model Context Protocol (stdio & SSE/HTTP) | `dmint-mcp` command |
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

## Quickstart: Python SDK

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
engine = Dmint(
    policy=policy,
    agent_id="data-analyst-agent",
    context=TrustedContext({"environment": "production"}),
    approval_store=store,
    policy_provenance=provenance,
    approval_ttl=timedelta(minutes=30),
)


# 4. Protect your tool callables with decorators
@engine.protect("database.select")
def select_users(query: str) -> list[dict]:
    return [{"id": 1, "username": "alice"}]


@engine.protect("database.update")
def update_user_role(user_id: int, role: str) -> str:
    return f"Updated user {user_id} to {role}"


@engine.protect("database.drop")
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
| `dmint create-policy` | `dmint create-policy -f access.md -o policy.json` | Interactive LLM wizard that converts markdown access requirements into validated policies. |
| `dmint create-mcp-policy` | `dmint create-mcp-policy --url https://api.example.com/mcp` | Discovers live MCP server tools and generates `policy.json` and `mcp_protection.json`. |
| `dmint verify-policy` | `dmint verify-policy policy.json` | 100% offline schema, capability, and secret scanner. Zero network, zero LLM. |
| `dmint compile-policy` | `dmint compile-policy policy.json -o compiled.json` | Normalizes and canonicalizes policies with RFC 8785 for deployment. |
| `dmint pending` | `dmint pending` | Lists all approval requests currently in `PENDING` state across SQLite or PostgreSQL. |
| `dmint approve` | `dmint approve <id> [--reason "..."]` | Signs and approves a pending request via Core Ed25519 primitives after policy re-verification. |
| `dmint reject` | `dmint reject <id> [--reason "..."]` | Marks a pending request as `REJECTED` with an optional audit reason. |
| `dmint dashboard` | `dmint dashboard --db-path ./approvals.sqlite3` | Launches the local human approval web dashboard (FastAPI). |
| `dmint install-skill` | `dmint install-skill -y` | Installs the `dmint-policy-manager` skill into `.agents/skills/` for AI coding assistants. |

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

---

## Security Invariants

Dmint enforces five fundamental invariants across all modules:

1. **Deterministic Enforcement**: Decisions are made solely through deterministic mathematical matching. LLMs draft policies, but never decide authorization at runtime.
2. **Fail-Closed Default**: Any request not explicitly allowed by a matching rule evaluates to `DENY`.
3. **Exact Request Binding**: Requests are canonicalized using RFC 8785 and fingerprinted with SHA-256 domain separation. Mismatched arguments invalidate approval tokens.
4. **Single-Use Approvals**: Approvals transition atomically in SQLite (`PENDING` $\to$ `APPROVED` $\to$ `CONSUMED`) to prevent race conditions and replay attacks.
5. **SSRF & Network Hardening**: Remote MCP transports reject loopback, link-local, private RFC 1918 addresses, and cloud instance metadata endpoints (`169.254.169.254`).

For complete vulnerability reporting guidelines and threat boundaries, see [SECURITY.md](SECURITY.md).

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

# 3. Type check all 71 source files
mypy src/

# 4. Run targeted tests for what you changed
pytest tests/<subsystem>/ -v   # e.g., tests/core/, tests/cli/, tests/mcp/, tests/dashboard/

# 5. Run full test suite (baseline: 968 passed, 0 skipped, 0 failed)
pytest tests/ -q

# 6. Run pre-commit checks across all files
pre-commit run --all-files
```

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
pip install "dist/dmint-2.0.0-py3-none-any.whl[all]"

# 4. Verify all installed CLI entrypoints
dmint --version        # Expected: dmint 2.0.0
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
- All 24 pages (Quickstart, Core Concepts, Guides, Architecture, and API Reference) are fully browsable with live search and code highlighting.
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

## Versioning & Severity Protocol

Dmint adheres strictly to **[Semantic Versioning 2.0.0](https://semver.org/)**:
- **Patch (`2.0.0` &rarr; `2.0.1`)**: Bug fixes, documentation updates, test additions, non-breaking refactors.
- **Minor (`2.0.0` &rarr; `2.1.0`)**: Backwards-compatible features, new CLI flags, new integrations.
- **Major (`2.0.0` &rarr; `3.0.0`)**: Incompatible API changes, breaking policy schema modifications.

> **CRITICAL RULE FOR AI AGENTS**: AI agents must **NEVER** change or bump version numbers silently. Always assess change severity, suggest the recommended SemVer bump to the user with clear rationale, and wait for explicit permission before updating `pyproject.toml`, `version.py`, `__init__.py`, or `CHANGELOG.md`.

---

## License

Dmint is licensed under the [Apache License, Version 2.0](LICENSE).
