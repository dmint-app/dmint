# Dmint — AGENTS.md

> **Authoritative guidance for AI agents working on the Dmint unified monorepo.**

---

## 1. CANONICAL CODEBASE LOCATION

| Location | Purpose |
|---|---|
| **`~/dmint`** | **Primary active codebase. All development, testing, and CI happens here.** |

**All source code, tests, and configuration changes must target `~/dmint`.**

---

## 2. PROJECT MISSION & SCOPE

**Dmint** is a deterministic security authorization and enforcement engine for AI-agent tool calls.

> **The non-negotiable rule:** LLMs NEVER make runtime authorization decisions. Runtime authorization is strictly code- and policy-driven.

### What Dmint Does

```text
AI Agent → Dmint → Tool
```

Every tool call passes through a deterministic policy evaluator before it reaches the protected capability. The result is one of exactly three decisions:

- `ALLOW` — execute the tool
- `DENY` — reject immediately, tool never called
- `APPROVAL_REQUIRED` — persist pending request, return immediately, human approves, host retries

---

## 3. MONOREPO ARCHITECTURE (v2.0.0)

The monorepo lives at `~/dmint` and ships as a **single distribution package** (`dmint v2.0.0`) containing five unified subsystems:

```text
~/dmint
├── src/dmint/                    # Single distribution package
│   ├── core/                     # Deterministic policy engine, SQLite approval store, Ed25519 signing
│   ├── cli/                      # Policy authoring wizards, MCP config generator, skill installer
│   ├── mcp/                      # Multi-integration MCP gateway, stdio/SSE proxy, SSRF filter
│   ├── dashboard/                # Local human approval UI (FastAPI + Jinja2, zero direct SQL)
│   └── skills/                   # Installable skill assets (dmint-policy-manager)
├── tests/                        # Test suites mirroring src/ structure
│   ├── core/
│   ├── cli/
│   ├── mcp/
│   ├── dashboard/
│   └── skills/
├── .agents/                      # AI agent skills for working on this codebase
│   └── skills/
│       ├── dmint-agent-execution/
│       ├── dmint-adversarial-testing/
│       ├── dmint-security/
│       ├── dmint-policy-authoring/
│       ├── dmint-approval-security/
│       └── dmint-authorization/
├── .github/workflows/            # CI, CodeQL, publish
├── pyproject.toml                # Single source of truth for packaging, tooling, versions
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

### Subsystem Inventory

| Subsystem | Module | Entry Point | Role |
|---|---|---|---|
| **Core Engine** | `dmint.core` | Python API | Deterministic authorization, frozen SQLite state machine, Ed25519 signing |
| **CLI** | `dmint.cli` | `dmint` command | Policy authoring wizards, offline validation, skill installer, dashboard launcher |
| **MCP Gateway** | `dmint.mcp` | `dmint-mcp` command | Transparent stdio/SSE proxy, protocol-level enforcement, SSRF defense |
| **Dashboard** | `dmint.dashboard` | `dmint-dashboard` command | Human approval UI — never queries SQLite directly |
| **Skills** | `dmint.skills` | `dmint install-skill` | Installable AI coding assistant skill assets |

---

## 4. DEVELOPMENT OPERATIONS

### Python Environment

Commands can be run using the active virtual environment:

```bash
# Run all tests (always with PYTHONPATH pointing to src/):
PYTHONPATH=src pytest tests/

# Lint (zero warnings allowed):
ruff check .

# Format check:
ruff format --check .

# Type check (all 71 source files must pass):
mypy src/
```

### Test Execution Rules

- **Always run from `~/dmint`** (the monorepo root).
- **Always set `PYTHONPATH=src`** so all `dmint.*` imports resolve correctly.
- **Current baseline:** 971 tests — 971 passed, 0 failed, 0 skipped.
- **Any new code must maintain 0 skipped tests.** The `skipTest()` pattern is banned. If a test depends on a file, that file must exist at the exact path (no fallback logic).

### Pre-commit Hooks

```bash
pre-commit run --all-files
```

Hooks configured in `.pre-commit-config.yaml`:
- **Ruff** — linter + formatter
- **Commitizen** — commit message format enforcement (`fix:`, `feat:`, `chore:`, `docs:`, etc.)

### Mandatory Verification Flow (`FLOW.md`)

All agents and contributors must follow the step-by-step verification checklist in [`FLOW.md`](FLOW.md) after making any code, documentation, or configuration changes before committing.

---

## 5. SECURITY INVARIANTS (NON-NEGOTIABLE)

All code in this monorepo must preserve these five invariants:

1. **Deterministic Fail-Closed Default** — If an agent requests an action not explicitly `ALLOW`-listed, Dmint rejects it (`DENY`) without exception.
2. **Exact Request Binding** — An approval is cryptographically bound to the canonical RFC 8785 + SHA-256 fingerprint of the exact request (tool, action, sorted arguments, environment). Approving `update(id=1)` CANNOT authorize `update(id=2)`.
3. **Single-Use Consumption** — Once consumed, an approval is atomically marked `CONSUMED`. Replaying the same assertion fails closed (`DMT_APPROVAL_CONSUMED`).
4. **Policy Provenance Invalidation** — Modifying `policy.json` changes its SHA-256 digest, automatically invalidating any pending approvals tied to the old policy epoch.
5. **Zero Direct SQL from Dashboard** — The `dmint.dashboard` module never queries the SQLite store directly; all data access goes through `dmint.core`'s public APIs (`list_pending`, `approve_pending`, `reject_pending`).

### Authorization Decisions: Three States Only

```
ALLOW | DENY | APPROVAL_REQUIRED
```

No other states. No probabilistic decisions. No LLM calls in the decision path.

---

## 6. CODE CHANGE RULES

### Never Do
- Run `git init` in `~/dmint` without **explicit** user permission.
- Change, bump, or commit a new version number without **explicit** user permission.
- Use `self.skipTest()` or legacy multi-path fallbacks in any test.
- Add `from dmint.canonicalize import ...` in `dmint.mcp` — always use `from dmint.core.canonicalize import ...` directly.
- Manually write or patch `policy.json` files — all policy creation must go through `dmint-cli`.
- Use an LLM call inside the authorization decision path.
- Implement approval as a blocking poll/sleep — always return immediately and let the host retry.

### Always Do
- Follow the mandatory 6-step verification flow in [`FLOW.md`](FLOW.md) after any edits before proposing commits.
- Assess change severity (Patch/Minor/Major) and suggest the recommended SemVer bump to the user, asking for permission before modifying any version strings.
- Point test subprocess helpers directly to `tests/mcp/mock_server.py` (never via legacy fallback paths).
- Keep `proxy_entrypoint.py` self-contained with `sys.path` setup so it works as a spawned subprocess.
- Match the `PYTHONPATH=src` prefix when running any `pytest` or `mypy` invocation.
- Update `pyproject.toml` as the single source of truth for version (`version = "2.0.0"`).

---

## 7. AI CODING SKILLS FOR THIS CODEBASE

The `.agents/skills/` directory contains specialized prompt skills for agents working on Dmint:

| Skill | When to Activate |
|---|---|
| [`dmint-security`](.agents/skills/dmint-security/SKILL.md) | Implementing or reviewing any authorization, approval, or enforcement code |
| [`dmint-authorization`](.agents/skills/dmint-authorization/SKILL.md) | Designing policies, request models, PDP adapters, or the decision path |
| [`dmint-approval-security`](.agents/skills/dmint-approval-security/SKILL.md) | Working on approval lifecycle, request binding, expiry, replay protection, or atomic consumption |
| [`dmint-adversarial-testing`](.agents/skills/dmint-adversarial-testing/SKILL.md) | Adding security tests, reviewing enforcement code, writing regression tests |
| [`dmint-policy-authoring`](.agents/skills/dmint-policy-authoring/SKILL.md) | Generating `policy.json` or `mcp_protection.json` from developer intent |
| [`dmint-agent-execution`](.agents/skills/dmint-agent-execution/SKILL.md) | Integrating Dmint with AI-agent frameworks, decorators, MCP, or tool-calling pipelines |

> **When in doubt about security-sensitive changes, read `dmint-security` and `dmint-adversarial-testing` first.**

---

## 8. PACKAGE & DISTRIBUTION

```bash
# Clean and rebuild:
python3 -m build --no-isolation

# Validate both wheel and sdist:
twine check dist/*
```

Build artifacts: `dist/dmint-2.0.0-py3-none-any.whl` and `dist/dmint-2.0.0.tar.gz`

---

## 9. VERSION & VERSION BUMPING PROTOCOL

**Current Version: `2.0.0`**

Version is the single source of truth in `pyproject.toml` (`version = "2.0.0"`) and propagated to:
- `src/dmint/version.py`
- `src/dmint/core/__init__.py` (`__version__`)
- All subsystem `__init__.py` files

### Version Severity Guidelines (Semantic Versioning)
When proposing changes, assess severity to recommend the appropriate SemVer bump:
- **Patch (`2.0.0` → `2.0.1`)**: Bug fixes, documentation improvements, test additions, internal refactoring, non-breaking maintenance (`fix:`, `docs:`, `chore:`, `test:`, `refactor:`).
- **Minor (`2.0.0` → `2.1.0`)**: Backwards-compatible features, new CLI commands/flags, new integrations, new capabilities (`feat:`).
- **Major (`2.0.0` → `3.0.0`)**: Incompatible API changes, breaking policy schema modifications, removed public methods (`feat!:`, `fix!:`, `BREAKING CHANGE:`).

### Mandatory User Permission Protocol
> **CRITICAL RULE**: AI agents must NEVER change or bump version numbers silently.
> 
> Always suggest the recommended version to the user with clear rationale based on change severity, and wait for the user's **explicit permission** before updating version strings in `pyproject.toml`, `version.py`, `__init__.py`, or `CHANGELOG.md`.
