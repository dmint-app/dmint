# Dmint — PLAIN.md

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

`APPROVAL_REQUIRED` is one of the three authorization decisions; it is not a separate approval system or a fourth authorization state.

---

## 3. HIGH-LEVEL ARCHITECTURE & RESPONSIBILITY MODEL

Dmint is a security enforcement system, not an AI decision-making system.

The central mental model is:

```text
                         ┌─────────────────────┐
                         │      AI Agent       │
                         └──────────┬──────────┘
                                    │ tool call
                                    ▼
                         ┌─────────────────────┐
                         │     Dmint Layer     │
                         │                     │
                         │  integration/MCP    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                    ┌──────────────────────────────┐
                    │         Dmint Core           │
                    │                              │
                    │ Request → Policy → Decision │
                    │                              │
                    │ ALLOW                      │
                    │ DENY                       │
                    │ APPROVAL_REQUIRED          │
                    │                              │
                    │ Approval + Binding + Store  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
             ┌──────────────┐             ┌──────────────┐
             │ MCP / Tool   │             │  Dashboard   │
             │ Downstream   │             │ Human UI     │
             └──────────────┘             └──────────────┘
```

### 3.1 Core Is the Security Authority

`dmint.core` is the authoritative security subsystem.

Core owns:

- request representation and canonicalization;
- policy evaluation;
- authorization decisions;
- approval lifecycle/state machine;
- request fingerprints;
- policy provenance;
- cryptographic approval assertions;
- approval verification;
- atomic approval consumption;
- persistent approval state;
- SQLite storage for the current deployment model.

Core does **not** own MCP protocol semantics, browser/UI behavior, dashboard presentation, or AI-agent UX.

Core must remain usable independently as a Python library.

### 3.2 CLI Responsibility

`dmint.cli` is the developer/operator interface.

The CLI is responsible for:

- creating policy artifacts;
- validating policy/configuration;
- generating MCP protection configuration;
- installing Dmint skills;
- launching supporting Dmint components;
- exposing convenient developer workflows.

The CLI does not independently implement runtime authorization logic.

### 3.3 MCP Responsibility

`dmint.mcp` is an integration and protocol-enforcement layer around Core.

Its responsibility is to:

1. receive MCP requests;
2. authenticate the calling agent where applicable;
3. map MCP requests into Core request models;
4. pass requests to Core for authorization;
5. honor Core's decision;
6. forward only authorized requests to downstream MCP servers;
7. handle approval/retry flows through Core;
8. translate Core results/errors back into MCP responses;
9. provide transport-specific protections such as SSRF validation.

The MCP layer must **not** create a second authorization engine, approval engine, or policy evaluator.

There is exactly one authoritative authorization path:

```text
MCP request
    ↓
Core
    ↓
ALLOW / DENY / APPROVAL_REQUIRED
```

### 3.4 Dashboard Responsibility

`dmint.dashboard` is a human-facing approval interface.

It is responsible for:

- displaying pending approval requests;
- displaying relevant request details;
- allowing the human operator to approve/reject;
- calling Core public APIs for those operations;
- displaying resulting state.

The dashboard must **not**:

- query SQLite directly;
- execute raw SQL;
- create a second approval database;
- implement policy evaluation;
- implement authorization rules;
- create its own approval state machine;
- independently calculate/verify request fingerprints;
- generate approval assertions directly;
- duplicate Core security logic.

The dashboard is a UI over Core, not a second security authority.

### 3.5 Skills Responsibility

`dmint.skills` contains installable guidance/assets for AI coding agents.

Skills may help an AI agent understand Dmint workflows, policies, integration steps, commands, and security-sensitive development practices.

Skills are advisory/instructional.

Skills are **never** a runtime authorization mechanism.

An LLM or skill must never become the runtime authority for whether a tool call is allowed.

### 3.6 Policy Artifact Flow

Policies/configuration are authored and validated through supported developer workflows and then consumed by Dmint runtime components.

```text
Developer intent
      │
      ▼
     CLI
      │
      ├── policy.json
      │
      └── mcp_protection.json
                │
                ▼
          Dmint runtime
                │
                ▼
               Core
                │
                ▼
         policy evaluation
```

Do not duplicate policy semantics in CLI, MCP, Dashboard, or Skills.

### 3.7 Approval Flow

Approval semantics are owned by Core.

```text
Tool request
    │
    ▼
Core policy evaluation
    │
    └── APPROVAL_REQUIRED
            │
            ▼
    persist pending approval
            │
            ▼
    return approval information
            │
            ▼
    human approves/rejects
            │
            ▼
    host retries exact request
            │
            ▼
    Core revalidates request
            │
            ├── invalid/stale/replayed → fail closed
            │
            └── valid → atomic consume
                                      │
                                      ▼
                                  execute tool
```

Do not block a Python thread/process waiting for human approval.

### 3.8 Data Ownership

For the current deployment, Core owns exactly one approval persistence layer:

```text
Core
 └── SQLiteApprovalStore
       ├── pending approvals
       ├── approved approvals
       ├── consumed/rejected state
       ├── policy provenance
       └── approval security state
```

No subsystem should create a second approval database.

SQLite is an implementation detail of Core's persistence layer for the current deployment. Future distributed storage should be introduced behind Core's persistence boundary rather than moving storage logic into MCP or Dashboard.

### 3.9 Dependency Direction

Preferred dependency direction:

```text
CLI ───────────────► Core
MCP ───────────────► Core
Dashboard ─────────► Core
Skills ────────────► developer/agent workflow
```

Core must not depend on:

- MCP;
- Dashboard;
- browser/UI frameworks;
- HTTP server implementation;
- AI/LLM providers.

### 3.10 One Security Decision Path

Correct:

```text
Agent
  ↓
MCP / integration adapter
  ↓
Core
  ↓
Policy evaluation
  ↓
ALLOW / DENY / APPROVAL_REQUIRED
```

Incorrect:

```text
Agent → MCP-specific policy → Core
```

```text
Agent → Dashboard decision logic → Tool
```

```text
Agent → LLM decides → Tool
```

```text
MCP and Core independently evaluate the same authorization request.
```

If a feature requires authorization logic, determine whether it belongs in Core before implementing it elsewhere.

### 3.11 Current Product Boundary

Dmint consists of five cooperating subsystems:

```text
┌────────────────────────────────────────────┐
│                    Dmint                   │
│                                            │
│  Core       → security authority           │
│  CLI        → developer/operator tooling   │
│  MCP        → protocol/integration gateway │
│  Dashboard  → human approval interface     │
│  Skills     → AI-agent workflow guidance   │
│                                            │
└────────────────────────────────────────────┘
```

When implementing a feature, first identify which subsystem owns the responsibility. Do not move functionality into another subsystem merely because it is convenient to implement there.

---

## 4. MONOREPO ARCHITECTURE (v2.0.0)

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
| **CLI** | `dmint.cli` | `dmint` command | Policy authoring wizards, offline validation, MCP config generator, skill installer, dashboard launcher |
| **MCP Gateway** | `dmint.mcp` | MCP runtime | Transparent stdio/SSE/HTTP proxy, protocol-level enforcement, SSRF defense |
| **Dashboard** | `dmint.dashboard` | `dmint-dashboard` command | Human approval UI — never queries SQLite directly |
| **Skills** | `dmint.skills` | `dmint install-skill` | Installable AI coding-assistant skill assets |

---

## 5. END-TO-END RUNTIME FLOWS

### 5.1 ALLOW

```text
AI Agent
   ↓
Integration/MCP
   ↓
Core canonicalization
   ↓
Core policy evaluation
   ↓
ALLOW
   ↓
Downstream tool
   ↓
Result
```

### 5.2 DENY

```text
AI Agent
   ↓
Integration/MCP
   ↓
Core canonicalization
   ↓
Core policy evaluation
   ↓
DENY
   ↓
No downstream call
   ↓
Agent receives denial
```

### 5.3 APPROVAL_REQUIRED

```text
AI Agent
   ↓
Integration/MCP
   ↓
Core canonicalization
   ↓
Core policy evaluation
   ↓
APPROVAL_REQUIRED
   ↓
Core persists pending approval
   ↓
Agent receives approval information
   ↓
Human uses Dashboard / approved authority
   ↓
Core changes approval state
   ↓
Agent/host retries
   ↓
Core revalidates
   ↓
Core atomically consumes approval
   ↓
Downstream tool executes
```

No component should block waiting for human approval.

---

## 6. SECURITY INVARIANTS (NON-NEGOTIABLE)

All code in this monorepo must preserve these five invariants:

1. **Deterministic Fail-Closed Default** — If an agent requests an action not explicitly `ALLOW`-listed, Dmint rejects it (`DENY`) without exception.
2. **Exact Request Binding** — An approval is cryptographically bound to the canonical RFC 8785 + SHA-256 fingerprint of the exact request (tool, action, canonical arguments, trusted context/identity as applicable). Approving `update(id=1)` CANNOT authorize `update(id=2)`.
3. **Single-Use Consumption** — Once consumed, an approval is atomically marked `CONSUMED`. Replaying the same assertion fails closed (`DMT_APPROVAL_CONSUMED`).
4. **Policy Provenance Invalidation** — Modifying `policy.json` changes its SHA-256 digest, invalidating approvals tied to the old policy provenance/epoch.
5. **Zero Direct SQL from Dashboard** — The `dmint.dashboard` module never queries the SQLite store directly; all data access goes through Core public APIs such as `list_pending`, `list_records`, `get`, `approve_pending`, and `reject_pending`.

### Authorization Decisions: Three States Only

```text
ALLOW | DENY | APPROVAL_REQUIRED
```

No other authorization states exist.

No probabilistic decisions.

No LLM calls in the runtime authorization decision path.

---

## 7. APPROVAL STATE OWNERSHIP

Approval state belongs to Core.

Conceptually:

```text
PENDING
   │
   ├── human rejects ─────► REJECTED
   ├── expires ───────────► EXPIRED
   ├── cancel ────────────► CANCELLED
   ├── policy invalidated ► POLICY_INVALIDATED
   └── human approves
          │
          ▼
       APPROVED
          │
          └── valid retry ──► CONSUMED
```

The exact state transition graph in Core is authoritative. Other subsystems must use Core APIs rather than recreating these transitions.

---

## 8. CONFIGURATION & ARTIFACT OWNERSHIP

### `policy.json`

Represents authorization policy consumed by Core.

Policy creation should go through the CLI workflows.

Do not manually patch policy files as a substitute for the supported policy-authoring workflow.

### `mcp_protection.json`

Describes MCP integrations and protection configuration consumed by the MCP runtime.

The CLI is responsible for generating and validating this artifact.

MCP should consume the artifact; it should not redefine policy semantics.

### Runtime Relationship

```text
mcp_protection.json ──► MCP integration configuration
policy.json ───────────► Core policy evaluation
```

The two concerns must remain distinct.

---

## 9. DEVELOPMENT OPERATIONS

### Python Environment

Commands can be run using the active virtual environment:

```bash
# Run all tests (always from ~/dmint with PYTHONPATH pointing to src):
PYTHONPATH=src pytest tests/

# Lint (zero warnings allowed):
ruff check .

# Format check:
ruff format --check .

# Type check:
mypy src/
```

### Test Execution Rules

- **Always run from `~/dmint`** (the monorepo root).
- **Always set `PYTHONPATH=src`** when running pytest/mypy commands that need explicit source resolution.
- Current baseline: **971 tests — 971 passed, 0 failed, 0 skipped**.
- Any new code must maintain 0 skipped tests.
- The `skipTest()` pattern is banned.
- If a test depends on a file, that file must exist at the exact expected path (no fallback logic).
- Do not introduce legacy multi-path fallback behavior.

### Pre-commit Hooks

```bash
pre-commit run --all-files
```

Hooks configured in `.pre-commit-config.yaml`:

- **Ruff** — linter + formatter
- **Commitizen** — commit message format enforcement (`fix:`, `feat:`, `chore:`, `docs:`, etc.)

---

## 10. CODE CHANGE RULES

### Never Do

- Run `git init` in `~/dmint` without **explicit** user permission.
- Use `self.skipTest()` or legacy multi-path fallbacks in tests.
- Add `from dmint.canonicalize import ...` in `dmint.mcp`; always use `from dmint.core.canonicalize import ...` directly.
- Manually write or patch `policy.json` files; all policy creation must go through `dmint-cli`.
- Use an LLM call inside the authorization decision path.
- Implement approval as a blocking poll/sleep — always return immediately and let the host retry.
- Create a second approval database in Dashboard or MCP.
- Put authorization/policy semantics into MCP or Dashboard merely for convenience.
- Bypass Core public APIs to reach its private state or database.
- Trust client-supplied identity when a stronger authenticated/immutable identity exists.

### Always Do

- Point test subprocess helpers directly to `tests/mcp/mock_server.py`.
- Keep `proxy_entrypoint.py` self-contained with `sys.path` setup so it works as a spawned subprocess.
- Match the `PYTHONPATH=src` prefix when running pytest/mypy invocations that require it.
- Treat `pyproject.toml` as the single source of truth for version (`version = "2.0.0"`).
- Use Core public APIs from Dashboard.
- Preserve exact request binding and fail-closed behavior.
- Run the complete relevant test suite after security-sensitive changes.

---

## 11. MCP-SPECIFIC ARCHITECTURE

The MCP subsystem is an adapter around Core.

```text
MCP Client / AI Agent
        │
        ▼
Agent-facing MCP transport
        │
        ▼
Authentication / identity binding
        │
        ▼
MCP request mapping
        │
        ▼
Dmint Core
        │
        ├── ALLOW ──────────────► downstream MCP server
        ├── DENY
        └── APPROVAL_REQUIRED
                 │
                 ▼
             Dashboard / approval authority
                 │
                 ▼
             Core retry/revalidation
                 │
                 ▼
             downstream MCP server
```

### MCP Must Not

- independently decide authorization;
- maintain an independent approval state machine;
- trust agent-supplied identity;
- bypass Core on retries;
- execute downstream calls before Core authorization;
- treat hidden tools as authorized merely because they are hidden.

### MCP May Own

- MCP protocol parsing/serialization;
- transport handling;
- agent authentication;
- MCP-to-Core request mapping;
- downstream server routing;
- transport-specific security such as SSRF validation;
- protocol error translation.

---

## 12. DASHBOARD-SPECIFIC ARCHITECTURE

The Dashboard is intentionally simple.

```text
Browser
   │
   ▼
Dashboard HTTP server
   │
   ▼
Core public API
   │
   ▼
SQLiteApprovalStore
```

The Dashboard must not directly access SQLite.

For the current local/demo deployment, use server-rendered templates, Bootstrap UI, and lightweight client-side refresh/polling where needed. WebSockets, SSE, Redis/pub-sub, event buses, or other complex realtime infrastructure are not required for the current V1/V2 demo architecture.

### Dashboard Data/Approval APIs

Dashboard should use Core public APIs, including where applicable:

```python
store.list_pending()
store.list_records(...)
store.get(approval_id)
store.approve_pending(...)
store.reject_pending(...)
```

The dashboard passes only the minimum human-operation inputs. Core derives and validates security-sensitive fields from the stored record.

### Dashboard UI

The dashboard may use:

- FastAPI;
- Jinja2/server-rendered templates;
- Bootstrap;
- vanilla JavaScript;
- simple 5-second client-side polling for fresh dashboard data.

It does not need to become a separate frontend application.

---

## 13. SKILLS & AI-AGENT INTEGRATION

Skills exist to guide AI coding agents and developers.

They may describe:

- how to create policies;
- how to configure integrations;
- how to use Dmint;
- how to test protected tool calls;
- how to follow security invariants.

They must never be treated as a runtime security boundary.

The runtime must remain safe even if an AI agent:

- ignores the skill;
- misunderstands the skill;
- sends malformed arguments;
- attempts identity injection;
- attempts approval replay;
- attempts argument tampering.

Security comes from Core and deterministic enforcement, not agent compliance.

---

## 14. AI AGENT DEVELOPMENT GUIDANCE

Before changing code, determine:

1. What responsibility is being changed?
2. Which subsystem owns that responsibility?
3. Does the change affect Core security invariants?
4. Can the feature be implemented using an existing Core public API?
5. Would this introduce duplicated policy/authorization logic?
6. Does the change require a new Core public API instead?

### Preferred Decision Process

```text
Feature request
      │
      ▼
Identify responsibility
      │
      ├── Authorization/security semantics? → Core
      ├── Developer/operator workflow? → CLI
      ├── MCP protocol/transport? → MCP
      ├── Human approval presentation? → Dashboard
      └── AI-agent guidance? → Skills
```

If the requested feature crosses subsystem boundaries, preserve the ownership model rather than moving the responsibility into whichever subsystem is easiest to modify.

### Before Implementing a Security-Sensitive Feature

- Read the relevant `.agents/skills/*` security guidance.
- Inspect existing public Core APIs before creating new ones.
- Prefer extension over duplication.
- Preserve existing tests and security invariants.
- Add adversarial tests for new attack surfaces.
- Do not accept an AI-generated rationale as evidence that a security boundary is safe; verify behavior in code/tests.

---

## 15. SECURITY REVIEW CHECKLIST

For any authorization/approval-related change, verify:

### Request Integrity

- Is the request canonicalized?
- Is the exact request fingerprint preserved?
- Can arguments be changed after authorization?
- Can identity be injected through tool arguments?

### Policy

- Is policy evaluation performed by Core?
- Is default-deny preserved?
- Are deny-overrides semantics preserved?
- Are policy provenance checks preserved?

### Approval

- Is the approval bound to the exact request?
- Is expiry checked?
- Is policy staleness checked?
- Is the approval single-use?
- Is consumption atomic?
- Can the approval be replayed?
- Can another agent consume it?

### Runtime

- Does DENY result in zero downstream calls?
- Does APPROVAL_REQUIRED result in zero downstream calls?
- Does only a valid ALLOW or approved retry reach the downstream tool?
- Do downstream failures fail cleanly?
- Are timeouts bounded where applicable?

### Architecture

- Is there any duplicated authorization logic?
- Is Dashboard bypassing Core?
- Is MCP bypassing Core?
- Is a new approval database being introduced unnecessarily?
- Is an LLM being inserted into the authorization path?

---

## 16. AI-AGENT RULES FOR POLICY & CONFIGURATION

- Policy creation belongs to the CLI workflows.
- Do not hand-edit generated `policy.json` or `mcp_protection.json` as a substitute for supported commands.
- When a configuration artifact is generated by CLI, verify it against the actual runtime schema before changing consumers.
- Never silently invent fields because they are convenient for documentation or tooling.
- If docs and runtime disagree, verify the runtime/source of truth first.
- If a runtime public API is genuinely missing, prefer adding the smallest public Core API over bypassing Core internals.

---

## 17. TESTING & RELEASE DISCIPLINE

For changes that touch only one subsystem, run that subsystem's tests first, then the full cross-subsystem suite when the change crosses a boundary.

Minimum expectations for security-sensitive changes:

```text
unit tests
+ integration tests
+ adversarial/regression tests
+ full relevant suite
```

Do not consider a feature complete merely because a happy-path test passes.

Before release, verify:

- tests pass with zero skips;
- package builds cleanly;
- installed package works in a clean environment where practical;
- version is sourced from `pyproject.toml`;
- documentation matches the released API/CLI behavior;
- git working tree is clean;
- unrelated repositories are untouched.

---

## 18. PACKAGE & DISTRIBUTION

```bash
# Clean and rebuild:
python3 -m build --no-isolation

# Validate both wheel and sdist:
twine check dist/*
```

Build artifacts:

```text
dist/dmint-2.0.0-py3-none-any.whl
dist/dmint-2.0.0.tar.gz
```

---

## 19. VERSION

**Current Version: `2.0.0`**

Version is the single source of truth in `pyproject.toml`:

```toml
version = "2.0.0"
```

and is propagated to:

- `src/dmint/version.py`;
- `src/dmint/core/__init__.py`;
- subsystem `__init__.py` files where applicable.

Do not update one copied version string while leaving `pyproject.toml` inconsistent.

---

## 20. CURRENT BASELINE

The current unified monorepo baseline is:

```text
Dmint v2.0.0

Core
 └── deterministic authorization + approval security

CLI
 └── policy/configuration/developer workflows

MCP
 └── protocol gateway + downstream enforcement

Dashboard
 └── human approval UI through Core

Skills
 └── AI-agent guidance
```

The architectural priority is:

```text
                 SECURITY AUTHORITY
                       CORE
                        │
          ┌─────────────┼─────────────┐
          │             │             │
         CLI            MCP       Dashboard
          │             │             │
          └─────────────┼─────────────┘
                        │
                      Skills
                (agent guidance only)
```

**Core remains the authoritative security boundary.**

Any future subsystem must integrate with Core rather than creating an alternative authorization, approval, or persistence mechanism.

---

## 21. WHEN IN DOUBT

Use this decision order:

```text
1. Is this authorization/security semantics?
   → Core

2. Is this policy/configuration/developer workflow?
   → CLI

3. Is this MCP protocol/transport/routing?
   → MCP

4. Is this human approval presentation?
   → Dashboard

5. Is this AI-agent instruction/guidance?
   → Skills

6. Does the proposed solution create a second security authority,
   approval system, or database?
   → Stop and redesign around Core.
```

The primary architectural rule is:

> **Dmint Core is the security authority. Everything else integrates with it.**
