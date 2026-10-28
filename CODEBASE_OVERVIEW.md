# Dmint: codebase overview

Snapshot: commit `8e54b57`, 2026-10-27, package version `2.0.4`, Python `>=3.10`.

---

## 1. TL;DR

1. Dmint is a deterministic authorization gate between AI agents and tools — no LLMs in the decision path.
2. The runtime returns exactly three decisions: `ALLOW`, `DENY`, or `APPROVAL_REQUIRED`.
3. Every tool call is canonicalized with RFC 8785 (JCS), SHA-256 fingerprinted, and evaluated against declarative policy.
4. Approvals are Ed25519-signed, bound to the exact request, single-use, and protected by HMAC-SHA256 row integrity.
5. Three integration surfaces share the same core: the Python SDK (`@dmint.protect`), coding-agent hooks (`dmint hook run`), and the MCP gateway (`dmint-mcp`).
6. Storage is SQLite by default or PostgreSQL via `DMINT_DATABASE_URL`; both implement the same approval state machine.
7. Audit events are written as a SHA-256 hash-chained JSONL trail and verified with `dmint logs --verify`.
8. Shadow mode (`--mode shadow` / `DMINT_MODE=shadow`) records would-be blocks without blocking, and `dmint learn-policy` can synthesize a reviewed least-privilege policy from those observations.

---

## 2. Repository map

```text
src/dmint/
├── core/          # Policy engine, canonicalization, approvals, storage, keys, audit, webhooks
├── cli/           # `dmint` command — setup, policy authoring, hooks, logs, demo, approvals, keys
├── mcp/           # `dmint-mcp` command — MCP gateway/proxy, SSRF guard, schema pinning, auth
├── dashboard/     # `dmint-dashboard` command — local human approval UI (no direct SQL)
├── skills/        # Installable AI coding-assistant skill assets
├── templates/     # Built-in policy templates used by the CLI
└── storage/       # Compatibility package for the storage API
```

Top-level compatibility shims (`dmint.canonicalize`, `dmint.enforcement`, `dmint.hashing`) re-export the corresponding `dmint.core` modules. They emit deprecation warnings and are scheduled for removal in v3.0.0.

### Subsystem inventory

| Subsystem | Module | Entry point | Responsibility |
|---|---|---|---|
| Core engine | `dmint.core` | Python API | Deterministic policy evaluation, request binding, approval verification, storage abstraction, audit logging |
| CLI | `dmint.cli` | `dmint` | Project setup, policy authoring/verification, harness hooks, audit inspection, red-team demo, approval/key management |
| MCP gateway | `dmint.mcp` | `dmint-mcp` | Protocol-level enforcement for stdio and Streamable-HTTP MCP servers, SSRF defense, schema pinning |
| Dashboard | `dmint.dashboard` | `dmint-dashboard` | Authenticated local approval UI; all reads/writes go through public core APIs |
| Skills | `dmint.skills` | `dmint install-skill` | Installable policy-manager and coding-agent skill assets |

### Package counts

- 86 Python source files under `src/dmint/`.
- 24 core modules (including the SQLite/PostgreSQL storage layer).
- 24 CLI modules, 12 MCP modules, and 6 dashboard modules.
- 128 test modules under `tests/` (45 core, 41 CLI, 32 MCP, 8 dashboard, 2 skills).
- 70 mutation-testing targets in `scripts/mutation/mutations.json`.

---

## 3. Runtime decision flow

```text
AI agent / host
      │
      │  tool call (tool, action, arguments, resource)
      ▼
Dmint request binding
      │  RFC 8785 JCS + SHA-256 fingerprint
      ▼
Policy.evaluate()
      │  candidate rules → resource validation → argument constraints
      │  precedence: DENY > APPROVAL_REQUIRED > ALLOW > default DENY
      ▼
┌─────────────┬───────────────────────┬──────────────────────────────┐
│   ALLOW     │        DENY           │     APPROVAL_REQUIRED        │
│ execute     │ reject immediately    │ persist pending request,     │
│ tool        │ (tool never called)   │ return immediately, retry    │
└─────────────┴───────────────────────┴──────────────────────────────┘
```

The decision path is a pure function of the request and policy. It performs no network calls, no model calls, and no probabilistic scoring.

`Policy.evaluate()` uses explicit precedence, not first-match ordering:

1. Validate the request resource against every candidate rule; malformed or unnormalizable resources fail closed with `DMT_RESOURCE_INVALID`.
2. Evaluate argument constraints; a constraint failure returns `DENY` with `DMT_CONSTRAINT_VIOLATION`.
3. If any matching rule is `DENY`, the result is `DENY`.
4. Otherwise, if any matching rule is `APPROVAL_REQUIRED`, the result is `APPROVAL_REQUIRED`.
5. Otherwise, if any matching rule is `ALLOW`, the result is `ALLOW`.
6. If no rule matches, the result is `DENY` with `DMT_DEFAULT_DENIED`.

---

## 4. Policy model

A policy is a JSON mapping with:

- `rules` — an array of rule objects.
- `strict_arguments` — optional policy-wide constraint default (`false` by default).
- `tool_schemas` — optional mapping of `<tool>.<action>` capabilities to pinned SHA-256 tool-schema digests.

Each rule supports:

- `effect` — `allow`, `deny`, or `approval_required`.
- `tool` and `action` — capability selectors; `*` is a wildcard.
- `agent_id` — optional principal restriction.
- `resource` and `resource_kind` — `exact`, `path`, `url`, `domain`, `glob`, `any`, or `none`.
- `case_sensitive` — supported for `path` and `exact` resources.
- `conditions` — trusted-context conditions over environment, agent, or other attributes.
- `constraints` — JSON-Schema-like argument validation for `allow` and `approval_required` rules.
- `schema_hash` — optional per-rule SHA-256 pin of the downstream tool schema.

The runtime default is always `deny`. `Policy.from_mapping()` rejects an explicit top-level `default` key; `default` is an invariant of the evaluator, not a configurable switch.

Policies can be authored with `dmint create-policy`, `dmint create-mcp-policy`, the interactive wizard, or `dmint learn-policy`, and are validated offline with `dmint verify-policy`.

---

## 5. Cryptographic invariants

| Invariant | Primitive | Domain / binding |
|---|---|---|
| Request fingerprint | SHA-256 over RFC 8785 JCS canonical request | `b"dmint/request-fingerprint/v2\x00"` |
| Policy digest | SHA-256 over canonical policy content | `b"dmint/policy-digest/v1\x00"` |
| Approval assertion | Ed25519 signature over the canonical assertion envelope | Exact request fingerprint, policy digest, deployment epoch, expiry, issuer |
| Approval row integrity | HMAC-SHA256 over canonical row bytes | `b"dmint/approval-record-integrity/v2\x00"` |
| Audit log chain | SHA-256 over RFC 8785 JCS entry without `entry_hash` | `b"dmint/audit-log/v1\x00"` |
| MCP tool schema pin | SHA-256 over RFC 8785 JCS `{"description": ..., "inputSchema": ...}` | Stored in `policy.json` (`tool_schemas` or rule `schema_hash`) |

The non-negotiable security properties are:

1. **Fail-closed default** — no matching `ALLOW` rule means `DENY`.
2. **Exact request binding** — approving `update(id=1)` cannot authorize `update(id=2)`.
3. **Single-use consumption** — a consumed approval cannot be replayed (`DMT_APPROVAL_CONSUMED`).
4. **Policy provenance invalidation** — changing `policy.json` changes its digest and invalidates approvals tied to the old epoch.
5. **No direct SQL from the dashboard** — all dashboard data access goes through public core APIs.

Additional production defenses:

- Ed25519 private signing keys never need to live on the enforcement host; the gateway only needs the public key.
- The SQLite store maintains a monotonic `store_recovery` counter mirrored to a `0600` `.epoch` sidecar file. A DB-only rollback is detected and fails closed with `ApprovalStoreError` (`DMT_APPROVAL_STORE_ERROR`).
- Audit entries are hash-chained; `dmint logs --verify` detects insertion, reordering, mid-chain deletion, and payload edits.
- Downstream MCP tool definitions are pinned; schema drift fails with `DMT_MCP_SCHEMA_MISMATCH`.

---

## 6. Approval lifecycle and storage

Approval states are `PENDING`, `APPROVED`, `REJECTED`, and `CONSUMED`.

```text
PENDING ──approve──▶ APPROVED ──consume──▶ CONSUMED
   │
   └──reject──▶ REJECTED
```

- **PENDING** is persisted when a policy returns `APPROVAL_REQUIRED`. The host receives the request ID immediately; it does not sleep or block.
- **APPROVED** carries a signed `ApprovalAssertion` bound to the exact request fingerprint, policy digest, deployment epoch, and expiry.
- **CONSUMED** is set atomically during execution. Replaying the same assertion fails closed.
- **REJECTED** records the human decision and optional reason; the request can never be approved later.

Storage backends:

- **SQLite** — default, zero external dependencies, WAL mode, `busy_timeout`, cross-process locking, row HMAC, recovery counter.
- **PostgreSQL** — enabled with `DMINT_DATABASE_URL=postgresql://...`; uses row-level locks (`SELECT ... FOR UPDATE`) for high-concurrency environments.

Both backends implement the same `ApprovalStore` interface, so the policy and approval semantics do not change with the database.

---

## 7. Integration surfaces

### Python SDK

```python
from dmint import Dmint

engine = Dmint.local("policy.json", agent_id="my-agent")


@engine.protect("shell.execute", resource_param="command")
def run(command: str) -> str: ...
```

`Dmint.local()` provisions `.dmint/signing.key` (`0600`), `.dmint/integrity.key` (`0600`), and `.dmint/approvals.sqlite3` automatically. The lower-level `Dmint(...)` constructor accepts explicit stores, verifiers, provenance, clocks, and webhooks.

### Coding-agent hooks

`dmint hook install` writes PreToolUse hooks for Claude Code, Codex, OpenCode, Cursor, Windsurf, and Cline. At runtime, `dmint hook run` normalizes harness payloads, canonicalizes paths, evaluates the harness-specific policy, and returns the harness-native allow/deny/ask response.

Shadow mode is available for rollout:

```bash
dmint hook run --harness claude-code --mode shadow < payload.json
```

### MCP gateway

`dmint-mcp` proxies stdio and Streamable-HTTP MCP servers. It intercepts tool invocations, maps MCP arguments to Dmint requests, enforces policy before forwarding, pins tool schemas, and validates remote endpoints against SSRF and DNS-rebinding attacks.

### Dashboard

`dmint-dashboard` is a local, authenticated FastAPI/Jinja2 UI for pending approvals. It never imports or queries the SQLite/PostgreSQL store directly; it calls `list_pending`, `approve_pending`, and `reject_pending` from `dmint.core`.

---

## 8. Audit logging, shadow mode, and policy learning

`dmint.core.audit` writes structured JSONL events to `.dmint/audit.jsonl` by default (override with `DMINT_AUDIT_LOG` or `DMINT_LOG_FILE`).

Each entry includes sequence number, timestamp, level, event type, decision, error code, harness, agent ID, tool, action, resource, mode, shadow-block flag, approval ID, latency, redacted details, `prev_hash`, and `entry_hash`.

Key commands:

```bash
dmint logs --verify                                  # verify the SHA-256 hash chain
dmint logs --mode shadow --stats                     # shadow-block and decision counts
dmint logs --mode shadow --search DMT_POLICY_DENIED  # inspect would-be blocks
dmint demo                          # 7-scenario red-team simulation
dmint learn-policy --from-logs .dmint/audit.jsonl -o policy.learned.json
dmint doctor                        # keys, store, hooks, policy audit, 4-vector self-test
```

`dmint learn-policy` never learns destructive commands or secret-path access as `ALLOW`; those are emitted as explicit `DENY` rules. Generated policies must still be reviewed and verified before enforcement.

---

## 9. Test and verification summary

The repository uses `unittest`-style tests executed by `pytest`, with no skipped tests allowed.

Baseline verification commands:

```bash
cd ~/dmint
PYTHONPATH=src .venv/bin/pytest -q
ruff check .
ruff format --check .
mypy src/
cd docs && npm run build
```

Current test result: **1,565 passed, 0 failed, 0 skipped** across 128 test modules (run with the PostgreSQL integration test server available).

Mutation testing targets: **70** entries in `scripts/mutation/mutations.json`.

The docs build uses Holocron/Vite. The generated LLM corpus (`docs/public/llms-full.txt`) is produced from `docs/docs.json` navigation by:

```bash
python3 scripts/gen_llms_txt.py
```

Do not hand-edit `docs/public/llms-full.txt`; regenerate it.

---

## 10. Versioning and compatibility

- Current package version: `2.0.4` (`pyproject.toml`, `src/dmint/version.py`, subsystem `__init__.py` files).
- Python support: `>=3.10`.
- Deprecated top-level shims remain until v3.0.0.
- Version bumps require explicit user approval and follow SemVer: patch for fixes/docs, minor for backward-compatible features, major for breaking API/schema changes.
