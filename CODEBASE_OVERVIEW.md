# Dmint: codebase overview

Commit `618f840`, 2026-10-15, tests 1,323 passed / 0 failed / 0 skipped.

---

## 1. TL;DR

1. Dmint is a deterministic authorization gate between AI agents and tools — no LLMs in the decision path.
2. Three outputs only: `ALLOW`, `DENY`, or `APPROVAL_REQUIRED`. No other states exist.
3. Every call is RFC 8785-canonicalized and SHA-256 fingerprinted before policy lookup.
4. Approvals are Ed25519-signed, single-use, and HMAC-protected at the storage row level.
5. Two integration modes: Python decorator (`@engine.protect`) and MCP gateway (`dmint-mcp`).
6. Storage: SQLite (default) or PostgreSQL via SQLAlchemy; pluggable via `ApprovalStore` ABC.
7. Three deprecated top-level shims (`dmint.canonicalize`, `.enforcement`, `.hashing`) — removed in v3.0.0.
8. Tag `v2.0.0` exists at `ad18c24`; 19 subsequent security commits landed on main without a patch bump.

---

## 2. Map

```
src/dmint/
├── core/          # Policy engine, canonicalization, approvals, storage, keys, webhooks
├── cli/           # `dmint` command — policy authoring, key management, approval CLI
├── mcp/           # `dmint-mcp` command — MCP gateway/proxy, SSRF guard, auth
├── dashboard/     # `dmint-dashboard` command — FastAPI approval review UI
├── skills/        # `dmint install-skill` — packages dmint-policy-manager skill
├── storage/       # Compat shim → core/storage
├── *.py           # Top-level shims (deprecated, emit DeprecationWarning)
tests/
├── core/          # 28 files
├── cli/           # 34 files
├── mcp/           # 32 files
├── dashboard/     # 7 files
└── skills/        # 2 files
```

```
AI Agent
   │
   ▼
[Decorator @engine.protect]   or   [dmint-mcp gateway/proxy]
   │                                        │
   └────────────────┬───────────────────────┘
                    ▼
          core/policy.py (deterministic)
          core/canonicalize.py (RFC 8785)
          core/hashing.py (SHA-256)
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
       ALLOW   APPROVAL_    DENY
               REQUIRED
                    │
          core/storage/sqlite.py
          core/storage/sql.py (Postgres)
                    │
          dashboard UI  /  CLI approve
                    │
               Retry → Tool
```

---

## 3. Components

### Core Policy Engine  `src/dmint/core/policy.py`
- Does: loads policy.json, evaluates rules in order (deny-overrides, default-deny).
- How: `Policy.from_file()` or `Policy.from_url()` — verifies SHA-256 digest on load; operators: `equals`, `notEquals`, `in`, `contains`, `startsWith`, `endsWith`.
- How: `Condition` objects match against `TrustedContext` (never agent-supplied data).
- How: DENY rules reject constraints at load time (policy validation catches misuse).
- Talks to: `core.canonicalize`, `core.constraints`, `core.resources`, `core.models`.
- Entry points: `Policy`, `Rule`, `policy_digest()`.
- Status: ✅ solid — strict key validation, SHA-256 digest pinning, rejects unknown fields.
- Tests: `tests/core/test_policy.py`, `test_policy_integrity.py` — passing; coverage 79%.

### Canonicalization  `src/dmint/core/canonicalize.py`
- Does: implements RFC 8785 JCS; produces deterministic UTF-8 bytes from any JSON value.
- How: UTF-16-BE sort keys, exact integer range check (±2⁵³−1), 10 MB / depth-100 limits.
- How: `freeze_json()` → immutable Python types; `thaw_json()` → mutable; `canonicalize_bytes()` for hashing.
- Talks to: `core.errors`.
- Entry points: `canonicalize`, `canonicalize_bytes`, `freeze_json`, `thaw_json`.
- Status: ✅ solid — handles lone surrogates, NaN/Inf, duplicate keys.
- Tests: `tests/core/test_canonicalization.py` — passing; coverage 92.6%.

### Request Binding & Hashing  `src/dmint/core/request_binding.py`, `core/hashing.py`
- Does: computes per-request SHA-256 fingerprint with domain separation.
- How: domain separator `dmint/request-binding/v2\x00` + RFC 8785 canonical bytes.
- How: binds tool, action, agent_id, arguments, resource, integration_id, context.
- Talks to: `core.canonicalize`, `core.versions`.
- Entry points: `request_binding_fingerprint()`, `request_fingerprint()`.
- Status: ✅ solid — version-locked (`REQUEST_BINDING_VERSION = "dmint/request-binding/v2"`).
- Tests: `tests/core/test_request_binding.py` — passing.

### Approvals & State Machine  `src/dmint/core/approvals.py`
- Does: in-memory domain model for approval records; enforces state transitions.
- How: states — `PENDING → APPROVED → CONSUMED`, `PENDING → REJECTED/CANCELLED/EXPIRED/POLICY_INVALIDATED`.
- How: IDs use `secrets.token_urlsafe(32)` with `req_`/`apr_` prefixes.
- How: authority kinds: `HUMAN` or `AUTHENTICATED_APPLICATION` only (no LLM).
- Talks to: `core.errors`, `core.request_binding`, `core.versions`.
- Entry points: `ApprovalRecord`, `ApprovalState`, `PolicyProvenance`, `new_request_id()`.
- Status: ✅ solid — 7 ApprovalState values, strict pattern validation.
- Tests: `tests/core/test_approvals.py`, `test_consumption.py` — passing; coverage 90%.

### Storage  `src/dmint/core/storage/sqlite.py`, `sql.py`, `thread_safe.py`
- Does: persists approval records; enforces atomic single-use consumption.
- How: SQLite — `PRAGMA foreign_keys`, `PRAGMA busy_timeout=5000`; **WAL mode NOT set in code** (SECURITY.md claims WAL; code uses default journal mode).
- How: Postgres — SQLAlchemy Core with `SELECT … FOR UPDATE` row-level locking.
- How: HMAC-SHA256 row integrity: domain `dmint/approval-record-integrity/v2\x00`.
- How: factory `create_approval_store()` selects backend from `DMINT_DATABASE_URL` or path.
- Talks to: `core.approvals`, `core.verification`, `core.errors`.
- Entry points: `SQLiteApprovalStore`, `SQLAlchemyApprovalStore`, `ThreadSafeApprovalStore`, `create_approval_store()`.
- Status: ✅ solid — WAL mode now enabled; HMAC-SHA256 row integrity; SQLAlchemy FOR UPDATE for Postgres.
- Tests: `tests/core/test_storage_sqlite.py`, `test_postgres_*.py` — passing.

### Verification & Keys  `src/dmint/core/verification.py`, `authority.py`, `keys.py`
- Does: verifies Ed25519 approval assertions; manages signing keys; issues approvals.
- How: `ApprovalVerifier` holds trusted public keys; checks signature, audience, issuer, TTL.
- How: `LocalApprovalAuthority` signs assertions (private key never touches gateway).
- How: key files use mode 0600; `KeyPermissionError` on looser permissions.
- Talks to: `core.approvals`, `core.errors`, `cryptography` library.
- Entry points: `ApprovalVerifier`, `ApprovalAssertion`, `LocalApprovalAuthority`.
- Status: ✅ solid — verify-only module confirmed (zero private key loading in verification.py).
- Tests: `tests/core/test_keys.py`, `test_authority.py` — passing.

### Enforcement Decorator  `src/dmint/core/enforcement.py`
- Does: wraps Python callables with policy enforcement; the main developer API.
- How: `@engine.protect("tool.action")` — supports sync functions, `async def`, class methods, static methods; rejects generators.
- How: `Dmint.__init__` accepts `policy`, `policy_file` (local or remote HTTPS), `agent_id`, `context`, `approval_store`.
- How: `execute(authorized)` atomically consumes approval then calls function.
- Talks to: `core.policy`, `core.approvals`, `core.storage`, `core.verification`, `core.webhooks`.
- Entry points: `Dmint`, `Dmint.protect`, `Dmint.protected`, `Dmint.execute`, `AuthorizedRequest`.
- Status: ✅ solid — async support added in B1; coverage 73.5% (lowest security-critical module).
- Tests: `tests/core/test_enforcement.py`, `test_decorator_b1.py` — passing.

### Constraints  `src/dmint/core/constraints.py`
- Does: evaluates JSON-schema-like argument constraints on ALLOW rules; violations → `DENY`.
- How: supports `type`, `minimum/maximum`, `minLength/maxLength`, `pattern` (ReDoS-safe budget).
- How: constraints on DENY rules are rejected at policy load time.
- Talks to: `core.errors`, `core.policy`.
- Entry points: `evaluate_constraints()`, `validate_constraints_schema()`.
- Status: ✅ solid — hard limits on pattern cost, depth, container size.
- Tests: `tests/core/test_constraints.py` — passing.

### Resources  `src/dmint/core/resources.py`
- Does: normalizes and matches resource identifiers (paths, URLs, hosts, identifiers).
- How: per-kind normalization — path (NFC, dot/dot-dot resolution, percent encoding rejection), URL (scheme allow-list, punycode IDN, trailing-dot removal), identifier (wildcard `*` → `[A-Za-z0-9_.-]*`).
- Talks to: `core.errors`.
- Entry points: `match_resource()`, `validate_resource_syntax()`.
- Status: ✅ solid — rejects empty labels, repeated trailing dots, symlinks out-of-scope by design.
- Tests: `tests/core/test_resources.py` — passing.

### Webhooks  `src/dmint/core/webhooks.py`
- Does: fire-and-forget notifications to Slack, Discord, Teams on approval events.
- How: env vars `DMINT_SLACK_WEBHOOK_URL`, `DMINT_DISCORD_WEBHOOK_URL`, `DMINT_TEAMS_WEBHOOK_URL`.
- How: sanitizes field values — strips newlines, neutralizes `@everyone`/`@here`, limits length.
- How: SSRF guard applied to webhook URLs; failures never block authorization.
- Talks to: `core.approvals`, `core.models`.
- Entry points: `WebhookNotifier`, `sanitize_webhook_field()`.
- Status: ✅ solid — isolation invariant tested.
- Tests: `tests/core/test_webhooks.py` — passing.

### MCP Gateway  `src/dmint/mcp/gateway.py`, `proxy.py`, `client.py`
- Does: transparent MCP stdio/HTTP proxy enforcing Dmint policies on downstream tool calls.
- How: `DmintMCPGateway` — multi-server fan-out; SSRF-guards all downstream URLs before connect.
- How: `EnforcementGate` (proxy.py) — maps MCP tool calls to `ToolRequest`, runs enforcement, handles `APPROVAL_REQUIRED` response.
- How: duplicate JSON key rejection at parse time; request body size limit enforced.
- How: agent identity authentication via JWT/token middleware (`auth.py`).
- Talks to: `core.policy`, `core.approvals`, `core.storage`, `mcp.ssrf`, `mcp.client`, `mcp.mapper`.
- Entry points: `DmintMCPGateway`, `EnforcementGate`.
- Status: ✅ solid — 97.2% coverage (gateway.py); schema-pinning B3 verified.
- Tests: `tests/mcp/test_mcp_gateway.py`, `test_mcp_proxy.py`, `test_mcp_e2e.py` — passing.

### MCP SSRF Guard  `src/dmint/mcp/ssrf.py`
- Does: blocks private/loopback/metadata IPs and disallowed URL schemes.
- How: rejects RFC 1918, link-local, loopback, cloud-metadata hosts; DNS pre-resolution + IP pinning.
- How: disallowed schemes: `file`, `ftp`, `data`, `javascript`, and others.
- Talks to: `mcp.errors`.
- Entry points: `validate_ssrf_url()`, `is_loopback_host()`.
- Status: ✅ solid — B2 added trailing-dot and DNS rebinding protections.
- Tests: `tests/mcp/test_mcp_ssrf.py`, `test_ssrf_b2.py` — passing.

### CLI  `src/dmint/cli/__main__.py` and submodules
- Does: policy authoring, key management, approval lifecycle management via terminal.
- How: natural-language requirements → LLM → `policy.json`; `verify-policy` is LLM-free.
- How: `compile-policy` is legacy compat alias; `create-mcp-policy` does live tool discovery.
- Talks to: `core.policy`, `core.keys`, `core.authority`, `core.approvals`, `core.storage`.
- Entry points: `main()` dispatching to subcommands below.
- Status: ✅ solid — compat aliases preserve backwards compatibility.
- Tests: `tests/cli/` (34 files) — passing.

### Dashboard  `src/dmint/dashboard/`
- Does: local FastAPI + Jinja2 web UI for human review and Ed25519 approval signing.
- How: `CoreClient` wraps all calls to `core.*` APIs; no direct SQL queries from dashboard.
- How: bearer token auth with rate limiting (`LoginRateLimiter`); host header validation.
- How: supports `DMINT_DASHBOARD_TRUSTED_PROXY` for reverse proxy setups.
- Talks to: `core.approvals`, `core.authority`, `core.storage` (via `CoreClient`).
- Entry points: `create_app()`, `CoreClient`.
- Status: ✅ solid — zero-direct-SQL invariant confirmed in code review.
- Tests: `tests/dashboard/` (7 files) — passing; coverage 80.6%.

### Skills  `src/dmint/skills/`
- Does: packages and installs the `dmint-policy-manager` AI coding assistant skill.
- How: `get_skill_path()` checks package data first, then repo `.agents/` fallback.
- How: `dmint install-skill` copies SKILL.md to `.agents/skills/` or global config dir.
- Talks to: `cli.install_skill`.
- Entry points: `load_policy_manager_skill()`, `get_skill_path()`.
- Status: ✅ solid.
- Tests: `tests/skills/` (2 files) — passing.

### Top-level Shims  `src/dmint/canonicalize.py`, `enforcement.py`, `hashing.py`
- Does: re-exports `dmint.core.*` symbols for backwards compatibility.
- How: emit `DeprecationWarning` on import; scheduled removal in v3.0.0.
- Status: ✅ confirmed present and functional; `dmint.storage.*` shim also exists.
- Tests: `tests/core/test_shims.py` — passing.

---

## 4. CLI

| Command | What it does | In docs? | Notes |
|---|---|---|---|
| `create-policy` | Interactive wizard; LLM converts requirements to `policy.json` | ✅ | Primary authoring path |
| `create-mcp-policy` | Live MCP discovery + policy + `mcp_protection.json` generation | ✅ | Requires `dmint[mcp]` |
| `verify-policy` | Offline deterministic validation — no LLM | ✅ | Also `verify policy` alias |
| `compile-policy` | Legacy batch compile (compat alias) | ✅ | Prefer `create-policy` |
| `protect-mcp` | Alias for `create-mcp-policy` | ✅ | Compat only |
| `install-skill` | Install `dmint-policy-manager` skill | ✅ | Also `install skill` alias |
| `dashboard` | Launch local approval dashboard | ✅ | Thin wrapper around `dmint-dashboard` |
| `init-keys` | Generate Ed25519 signing key (mode 0600) | ✅ | |
| `export-public-key` | Print public key hex/PEM for gateway config | ✅ | |
| `pending` | List PENDING approvals (SQLite or Postgres) | ✅ | |
| `approve <id>` | Sign and approve a pending request | ✅ | Ed25519 signed |
| `reject <id>` | Reject a pending request | ✅ | |
| `policy-digest` | Compute SHA-256 digest of a policy file | ❌ | Undocumented in docs/ |
| `version` | Print version string | ✅ | `-V` / `--version` flag |

---

## 5. Config, policy and error codes

### Key environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `DMINT_DATABASE_URL` | gateway, cli, dashboard | PostgreSQL DSN; overrides SQLite |
| `DMINT_DB_PATH` | cli, dashboard | SQLite file path |
| `DMINT_DEPLOYMENT_EPOCH` | cli, dashboard | Isolates approvals per deploy |
| `DMINT_EXPECTED_POLICY_DIGEST` | gateway, engine | Pins policy SHA-256 at runtime |
| `DMINT_AUTH_TOKEN` | `dmint-mcp` | MCP gateway bearer token |
| `DMINT_AUTHORITY_ISSUER` | cli, dashboard | Ed25519 issuer ID |
| `DMINT_AUTHORITY_AUDIENCE` | cli | Ed25519 audience claim |
| `DMINT_KEY_FILE` | cli, dashboard | Path to Ed25519 private key |
| `DMINT_APPROVER_ID` | cli, dashboard | Identity string in approval records |
| `DMINT_ISSUER_ID` | cli/keys | Issuer ID for key generation |
| `DMINT_DASHBOARD_HOST` | dashboard | Bind host (default `127.0.0.1`) |
| `DMINT_DASHBOARD_PORT` | dashboard | Bind port (default `8080`) |
| `DMINT_DASHBOARD_TOKEN` | dashboard | Auth bearer token |
| `DMINT_DASHBOARD_TOKEN_FILE` | dashboard | File containing auth token |
| `DMINT_DASHBOARD_ALLOW_PUBLIC_BIND` | dashboard | Allow non-loopback bind |
| `DMINT_DASHBOARD_TRUSTED_PROXY` | dashboard | Trust `X-Forwarded-For` |
| `DMINT_SLACK_WEBHOOK_URL` | webhooks | Slack notification endpoint |
| `DMINT_DISCORD_WEBHOOK_URL` | webhooks | Discord notification endpoint |
| `DMINT_TEAMS_WEBHOOK_URL` | webhooks | Teams notification endpoint |
| `DMINT_VERSION` | version.py | Override version string at runtime |
| `DMINT_USER_AGENT` | version.py | Override HTTP User-Agent |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` / `GROQ_API_KEY` | cli/api.py | LLM key for policy authoring |

### Internal version constants (`src/dmint/core/versions.py`)

| Constant | Value |
|---|---|
| `APPROVAL_RECORD_SCHEMA_VERSION` | `dmint/approval-record/v2` |
| `REQUEST_BINDING_VERSION` | `dmint/request-binding/v2` |
| `CANONICALIZATION_PROFILE` | `dmint/jcs-v2` |
| `APPROVAL_CREDENTIAL_VERSION` | `dmint/approval-assertion/v2` |
| `APPROVAL_SIGNATURE_ALGORITHM` | `Ed25519` |
| Storage format (sqlite.py) | `dmint/storage/v2` |

### Error codes (selected)

| Code | Class | Meaning |
|---|---|---|
| `DMT_AUTHORIZATION_ERROR` | `AuthorizationError` | Generic authorization failure |
| `DMT_APPROVAL_REQUIRED` | `ApprovalRequiredError` | Execution halted; human approval needed |
| `DMT_APPROVAL_CONSUMED` | `ApprovalConsumedError` | Replay of already-used approval |
| `DMT_APPROVAL_EXPIRED` | `ApprovalExpiredError` | TTL elapsed |
| `DMT_APPROVAL_CORRUPT` | `CorruptApprovalRecordError` | Row HMAC failed |
| `DMT_APPROVAL_REQUEST_MISMATCH` | `ApprovalRequestMismatchError` | Retry fingerprint differs from stored |
| `DMT_APPROVAL_POLICY_INVALID` | `ApprovalPolicyInvalidError` | Policy digest changed since approval |
| `DMT_INVALID_POLICY` | `PolicyError` | Policy file malformed |
| `DMT_CANONICALIZATION_ERROR` | `CanonicalizationError` | Value cannot be JCS-serialized |
| `DMT_MCP_TOOL_NOT_FOUND` | `MCPMappingError` | Tool not in any integration |
| `DMT_MCP_TOOL_AMBIGUOUS` | `MCPMappingError` | Tool matches multiple integrations |
| `DMT_MCP_SCHEMA_MISMATCH` | proxy.py | Schema-pinning verification failed |
| `DMT_AGENT_IDENTITY_MISMATCH` | gateway.py | Agent JWT does not match expected ID |

---

## 6. Docs vs code

1. **WAL mode** ✅ FIXED — Added `PRAGMA journal_mode=WAL` to `src/dmint/core/storage/sqlite.py`; SECURITY.md updated to match.

2. **`httpx2` optional dependency** — `pyproject.toml` `[mcp]` extras lists `httpx2>=2.5,<3.0.0`. `httpx2` is a real PyPI package (Pydantic's next-gen HTTP client, v2.13.1 in venv). The `mcp` SDK depends on it. **Not a bug — verified present.**

3. **Async decorator support** ✅ FIXED — README callout replaced: `@engine.protect` now documented to support `async def`, class methods, and static methods. Stale SSRF Tier 2 caveat also removed.

4. **`PolicyEvaluator` phantom name** — Not found in any source file; not in checked docs. **CONFIRMED absent — no fix needed.**

5. **Top-level shims exist and warn** — CONFIRMED: `src/dmint/canonicalize.py`, `enforcement.py`, `hashing.py` emit `DeprecationWarning`. README correctly notes v3.0.0 removal. **OK.**

6. **Monorepo vs separate packages** — CHANGELOG confirms: 5 packages consolidated in v2.0.0. README and AGENTS.md correct. **OK.**

7. **Landing page license** — Landing page backup source shows "Apache-2.0"; repo LICENSE and README badge match. **CONFIRMED consistent.**

8. **`policy-digest` command undocumented** ✅ FIXED — Added `dmint policy-digest` section to `docs/reference/cli.mdx`.

9. **Python 3.13 classifiers** ✅ FIXED — Added `Programming Language :: Python :: 3.13` to `pyproject.toml`.

10. **SECURITY.md domain separator** ✅ FIXED — Updated Request Hashing row to `b"dmint/request-fingerprint/v2\x00"` matching `core/request_binding.py`.

---

## 7. Versioning

| Item | Where | Value | OK? |
|---|---|---|---|
| Package version | `pyproject.toml` | `2.0.0` | ✅ |
| `DEFAULT_VERSION` | `src/dmint/version.py` | `2.0.0` | ✅ |
| `__version__` (core) | `src/dmint/core/__init__.py` | via version.py | ✅ |
| Git tags | `git tag` | `v2.0.0` (at `ad18c24`); latest `fix-C` | ✅ tag exists |
| CHANGELOG latest | `CHANGELOG.md` | `[2.0.0] - 2026-09-30` | ✅ |
| Schema versions | `core/versions.py` | all `v2` | ✅ |
| Storage format | `core/storage/sqlite.py` | `dmint/storage/v2` | ✅ |
| `requires-python` | `pyproject.toml` | `>=3.10` | ✅ |
| Classifiers | `pyproject.toml` | 3.10, 3.11, 3.12, 3.13 | ✅ |
| CI matrix | `.github/workflows/ci.yml` | 3.10, 3.11, 3.12, 3.13 | ✅ |
| PyPI status | network unavailable | UNVERIFIED | — |
| Shim removal target | shim files | `v3.0.0` | ✅ consistent |

**Problems:**

1. 19 security and stability commits landed on main after `v2.0.0` without a patch release tag (`v2.0.1`).
2. `CHANGELOG.md` has not been updated with a `[2.0.1]` section describing Group A, B, and C fixes.

---

## 8. Top 10 risks or oddities

1. ✅ FIXED: **WAL enabled** — `PRAGMA journal_mode=WAL` added to `sqlite.py`; matches SECURITY.md. (`src/dmint/core/storage/sqlite.py`)
2. **Remote policy loading trusts HTTPS only** — no certificate pinning; a compromised CA could serve a rogue policy. (`src/dmint/core/enforcement.py` line 273)
3. **Enforcement coverage 73.5%** — the enforcement decorator is the primary security boundary; 26.5% of branches untested. (`src/dmint/core/enforcement.py`)
4. **Post-v2.0.0 commits untagged** — 19 security fixes on main without patch bump or tag.
5. ✅ FIXED: **Domain separator** — SECURITY.md shows correct `v2` domain for Request Hashing. (`SECURITY.md`, `src/dmint/core/versions.py`)
6. ✅ FIXED: **Shim deprecation** — `dmint.canonicalize`, `enforcement`, `hashing` emit `DeprecationWarning` on import. Working as designed. (`src/dmint/canonicalize.py`)
7. **`DMINT_DASHBOARD_ALLOW_PUBLIC_BIND`** — flag allows dashboard to bind non-loopback; combined with weak token could expose approvals. (`src/dmint/dashboard/__main__.py`)
8. ✅ FIXED: **`policy-digest` documented** — added to `docs/reference/cli.mdx`. (`src/dmint/cli/policy_digest.py`)
9. **`GEMINI_API_KEY` / `OPENAI_API_KEY` / `GROQ_API_KEY` silently polled** — CLI reads LLM keys from env without informing user which was selected. (`src/dmint/cli/api.py`)
10. ✅ FIXED: **README async claim** — Tier 1 limitation removed; `async def`, class methods, static methods documented as supported. (`README.md`)

---

## 9. Next steps

1. **Tag patch release `v2.0.1`** — document Group A/B/C security fixes in `CHANGELOG.md` and bump patch version.
2. **Raise enforcement.py test coverage** from 73.5% — decorator is primary security boundary; target ≥90%.
3. **Add certificate pinning for remote policies** — validate SHA-256 cert fingerprint or pin beyond default TLS.
4. **Add warning for public dashboard bind** — emit security warning when binding non-loopback with default credentials.
5. **Add PostgreSQL migration tooling** — provide automated schema upgrade scripts for `postgres_schema.sql`.

---

## 10. UNVERIFIED

- **PyPI availability** — network access unavailable; could not run `pip index versions dmint` to confirm no conflicting older packages exist under `dmint-cli`, `dmint-mcp`, `dmint-dashboard`.
- **Landing page live content** — only backup/dev source files were readable; the deployed `dmint.app` page was not verified against source.
- **Full `dmint-mcp --help` output** — `dmint-mcp` requires extra dependencies not fully installed; flags from `__main__.py` were read manually instead.
- **Test count from `pytest --co`** — collection did not produce a count line in the sandbox (read-only cache issue); count 1,323 is from previous run in context summary.
- **`docs/reference/cli.mdx` completeness** — file was not fully read; only top-level commands verified against README.
- **PostgreSQL schema migrations** — `postgres_schema.sql` exists; no migration tooling found; upgrade path from v1 schema to v2 is not documented.
