# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.4] - 2026-10-25

### Added
- **Per-Harness Dedicated Policies (`.dmint/policies/<harness>.policy.json`)**: Shipped 6 dedicated built-in tool policies (`claude-code`: 722 rules, `codex`: 729, `opencode`: 465, `cursor`: 899, `windsurf`: 715, `cline`: 716) covering every default tool in each coding harness.
- **End-to-End Workspace Diagnostic (`dmint doctor`)**: Added `dmint doctor` (`--dir`, `--json`) to verify RFC 8785 + Ed25519 crypto, `0600` keys, per-harness policies, installed hooks, and a live 4-vector security self-test.
- **Multi-Harness `PreToolUse` Hooks (`dmint hook`)**: Native pre-execution tool interception (`dmint hook install|run|status|uninstall`) for **Claude Code**, **OpenAI Codex CLI**, **OpenCode**, **Cursor**, **Windsurf**, and **Cline / Roo Code**.
- **60-Second Developer Experience (`dmint init`, `dmint check`, `Dmint.local()`)**: One-command workspace bootstrap (`dmint init`), offline CLI policy simulator (`dmint check`), zero-config Python SDK constructor (`Dmint.local()`), and credential-free `dmint.retry()` auto-lookup.
- **Automatic Store-Backed Approval Retry (`F4`)**: `approve_pending()` persists signed Ed25519 assertions in `approval_assertions` so `dmint-mcp`, `dmint hook run`, and `Dmint.retry()` can verify and consume single-use approvals by RFC 8785 fingerprint without requiring the LLM to carry a 942-byte token.
- **Documentation & Generator (`scripts/gen_llms_txt.py`)**: Added dedicated guides for Coding-Agent Hooks, Codex CLI, OpenCode, and Windsurf/Cline (33 total pages) plus deterministic `llms.txt` / `llms-full.txt` / `sitemap.xml` generation.

### Fixed
- **Shared Store Policy Snapshot (`F2`)**: `set_authoritative_policy()` in `SQLiteApprovalStore` and `SQLAlchemyApprovalStore` now serializes via `Policy.to_dict()`, preserving `resource_kind`, `case_sensitive`, `constraints`, `schema_hash`, `strict_arguments`, and `tool_schemas`, with automatic self-healing via `sync_authoritative_policy()`.
- **Overview Example & Missing Config Error (`F1`)**: `Dmint._persist_pending` now explicitly names every missing argument (`approval_store`, `policy_provenance`, `approval_ttl`).
- **Rich Argument Types & `NaN` Error Code (`F7`)**: Non-JSON arguments and non-finite floats (`NaN`, `Infinity`) now consistently surface `DMT_CANONICALIZATION_ERROR` with the argument path.
- **Compound Shell Command & Relative Symlink Smuggling Protection**: Blocked unquoted shell chaining (`&&`, `||`, `;`, `|`, `$()`, backticks) from matching prefix globs, added quote-aware compound command splitting, and resolved relative symlinks via `Path.resolve()` before path matching.
- **Shell Command Prefix/Suffix Wildcards**: `match_resource(..., kind="exact")` now supports bounded command prefix/suffix wildcards (`"docker *"`, `"rm -rf /*"`, `"* | sh"`).
- **Remote Policy SSRF & Postgres Recovery Lock**: `Policy.from_url()` enforces DNS pinning (`_PinnedHTTPSHandler`), redirect blocking, and 10 MB size bounds; `SQLAlchemyApprovalStore` enforces cross-process `.recovery` sidecar locking and pre-increment rollback checks.
- **Test Portability (`F8`)**: Fixed root-user `chmod 000` test skip, optional Node `canonicalize` fixture skip, `FakeStat` owner check, and regex timing assertions.

### Changed
- **Unified Default Deployment Epoch (`F3`)**: `MCPGateway` now defaults `deployment_epoch` to `"default"` (configurable via `"deployment_epoch"` in `mcp_protection.json` or `DMINT_DEPLOYMENT_EPOCH`), matching `dmint pending`, `dmint approve`, and `dmint dashboard` out of the box.
- **PyPI Maturity Classifier (`F6`)**: Updated classifier from `5 - Production/Stable` to `4 - Beta`.

## [2.0.3] - 2026-10-24

### Security & Supply Chain
- **Dependency Lower Bounds Hardening**: Tightened Python package minimum bounds across core, MCP, and dashboard to eliminate known vulnerabilities (GHSA/PYSEC advisories):
  - `cryptography`: bumped minimum from `>=42` to `>=50.0.0,<52` (mitigating 15 historical CVEs).
  - `starlette`: bumped minimum from `>=0.27` to `>=0.40.0` (mitigating 14 historical multipart/path traversal CVEs).
  - `httpx2`: bumped minimum from `>=2.5` to `>=2.12.0,<3.0.0` (mitigating 5 connection-splitting CVEs).
  - `fastapi`: bumped minimum from `>=0.110` to `>=0.116.0,<1.0` to enforce secure Starlette pairing.
  - `jinja2`: bumped minimum from `>=3.1` to `>=3.1.6,<4.0` (mitigating 10 HTML attribute injection CVEs).
  - `python-multipart`: bumped minimum from `>=0.0.9` to `>=0.0.20,<1.0` (mitigating 14 ReDoS/parsing CVEs).
  - `psycopg2-binary`: bumped minimum from `>=2.9.0` to `>=2.9.9` (eliminating source build failures on Python 3.12+).
  - `psycopg[binary]`: bumped minimum from `>=3.1.0` to `>=3.1.18`.
- **Docs & Frontend Supply Chain**: Remediated 11 npm vulnerabilities in `docs/package-lock.json` via `npm audit fix`, eliminating 1 critical vulnerability (`dompurify` DOM XSS) and 8 high vulnerabilities (`@modelcontextprotocol/sdk`, `undici`, `sharp`, `source-map-js`, `vite`).

### CI
- **Conditional PyPI Publish**: Updated `.github/workflows/publish.yml` to publish exclusively when an unpublished version is introduced on `main`, cleanly skipping already-published releases without failing the CI/CD pipeline.

## [2.0.2] - 2026-10-23

### Fixed
- Updated test version assertions and user-agent strings to match `2.0.2` monorepo version.
- Aligned `tests/cli/test_version_consistency.py`, `tests/core/test_webhooks.py`, and `tests/skills/test_policy_manager_skill.py` with the `2.0.2` release.

### CI
- Added `workflow_run` trigger to `publish.yml` so every successful CI push to `main` automatically publishes to PyPI without requiring a manual GitHub Release.
- Added PyPI version existence check to reject re-publishing an already-published version.
- Added `concurrency` guard to prevent double-publish races.

## [2.0.1] - 2026-10-21

### Security
- **Policy wildcard enforcement (H1)**: `tool` and `action` selectors now honor whole-field `*` wildcards consistently in both candidate selection and full rule matching. Wildcard `deny` and `approval_required` rules now override matching `allow` rules under the fixed precedence `DENY > APPROVAL_REQUIRED > ALLOW`.
- **Recovery-counter race (H2)**: serialized recovery sidecar/database synchronization across store instances and processes with a dedicated file lock, preventing false rollback detection during concurrent construction and consumption.
- **MCP/OAuth SSRF hardening (M1, M2)**: canonicalized IDNA hostnames before SSRF checks, pinned validated destinations for transport connections, rejected unpinned fallbacks, rejected remote MCP hostnames whose DNS answers resolve to loopback, and restricted loopback OAuth endpoints to loopback MCP servers.
- **Webhook DNS pinning (M3)**: webhook delivery now connects to the IP validated during the SSRF check while preserving Host/SNI, closing the DNS-rebinding window; redirects and environment proxies remain disabled.
- **Webhook dispatch correctness (M4)**: Core’s `webhook_notifier` parameter is deprecated and inert, preserving Core’s zero-network authorization invariant. MCP notification dispatch runs off the asyncio event loop in a serialized worker thread and remains isolated from authorization decisions.
- **Approval handoff and identity attribution (M5)**: added a dashboard assertion download endpoint for approved records, `CoreClient.approve_with_assertion()` / `issue_assertion()`, and `LocalApprovalAuthority.issue_for_human()`. Dashboard identities are labeled self-asserted unless supplied by a configured trusted proxy; missing trusted-proxy headers fail closed for login and state-changing approval actions.

### Documentation
- Corrected policy effects, precedence, wildcard, resource-default, and constraint semantics.
- Replaced the refund tutorial with an executable two-capability approval/retry flow and corrected the quickstart.
- Corrected Core API signatures, approval CLI/dashboard handoff, MCP gateway flags and retry payloads, notification behavior, error codes, and MCP protection schema.

### Fixed
- Added the Python 3.13 classifier and aligned package metadata, CI coverage, and release/version declarations with the supported Python 3.10–3.13 range and `2.0.1`.

### Tests
- Added regressions for wildcard policy precedence, cross-instance recovery locking, IDN SSRF, OAuth loopback policy, webhook DNS pinning/rebinding, off-loop serialized MCP notification dispatch, Core notifier deprecation, dashboard assertion handoff, and trusted-proxy missing-header failure.

## [2.0.0] - 2026-09-30

### Added
- **PostgreSQL Database Storage (`DMINT_DATABASE_URL`)**:
  - Added `SQLAlchemyApprovalStore` and `ThreadSafeApprovalStore` powered by SQLAlchemy Core.
  - Concurrency guarantees with row-level locking (`SELECT ... FOR UPDATE`), preventing double-consumption races.
  - Unified factory `create_approval_store()` supporting automatic switching between SQLite and PostgreSQL.
  - Fail-closed configuration: invalid or unreachable `DMINT_DATABASE_URL` halts execution at startup with `ApprovalStoreConfigurationError` (no silent SQLite fallback).
- **Terminal Approval Management (CLI)**:
  - Added `dmint pending` command to query pending approvals across SQLite and PostgreSQL.
  - Added `dmint approve <id>` command with policy re-verification, Ed25519 signing, and optional `--reason` audit notes.
  - Added `dmint reject <id>` command to explicitly mark requests as `REJECTED`.
- **Real-Time Webhook Notifications**:
  - Real-time outgoing notifications to Slack, Discord, and Microsoft Teams on `APPROVAL_REQUIRED` events via `DMINT_SLACK_WEBHOOK_URL`, `DMINT_DISCORD_WEBHOOK_URL`, and `DMINT_TEAMS_WEBHOOK_URL`.
  - Real-time policy denial notifications on `DENY` events via `build_denial_payload` and `dispatch_denial_webhook`.
  - Strict isolation: webhook network errors or timeouts never block runtime authorization decisions.
- **Security & SSRF Hardening**:
  - Gated OAuth PKCE loopback validation with full IP and DNS resolution via `is_loopback_host` to prevent SSRF vulnerabilities.
- **Centralized Version & User-Agent Management**:
  - Centralized runtime version resolution via `dmint.version` with `DMINT_VERSION` override support.
  - Centralized HTTP User-Agent builder with `DMINT_USER_AGENT` override support.

### Changed
- **Unified Monorepo Architecture**: Consolidated 5 separate packages (`dmint`, `dmint-cli`, `dmint-mcp`, `dmint-dashboard`, `dmint-skills`) into a single distribution package (`dmint`).
- Submodules are now organized as:
  - `dmint.core`: Core deterministic policy evaluation, canonicalization, request binding, and storage.
  - `dmint.cli`: Command-line tools and interactive wizards (`dmint`).
  - `dmint.mcp`: Model Context Protocol proxy and gateway (`dmint-mcp`).
  - `dmint.dashboard`: Local human approval review dashboard (`dmint-dashboard`).
  - `dmint.skills`: Policy management skills and prompts.
- Top-level `dmint` package preserves backwards-compatible imports for core symbols (`Dmint`, `Policy`, `Rule`, `SQLiteApprovalStore`, etc.).
- Optional extras allow granular dependency installation: `pip install dmint[mcp]`, `pip install dmint[dashboard]`, or `pip install dmint[all]`.
