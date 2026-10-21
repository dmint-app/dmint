# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
