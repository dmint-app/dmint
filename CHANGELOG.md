# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
