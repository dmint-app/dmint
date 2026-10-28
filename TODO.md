# Dmint Roadmap & Engineering Backlog

This document tracks shipped milestones and focused near-term priorities for Dmint. Our philosophy is **ship a sharp, reliable library and CLI first**—focusing on deterministic enforcement, cryptographic single-use human approvals, and zero-friction developer ergonomics across AI coding harnesses and Python agents.

---

## ✅ Shipped in v2.0.4

### 1. Multi-Harness Pre-Tool Execution Hooks (`dmint hook`)
- [x] **Claude Code (`PreToolUse`)**: Native `.claude/settings.json` hook intercepting `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, and `mcp__*` calls.
- [x] **OpenAI Codex CLI**: Native `.codex/hooks.json` and `.codex/dmint-hook.sh` pre-execution hook.
- [x] **OpenCode**: Native `.opencode/plugin/dmint-guard.ts` (`tool.execute.before`) TypeScript guard plugin.
- [x] **Cursor, Windsurf & Cline / Roo Code**: Pre-tool hook installation (`.cursor/hooks.json`, `.windsurf/hooks.json`, `.clinerules/hooks.json`).
- [x] **Automatic Single-Use Approval Consumption**: Re-running an approved tool call in any hooked harness or MCP gateway automatically verifies and consumes the Ed25519 approval assertion (`APPROVED -> CONSUMED`) without requiring the LLM to copy-paste a 942-byte token.

### 2. 60-Second Developer Experience (`dmint init`, `dmint check`, `Dmint.local()`)
- [x] **`dmint init`**: One-command project bootstrap that generates `.dmint/signing.key` (`0600`), `.dmint/integrity.key` (`0600`), `.dmint/approvals.sqlite3`, a starter `policy.json` from built-in templates (`shell,filesystem`), and harness hooks.
- [x] **`dmint check` / `dmint test-policy`**: Instant offline terminal simulator to test `ALLOW`, `APPROVAL_REQUIRED`, and `DENY` decisions against `policy.json`.
- [x] **`Dmint.local()`**: Zero-boilerplate Python SDK constructor with automatic `.dmint/` key and SQLite store provisioning, plus credential-free `dmint.retry()` auto-lookup.

### 3. Tamper-Evident Auditing, Shadow Rollouts & Policy Learning
- [x] **`dmint logs` / `dmint audit`**: Inspect, filter, tail, export, and cryptographically verify the SHA-256 hash-chained `.dmint/audit.jsonl` trail.
- [x] **`dmint demo` / `dmint redteam`**: One-command 7-vector attack simulation with live audit-chain verification.
- [x] **Shadow Mode (`--mode shadow` / `DMINT_MODE=shadow`)**: Observe would-be policy blocks without blocking the agent.
- [x] **`dmint learn-policy`**: Synthesize a least-privilege, verified policy from observed audit logs.
- [x] **`dmint doctor`**: Diagnose keys, SQLite store, per-harness policies, hooks, and run the 4-vector security self-test.

---

## 🎯 Near-Term Priorities (Focused & User-Driven)

### 1. Python Agent Framework Helpers
- [ ] **LangGraph / LangChain Tool Wrapper**: Lightweight helper to pause and resume LangGraph node execution cleanly on `ApprovalRequiredError`.
- [ ] **OpenAI Agents SDK / PydanticAI Guard**: Drop-in function decorator adapter with built-in approval polling/webhook callback support.

### 2. Standards & Policy Ergonomics
- [ ] **OpenID AuthZEN Alignment**: Optional adapter mapping Dmint's `ToolRequest` and single-use approval records to emerging OpenID AuthZEN tool-authorization payloads.

---

## ⏸ Deferred (Until Community Demand Warrants)

To keep the core small, auditable, and fast (~50 µs per evaluation in pure Python), the following items are intentionally deferred unless concrete user workloads require them:

- Native Rust/PyO3 core rewrite and WebAssembly compilation.
- Kernel-level eBPF / Linux namespace sandboxing (use container/VM isolation or separate OS users alongside Dmint).
- Hardware Security Module (HSM / PKCS#11) signing and $k$-of-$n$ threshold multisig approvals.
- Standalone TypeScript / Go re-implementations of the core evaluation engine.
