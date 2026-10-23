# Dmint Roadmap & Engineering Backlog

This document outlines active development initiatives, upcoming architectural enhancements, and ecosystem extensions for the Dmint deterministic security engine.

---

## 🚀 Active Initiatives (Ongoing / Started Phase)

### 1. `dmint-core-rs` — Native Rust Core Engine
> **Status:** 🟡 **In Progress / Started Phase**  
> **Goal:** High-throughput, zero-GIL deterministic policy evaluation and memory-safe cryptography.

- [ ] **Deterministic Policy Evaluator**: Port the 3-state (`ALLOW`, `DENY`, `APPROVAL_REQUIRED`) decision engine to pure Rust.
- [ ] **Zero-Allocation Canonicalizer**: Implement RFC 8785 JSON Canonicalization Scheme (JCS) in Rust with minimal heap allocations.
- [ ] **Ed25519 Cryptographic Layer**: Native assertion signing, verification, and key management using `ed25519-dalek`.
- [ ] **Embedded State Machine**: High-concurrency SQLite storage with native write-ahead logging (WAL) and atomic single-use consumption.
- [ ] **PyO3 Python Bindings**: Drop-in native extension module for `dmint.core`, transparently accelerating Python evaluations with zero GIL contention.
- [ ] **WebAssembly (WASM) Compilation**: Target `wasm32-unknown-unknown` for edge environments (Cloudflare Workers, Fastly Compute).

---

### 2. `@dmint.app/core` & `@dmint.app/mcp` — JavaScript / TypeScript SDK
> **Status:** 🟡 **In Progress / Started Phase**  
> **Goal:** First-class Node.js, Bun, Deno, and browser support for modern AI agent stacks under `@dmint.app`.

- [ ] **TypeScript Core Implementation**: Native RFC 8785 canonicalization and Ed25519 verification with zero native dependencies.
- [ ] **MCP Gateway for TypeScript**: Standard transport proxy wrapping `@modelcontextprotocol/sdk` servers with deterministic parameter interception.
- [ ] **Framework Adapters**:
  - [ ] Vercel AI SDK tool call authorization wrapper (`createDmintTool`).
  - [ ] LangChain.js / LangGraph checkpoint and approval hook integration.
  - [ ] AutoGen and LlamaIndex.ts tool interception middleware.
- [ ] **Client SDK**: Lightweight HTTP/SSE client for interacting with the local approval dashboard and webhook notifications.

---

## 📋 Upcoming Roadmap & Planned Features

### 3. Agent Framework Pause & Resume Adapters
> **Status:** ⚪ **Planned**  
> **Goal:** Eliminate agent hallucination when encountering `APPROVAL_REQUIRED`.

- [ ] **LangGraph Interrupt Hook**: First-class integration with LangGraph's human-in-the-loop state checkpointing.
- [ ] **CrewAI Task Interceptor**: Middleware to park agent tasks cleanly while waiting for human sign-off.
- [ ] **Claude Code & Cursor Bridge**: Seamless retry loop management that prevents rapid polling or broken tool calls during human review.

---

### 4. Automated Policy Discovery & Synthesis
> **Status:** ⚪ **Planned**  
> **Goal:** Zero-friction policy bootstrapping from existing tool definitions.

- [ ] **OpenAPI 3.1 Compiler**: Ingest Swagger/OpenAPI specs and auto-generate least-privilege `policy.json` rules.
- [ ] **MCP Server Introspection**: Scan running MCP servers via `tools/list` and synthesize initial protection manifests.
- [ ] **Interactive TUI Policy Wizard**: Terminal interface to review, tighten, and test auto-generated policies against sample payloads.

---

### 5. Advanced Security & Infrastructure Hardening
> **Status:** ⚪ **Planned**  
> **Goal:** Enterprise defense-in-depth and distributed trust.

- [ ] **Threshold Multisig Approvals**: Require $k$-of-$n$ trusted human approvers for critical capabilities (e.g., production database updates, financial transactions).
- [ ] **eBPF / Linux Namespaces Sandbox**: Kernel-enforced filesystem and network isolation for tools executed by local agent runners.
- [ ] **OpenTelemetry Integration**: W3C `traceparent` context propagation through policy decisions, approval lifecycles, and audit logs.
- [ ] **Hardware Security Module (HSM) Signing**: Support PKCS#11 and AWS KMS / GCP Cloud KMS for authoritative Ed25519 assertion signing.
