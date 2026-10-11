# Phase 10: Fuzz, Differential, and Performance Benchmarks Report

**Run ID:** `audit_runs/20261010-1033-de708c6`  
**Target:** Dmint `de708c6` (`phase6c-final`)  
**Status:** COMPLETE (46,000 empirical benchmark & fuzzing operations evaluated)

---

## 1. Executive Summary

Phase 10 executed performance benchmarking and differential fuzzing across Dmint's core authorization pipeline, canonicalization engine, resource normalizer, and constraint evaluator under evidence `[E-070]`.

| Category | Iterations | Empirical Metrics / Findings | Status |
|---|---|---|:---:|
| **Policy Evaluation Latency** | 10,000 evals | 1-rule: **p50=2.81µs, p95=3.01µs, p99=5.73µs**<br>10-rules: **p50=7.01µs, p95=8.04µs, p99=11.82µs** | **PASS** (< 50ms bound verified) |
| **Decorator Overhead** | 5,000 invocations | Bare function: **p50=0.32µs**<br>Protected function: **p50=73.08µs** (overhead: **72.76µs**) | **PASS** |
| **SQLite Lifecycle Latency** | 1,000 lifecycles | `save_pending`: **p50=2.44ms, p99=3.42ms**<br>`approve`: **p50=2.27ms, p99=2.92ms**<br>`consume_approved`: **p50=4.81ms, p99=5.95ms** | **PASS** |
| **Canonicalization Fuzzing** | 10,000 cases | 0 mismatches, 0 unhandled exceptions, 100% round-trip parity between raw and thawed inputs | **PASS** |
| **Resource Normalization Fuzzing** | 10,000 cases | 0 unhandled exceptions. **1 idempotence anomaly discovered** (`normalize_host` strips only one trailing dot per invocation on multiple trailing dots) | **PARTIAL** (New Finding) |
| **Constraint Evaluation Safety** | 10,000 cases | 0 unhandled exceptions under NaN, Infinity, ReDoS, type confusion, or deep nesting (100% fail-closed) | **PASS** |

---

## 2. Performance Benchmarks

### 2.1 Policy Evaluation Latency (C-21 Verification)
- **Claim:** `docs/concepts/policies.mdx:240` claims: *"All patterns guaranteed to evaluate in sub-millisecond time bound (< 50 ms)."*
- **Measurements (5,000 iterations, garbage collection disabled during timing):**
  - **Single Rule (ALLOW):**
    - Min: `2.68 µs`
    - **p50: `2.82 µs`**
    - **p95: `3.01 µs`**
    - **p99: `5.73 µs`**
    - Max: `22.03 µs`
  - **10 Rules (Mix of DENY, APPROVAL_REQUIRED, ALLOW with constraints and resource patterns):**
    - Min: `6.70 µs`
    - **p50: `7.01 µs`**
    - **p95: `8.04 µs`**
    - **p99: `11.82 µs`**
    - Max: `26.97 µs`
- **Verdict:** **REAL**. Policy evaluation executes in single-digit microseconds, over 3 orders of magnitude faster than the conservative 50ms documentation bound.

### 2.2 Decorator In-Process Enforcement Overhead
- Measured bare function invocation vs `@dmint.protected("bash.exec")`:
  - Bare function: p50 = `0.32 µs`
  - Decorated function: p50 = `73.08 µs`
  - Net decorator overhead: **`72.76 µs`**
- The overhead comprises tool request validation, canonical request binding, policy rule matching, and decision emission.

### 2.3 SQLite Approval Lifecycle Latency
- Measured full pending-approval-consumption lifecycle across 1,000 iterations:
  - `save_pending`: p50 = `2.44 ms`, p95 = `3.09 ms`, p99 = `3.42 ms`
  - `approve`: p50 = `2.27 ms`, p95 = `2.68 ms`, p99 = `2.92 ms`
  - `consume_approved` (includes Ed25519 cryptographic verification and atomic state update): p50 = `4.81 ms`, p95 = `5.39 ms`, p99 = `5.95 ms`
- Total end-to-end approval cycle latency: **~9.52 ms** on local NVMe storage.

---

## 3. Differential and Property-Based Fuzzing

### 3.1 Canonicalization Round-Trip Fuzzing (10,000 cases)
- Generated random primitives, deep recursive dictionaries (up to 5 levels), lists, IEEE-754 floats (-0.0, subnormals, large powers), unicode, emojis, control characters, and nulls.
- Tested:
  1. `canonicalize(thaw_json(x)) == canonicalize(x)`
  2. UTF-8 byte decodability.
  3. Strict key sorting under RFC 8785.
- Results: **10,000 / 10,000 passed with 0 mismatches and 0 errors**.

### 3.2 Resource Normalization Fuzzing & Anomaly Discovery (10,000 cases)
- Fuzzed paths, URLs, hostnames, and identifiers with directory traversals, encoded tokens, UNC paths, and strange ports.
- **Idempotence Anomaly Discovered:**
  - Input: `'zt8ggjag8bj..'` (hostname with two trailing dots).
  - First call `normalize_host('zt8ggjag8bj..')` -> `'zt8ggjag8bj.'`
  - Second call `normalize_host('zt8ggjag8bj.')` -> `'zt8ggjag8bj'`
  - **Root Cause:** In `src/dmint/core/resources.py:372`, trailing dot removal uses `if host_part.endswith("."): host_part = host_part[:-1]`, stripping only a single trailing character per execution rather than stripping all trailing dots (`.rstrip(".")`) or strictly rejecting consecutive dots (`..`).
  - **Impact:** Low/Medium. Host normalization is non-idempotent for multi-dot suffixes, creating potential divergence if policies compare against single-pass normalized hostnames.

### 3.3 Constraint Evaluation Exception Safety (10,000 cases)
- Fuzzed randomized schemas and payloads containing `NaN`, `Infinity`, `-Infinity`, `Decimal`, ReDoS strings (`a` * 100 + `!`), type confusion, and `__proto__` objects.
- Results:
  - Valid evaluations: 514
  - Rejected evaluations: 9,486
  - **Unhandled exceptions: 0 (100% fail-closed exception safety)**.

