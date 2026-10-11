# Phase 3: Core Engine Adversarial Retests

**Run ID:** `audit_runs/20261010-1033-de708c6`  
**Target:** Dmint `de708c6` (`phase6c-final`)  
**Status:** COMPLETE (10 of 10 items tested with runtime evidence)

---

## 1. Executive Summary

Phase 3 empirically retested the core policy engine, canonicalization primitives, constraint validator, and resource matcher across 10 security-critical properties (`K-07`, `K-08`, `K-09`, `K-10`, `K-11`, `K-12`, `K-13`, `K-14`, `K-15`, `K-26`).

All 10 properties achieved a verdict of **REAL** backed by concrete reproducible test suites executed through `$AUDIT_RUN/tools/ev.py` under clean venv isolation.

| Ledger ID | Property | Verdict | Evidence ID | Exit Code | Summary |
|---|---|---|---|---|---|
| **K-07** | Evaluator fail-closed on invalid resources | **REAL** | `[E-044]` | `rc=0` | All 7 hostile vectors (root escape, NUL, %2e%2e, backslash, non-strings, 100k length) fail closed with `DMT_RESOURCE_INVALID`. Tool spy zero calls. |
| **K-08** | Evaluator purity and thread-safety | **REAL** | `[E-045]` | `rc=0` | 20 threads executing 4,000 interleaved requests matched single-threaded baseline with zero race conditions or mutations. |
| **K-09** | Canonicalization parity and edge rejection | **REAL** | `[E-046]` | `rc=0` | Byte-for-byte exact RFC 8785 parity with Node.js across 10,021 random doubles and edge cases. Duplicate JSON keys rejected at gateway. |
| **K-10** | Fingerprint coverage and versioning | **REAL** | `[E-047]` | `rc=0` | Changing any of 8 semantic fields alters request fingerprint. v1 records fail closed safely without crashing `list_pending`. |
| **K-11** | Regex cost and differential parser validation | **REAL** | `[E-048]` | `rc=0` | `validate_pattern_safety` intercepts ReDoS patterns at load time; 5,000 patterns fuzz-checked against stdlib `sre_parse` with 0 bypasses. Multi-quantifier patterns evaluate in <1.8s. |
| **K-12** | Constraint semantics | **REAL** | `[E-049]` | `rc=0` | Failing constraints never rescued by broader ALLOW; multiple ALLOW enforce strict AND; constrained DENY never loosens denial; strict type distinction (bool vs int). |
| **K-13** | Unicode digits and pattern semantics | **REAL** | `[E-050]` | `rc=0` | Documented empirical behavior: `^\d{3}$` matches Arabic-Indic digits `١٢٣` because `re.compile` defaults to `re.UNICODE`; `\w` matches accented chars; `(?i)` flag supported. |
| **K-14** | Ordering of constraint check and approval creation | **REAL** | `[E-051]` | `rc=0` | Constraint evaluation strictly precedes approval creation: invalid arguments return `DENY` (`DMT_CONSTRAINT_VIOLATION`) and store remains empty; valid request creates exactly 1 record. |
| **K-15** | TOCTOU argument mutation defense | **REAL** | `[E-052]` | `rc=0` | In-place mutation of caller argument dictionary after authorization has zero effect on executed call, stored record, or request fingerprint. |
| **K-26** | Resource matching differential | **REAL** | `[E-053]` | `rc=0` | Verified against Node WHATWG URL (188 URLs) and posixpath (10,000 paths). Wildcard host boundaries strictly enforced (`*.github.com` does not match `evil-github.com` or `github.com.evil.com`). Segment glob matcher runs in <0.2ms. |

---

## 2. Detailed Findings by Item

### K-07: Evaluator Fail-Closed on Invalid Resources (`E-044`)
- **Script:** `audit_scratch/test_k07_resources.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k07_resources.py`
- **Output:** All 7 test cases passed (`rc=0`).
- **Mechanics:**
  - `Policy.evaluate_detailed` loops through candidate rules and calls `validate_resource_syntax` before rule matching.
  - Path traversal `/../etc/passwd` immediately raises `ResourceMatchingError("path escapes root directory")`, returning `(Decision.DENY, "DMT_RESOURCE_INVALID")`.
  - Non-string resources (`int`, `list`, `dict`, `None`) fail fast in `ToolRequest.__post_init__` with `RequestValidationError`.
  - Hostile strings (`\x00`, `\`, `%2e%2e`, `%252e%252e`, 100k length) all fail closed.
  - The runtime tool spy executed **0 times**.

### K-08: Evaluator Purity and Thread-Safety (`E-045`)
- **Script:** `audit_scratch/test_k08_thread_safety.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k08_thread_safety.py`
- **Output:** 4,000 interleaved evaluations across 20 threads completed in 0.29s with 0 errors (`rc=0`).
- **Mechanics:** `Policy` is an immutable dataclass (`frozen=True`) with tuple rules. No internal state, caching, or shared mutable variables exist in `evaluate` or `evaluate_detailed`.

### K-09: Canonicalization Parity and Edge Rejection (`E-046`)
- **Script:** `audit_scratch/test_k09_canonicalization.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k09_canonicalization.py`
- **Output:** 10,021 random and edge numbers matched Node.js RFC 8785 byte-for-byte (`rc=0`).
- **Mechanics:**
  - Python `canonicalize()` reproduces ECMAScript Number formatting and UTF-16 code unit key sorting.
  - Duplicate keys in JSON payloads are rejected at the gateway level by `parse_gateway_request(object_pairs_hook=_reject_duplicate_keys)`.
  - Depth limit (100), size limit (10MB), non-finite floats, circular references, and lone surrogates are rejected fail-closed.

### K-10: Fingerprint Coverage and Versioning (`E-047`)
- **Script:** `audit_scratch/test_k10_fingerprint_coverage.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k10_fingerprint_coverage.py`
- **Output:** All 8 semantic fields alter fingerprint; domain separation constant verified; v1 records handled safely (`rc=0`).
- **Mechanics:**
  - Domain separation: `b"dmint/request-binding/v1\x00"` prefix.
  - Mutating any of: `agent_id`, `tool`, `action`, `resource`, `arguments`, `context`, `integration_id`, or `capability_id` alters the SHA-256 fingerprint.
  - Stored records with legacy/unknown schema versions raise `UnknownApprovalVersionError` on lookup (fail-closed), while `list_pending` safely skips them with a warning without crashing.

### K-11: Regex Cost and Differential Parser Validation (`E-048`)
- **Script:** `audit_scratch/test_k11_regex_cost.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k11_regex_cost.py`
- **Output:** ReDoS patterns rejected at load time; 5,000 patterns fuzz-checked with 0 parser bypasses (`rc=0`).
- **Mechanics:**
  - `validate_pattern_safety` in `dmint/core/constraints.py:267` detects nested and consecutive quantifiers, unanchored wildcards, and quantifier combinations exceeding complexity thresholds.
  - Patterns like `^.*a.*a.*a.*a.*b$`, `^(a|a)+$`, `^(a*)*$`, `{0,50}x4`, and `{0,500}x4` raise `PolicyError("regex pattern exceeds complexity limit")`.
  - Allowed multi-quantifier patterns evaluated in 1.27s-1.71s against `a * 4096`.

### K-12: Constraint Semantics (`E-049`)
- **Script:** `audit_scratch/test_k12_constraint_semantics.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k12_constraint_semantics.py`
- **Output:** All 8 constraint semantic rules passed (`rc=0`).
- **Mechanics:**
  - Failing constrained ALLOW rule is NEVER rescued by a broader unconstrained ALLOW rule.
  - Multiple matching ALLOW rules enforce strict AND semantics (all must pass).
  - Constrained DENY rule never loosens denial: matching enum returns `DMT_POLICY_DENIED`, non-matching returns `DMT_CONSTRAINT_VIOLATION`.
  - Strict type distinction: `bool True != int 1` (`validate_constraints_schema` and `evaluate_constraints`).
  - Tuples in schemas are rejected with `PolicyError`.

### K-13: Unicode Digits and Pattern Semantics (`E-050`)
- **Script:** `audit_scratch/test_k13_unicode_patterns.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k13_unicode_patterns.py`
- **Output:** Verified Python regex default UNICODE semantics (`rc=0`).
- **Mechanics:**
  - Python's standard `re.compile` compiles `\d` with `re.UNICODE` mode enabled by default. Consequently, `^\d{3}$` matches Eastern Arabic-Indic digits `١٢٣`.
  - `\w` matches Unicode alphanumeric characters (e.g. `café`).
  - `\s` matches Unicode whitespace (e.g. `\u2002`).
  - `(?i)` inline flag is supported and matches case-insensitively.

### K-14: Ordering of Constraint Check and Approval Creation (`E-051`)
- **Script:** `audit_scratch/test_k14_constraint_ordering.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k14_constraint_ordering.py`
- **Output:** 3 tests passed in 0.046s (`rc=0`).
- **Mechanics:**
  - In `Dmint._authorize_call` and `EnforcementGate.route_call`, `self._policy.evaluate_detailed(request)` executes *before* `self._persist_pending(request)`.
  - For a rule requiring approval with constraints (e.g. `amount <= 100`):
    - Request with `amount = 500` returns `Decision.DENY` (`DMT_CONSTRAINT_VIOLATION`). It raises `AuthorizationError` immediately, `_persist_pending` is never reached, and `store.list_pending()` remains completely empty (0 records).
    - Request with `amount = 50` passes constraints and returns `Decision.APPROVAL_REQUIRED`. It calls `_persist_pending`, inserts exactly 1 pending record into `SQLiteApprovalStore`, and raises `ApprovalRequiredError`.

### K-15: TOCTOU Argument Mutation Defense (`E-052`)
- **Script:** `audit_scratch/test_k15_toctou.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k15_toctou.py`
- **Output:** 3 tests passed in 0.040s (`rc=0`).
- **Mechanics:**
  - In Decorator mode: `InvocationSnapshot.from_bound` uses `freeze_json` to recursively freeze arguments into immutable `MappingProxyType` and tuples. When the caller mutates the original dictionary after `authorize()`, `authorized.fingerprint` and the parameters executed by `engine.execute(authorized)` reflect the pre-mutation snapshot.
  - In Gateway mode: `MCPRequestMapper.map` deep-copies and freezes arguments into `ToolRequest`. Mutating the original input dictionary does not alter `mapped.fingerprint` or `mapped.tool_request.arguments`.
  - In APPROVAL_REQUIRED flows: The record stored in `SQLiteApprovalStore` retains the immutable pre-mutation snapshot.

### K-26: Resource Matching Differential (`E-053`)
- **Script:** `audit_scratch/test_k26_differential.py`
- **Command:** `PYTHONPATH=src audit_scratch/venv/bin/python audit_scratch/test_k26_differential.py`
- **Output:** 4 tests passed in 0.132s (`rc=0`).
- **Mechanics:**
  - **Tricky URLs vs Node WHATWG URL (188 URLs tested):**
    - 52 standard HTTP/HTTPS URLs were accepted by both Dmint and Node WHATWG with matching scheme, host, and port stripping.
    - 136 URLs were rejected fail-closed by Dmint with `ResourceMatchingError`.
    - Dmint blocked 96 permissive WHATWG constructs, including non-HTTP schemes (`javascript:`, `file:`, `ftp:`), userinfo confusion (`@`), backslashes in authority/path, double-encoded traversals (`%252e%252e`), unbracketed IPv6, whitespace injection, and port 0 (reserved/invalid for outbound sockets).
  - **10,000 Random Paths vs posixpath:**
    - 6,295 paths normalized identically between Dmint and POSIX (accounting for Dmint's intentional collapse of `//` to `/` to eliminate POSIX's implementation-defined dual-slash quirk).
    - 3,705 root traversal attempts (including intermediate `/..` escapes) were strictly rejected by Dmint with `ResourceMatchingError("path escapes root directory")`, whereas `posixpath.normpath` permits clamping to `/`.
  - **Wildcard Host Boundaries:**
    - Rule `*.github.com` strictly matches `api.github.com`, `raw.github.com`, and `sub.api.github.com`.
    - Rule `*.github.com` strictly rejects `evil-github.com`, `github.com.evil.com`, `evilgithub.com`, `github.com`, `notgithub.com`, and `attackergithub.com`.
  - **Segment Glob Matcher Timing:**
    - Evaluated adversarial pattern `/a/**/b/**/c/**/d/**/e/**/f/**/g` against a 600-segment mismatch and matching input.
    - Executed in **0.13ms** with zero exponential backtracking blowup, verifying the bounded $O(N \cdot M)$ segment algorithm.
