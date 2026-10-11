# Phase 5: Gateway and Network

**Run ID:** `audit_runs/20261010-1033-de708c6`  
**Target:** Dmint `de708c6` (`phase6c-final`)  
**Status:** COMPLETE (4 of 4 items verified with runtime evidence)

---

## 1. Executive Summary

Phase 5 empirically audited Dmint's network-facing MCP gateway defenses, SSRF filtering, and Python decorator execution boundaries across 4 properties (`K-17`, `K-18`, `K-19`, `K-22`).

Testing confirmed robust fail-closed defenses against credential tampering and replay, strict multi-agent HTTP bearer authentication, and comprehensive IP/scheme SSRF protections. The audit identified **2 architecture/security gaps**:
1. **SSRF DNS Rebinding Gap (`K-19`):** While `validate_mcp_url` verifies DNS pre-resolution, `DownstreamMCPClient` passes the hostname URL directly to `httpx.AsyncClient` without IP pinning or custom transport, leaving a DNS rebinding window between verification and connection. In addition, static checks (`resolve_dns=False`) miss trailing-dot metadata hostnames (`metadata.google.internal.`) and octal/short IPs (`0177.0.0.1`, `127.1`), though standard runtime DNS resolution blocks them.
2. **Decorator Generator Lazy Execution & Address Reuse (`K-22`):** Generator functions decorated with `@protect` return a generator object immediately without executing the generator body inside `execute()`; actual execution happens lazily outside Dmint when `next()` is called. Furthermore, `_registered` dict stores integer memory addresses without garbage-collection cleanup, allowing newly allocated functions reusing memory addresses to inherit stale capability bindings.

| Ledger ID | Property | Verdict | Evidence ID | Exit Code | Summary |
|---|---|---|---|---|---|
| **K-17** | Retry credential attacks in Gateway | **REAL** | `[E-055]` | `rc=0` | 9 attack vectors blocked (tampered args, wrong agent, wrong aud, unknown issuer, expired, bad sig, replay, concurrent race, downstream credential stripping). Tool spy 0 calls. |
| **K-18** | Agent identity binding | **REAL** | `[E-056]` | `rc=0` | HTTP bearer token strictly binds agent identity; missing/invalid tokens 401; zero fallback to default agent; client body/meta parameters cannot spoof identity. |
| **K-19** | SSRF defense analysis | **PARTIAL** | `[E-061]` | `rc=0` | Private ranges, loopback, link-local, cloud metadata, integer IPs, userinfo, plain HTTP, and redirects blocked. Gaps: no IP pinning between DNS check and httpx connect (DNS rebinding window); static checks miss trailing-dot metadata hosts and octal/short IPs; `ssrf.py:98` is dead code. |
| **K-22** | Decorator bypass analysis | **PARTIAL** | `[E-062]` | `rc=0` | Async functions rejected at decoration time; positional/keyword and default arguments normalized; `__wrapped__` rejected; exception after consume blocks replay. Gaps: generator functions execute lazily outside gate; instance/class methods fail on `self`/`cls`; address reuse in `_registered` causes stale binding inheritance. |

---

## 2. Detailed Findings by Item

### K-17: Retry Credential Attacks in Gateway (`E-055`)
- **Target:** `src/dmint/core/enforcement.py`, `src/dmint/mcp/proxy.py`
- **Evidence:** `[E-055]` (`audit_scratch/test_k17_credentials.py`, `rc=0`)
- **Evaluated Vectors:**
  1. **Argument Tampering:** Assertion issued for `{"id": 1}` presented for `{"id": 2}` -> Blocked with `DMT_FINGERPRINT_MISMATCH`.
  2. **Agent Substitution:** Assertion issued for `agent-alice` presented by `agent-bob` -> Blocked with `DMT_FINGERPRINT_MISMATCH`.
  3. **Audience Spoofing:** Assertion with foreign audience -> Blocked with `DMT_AUDIENCE_MISMATCH`.
  4. **Unknown Issuer:** Key not in trusted keystore -> Blocked with `DMT_UNKNOWN_ISSUER`.
  5. **Expired Assertion:** Expired timestamp -> Blocked with `DMT_APPROVAL_EXPIRED`.
  6. **Signature Corruption:** 1 corrupted byte -> Blocked with `DMT_INVALID_SIGNATURE`.
  7. **Assertion Replay:** Consuming once transitions state to `CONSUMED`; replay fails with `DMT_APPROVAL_CONSUMED`.
  8. **Simultaneous Race:** 10 concurrent requests yield exactly 1 success and 9 rejections.
  9. **Downstream Credential Stripping:** Assertion dictionary is stripped from tool call arguments prior to downstream invocation.
- **Verdict:** **REAL**.

---

### K-18: Agent Identity Binding (`E-056`)
- **Target:** `src/dmint/mcp/proxy.py`, `src/dmint/mcp/server.py`
- **Evidence:** `[E-056]` (`audit_scratch/test_k18_agent_binding.py`, `rc=0`)
- **Key Findings:**
  1. Requests lacking an `Authorization: Bearer <token>` header return HTTP 401 Unauthorized (`DMT_MISSING_CREDENTIALS`).
  2. Requests with an invalid or unrecognized token return HTTP 401 Unauthorized (`DMT_INVALID_CREDENTIALS`).
  3. Tokens deterministically bind to specific agent identities without fallback to default or guest agents.
  4. Client-supplied `agent_id` in JSON payloads or `params._meta` cannot override the bearer-token-authenticated identity.
  5. Approvals issued for `agent-alice` cannot be consumed by `agent-bob` (fails closed with `DMT_FINGERPRINT_MISMATCH`).
- **Verdict:** **REAL**.

---

### K-19: SSRF Defense Analysis (`E-061`)
- **Target:** `src/dmint/mcp/ssrf.py`, `src/dmint/mcp/client.py`
- **Evidence:** `[E-061]` (`audit_scratch/test_k19_ssrf.py`, `rc=0`)
- **Verified Protections:**
  1. **Restricted IP Ranges:** Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), and `0.0.0.0/8` are blocked.
  2. **Cloud Metadata:** `169.254.169.254`, `metadata.google.internal`, `instance-data`, and `metadata` are blocked.
  3. **Integer IP Literals:** Decimal integer literals (e.g. `2130706433` for `127.0.0.1`, `2852039166` for `169.254.169.254`) are parsed and blocked.
  4. **Scheme Enforcement:** Disallowed schemes (`file://`, `gopher://`, `ftp://`, `data://`) and plain HTTP for remote endpoints are rejected.
  5. **Embedded Userinfo:** URLs with `username` or `password` components are rejected.
  6. **Redirect Following:** `DownstreamMCPClient` explicitly sets `follow_redirects=False` on `httpx.AsyncClient`, preventing redirect-based SSRF.
- **Identified Gaps & Weaknesses:**
  1. **DNS Rebinding Window (IP Not Pinned):** In `DownstreamMCPClient._connect_streamable_http`, `validate_mcp_url` resolves DNS and verifies that resolved addresses are public. However, `streamable_http_client(validated_url, http_client=http_client)` passes the hostname URL to `httpx`. `httpx` performs its own independent DNS resolution during TCP socket connection without IP pinning or custom resolver. A target domain returning a public IP on the first query (TTL=0) and a metadata/private IP on the second query bypasses the SSRF filter.
  2. **Static Trailing-Dot Bypass:** In `ssrf.py:264`, static metadata check tests `clean_host in METADATA_HOSTNAMES or clean_host.endswith(".internal")`. A URL with a trailing dot (`https://metadata.google.internal./mcp`) bypasses the static check when `resolve_dns=False`.
  3. **Static Octal/Hex/Short IP Bypass:** `parse_ip_literal` returns `None` for octal (`0177.0.0.1`), hex (`0x7f000001`), and short IP (`127.1`). When `resolve_dns=False`, these pass static validation. (When `resolve_dns=True`, system `getaddrinfo` resolves them to `127.0.0.1` and blocks them).
  4. **Dead Code in IPv4-Mapped IPv6:** In `ssrf.py:82`, `ip.is_reserved` is checked before `ip.ipv4_mapped` at line 98. In Python stdlib, all `::ffff:0:0/96` addresses have `is_reserved == True`. Consequently, all IPv4-mapped IPv6 addresses are blocked at line 82, and lines 97-99 are unreachable dead code.
- **Verdict:** **PARTIAL**.

---

### K-22: Decorator Bypass Analysis (`E-062`)
- **Target:** `src/dmint/core/enforcement.py`
- **Evidence:** `[E-062]` (`audit_scratch/test_k22_decorator.py`, `rc=0`)
- **Verified Behaviors:**
  1. **Async Functions Rejected:** `_validate_function` checks `inspect.iscoroutinefunction` and explicitly raises `RequestValidationError("async functions are not supported in Phase 1")`.
  2. **Wrapped Functions Rejected:** Functions with existing `__wrapped__` attributes are rejected with `RequestValidationError("Dmint must wrap the actual function, not a functools-wrapped callable")`.
  3. **Undecorated Functions Bypass:** Holding a reference to the unadorned function allows direct execution without authorization.
  4. **Positional vs Keyword Normalization:** `signature.bind(*args, **kwargs)` and `apply_defaults()` normalize positional and keyword arguments to identical argument dictionaries and fingerprints.
  5. **Default Arguments Normalization:** Default arguments are populated prior to hashing, ensuring identical fingerprints regardless of whether default arguments are specified or omitted.
  6. **Exception After Consume:** If a protected function raises an exception during execution, the approval record remains `CONSUMED`. Retrying fails closed with `ApprovalConsumedError` (`DMT_APPROVAL_CONSUMED`).
- **Identified Gaps & Weaknesses:**
  1. **Generator Lazy Execution Bypass:** Generator functions (`def f(): yield ...`) are NOT rejected by `_validate_function`. Decorating a generator function causes `execute()` to return a generator object immediately without executing the generator body. The actual execution runs lazily outside Dmint when `next()` is called.
  2. **Incompatibility with Methods and Classmethods:** Decorating instance methods passes `self`, and decorating classmethods passes `cls`. Because `self` and `cls` are non-serializable objects, RFC 8785 canonicalization raises `CanonicalizationError` at `arguments.self` / `arguments.cls`, wrapping into `AuthorizationError`. Static methods succeed only if `@staticmethod` is placed above `@protect`.
  3. **Address Reuse in `_registered`:** `self._registered` keys bindings by integer memory address (`id(target)`, `id(guarded)`) and does not clean them up on garbage collection. In `_prepare_call`, line 373 falls back to `self._registered.get(id(function))`. When CPython reuses memory addresses for newly created functions, unrelated functions inherit stale capability bindings.
- **Verdict:** **PARTIAL**.
