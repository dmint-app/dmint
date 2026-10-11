# Phase 1: Architecture, Trust Boundaries & Key Invariant Verification

## 1. Import Graph & Layering Purity ([E-015])
- **Cycles:** Zero circular imports detected across all 78 source files.
- **Layering:** `src/dmint/core/` contains strictly zero imports from `dmint.mcp`, `dmint.dashboard`, `dmint.cli`, or `dmint.skills`.
- **Private Key Isolation:** Cryptographic private key imports (`load_private_key`, `write_private_key_atomic`, `SigningKey`) are strictly isolated to `dmint.core.authority`, `dmint.core.keys`, and `dmint.cli.keys`.

## 2. K-06 Fresh-Process Gateway Isolation Proof ([E-016])
- In a fresh Python process loading `dmint.mcp.gateway`, `dmint.mcp.__main__`, and `dmint.mcp.config_loader`:
  - `dmint.core.keys`, `dmint.cli.keys`, and `nacl.signing` are **completely absent** from `sys.modules`.
  - Module attribute inspection confirms `dmint.mcp.gateway` exposes 0 private key or signing attributes.
  - Gateway holds public key verification logic (`dmint.core.verification`) only. **Verdict: REAL.**

## 3. Trust Boundaries Table
| Component | Process & User Context | Secrets Held | Read/Write Capabilities | Attacker Agent Restrictions |
| :--- | :--- | :--- | :--- | :--- |
| **Protected Tool / Agent SDK (`@protect`)** | Host / Agent UID | None | In-memory execution only | Cannot execute without `ALLOW`; cannot mutate arguments post-authorization (TOCTOU). |
| **Core Evaluator (`Policy`)** | In-process library | None | In-memory policy rules | Cannot influence decision path; cannot bypass argument constraints. |
| **Approval Store (`SQLite` / `SQLAlchemy`)** | App process or Postgres daemon | DB credentials | `approval_records` DB table | Cannot tamper with rows; cannot un-consume consumed records; cannot replay assertions. |
| **Approval Authority (`dmint approve`)** | Operator / Admin CLI UID | Ed25519 Private Key (`0600`) | Signs assertion binaries | Agent process cannot read private key (`0600`); cannot forge assertions. |
| **MCP Gateway (`dmint-mcp`)** | Dedicated gateway proxy UID | Public keys only (`trusted_issuers`) | Reads JSON-RPC; validates tokens | Cannot execute unauthorized tools; cannot spoof agent identity; cannot access private keys. |
| **Local Dashboard (`dmint-dashboard`)** | Web server process (FastAPI) | Bearer auth token, Session secret | Reads/Writes pending approvals | Cannot bypass CSRF / Host allowlists; cannot inject SQL. |

## 4. Exact Execution Call Sites & Invariant Proof ([E-017], [E-018])
- **Grep Call Sites ([E-017]):**
  - Decorator execution: `src/dmint/core/enforcement.py:515` inside `_execute_snapshot()`, reached exclusively via `execute()` (line 499) after `_evaluate()` returns ALLOW, or via `retry()` (line 601) after `consume_approved()`.
  - Gateway forwarding: `src/dmint/mcp/proxy.py:326` and `430` inside `route_call()` and `retry_call()`, reached exclusively on ALLOW or post-atomic consumption.
- **Runtime Spy Invariant Proof ([E-018]):**
  - Instrumented downstream spy subjected to 6 hostile request profiles in both modes:
    1. Explicitly DENIED action
    2. APPROVAL_REQUIRED action without approval
    3. Constraint-violating / schema-violating arguments
    4. Unknown / unbound tool name
    5. Invalid resource (path traversal `/../etc/passwd`)
    6. Error-inducing argument (NaN float for integer)
  - **Result:** Downstream spy execution count was exactly **0** in both Decorator mode and MCP Gateway mode. Zero execution bypasses exist.

## 5. Public API Export & Documentation Parity ([E-019])
- Confirmed documented public exports: `Dmint`, `Policy`, `Rule`, `Decision`, `ToolRequest`, `AuthorizedRequest`, `ApprovalRecord`, `ApprovalAuthority`, `SQLiteApprovalStore`, `SQLAlchemyApprovalStore`.
- **Discrepancies Found:**
  - `PolicyEvaluator`: Documented in older materials, but missing from public exports (evaluation is handled directly via `Policy.evaluate` / `Policy.evaluate_detailed`).
  - `protect`: Module-level function `dmint.protect` does not exist; decorator is an instance method (`dmint_instance.protected()` / `dmint_instance.authorize()`).

## 6. Code Smells Census ([E-020])
- Total code smells across `src/`: 76 items.
- Dangerous calls: `eval` (0), `exec` (0), `pickle` (0), `yaml.load` (0), `subprocess(shell=True)` (0).
- Assert statements: 3 instances in `src/dmint/mcp/proxy.py` (lines 534, 548, 607) used exclusively for mypy type narrowing after explicit `_check_ready()` validation.
- Broad except blocks: 17 instances of `except Exception: pass` found in CLI wizards (`create_mcp_policy.py`, `mcp_oauth.py`) and non-critical cleanup logic (flagged for review).
