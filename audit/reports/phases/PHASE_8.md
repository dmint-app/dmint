# Phase 8: Attacker Simulation with Real Processes

**Run ID:** `audit_runs/20261010-1033-de708c6`  
**Target:** Dmint `de708c6` (`phase6c-final`)  
**Status:** COMPLETE (3 of 3 items verified with real OS and container execution)

---

## 1. Executive Summary

Phase 8 executed empirical attacker simulations against Dmint's core assets across three real operational isolation boundaries:
1. **Same OS User Context:** Host user (`admin`, UID 1001) executing both the agent tool-calling process and the Dmint services.
2. **Different OS User Context:** Unprivileged user (UID 1002) executing inside a container mounting the host's files and inspecting host processes (`--pid=host`).
3. **Separate Isolated Container:** Fully isolated container with bridge networking, separate PID namespaces, and unmounted filesystems.

The experiments empirically proved the critical threat model invariant outlined in `docs/deployment-model.md`: **Dmint does NOT provide an authorization boundary against an attacker running under the same OS user context.** Every primary asset (signing key, approvals SQLite database, dashboard token, policy file, MCP client config, and gateway process) can be inspected, exfiltrated, or modified by a same-user agent to achieve complete authorization bypass or self-approval. 

Conversely, when agents and Dmint run as **different OS users** or in **separate containers**, Linux kernel discretionary access control (file modes `0600`/`0400`, process UID boundaries) and container namespace isolation completely block unauthorized access.

| Ledger ID | Property | Verdict | Evidence ID | Exit Code | Summary |
|---|---|---|---|---|---|
| **K-04** | Same-user attacker reads secrets | **REAL** | `[E-067]` | `rc=0` | Same-user attacker successfully exfiltrates Ed25519 signing key, tampers with SQLite DB, reads dashboard token from `/proc/<pid>/environ`, self-approves tool requests via HTTP API, modifies `policy.json` to ALLOW, and redirects MCP client configs. Different user and container contexts are BLOCKED. |
| **K-24** | Policy integrity | **CLAIM-ONLY / REAL** | `[E-059]`, `[E-067]` | `rc=0` | Policy digest pinning and remote CDN loading remain **CLAIM-ONLY**. Same-user attacker can overwrite `policy.json` and reload/restart the gateway process to achieve unauthorized `ALLOW` execution. Different user cannot overwrite file. |
| **K-34** | Deployment-model doc accuracy | **REAL** | `[E-067]`, `[E-068]` | `rc=0` | All 10 architectural statements in `docs/deployment-model.md` (shared user compromise, `/proc/cmdline` exposure of `--auth-token`, `/proc/environ` visibility, 0600 token enforcement, loopback bind refusal, origin checks) verified 100% accurate against runtime tests. |

---

## 2. Attack Matrix & Defense Analysis

The empirical attack simulation produced the matrix recorded in [`tables/attack_matrix.csv`](file:///home/admin/dmint/audit_runs/20261010-1033-de708c6/tables/attack_matrix.csv):

| Asset | Same OS User | Different OS User | Isolated Container | Primary Defense Mechanism | Evidence ID |
|---|---|---|---|---|---|
| **Signing Key (`signing.key`)** | **SUCCEEDED** | **BLOCKED** | **BLOCKED** | OS file permissions (mode `0600`, owner UID) | `[E-067]` |
| **Approvals DB (`approvals.sqlite3`)** | **SUCCEEDED** | **BLOCKED** | **BLOCKED** | OS file permissions (mode `0600`, owner UID) | `[E-067]` |
| **Dashboard Token** | **SUCCEEDED** | **BLOCKED** | **BLOCKED** | `/proc/<pid>/environ` (mode 0400) + mode `0600` token file + 127.0.0.1 netns | `[E-067]` |
| **Policy File (`policy.json`)** | **SUCCEEDED** | **BLOCKED** | **BLOCKED** | OS file write permissions + process signal isolation (`EPERM`) | `[E-067]` |
| **MCP Client Config** | **SUCCEEDED** | **BLOCKED** | **BLOCKED** | OS file permissions (mode `0600`, owner UID) | `[E-067]` |
| **Gateway Process** | **SUCCEEDED** | **BLOCKED** | **BLOCKED** | Linux kernel process UID boundary (`kill`/`ptrace` `EPERM`) | `[E-067]` |

### Defenses Relying Exclusively on File Permissions
- **Signing Key Protection:** Relies *entirely* on mode `0600`/`0400` file permissions on `signing.key` and its parent directory (`0700`). There is no hardware enclave, TPM, or OS keyring integration in standard file loading mode. Any process with read permissions on the key file can instantiate `LocalApprovalAuthority` and self-sign valid assertions.
- **Approvals DB Integrity:** Relies *entirely* on filesystem permissions on `approvals.sqlite3`. Because the database row integrity checksum is unkeyed SHA-256 (`K-21`), any process that can write to the SQLite file can tamper with records and recompute valid checksums.
- **MCP Client Bypass Prevention:** Relies *entirely* on protecting the client configuration file (e.g. `claude_desktop_config.json`). If an agent has write access to this configuration, it can redirect downstream tool execution away from the Dmint proxy.

---

## 3. Detailed Findings by Item

### K-04: Same-User Attacker Secret Exfiltration and Self-Approval (`E-067`)
- **Target:** `src/dmint/core/keys.py`, `src/dmint/dashboard/app.py`, `src/dmint/core/storage/sqlite.py`
- **Evidence:** `[E-067]` (`audit_scratch/test_phase8_runner.py`, `rc=0`)
- **Simulated Attacks & Outcomes:**
  1. **Signing Key Exfiltration & Self-Signing (`SUCCEEDED` under same user):**
     - An agent running as the same user reads `signing.key` via standard file I/O.
     - The agent calls `LocalApprovalAuthority(issuer_id=..., private_key=stolen_key).issue(record, approver)`.
     - The generated assertion passes full cryptographic verification via `ApprovalVerifier.verify()`, completely bypassing the human approver.
     - When executed as a different user (UID 1002 in Docker), reading `signing.key` fails with `cat: /mnt/signing.key: Permission denied` (`rc=1`).
  2. **Approvals Database Tampering (`SUCCEEDED` under same user):**
     - The agent directly opens `approvals.sqlite3` via `sqlite3.connect()`.
     - The agent executes `UPDATE approval_records SET state = 'APPROVED' WHERE approval_id = ?`.
     - When executed as a different user (UID 1002), accessing the SQLite file fails with `Permission denied` (`rc=1`).
  3. **Dashboard Token Extraction & HTTP Self-Approval (`SUCCEEDED` under same user):**
     - The dashboard process was launched in the background with `DMINT_DASHBOARD_TOKEN=secret_audit_token_...`.
     - An agent process running as UID 1001 reads `/proc/<dash_pid>/environ`, parses null-delimited environment strings, and recovers the plaintext token.
     - The agent issues an HTTP request to `http://127.0.0.1:<port>/api/dashboard` bearing `Authorization: Bearer <stolen_token>`. The dashboard returns HTTP 200 OK.
     - When executed as a different user (UID 1002 with `--pid=host`), reading `/proc/<dash_pid>/environ` fails with `Permission denied` (`rc=1`).
  4. **CLI Argument Exposure (`docs/deployment-model.md` warning):**
     - When a process is started with `--auth-token <token>`, reading `/proc/<pid>/cmdline` succeeds across different OS users (`rc=0`), confirming the documentation warning that passing tokens via CLI flags is insecure on multi-tenant hosts.

---

### K-24: Policy Integrity & Modification Replay (`E-067`)
- **Target:** `src/dmint/policy.py`, `src/dmint/mcp/gateway.py`
- **Evidence:** `[E-059]` (Phase 4), `[E-067]` (Phase 8, `rc=0`)
- **Simulated Attacks & Outcomes:**
  1. **Policy File Overwrite (`SUCCEEDED` under same user):**
     - `policy.json` initially defined a strict rule denying execution (`effect: "deny", tool: "exec", action: "run"`).
     - The agent overwrites `policy.json` with an allow rule (`effect: "allow", tool: "exec", action: "run", resource: "*"`).
     - The agent reloads or restarts the gateway process. The new policy evaluates `ToolRequest(tool="exec", action="run")` to `Decision.ALLOW`.
     - When executed as a different user (UID 1002), writing to `policy.json` fails with `bash: /mnt/policy.json: Permission denied` (`rc=1`).
  2. **Gateway Hot-Reload Defense:**
     - The gateway does not dynamically watch or reload `policy.json` on the fly without a restart or reload trigger. However, because a same-user agent has permissions to send `SIGTERM` to the gateway PID, it can terminate and restart the gateway process at will.

---

### K-34: Deployment Model Documentation Accuracy (`E-068`)
- **Target:** `docs/deployment-model.md`
- **Evidence:** `[E-068]` (`audit_scratch/test_phase8_k34_doc_accuracy.py`, `rc=0`)
- **Verified Statements:**
  1. *Caution Callout (lines 7–17):* "Always run the Dmint Dashboard and AI agents as DIFFERENT OS users or in separate isolated containers." -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  2. *CLI Arguments (lines 29–30):* `--auth-token <token>` exposed via `/proc/<pid>/cmdline` to other local users. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  3. *Environment Variables (lines 32–34):* `DMINT_DASHBOARD_TOKEN` visible via `/proc/<pid>/environ` to sibling processes under the same UID. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  4. *Restricted Token Files (lines 35–43):* Dmint enforces `0600`/`0400` permissions and refuses to start if loose. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  5. *Loopback Binding (lines 52–55):* Binds exclusively to `127.0.0.1` and refuses non-loopback binds without `--allow-public-bind`. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  6. *DNS Rebinding & Host Allowlist (line 56):* Enforces strict Host header allowlist. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  7. *Exact Origin Checking (line 57):* State-changing POST requests validate full scheme, host, and port. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  8. *Approver ID Enforcement (line 65):* Prohibits shared fallback constants and requires explicit approver configuration. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
  9. *Key Isolation (line 93):* Private key must be readable ONLY by the approver process and gateway only sees public keys. -> **ACCURATE & EMPIRICALLY CONFIRMED.**
