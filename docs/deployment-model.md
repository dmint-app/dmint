# Dmint Deployment & Threat Model

This document outlines the security architecture, trust boundaries, and credential management best practices for running Dmint services in production and local environments.

---

## 1. Dashboard Deployment & Credential Management

The Dmint Dashboard (`dmint dashboard`) provides a local web UI for human operators to inspect pending tool call requests, review request arguments, and record cryptographic approval or rejection decisions.

### Credential Visibility & Storage

When configuring authentication for the dashboard, consider process isolation on multi-tenant or shared hosts:

1. **CLI Arguments (`--auth-token <token>`) — INSECURE on shared hosts**:
   Command-line arguments are exposed in the system process table (via `ps aux`, `top`, or `/proc/<pid>/cmdline`) and can be inspected by any local user or unprivileged process on the host. **Do not use command-line flags to pass passwords or tokens in multi-user environments.**

2. **Environment Variables (`DMINT_DASHBOARD_TOKEN`) — CAUTION**:
   Environment variables are visible to other processes running under the same user UID via `/proc/<pid>/environ`. If an untrusted agent or script runs under the same OS user account, it can read the environment variables of sibling processes.

3. **Restricted Token Files (`--token-file /path/to/token`) — RECOMMENDED**:
   Store the authentication token in a dedicated file readable strictly by the owner:
   ```bash
   # Generate a high-entropy token and set strict 0600 permissions:
   umask 077
   openssl rand -hex 32 > /etc/dmint/dashboard.token
   chmod 0600 /etc/dmint/dashboard.token
   ```
   Dmint **refuses to start** if the token file has permissions looser than `0600` (or `0400`).

4. **Ephemeral Startup Token — DEFAULT**:
   If neither `--auth-token`, `DMINT_DASHBOARD_TOKEN`, nor `--token-file` is configured, Dmint automatically generates a cryptographically secure random 256-bit token (`secrets.token_urlsafe(32)`) at boot and prints it once to `stderr`/the operator terminal.

---

## 2. Network Exposure & Binding Policy

By default, the dashboard binds exclusively to the loopback interface (`127.0.0.1`):

- **Default Loopback Binding**: Refuses all incoming traffic from external network interfaces.
- **Strict Non-Loopback Refusal**: Binding to any non-loopback address (including `0.0.0.0`, `::`, or private LAN IPs like `192.168.1.5` and `10.0.0.1`) is **strictly refused** unless the operator explicitly supplies the `--allow-public-bind` CLI flag.
- **DNS Rebinding Defense**: Enforces a strict Host header allowlist (`localhost`, `127.0.0.1`, `[::1]`, plus explicitly configured hosts). Requests bearing unauthorized Host headers (e.g. from DNS rebinding attempts) are rejected with `400 Bad Request`.
- **Cross-Origin Defense**: All state-changing requests (`/approvals/.../approve`, `/approvals/.../reject`, `/logout`) validate `Origin` and `Referer` headers against the allowed host list, and mandate cryptographic per-session CSRF tokens.

---

## 3. Approver Identity & Audit Attribution

- Every approval or rejection recorded in Core must be attributed to an explicitly configured approver (`--approver-id <name>` or `DMINT_APPROVER_ID`).
- Shared fallback constants (such as `"dashboard-human"`) are prohibited.
- The authenticated dashboard session identity is recorded directly in Core's cryptographic assertion records as the `decision_authority.subject_id`.
