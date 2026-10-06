# Dmint Deployment & Threat Model

This document outlines the security architecture, trust boundaries, and credential management best practices for running Dmint services in production and local environments.

---

> [!CAUTION]
> **CRITICAL OS PROCESS & USER ISOLATION BOUNDARY**
>
> **Always run the Dmint Dashboard and AI agents as DIFFERENT OS users or in separate isolated containers.**
>
> If an AI agent or any untrusted script executes under the **same OS user account** as the Dmint Dashboard or Core approval store:
> 1. It can read the dashboard authentication token directly via `/proc/<pid>/environ` or memory inspection.
> 2. It can directly read and write the SQLite approval database file or token files.
> 3. It can bypass the entire authorization gate.
>
> **Isolation Rule:** The human approver's dashboard process and private signing keys must run in a security context strictly isolated from any agent execution process.

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
- **DNS Rebinding Defense**: Enforces a strict Host header allowlist (`localhost`, `127.0.0.1`, `[::1]`, plus explicitly configured hosts). Requests bearing unauthorized Host headers (including `Authorization: Bearer` requests) are rejected with `400 Bad Request`.
- **Exact Full Origin Cross-Site Defense**: State-changing POST requests validate the full origin (`scheme://host:port`) against the dashboard's exact expected origin. Cross-port requests (e.g. `http://localhost:3000` attempting to submit to a dashboard on port 8080) are rejected with `403 Forbidden`.
- **Reverse Proxy Header Trust**: The `X-Forwarded-Proto` header is **ignored by default** to prevent scheme spoofing. Reverse proxy scheme forwarding is only honored when `--trusted-proxy` (or `DMINT_DASHBOARD_TRUSTED_PROXY=1`) is explicitly configured.
- **Session Lifecycles & Timeouts**: Authenticated web sessions enforce a 30-minute idle inactivity timeout alongside a 12-hour maximum hard session limit.

---

## 3. Approver Identity & Audit Attribution

- Every approval or rejection recorded in Core must be attributed to an explicitly configured approver (`--approver-id <name>` or `DMINT_APPROVER_ID`).
- Shared fallback constants (such as `"dashboard-human"`) are prohibited.
- **Self-Declared Operator Identity Caution**:
  The login form's optional "Operator Identity" field is a **self-declared audit label** tied to possession of the shared dashboard authentication token. It provides operator distinction in logs and Core records, but is **not** a cryptographically verified individual user authentication system.

---

## 4. Roadmap: Multi-User Identity & Per-Approver Tokens

Planned future enhancements for Dmint Dashboard identity management include:

1. **Per-Approver Authentication Tokens & Keyrings**:
   Individual approver accounts with dedicated tokens and Ed25519 signing keys, replacing the shared dashboard access token.
2. **OIDC / WebAuthn Hardware Key Authentication**:
   Integration with enterprise identity providers (Okta, GitHub, Google Workspace) and FIDO2 / WebAuthn hardware tokens for high-assurance cryptographic attestation of approval decisions.
3. **Multi-Party Quorum Approvals**:
   Requiring M-of-N distinct human approver signatures before sensitive high-impact capabilities (e.g. production DB migrations, financial transfers) can transition to `APPROVED`.
