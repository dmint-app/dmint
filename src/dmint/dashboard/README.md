# `dmint.dashboard`

Local human approval web UI and FastAPI backend for Dmint.

`dmint.dashboard` provides real-time human oversight over AI agent tool calls. When a high-risk tool call triggers `APPROVAL_REQUIRED`, it is held in a pending state until a human operator inspects the request parameters in the dashboard and issues an Ed25519-signed approval assertion.

---

## Installation

Included in `dmint` with the `dashboard` extra:

```bash
pip install "dmint[dashboard]"
```

---

## Quickstart

Start the dashboard pointing to your Core SQLite database:

```bash
# Using dmint CLI:
dmint dashboard --db-path ./approvals.sqlite3 --deployment-epoch prod-v1 --port 8080

# Or using the dedicated entrypoint:
dmint-dashboard --db-path ./approvals.sqlite3 --deployment-epoch prod-v1 --port 8080
```

> **Important**: The `--deployment-epoch` parameter must match the `deployment_epoch` configured in the application runtime. Dmint uses deployment epochs to isolate environments—requests and approvals across mismatched epochs fail closed to prevent cross-environment replay attacks.

Open your browser at **http://127.0.0.1:8080** to view and act upon pending requests.

---

## Architecture & Security Boundaries

- **Zero Direct SQL**: The dashboard contains zero direct SQL queries and does not import `sqlite3`. It interacts with persistent storage strictly through Core public APIs (`list_pending()`, `approve_pending()`, `reject_pending()`).
- **Single Database Ownership**: `dmint.core` owns the SQLite schema; the dashboard never creates, alters, or directly manipulates database tables.
- **5-Second Short Polling**: Refreshes data automatically via `/api/dashboard` with in-flight lockouts and tab-visibility awareness (no WebSockets or complex background workers).
- **Local-Only Binding**: Binds to `127.0.0.1` by default without user authentication. Do not expose directly to public networks without an authenticating reverse proxy.
