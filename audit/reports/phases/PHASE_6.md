# Phase 6: Dashboard and Notifications

**Run ID:** `audit_runs/20261010-1033-de708c6`  
**Target:** Dmint `de708c6` (`phase6c-final`)  
**Status:** COMPLETE (6 of 6 items verified with runtime evidence)

---

## 1. Executive Summary

Phase 6 audited the human approval dashboard (`src/dmint/dashboard/`), outgoing notification webhooks (`src/dmint/core/webhooks.py`), and database credential redaction (`src/dmint/core/redaction.py`) across properties `K-01`, `K-02`, `K-03`, `K-16`, `K-29`, and `K-30`.

Testing verified comprehensive defenses against CSRF, DNS rebinding, session fixation, and database credential leakage. The audit uncovered **3 notable findings/vulnerabilities**:
1. **Webhook Notification Mention Injection & SSRF (`K-16`):** Outgoing Slack/Discord/Teams webhook formatters do not sanitize broadcast mentions (`@channel`, `@everyone`, `<!here>`) or markdown links from agent-controlled text. In addition, outgoing webhook dispatch uses raw `urllib.request.urlopen` with zero SSRF validation or private IP filtering.
2. **Dashboard Nested Arguments Render Failure (`K-02`):** In `routes.py:80`, `json.dumps(dict(record.request.arguments))` shallow-copies the top-level mappingproxy. Any request with nested dictionary arguments fails JSON serialization with `TypeError: Object of type mappingproxy is not JSON serializable` and renders `(could not render)` in the human approval UI.
3. **Unclosed SQLite Connection Warning on Python 3.13 (`K-30`):** `ThreadSafeApprovalStore` allocates thread-local `SQLiteApprovalStore` instances at `src/dmint/core/storage/sqlite.py:279`. When FastAPI threadpool workers terminate, connections are unclosed until GC, triggering `ResourceWarning: unclosed database`.

| Ledger ID | Property | Verdict | Evidence ID | Exit Code | Summary |
|---|---|---|---|---|---|
| **K-01** | Dashboard approve/reject protections | **REAL** | `[E-064]` | `rc=0` | CSRF token required, Origin/Referer checked on POST, Host header allowlist blocks DNS rebinding on all requests (including Bearer), non-loopback bind refused without flag, session regenerated on login, 30m idle / 12h hard expiries enforced. |
| **K-02** | Dashboard stored XSS from agent text | **REAL** | `[E-064]` | `rc=0` | Jinja2 autoescape strictly active; zero `|safe` filters in templates; hostile script/img payloads escaped in index and detail pages. Bug noted: nested arguments fail `json.dumps` and render `(could not render)`. |
| **K-03** | Login limiter bypass & token exposure | **REAL** | `[E-064]` | `rc=0` | 5-attempt limiter locks out with 429; `X-Forwarded-For` spoofing does not bypass limiter (`client_ip = request.client.host`); token never exposed in URLs, query params, or logs; token file requires 0600/0400. |
| **K-16** | Secret leakage & notification injection | **PARTIAL** | `[E-065]` | `rc=0` | Postgres password variants, percent-encoding, unescaped `@`/`/`, libpq strings, and driver error texts redacted by `redact_database_url`. Gaps: webhook payloads lack mention/markdown escaping (`@everyone` passes); webhook URL lacks SSRF validation. |
| **K-29** | Pydantic Field alias warning | **REAL** | `[E-064]` | `rc=0` | Dashboard handlers do not use Pydantic models or `Field(alias=...)`; form parameters use standard FastAPI `Form(...)` primitives with zero alias warnings or binding errors. |
| **K-30** | Unclosed sqlite connections on Python 3.13 | **REAL** | `[E-063]` | `rc=0` | Confirmed via Python 3.13 `-X tracemalloc=25 -W error::ResourceWarning`. Allocation site: `src/dmint/core/storage/sqlite.py:279` via `ThreadSafeApprovalStore` in `src/dmint/core/storage/thread_safe.py:99`. |

---

## 2. Detailed Findings by Item

### K-01: Dashboard Approve/Reject Protections (`E-064`)
- **Target:** `src/dmint/dashboard/app.py`, `src/dmint/dashboard/routes.py`, `src/dmint/dashboard/__main__.py`
- **Evidence:** `[E-064]` (`audit_scratch/test_phase6_dashboard.py`, `rc=0`)
- **Evaluated Defenses:**
  1. **Authentication Enforcement:** Unauthenticated GET requests to protected dashboard routes redirect to `/login?next=...` with HTTP 303. Unauthenticated API requests return HTTP 401 Unauthorized.
  2. **Host Header Validation (DNS Rebinding Defense):** Middleware verifies `Host` header against `allowed_hosts` (`localhost`, `127.0.0.1`, `[::1]`). Any foreign `Host` header (e.g. `evil.com`) returns HTTP 400 `Invalid Host header (DNS rebinding protection)`. This check applies to all requests, including requests carrying valid Bearer tokens.
  3. **Origin & Referer Validation:** Browser POST requests without Origin and Referer headers return HTTP 403 `missing_origin_referer`. Requests with foreign Origins return HTTP 403 `invalid_origin`.
  4. **CSRF Token Verification:** State-changing POST requests require a valid CSRF token matching the session. Requests with missing or invalid CSRF tokens return HTTP 403 `invalid_csrf_token`.
  5. **Session Regeneration:** Upon successful authentication, any pre-existing session ID is invalidated and a fresh cryptographically random session ID and CSRF token are generated.
  6. **Idle and Hard Expiration:** Sessions expire after 30 minutes of inactivity (`last_active`) or 12 hours total duration (`expires_at`).
  7. **Non-Loopback Interface Restriction:** `dmint-dashboard` CLI verifies bind host using `ipaddress.ip_address`. Binding to `0.0.0.0` or non-loopback addresses is refused unless `--allow-public-bind` is explicitly passed.

---

### K-02: Dashboard Stored XSS from Agent-Controlled Text (`E-064`)
- **Target:** `src/dmint/dashboard/templates/`, `src/dmint/dashboard/routes.py`
- **Evidence:** `[E-064]` (`audit_scratch/test_phase6_dashboard.py`, `rc=0`)
- **Evaluated Payloads:**
  - `agent_id`: `<script>alert('xss_agent')</script>`
  - `tool`: `"><img src=x onerror=alert(1)>`
  - `resource`: `javascript:alert('xss_res')`
  - `arguments`: `{"payload": "<svg/onload=alert('arg')>", "bidi": "‮RTL_OVERRIDE"}`
- **Results:**
  - Index page (`/`) and detail page (`/approvals/{id}`) render all hostile values HTML-escaped (`&lt;script&gt;`, `&#34;&gt;&lt;img`, `&lt;svg/onload`).
  - Zero raw script or image tags appear in the HTML source.
  - Grepped all templates in `src/dmint/dashboard/templates/`: zero instances of Jinja2 `|safe` filter exist.
  - Security headers present on all responses: `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Cache-Control: no-store`.
- **Architectural Bug Discovered:**
  - In `src/dmint/dashboard/routes.py:80`:
    ```python
    try:
        args_json = json.dumps(dict(record.request.arguments), indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        args_json = "(could not render)"
    ```
  - `record.request.arguments` contains frozen `mappingproxy` dictionaries. Calling `dict(record.request.arguments)` only converts the top-level mapping, leaving nested dictionaries as `mappingproxy` objects.
  - Because Python's `json.dumps` cannot serialize `mappingproxy`, any request with nested arguments fails with `TypeError` and renders as `(could not render)` in the arguments panel. The fix is calling `thaw_json(record.request.arguments)` before serialization.

---

### K-03: Login Limiter Bypass and Token Exposure (`E-064`)
- **Target:** `src/dmint/dashboard/auth.py`, `src/dmint/dashboard/routes.py`
- **Evidence:** `[E-064]` (`audit_scratch/test_phase6_dashboard.py`, `rc=0`)
- **Key Findings:**
  1. Failed login attempts increment an in-memory sliding window counter per client IP. After 5 failures within 60 seconds, subsequent login attempts return HTTP 429 Too Many Requests.
  2. `routes.py:139` extracts `client_ip = request.client.host`. Spoofing `X-Forwarded-For` or `X-Real-IP` headers does not affect `client_ip` or bypass the rate limiter.
  3. The authentication token is never rendered in HTML forms, URLs, query parameters, or redirect locations.
  4. `load_token_from_file` validates POSIX file permissions, strictly rejecting token files with permissions looser than `0600`/`0400` (`mode & 0o077 != 0`).

---

### K-16: Secret Leakage and Notification Injection (`E-065`)
- **Target:** `src/dmint/core/redaction.py`, `src/dmint/core/webhooks.py`
- **Evidence:** `[E-065]` (`audit_scratch/test_phase6_webhooks.py`, `rc=0`)
- **Evaluated Credential Redaction:**
  - Tested `redact_database_url` on 7 PostgreSQL credential formats:
    - Standard URI: `postgresql://user:pass@host/db` -> password redacted
    - Password-only URI: `postgresql://:pass@host/db` -> password redacted
    - Percent-encoded: `postgresql://user:p%40ss%2Fword@host/db` -> password redacted
    - Raw special chars: `postgresql://user:pass@word/foo@host/db` -> password redacted
    - Query parameters: `?password=...&sslkey=...` -> all sensitive parameters redacted
    - libpq format: `host=... password=... dbname=...` -> password redacted
    - Driver error text: operational errors with embedded URIs -> URIs redacted
  - `_format_approve_cmd` in `webhooks.py:48-50` deliberately omits `database_url` from generated approval commands, preventing credential leakage in notifications.
- **Identified Notification Vulnerabilities:**
  1. **Mention & Formatting Injection:** Slack, Discord, and Microsoft Teams payload formatters directly embed `agent_id`, `tool`, `action`, and `resource` into markdown fields without filtering broadcast pings (`@everyone`, `@channel`, `<!here>`) or markdown links. A malicious agent can trigger channel-wide notifications or embed phishing links into notifications.
  2. **Webhook URL Lacks SSRF Protection:** `_post_json` dispatches notifications using raw `urllib.request.urlopen` without URL scheme/IP validation or redirect restriction. Webhooks configured to internal services can be targeted by SSRF.

---

### K-29: Pydantic Field Alias Warning (`E-064`)
- **Target:** `src/dmint/dashboard/routes.py`
- **Evidence:** `[E-064]` (`audit_scratch/test_phase6_dashboard.py`, `rc=0`)
- **Finding:** Dashboard handlers do not use Pydantic models or `Field(alias=...)`. All form parameters are standard FastAPI `Form(...)` arguments. Zero alias warnings, serialization warnings, or binding errors occur in dashboard routes.

---

### K-30: Unclosed SQLite Connections on Python 3.13 (`E-063`)
- **Target:** `src/dmint/core/storage/sqlite.py`, `src/dmint/core/storage/thread_safe.py`
- **Evidence:** `[E-063]` (`audit_runs/20261010-1033-de708c6/logs/E-063.log`, `rc=0`)
- **Reproduction & Tracemalloc Allocation Backtrace:**
  - Ran pytest suite under official `python:3.13-slim` container with `-X tracemalloc=25 -W error::ResourceWarning`.
  - Python 3.13 garbage collector triggered `ResourceWarning: unclosed database in <sqlite3.Connection object>`, caught as `PytestUnraisableExceptionWarning`.
  - **Exact Allocation Sites in `src/`:**
    1. `src/dmint/core/storage/sqlite.py:279`:
       `self._connection = sqlite3.connect(db_str)`
    2. Instantiated by `src/dmint/core/storage/thread_safe.py:99`:
       `store = SQLiteApprovalStore(database=..., deployment_epoch=..., clock=...)`
    3. Called by `ThreadSafeApprovalStore._get_current_store()` in `src/dmint/core/storage/thread_safe.py:162`.
    4. Invoked during dashboard route handling in `src/dmint/dashboard/routes.py:296` (`client.list_pending`) and `routes.py:411` (`client.approve`).
  - **Root Cause:** `ThreadSafeApprovalStore` uses `threading.local()` to allocate a connection per thread. When worker threads terminate in FastAPI, connections are unclosed until GC triggers `ResourceWarning`.
