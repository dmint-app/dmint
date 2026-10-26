# `dmint.cli`

Developer CLI, agent harness hook manager, and policy authoring toolkit for Dmint (`v2.0.4`).

`dmint.cli` provides a fast, unified command-line interface for bootstrapping project security (`dmint init`), running end-to-end security diagnostics (`dmint doctor`), managing pre-tool hooks across 6 AI coding harnesses (`dmint hook`), authoring policies via 4 offline or AI-assisted modes (`dmint create-policy` and `dmint create-mcp-policy`), managing human approvals (`dmint pending`, `dmint approve`, `dmint reject`), and managing Ed25519/HMAC keys (`dmint init-keys`, `dmint export-public-key`).

---

## Installation

```bash
pip install dmint
dmint --version
# Output: dmint 2.0.4
```

---

## Primary Commands

### 1. `dmint init` & `dmint doctor`
```bash
# Bootstrap keys (.dmint/), per-harness policies (.dmint/policies/<harness>.policy.json), and hooks:
dmint init --harness all --templates shell,filesystem,postgres

# Run 4-vector security self-test, cryptographic check, and hook/policy verification:
dmint doctor
```

### 2. `dmint check`
Simulate how `policy.json` evaluates any tool call directly from your terminal:
```bash
dmint check shell.execute -r "git status"           # -> ALLOW (exit 0)
dmint check shell.execute -r "git push origin main" # -> APPROVAL_REQUIRED (exit 1)
dmint check shell.execute -r "rm -rf /"             # -> DENY (exit 2)
```

### 3. `dmint create-policy` (4 Policy Creation Modes)
```bash
# Mode 1: Built-in domain templates (100% offline, instant)
dmint create-policy --template shell,filesystem,postgres,stripe -o policy.json

# Mode 2: Repeatable inline rule flags (100% offline, scriptable)
dmint create-policy -r "allow:postgres.select:users" -r "approval_required:stripe.refund:*" -o policy.json

# Mode 3: Interactive terminal rule builder (100% offline)
dmint create-policy --interactive -o policy.json

# Mode 4: AI-assisted natural language prompt or markdown file (OpenAI / Gemini / Groq / Ollama)
dmint create-policy --prompt "Allow read-only SQL queries, require approval for schema changes" -o policy.json
dmint create-policy -f access.md -o policy.json -y
```

### 4. `dmint create-mcp-policy` (Offline Auto-Classification or AI-Assisted)
```bash
# 100% Offline mode (discovers live MCP tools, pins SHA-256 schema_hash, auto-classifies effects without an API key):
dmint create-mcp-policy --command npx --args -y @modelcontextprotocol/server-postgres --integration-id postgres --offline -y

# AI-assisted mode with natural-language requirements:
dmint create-mcp-policy --url https://mcp.example.com/api -f access.md -o policy.json --config-output mcp_protection.json
```

### 5. `dmint verify-policy` & `dmint policy-digest`
```bash
dmint verify-policy policy.json [--json]
dmint policy-digest policy.json [--json]
```

### 6. `dmint pending`, `dmint approve`, `dmint reject` (`deny`), & `dmint dashboard`
```bash
dmint pending [--json]
dmint approve <approval_id> --by alice@company.com --reason "Approved production action"
dmint reject <approval_id> --by alice@company.com --reason "Blocked"
dmint dashboard --db-path ./.dmint/approvals.sqlite3 --port 8080
```

### 7. `dmint init-keys` & `dmint export-public-key`
```bash
dmint init-keys --dir /etc/dmint/keys
dmint export-public-key --dir /etc/dmint/keys --json
```

### 8. `dmint logs` (`dmint audit`), `dmint demo` (`dmint redteam`), & `dmint learn-policy`
```bash
# View, filter, tail, export, and cryptographically verify .dmint/audit.jsonl:
dmint logs --level WARNING
dmint logs --denied
dmint logs --verify
dmint logs --stats
dmint logs --follow

# Run the 7-scenario live red-team attack simulation:
dmint demo

# Auto-learn a verified least-privilege policy.json from observed shadow/enforce logs:
dmint learn-policy --from-logs .dmint/audit.jsonl -o policy.json
```
