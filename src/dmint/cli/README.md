# `dmint.cli`

Developer CLI and policy authoring toolkit for Dmint.

`dmint.cli` provides command-line tools for compiling natural language access requirements (`access.md`) into validated Dmint policies (`policy.json`), scanning policies for security vulnerabilities, discovering MCP tools, managing OAuth credentials, and launching the local human review dashboard.

---

## Installation

Included by default in the base `dmint` distribution:

```bash
pip install dmint
```

Verify installation:
```bash
dmint --version
# Output: dmint 2.0.0
```

---

## Command Reference

### 1. `dmint create-policy`
Compiles natural language access requirements or discovers local Python tool functions into a strict, validated policy file:

```bash
# Interactive mode:
dmint create-policy -f access.md -o policy.json

# Non-interactive mode (for CI/CD pipelines):
dmint create-policy -f access.md -o policy.json -y --provider openai
```

### 2. `dmint create-mcp-policy`
Connects to live downstream MCP servers, performs tool discovery, handles OAuth authentication, and outputs matching `policy.json` and `mcp_protection.json` configuration files:

```bash
dmint create-mcp-policy --url https://mcp.example.com/api --output-dir ./config
```

### 3. `dmint verify-policy`
Performs 100% offline schema validation, capability validation, and secret scanning on a `policy.json` file. Zero network traffic, zero LLM dependencies:

```bash
dmint verify-policy policy.json
```

Output:
```text
✓ Verified policy.json: 3 rule(s)
  [ALLOW] tool='database', action='select', resource='*'
  [APPROVAL_REQUIRED] tool='database', action='update', resource='*'
  [DENY] tool='database', action='drop', resource='*'
```

### 4. `dmint compile-policy`
Canonicalizes and compiles policy rules into deterministic, production-ready JSON artifacts:

```bash
dmint compile-policy policy.json -o compiled_policy.json
```

### 5. `dmint dashboard`
Starts the local human approval web dashboard connected to a Core SQLite store:

```bash
dmint dashboard --db-path ./approvals.sqlite3 --deployment-epoch prod-v1 --port 8080
```

### 6. `dmint install-skill`
Installs the official `dmint-policy-manager` AI agent skill into the current workspace for Cursor, Claude Code, or Antigravity:

```bash
dmint install-skill -y
# Installs to: .agents/skills/dmint-policy-manager/SKILL.md
```
