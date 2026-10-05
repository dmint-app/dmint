# `dmint.mcp`

Security enforcement gateway and transparent proxy for Model Context Protocol (MCP) servers.

`dmint.mcp` connects AI agents (Cursor, Claude Code, Antigravity, custom MCP clients) to downstream MCP servers under deterministic policy enforcement. It intercepts protocol invocations, blocks unapproved actions before they reach downstream server processes, and protects remote endpoints against SSRF and metadata exfiltration.

---

## Installation

Included in `dmint` with the `mcp` extra:

```bash
pip install "dmint[mcp]"
```

---

## Architecture & Features

```
[ AI Agent / MCP Client ]
          │ (stdio or HTTP)
          ▼
┌──────────────────────────────────────┐
│          Dmint MCP Gateway           │
│  - tools/list discovery filtering    │
│  - SSRF & IP address validation      │
│  - tools/call policy enforcement     │
│  - Human approval state verification │
└──────────────────┬───────────────────┘
                   │ (stdio or HTTP)
                   ▼
       [ Downstream MCP Server ]
     (Postgres, Git, Filesystem)
```

- **Pre-Execution Gate**: Halts `tools/call` requests with `DENY` or `APPROVAL_REQUIRED` before child process or network transmission.
- **SSRF Defense**: Validates remote HTTP endpoints against RFC 1918 private IPs, loopback interfaces (`127.0.0.1`), link-local IPs, and cloud instance metadata endpoints (`169.254.169.254`).
- **Multi-Server Aggregation**: Routes and namespaces tools across multiple downstream servers with conflict-free capability mapping.
- **Atomic Approval Consumption**: Verifies Ed25519-signed human approval assertions and consumes them atomically in SQLite before executing approved retries.

---

## Configuration Example (`mcp_protection.json`)

```json
{
  "policy_file": "policy.json",
  "approval_db": "./approvals.sqlite3",
  "approval_ttl": 300,
  "integrations": [
    {
      "integration_id": "postgres-prod",
      "transport": "stdio",
      "connection": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
      },
      "tool_bindings": {
        "query": {
          "tool_name": "query",
          "capability": "postgres.query",
          "discovery": "exposed"
        }
      }
    }
  ]
}
```

---

## Running the Gateway

```bash
# Start the gateway with a configuration file:
dmint-mcp run --config mcp_protection.json
```

Or configure your AI coding assistant (e.g. `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "protected-db": {
      "command": "dmint-mcp",
      "args": ["run", "--config", "/path/to/mcp_protection.json"]
    }
  }
}
```
