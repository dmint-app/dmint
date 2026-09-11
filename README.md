# dmint (core)

`dmint` is the core deterministic authorization and enforcement primitive for AI-agent tool execution.

## Architecture & Security Boundary

Dmint enforces deterministic policy control pre-execution:

```text
AI AGENT → DMINT → PROTECTED TOOL
```

Runtime authorization decisions return `ALLOW`, `DENY`, or `APPROVAL_REQUIRED`. Dmint enforces fail-closed execution, canonical JSON request binding (RFC 8785), Ed25519 approval assertions, and replay/concurrency protection.

## Installation

```bash
pip install dmint
```

## Quickstart

```python
from dmint import Dmint, Policy

policy = Policy.from_mapping({
    "rules": [
        {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
        {"effect": "deny", "tool": "database", "action": "delete", "resource": "*"},
    ]
})

dmint = Dmint(policy=policy)

@dmint.protected("database.delete")
def delete_user(user_id: int):
    ...
```
