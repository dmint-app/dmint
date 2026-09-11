# Dmint (Core)

> **AI agents can request actions. Dmint deterministically decides whether those actions may execute.**

`dmint` is the core deterministic authorization and security enforcement primitive for AI-agent tool execution. It acts as an in-process security boundary between AI model tool requests and privileged system execution.

```text
┌─────────────────┐
│    AI Agent     │
└────────┬────────┘
         │ tool request
         ▼
┌─────────────────┐
│      Dmint      │
│                 │
│   ├─ ALLOW ───────────────────┐
│   ├─ DENY ──► Fail Closed     │
│   └─ APPROVAL_REQUIRED ──┐    │
└──────────────────────────┼────┼─┘
                           │    │
                   Persist │    │ Execute
                   Request │    │ Tool
                           ▼    ▼
┌─────────────────────────────────┐
│         Protected Tool          │
└─────────────────────────────────┘
```

## Core Principles

- **Deterministic Enforcement:** Runtime authorization is governed strictly by code and deterministic policy. An LLM never makes runtime authorization decisions.
- **Fail-Closed:** If Dmint cannot prove an action is allowed, execution is stopped immediately.
- **Pre-Execution Control:** Policy evaluation occurs *before* any tool code runs, never retroactively.
- **Exact Request Binding:** Human approvals bind to the exact SHA-256 canonical request fingerprint (agent, tool, action, resource, argument values, policy provenance).
- **Single-Use & Replay Protection:** Approved credentials are consumed atomically in SQLite storage; replay attempts fail closed.

## Installation

```bash
pip install dmint
```

## Quickstart

```python
from dmint import Dmint, Policy, TrustedContext, Decision, ApprovalRequiredError

# 1. Define authoritative policy
policy = Policy.from_mapping({
    "rules": [
        {"effect": "allow", "tool": "database", "action": "read", "resource": "*"},
        {"effect": "approval_required", "tool": "database", "action": "update", "resource": "*"},
        {"effect": "deny", "tool": "database", "action": "delete", "resource": "*"},
    ]
})

dmint = Dmint(policy=policy, agent_id="agent-prod")

# 2. Protect functions using the @dmint.protected decorator
@dmint.protected("database.delete")
def delete_user(user_id: int):
    # This code only runs if Dmint evaluates ALLOW
    return f"Deleted user {user_id}"

# 3. Execution attempts
try:
    delete_user(123)
except Exception as exc:
    print(exc)  # AuthorizationError: DMT_POLICY_DENIED (Fail closed)
```

## Exact Request Binding & Approval Lifecycle

Human approval is not a generic permission grant—it authorizes one exact request payload:

```text
Tool Request
     ↓
RFC 8785 JCS Canonicalization
     ↓
SHA-256 Request Fingerprint
     ↓
APPROVAL_REQUIRED (persisted in SQLite)
     ↓
Trusted Human Approval (Ed25519 assertion)
     ↓
Retry & Re-verify (Current Policy + Replay + Single-use Check)
     ↓
Execute Tool
```

## What Dmint Is NOT

- **Not an LLM or Model Guardrail:** Dmint does not perform prompt scanning or semantic intent analysis.
- **Not General IAM/RBAC:** Dmint answers *“May this AI-generated tool call run right now?”*, not general human authentication.
- **Not a Direct Bypass Barrier:** If an agent has direct shell access, DB credentials, or Docker daemon access outside Dmint, an in-process Python decorator cannot prevent out-of-band execution.

## Testing

Run the core security and unit test suite:

```bash
pytest -v
```

## License

Apache-2.0
