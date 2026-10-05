# `dmint.core`

The core deterministic policy authorization engine and storage subsystem of Dmint.

`dmint.core` provides the foundational cryptographic and policy evaluation primitives that power all higher-level Dmint components. It intercepts tool calls before execution, evaluates declarative policies without probabilistic models, and binds execution snapshots using RFC 8785 canonicalization.

---

## Key Modules

| Module | Purpose |
| :--- | :--- |
| [`policy.py`](policy.py) | Declarative policy rules (`Rule`, `Policy`, `Condition`, `Decision`). |
| [`enforcement.py`](enforcement.py) | Engine (`Dmint`), `@engine.protect(...)` decorator, snapshot binding, and atomic retry. |
| [`canonicalize.py`](canonicalize.py) | RFC 8785 JSON Canonicalization Scheme (JCS) and sensitive data redaction. |
| [`request_binding.py`](request_binding.py) | Domain-separated SHA-256 fingerprinting for tool requests and context. |
| [`storage/sqlite.py`](storage/sqlite.py) | Hardened SQLite approval state machine (`SQLiteApprovalStore`). |
| [`authority.py`](authority.py) | Ed25519 cryptographic approval assertions and signature verification. |
| [`models.py`](models.py) | Immutable request models (`ToolRequest`, `TrustedContext`, `AuthorizedRequest`). |

---

## Usage Example

```python
from datetime import datetime, timezone, timedelta
from dmint.core import (
    Dmint,
    Policy,
    Rule,
    Condition,
    Decision,
    TrustedContext,
    SQLiteApprovalStore,
    PolicyProvenance,
    policy_digest,
    ApprovalRequiredError,
    AuthorizationError,
)

# 1. Define declarative policy rules
policy = Policy(
    [
        Rule.allow("database", "select"),
        Rule.approval_required("database", "update", conditions=[Condition("env", "equals", "production")]),
        Rule.deny("database", "drop"),
    ]
)

# 2. Configure persistent SQLite store & policy provenance
store = SQLiteApprovalStore("./approvals.sqlite3", deployment_epoch="prod-v1")
provenance = PolicyProvenance("prod-v1", policy_digest(policy), datetime.now(timezone.utc))

# 3. Instantiate the engine
engine = Dmint(
    policy=policy,
    agent_id="agent-007",
    context=TrustedContext({"env": "production"}),
    approval_store=store,
    policy_provenance=provenance,
    approval_ttl=timedelta(minutes=15),
)


# 4. Decorate functions
@engine.protect("database.select")
def select_users(query: str) -> list[dict]:
    return [{"id": 1, "username": "alice"}]


@engine.protect("database.update")
def update_user_role(user_id: int, role: str) -> str:
    return f"Updated user {user_id} to {role}"


@engine.protect("database.drop")
def drop_table(table_name: str) -> str:
    return f"Dropped {table_name}"


# ALLOW: Runs immediately
users = select_users("SELECT * FROM users")
print(users)

# DENY: Raises AuthorizationError immediately
try:
    drop_table("users")
except AuthorizationError as exc:
    print(f"Blocked: {exc}")

# APPROVAL_REQUIRED: Suspends execution and writes pending record
try:
    update_user_role(1, "admin")
except ApprovalRequiredError as exc:
    print(f"Approval Required! ID: {exc.approval_id}")
    print(f"Fingerprint: {exc.request_fingerprint}")
```

---

## Security Invariants

- **Deny-overrides Precedence**: If any rule matches with `DENY`, the request is denied regardless of other matching rules.
- **Fail-Closed Default**: Requests matching no rules evaluate strictly to `DENY`.
- **Immutable Snapshots**: Tool call arguments are bound into an immutable snapshot before policy evaluation. Post-evaluation modifications are impossible.
- **Atomic Approval Consumption**: Approval records in SQLite transition (`PENDING` $\to$ `APPROVED` $\to$ `CONSUMED`) inside a single serialized transaction to prevent double-spending or replay attacks.
