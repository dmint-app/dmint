---
name: dmint-agent-execution
description: Rules for integrating Dmint with AI-agent tool calling, Python/TypeScript SDKs, decorators, middleware, and future MCP gateways while preserving the execution security boundary.
---

# Dmint AI-Agent Execution

## Purpose

Dmint exists at the execution boundary:

AI AGENT -> DMINT -> TOOL

The model is responsible for requesting/selecting an action. Dmint is responsible for deciding whether the action may execute.

## Tool-call lifecycle

```text
LLM output
   ↓
structured tool request
   ↓
Dmint request construction
   ↓
policy evaluation
   ↓
ALLOW / DENY / APPROVAL_REQUIRED
```

The LLM must never directly invoke a protected capability around Dmint.

## SDK integration

For developer-controlled functions, a decorator/wrapper is a good V1 integration:

```python
@dmint.protected("database.delete")
def delete_user(user_id: int):
    ...
```

The wrapper MUST perform authorization before calling the original function.

If the result is DENY:

- raise/return a structured denial
- do not invoke the function

If the result is APPROVAL_REQUIRED:

- persist the pending request
- raise/return a structured approval-required response
- do not invoke the function
- do not block waiting for a human

If the result is ALLOW:

- invoke the protected function

## Sync and async

If the SDK supports both sync and async functions, both paths must preserve identical security semantics.

Do not accidentally implement authorization in the sync wrapper but bypass it in the async wrapper.

Test both.

## Request/argument integrity

The wrapper should construct one well-defined request and authorize the same security-relevant values that will reach the protected function.

Avoid:

```text
authorize(request derived from A)
execute(values derived from B)
```

Prefer one consistent request path.

## Exception semantics

Authorization exceptions/results should be explicit and machine-readable.

Examples:

- DMT_POLICY_DENIED
- DMT_APPROVAL_REQUIRED
- DMT_REQUEST_MISMATCH
- DMT_APPROVAL_EXPIRED

Do not swallow authorization errors.

## Host workflow ownership

Dmint should not become a full agent workflow engine.

When approval is required:

```text
Dmint -> stop current tool execution -> return
```

The host agent runtime decides how to pause/resume conversational or workflow state and when to retry.

Dmint verifies the authorization state again during retry.

## Agent identity

If the deployment provides reliable agent/workload identity, include it in authorization and approval binding.

Do not pretend that a model-supplied string is secure identity.

## OpenAI/Anthropic/framework neutrality

Core Dmint should not depend on a specific LLM vendor.

Keep provider/framework integrations at the edges.

Good architecture:

```text
OpenAI adapter      ─┐
Anthropic adapter   ─┤
LangChain adapter   ─┼-> Dmint request model -> policy -> enforcement
Custom agent        ─┘
```

Do not put provider-specific logic into the core authorization engine.

## MCP

Future MCP architecture:

```text
AI Agent
   ↓
Dmint MCP Proxy
   ↓
Existing MCP Server
   ↓
Tool
```

The proxy should enforce `tools/call` before forwarding a privileged call.

Use an official MCP SDK rather than implementing MCP manually.

For `tools/list`, consider capability disclosure and whether unauthorized tools should be hidden, but keep discovery policy distinct from execution authorization.

## Tool discovery

Do not assume hiding a tool is equivalent to authorization.

A tool may be hidden from discovery but still require execution checks.

Conversely, exposure of tool metadata can leak capabilities or sensitive information.

Treat tool discovery as a separate security surface.

## Direct bypass

SDK enforcement cannot stop an agent that has a direct alternate route to the underlying capability.

Examples:

```text
AI -> direct DB credentials -> DB
AI -> shell -> privileged command
AI -> Docker socket -> host
AI -> raw HTTP -> protected service
```

The deployment must make Dmint the path to the protected capability where the security guarantee requires it.

## Indirect calls

Check tool-to-tool behavior:

```text
AI -> tool A -> privileged tool B
```

If B can be called without Dmint, A may become a bypass channel.

## Execution-time correctness

For sensitive tools, minimize the time between authorization and execution and document any TOCTOU limitations.

Never claim atomic authorization plus execution unless the underlying integration truly provides it.

## Performance

Do not invoke an LLM for every authorization decision.

Prefer:

request -> deterministic evaluator -> tool

Authorization should normally be lightweight. External PDPs may add network latency; failures must remain fail-closed.

## Developer experience

V1 should be simple:

```bash
pip install dmint
```

then:

```python
@dmint.protected("database.delete")
def delete_customer(customer_id):
    ...
```

The first experience should demonstrate real prevention of a dangerous tool call in minutes.

## Execution tests

For every enforcement path, prove:

- ALLOW calls the function
- DENY never calls the function
- APPROVAL_REQUIRED never calls the function
- approved retry calls the function only after verification
- malformed authorization never calls the function
- authorization infrastructure failure never calls the function

The best tests use a spy/mock/flag to prove non-execution.
