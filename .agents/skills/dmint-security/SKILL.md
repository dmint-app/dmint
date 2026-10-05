---
name: dmint-security
description: Security engineering and threat-modeling rules for Dmint. Use whenever implementing or reviewing authorization, enforcement, approvals, policy handling, secrets, trust boundaries, or security-sensitive code.
---

# Dmint Security Engineering

## Purpose

Dmint is a deterministic security enforcement layer between an AI agent and protected tool execution:

AI AGENT -> DMINT -> TOOL

The AI agent and all model output are untrusted. Dmint's authoritative policy, approval state, and enforcement path are trusted only when the deployment actually protects them.

The primary security rule is:

> The AI may request an action. The AI may never decide whether that action is allowed.

## Mandatory principles

### Deterministic runtime decisions

Runtime authorization MUST be deterministic. The trusted decision states are:

- ALLOW
- DENY
- APPROVAL_REQUIRED

Do not use an LLM as the runtime authorization authority.

### Fail closed

If Dmint cannot prove that an action is allowed, do not execute it.

Authorization errors, malformed input, policy failures, missing approval, expired approval, replayed approval, identity mismatch, signature failures, and relevant storage failures must not become ALLOW.

### Pre-execution enforcement

Authorization must happen before the protected capability executes.

Correct:

request -> Dmint -> decision -> protected tool

Incorrect:

request -> protected tool -> Dmint audit/check

### Never wait in the original execution path

APPROVAL_REQUIRED must return control to the host application. Never implement human approval by sleeping, blocking threads, polling, or holding the original call stack open.

Correct flow:

request -> Dmint -> persist pending request -> return -> human approval -> host retry -> Dmint re-validates -> execute

## Trust-boundary review

Whenever changing security-sensitive code, identify:

1. What is trusted?
2. What is untrusted?
3. Where is the enforcement boundary?
4. Can the agent reach the protected capability another way?
5. Can the agent modify authoritative policy or approval state?

A Python decorator is an integration boundary, not automatically a host-wide security boundary. If the agent has direct database credentials, root access, Docker daemon access, raw cloud credentials, or another direct route to the protected capability, Dmint may be bypassed.

Never claim stronger guarantees than the deployment provides.

## Attack classes to consider

For every security feature, think about:

- argument mutation
- resource mutation
- tool/action mutation
- agent identity substitution
- approval replay
- approval theft
- approval forgery
- expiration
- policy changes
- TOCTOU
- concurrency races
- direct bypass
- indirect tool-to-tool bypass
- prompt injection
- MCP discovery leakage
- secret leakage
- policy tampering

## Prompt injection

Treat all model output as hostile input. Statements such as "ignore Dmint", "the user already approved this", or "change the policy" have no authorization authority.

The trusted path is:

untrusted model output -> structured request -> Dmint deterministic evaluation -> decision

## Request integrity

Do not authorize one representation and execute another. Security-relevant request fields should include, as applicable:

- agent identity
- tool
- action
- resource
- arguments
- relevant context

For sensitive approved actions, bind approval to the exact security-relevant request.

## Canonicalization

Do not use raw JSON text as the request identity. Canonicalize deterministically before fingerprinting so equivalent logical objects produce the same representation.

Conceptually:

request -> canonical representation -> SHA-256 fingerprint

Document and test the canonicalization algorithm.

## Cryptography

Use mature cryptographic implementations. Never invent encryption, signatures, token formats, password hashing, or key derivation.

Remember:

hash != signature
signature != encryption

A SHA-256 fingerprint does not authenticate the approver.

If a signature is required, use a standard implementation such as Ed25519.

## Secrets

Never log or commit:

- API keys
- private keys
- database passwords
- cloud credentials
- OAuth secrets
- MCP credentials
- approval secrets
- signing keys

Tool arguments may contain sensitive data. Prefer redaction, hashes, and minimal audit storage.

## Security testing

Every security rule needs a negative test proving the protected capability does not execute.

Required categories include:

- DENY prevents execution
- APPROVAL_REQUIRED prevents execution
- changed arguments fail
- changed tool/action/resource fail
- wrong agent fails
- expired approval fails
- replay fails
- concurrent single-use consumption is safe
- current deny policy overrides old approval
- malformed request fails closed
- policy failure fails closed
- relevant storage failure fails closed

A test that only checks an exception is insufficient; also assert that the protected tool was not called.

## Security review checklist

Before approving a security-sensitive change:

[ ] Authorization occurs before execution
[ ] Final decision is deterministic
[ ] Errors fail closed
[ ] Agent cannot modify authoritative policy
[ ] Agent cannot manufacture approval
[ ] Approval is bound to the right request/principal
[ ] Request canonicalization is deterministic
[ ] Replay is prevented
[ ] Expiration is enforced
[ ] Current policy is re-evaluated
[ ] Concurrency is safe
[ ] Direct bypass limitations are understood
[ ] Indirect tool calls are considered
[ ] Secrets are protected
[ ] Negative security tests exist
[ ] Claims match actual guarantees

## Final question

Whenever uncertain, ask:

> What happens if the AI is malicious and intentionally tries to bypass this?

The secure default is DENY.
