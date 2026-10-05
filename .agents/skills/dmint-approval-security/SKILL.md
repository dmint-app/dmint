---
name: dmint-approval-security
description: Secure approval lifecycle for Dmint, including request binding, exact-request verification, expiry, replay protection, concurrency, trusted human approval, and retry semantics.
---

# Dmint Approval Security

## Purpose

`APPROVAL_REQUIRED` means a specific AI action may proceed only after a trusted human-controlled approval step.

Approval is not a generic permission.

It is authorization for a specific pending request.

## Required lifecycle

```text
AI request
   ↓
Dmint
   ↓
APPROVAL_REQUIRED
   ↓
persist exact pending request
   ↓
return immediately
   ↓
human approves
   ↓
host retries
   ↓
Dmint verifies
   ↓
current policy re-check
   ↓
atomic approval consumption
   ↓
execute
```

Never block the original function call waiting for approval.

## Pending request fields

At minimum, persist the security-relevant information needed to prove what was approved:

- approval_id
- request_id
- agent_id / principal
- tool
- action
- resource
- canonical request fingerprint
- policy/version context
- created_at
- expires_at
- status
- approved_by
- approved_at
- consumed_at

Store raw arguments only when there is a clear need and appropriate privacy protection.

## Exact-request binding

Approval must cover the exact request that will execute.

Example:

Approved:

delete_user(123)

Retry:

delete_user(999)

Result:

DENY

Any security-relevant difference must invalidate the approval.

Bind at least:

- principal/agent
- tool
- action
- resource
- canonicalized arguments fingerprint
- relevant policy constraints

## Canonicalization

Fingerprint a deterministic canonical representation rather than arbitrary JSON text.

Equivalent serialization order should not create false mismatches.

Changed security-relevant values must create a different fingerprint.

## Human approval authenticity

The LLM cannot create human approval.

These are not valid approval mechanisms by themselves:

- `approved=true` supplied by the agent
- an LLM message saying "user said yes"
- a tool argument naming an approver
- a model-generated approval token

Approval must originate from a trusted human-controlled application, CLI, service, or equivalent authenticated workflow.

## Expiration

Every approval needs an expiration time.

After expiration:

DENY

Use timezone-aware timestamps, preferably UTC internally.

Do not silently extend expired approvals.

## Replay protection

Approvals should normally be single-use.

Lifecycle:

PENDING -> APPROVED -> CONSUMED

A consumed approval must not authorize another execution.

## Atomic consumption

Do not implement single-use state with a non-atomic read-then-write sequence.

Bad:

```python
if not approval.consumed:
    approval.consumed = True
    execute()
```

Two concurrent requests could both pass the check.

Use a storage transaction or atomic conditional update so that at most one request consumes the approval.

Expected security property:

N concurrent retries -> at most 1 execution

## Retry verification

On an approved retry, verify all applicable properties:

1. approval exists
2. approval status permits consumption
3. approval is not expired
4. approval has not been consumed
5. request_id matches
6. agent/principal matches
7. tool matches
8. action matches
9. resource matches
10. request fingerprint matches
11. current policy still permits execution
12. all relevant constraints still hold

Do not reduce retry verification to `approval_id exists`.

## Current policy wins

Approval does not freeze a past allow forever.

Example:

10:00 -> approved
10:01 -> policy changes to DENY
10:02 -> retry

Result:

DENY

Store policy-version data for audit, but do not let stale approval state defeat current policy.

## Bearer-token threat model

A bearer approval credential may be stolen. Do not claim sender-constrained security unless the implementation actually binds it to a trusted principal/runtime/key.

Do not log full approval secrets.

Possible future strengthening includes binding approvals to:

- agent identity
- workload identity
- runtime/session
- cryptographic key

## Audit

Audit state transitions such as:

- approval_created
- approval_granted
- approval_rejected
- approval_expired
- approval_consumed
- approval_replay_attempt
- request_mismatch
- policy_changed

Avoid logging sensitive raw arguments by default.

## Approval tests

Mandatory negative tests include:

- changed arguments
- changed resource
- changed action
- changed tool
- changed agent
- expired approval
- replayed approval
- malformed approval
- nonexistent approval
- concurrent consumption
- policy changed to DENY
- agent attempts to self-approve

Also test that the original protected tool is not executed before approval.

## Final rule

The question is never:

> "Does this approval token exist?"

The question is:

> "Does this exact trusted approval still authorize this exact AI request under the current policy, right now, and can it be consumed only once?"
