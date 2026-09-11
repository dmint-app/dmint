---
name: dmint-authorization
description: Authorization and policy-engineering rules for Dmint. Use when designing policies, request models, deterministic decisions, PDP adapters, policy precedence, context, or authorization APIs.
---

# Dmint Authorization Engineering

## Purpose

Dmint is an authorization enforcement layer specifically for AI-agent actions. It is not general human IAM.

The authorization question is:

> May this AI-generated action execute right now?

## Core model

Represent authorization around a structured request:

- principal / agent_id
- tool
- action
- resource
- arguments
- context

Then evaluate a deterministic policy to produce:

- ALLOW
- DENY
- APPROVAL_REQUIRED

Do not let natural language or model judgment become the final authority.

## Policy examples

V1 can support simple rules such as:

ALLOW database.read
DENY database.delete

ALLOW database.update IF environment == development

ALLOW filesystem.write IF path startsWith /workspace

APPROVAL_REQUIRED github.merge

Useful operators include:

- equals
- notEquals
- in
- contains
- startsWith
- endsWith
- AND
- OR
- NOT

Keep the language small, explicit, deterministic, and testable.

## Policy precedence

Policy conflicts must have explicit deterministic semantics. Do not leave behavior undefined for contradictory rules.

When in doubt, prefer explicit conflict detection or a deny-safe result rather than an accidental allow.

## Current policy is authoritative

Stored policy version information is useful for audit, but an older approval must not override a newer deny.

On approved retry:

1. validate approval
2. validate exact request
3. evaluate current policy
4. validate constraints
5. execute only if the current decision permits it

## Policy context

Only security-relevant context should affect authorization.

Clearly define the source and trust level of context values such as:

- environment
- tenant
- time
- deployment
- agent identity
- workload identity
- resource ownership

Never treat attacker-controlled strings as trustworthy merely because they have a convenient field name.

## Separation of concerns

Keep these concepts separate:

Authentication:
Who is the principal?

Authorization:
May this action happen?

Execution:
Actually invoke the tool.

Approval:
A trusted human-controlled authorization step for a specific pending AI action.

Dmint primarily owns authorization/enforcement and the approval lifecycle, while host applications may own human authentication and workflow resumption.

## PDP architecture

Dmint should be able to use a built-in evaluator at first and later delegate policy decisions to mature systems such as:

- OpenFGA
- Cerbos
- OPA
- Cedar
- AuthZEN-compatible systems

Use an adapter interface rather than coupling core Dmint semantics directly to a provider.

Conceptually:

Dmint -> policy provider -> deterministic decision

Do not rebuild a general IAM platform without a concrete need.

## Decision purity

The policy evaluator should be as close to a pure deterministic function as practical:

request + policy + trusted context -> decision

Avoid hidden side effects inside policy evaluation.

Do not execute tools during evaluation.

Do not mutate authoritative approval state merely to answer whether something is allowed.

## Authorization and execution

A successful authorization result should refer to the same request that will execute.

Do not do:

authorize(request A)
execute(request B)

For sensitive actions, the execution path should carry forward the exact authorized request or an unambiguous verified representation of it.

## Fail-closed behavior

Unexpected policy-engine errors must not become ALLOW.

If the external PDP is unavailable, decide and document whether the secure behavior is to fail closed. For security-sensitive Dmint actions, the default should be no execution.

## Tests

Test both positive and negative policy behavior:

- exact allow
- exact deny
- approval-required
- contradictory rules
- condition evaluation
- missing context
- malformed context
- changed resource
- changed action
- changed agent
- current policy after approval

Also test that denied and approval-required paths do not invoke the protected tool.

## Design principle

Dmint should complement existing authorization systems rather than pretending to replace every policy engine. Its special responsibility is safe enforcement of AI-generated actions and request-bound approval semantics.
