---
name: dmint-policy-authoring
description: Development-time skill for authoring, translating, and validating Dmint security policies from human intent and developer requirements into schema-compliant Dmint policy JSON.
---

# Dmint Policy Authoring Skill

## Overview

This is a **development-time skill** for AI coding assistants helping developers create deterministic security policies for **Dmint** (`dmint.app`).

---

## 1. Security Boundary & Core Principle

```text
Human Intent (access.md / prompt)
       ↓
Policy Authoring Assistant (AI)
       ↓
Candidate Dmint Policy JSON
       ↓
Dmint Core Validation (Policy.from_mapping)
       ↓
Authoritative Runtime policy.json
       ↓
Dmint Deterministic Enforcement (ALLOW / DENY / APPROVAL_REQUIRED)
```

### The Non-Negotiable Boundary
- **AI may help WRITE policies during development time.**
- **AI must NEVER decide runtime authorization decisions.**
- An LLM prompt or AI confidence score is **never** a runtime authorization authority.
- Every generated policy must pass strict Dmint core validation (`dmint.policy.Policy.from_mapping`) before it becomes an authoritative policy file.

---

## 2. Policy Authoring Rules & Invariants

When translating developer intent into Dmint policy rules:

1. **Least Privilege by Default:** Unspecified or ambiguous capabilities must default to **DENY**.
2. **No Silent Permission Expansion:**
   - Never change `DENY` to `ALLOW` or `APPROVAL_REQUIRED`.
   - Never turn a specific resource restriction (e.g. `"PR-100"`) into a wildcard (`"*"`).
   - Never interpret a missing or unstated resource as a wildcard `*`.
3. **No Schema Inventions:**
   - Do not invent custom rule effects, operators, fields, or version strings.
   - Effects MUST be one of: `"allow"`, `"deny"`, `"approval_required"`.
   - Condition operators MUST be one of: `"equals"`, `"notEquals"`, `"in"`, `"contains"`, `"startsWith"`, `"endsWith"`.
4. **Never Guess Ambiguities:**
   - If user intent is ambiguous (e.g., *"The agent can delete records with permission"*), **STOP and ASK THE DEVELOPER**.
   - Ask clarifying questions:
     1. Which specific tool name and action slug performs deletion?
     2. Which resource target is affected?
     3. Is approval required, or is deletion prohibited entirely?
     4. Does this apply to all environments or specific context values?
5. **No Invented Approvers or Identity:**
   - Do not invent approval authorities, signing keys, or human identity claims inside rule definitions.
6. **Validation Requirement:**
   - Every candidate JSON must be verified against `dmint.policy.Policy.from_mapping()`.
   - If validation fails, explain the exact schema error to the developer and ask for clarification rather than making assumptions.

---

## 3. Policy Authoring Workflow

```text
access.md / Developer Intent
       ↓
Identify Tools & Actions (e.g. sqlite.read_data, sqlite.delete_data)
       ↓
Identify Resource Scopes (e.g. "*", "user_id", specific strings)
       ↓
Identify Trusted Context Conditions (e.g. env == "production")
       ↓
Identify Decision Effects (allow, deny, approval_required)
       ↓
Check for Ambiguities (if ambiguous -> STOP and ASK DEVELOPER)
       ↓
Generate Candidate Policy JSON
       ↓
Validate with Dmint Core (Policy.from_mapping)
       ↓
Save Authoritative policy.json
```

---

## 4. Dmint Policy JSON Schema Reference

Every generated `policy.json` MUST adhere to Dmint's exact internal schema:

```json
{
  "rules": [
    {
      "effect": "allow",
      "tool": "sqlite",
      "action": "read_data",
      "resource": "*"
    },
    {
      "effect": "approval_required",
      "tool": "sqlite",
      "action": "delete_data",
      "resource": "*",
      "conditions": [
        {
          "field": "env",
          "operator": "equals",
          "value": "production"
        }
      ]
    },
    {
      "effect": "deny",
      "tool": "sqlite",
      "action": "delete_data",
      "resource": "*"
    }
  ]
}
```

### Rule Field Specifications:
- `effect` (string, required): `"allow"`, `"deny"`, or `"approval_required"`.
- `tool` (string, required): Tool domain name (e.g. `"sqlite"`, `"github"`, `"aws"`).
- `action` (string, required): Action name (e.g. `"read_data"`, `"merge"`, `"terminate"`).
- `resource` (string, optional): `"*"`, `null` (for `NO_RESOURCE`), or exact resource string. Defaults to `NO_RESOURCE`.
- `agent_id` (string, optional): Specific agent principal ID if restricted to one calling principal.
- `conditions` (array, optional): Array of condition objects `{"field": "...", "operator": "...", "value": "..."}` matching against trusted context.

---

## 5. Examples

### Example 1: Clear Intent
**Developer Intent:**
> "Support agents can read customer records. They can update customer records in development. Production updates require approval. Customer deletion is never allowed."

**Generated & Verified Dmint Policy (`policy.json`):**
```json
{
  "rules": [
    {
      "effect": "allow",
      "tool": "customer",
      "action": "read",
      "resource": "*"
    },
    {
      "effect": "allow",
      "tool": "customer",
      "action": "update",
      "resource": "*",
      "conditions": [
        {
          "field": "env",
          "operator": "equals",
          "value": "development"
        }
      ]
    },
    {
      "effect": "approval_required",
      "tool": "customer",
      "action": "update",
      "resource": "*",
      "conditions": [
        {
          "field": "env",
          "operator": "equals",
          "value": "production"
        }
      ]
    },
    {
      "effect": "deny",
      "tool": "customer",
      "action": "delete",
      "resource": "*"
    }
  ]
}
```

### Example 2: Ambiguous Intent (Requires Asking Questions)
**Developer Intent:**
> "The agent can delete important records with permission."

**Required Response:**
> "This policy statement is ambiguous. Before generating `policy.json`, please clarify:
> 1. What is the tool and action name for record deletion (e.g. `sqlite.delete_data`)?
> 2. Does 'with permission' mean human approval is required (`APPROVAL_REQUIRED`), or is it restricted to specific principals/environments?
> 3. Does this apply to all databases or specific resource targets?
> 4. Are there any conditions under which deletion should be DENIED completely (e.g. production)?"
