# Dmint.app — AGENTS.md

> **Authoritative guidance for AI agents working on the Dmint public documentation site (`dmint.app`).**

---

## 1. PROJECT MISSION & SCOPE

This directory is the dedicated documentation platform and public knowledge base for the **Dmint** ecosystem.

- **Repository Path**: `~/dmint/docs` (canonical)
- **Domain**: `https://dmint.app`
- **Technology Stack**: **Holocron / Mintlify** (`docs.json` + MDX + Cloudflare Worker)
- **Hosting Target**: Cloudflare Workers (`docs.dmint.app`)
- **Local Preview**: `npm run dev` (Node.js >= 18)

### Core Directives
1. **Zero Custom Docs Engines**: Do NOT build a documentation engine from scratch. Use standard configuration and native components.
2. **Docs-First Focus**: The immediate priority is developer documentation so users can evaluate, learn, and implement Dmint on real projects (Cursor, Claude Code, Antigravity/Gemini CLI, and custom Python agents).
3. **Outside Runtime Security Boundary**: This directory is purely presentation and technical documentation. It is NOT part of the runtime authorization engine. Never copy internal Python code or duplicate SQLite stores here.

---

## 2. THE DMINT ECOSYSTEM (SOURCE OF TRUTH)

Dmint is a deterministic security authorization and enforcement engine for AI-agent tool calls. Runtime authorization is strictly code- and policy-driven; LLMs NEVER make runtime authorization decisions.

| Subsystem | Module | Role | Key Technologies |
|---|---|---|---|
| **Core Engine** | `dmint.core` | Deterministic authorization, frozen SQLite state machine, Ed25519 signing | Python >=3.10, cryptography, rfc8785 (JCS) |
| **CLI** | `dmint.cli` | Policy authoring wizards, offline validation, agent skill installer, dashboard launcher | Python >=3.10, questionary |
| **MCP Gateway** | `dmint.mcp` | Multi-integration gateway, downstream stdio/HTTP proxy, SSRF filter, approval retry | Python >=3.10, mcp SDK, starlette, uvicorn |
| **Dashboard** | `dmint.dashboard` | Local human approval UI (Core-owned SQLite, zero direct SQL) | FastAPI, Jinja2, uvicorn |
| **Skills** | `dmint.skills` | AI coding assistant skill assets (`dmint-policy-manager`) for policy authoring | Markdown prompt assets |
| **Docs** | `docs/` | Documentation site and developer portal | Holocron / Mintlify (`docs.json` + MDX) |

---

## 3. MINTLIFY SITE ARCHITECTURE

All documentation files live inside `docs/` following standard structure:

```text
docs/
├── docs.json                   # Master site configuration (theme, navigation, layout)
├── favicon.svg                 # Browser tab favicon
├── logo.svg                    # Brand logo
├── global.css                  # Global styling overrides
├── public/                     # Static assets served at domain root
│   ├── favicon.svg             # Favicon asset
│   ├── logo.svg                # Brand logo asset
│   ├── logo-dark.svg           # Dark mode logo asset
│   ├── llms.txt                # Structured overview & index for AI agents
│   └── llms-full.txt           # Consolidated single-file docs corpus for AI context
│
├── index.mdx                   # 60-second Overview
├── quickstart.mdx              # 5-minute hands-on walkthrough
│
├── tutorials/                  # Learning-oriented guides
│   └── protect-a-tool.mdx      # Real-world tutorial: conditional approvals for refunds
│
├── concepts/                   # Deep mental models & primitives
│   ├── how-dmint-works.mdx     # Architecture, sequence flow, and decision engine
│   ├── policies.mdx            # Policy structure, rule evaluation, fail-closed defaults
│   ├── request-binding.mdx     # RFC 8785 canonicalization & SHA-256 fingerprinting
│   ├── approvals.mdx           # Lifecycle: 7-state machine, Ed25519 assertions, consumption
│   └── resources.mdx           # Resource engine: path, url, host, id matching & traversal defense
│
├── guides/                     # Task-oriented, step-by-step how-to guides
│   ├── python-integration.mdx  # @engine.protect decorator for def, async def, class/static methods
│   ├── protecting-mcp.mdx      # Wrapping MCP servers with dmint-mcp gateway & schema pinning
│   ├── human-approvals.mdx     # Operating dashboard UI, CLI approvals, executing retries
│   ├── notifications.mdx       # Real-time webhook notifications (Slack, Discord, Teams)
│   ├── authoring-policies.mdx  # Using dmint create-policy & create-mcp-policy
│   └── agent-skills.mdx        # Installing AI agent skills with dmint install-skill
│
├── integrations/               # Host environment & AI tool copy-paste setup recipes
│   ├── cursor.mdx              # .cursor/mcp.json integration
│   ├── claude-code.mdx         # Claude Code gateway configuration
│   ├── antigravity.mdx         # Google Antigravity & Gemini CLI skill integration
│   └── custom-agents.mdx       # LangChain, CrewAI, AutoGen, and custom Python loops
│
├── operations/                 # Security architecture & operations
│   ├── deployment-model.mdx    # OS user separation, process boundaries, permissions matrix
│   ├── security-model.mdx      # Attacker capabilities, formal guarantees, test traceability
│   └── known-limitations.mdx   # Non-goals, database rollbacks, symlink caveats
│
├── reference/                  # Complete technical reference manual
│   ├── cli.mdx                 # Exhaustive CLI reference for dmint, dmint-mcp, dashboard
│   ├── core-api.mdx            # Python dmint package classes, methods, exceptions
│   ├── policy-schema.mdx       # policy.json formal JSON schema specification
│   ├── mcp-protection-schema.mdx # mcp_protection.json format & routing specification
│   └── errors.mdx              # Comprehensive index of all 32 DMT_* error codes
│
├── troubleshooting.mdx         # Symptom -> Cause -> Fix diagnostic index
└── faq.mdx                     # Candid answers to top architecture & security questions
```

---

## 4. MASTER CONFIGURATION (`docs.json`) NAVIGATION

`docs.json` configures the 8 Diátaxis navigation groups matching the directory structure:

```json
{
  "navigation": {
    "groups": [
      {
        "group": "Get Started",
        "pages": ["index", "quickstart"]
      },
      {
        "group": "Tutorials",
        "pages": ["tutorials/protect-a-tool"]
      },
      {
        "group": "Core Concepts",
        "pages": [
          "concepts/how-dmint-works",
          "concepts/policies",
          "concepts/request-binding",
          "concepts/approvals",
          "concepts/resources"
        ]
      },
      {
        "group": "How-To Guides",
        "pages": [
          "guides/python-integration",
          "guides/protecting-mcp",
          "guides/human-approvals",
          "guides/notifications",
          "guides/authoring-policies",
          "guides/agent-skills"
        ]
      },
      {
        "group": "Integrations",
        "pages": [
          "integrations/cursor",
          "integrations/claude-code",
          "integrations/antigravity",
          "integrations/custom-agents"
        ]
      },
      {
        "group": "Operations & Security",
        "pages": [
          "operations/deployment-model",
          "operations/security-model",
          "operations/known-limitations"
        ]
      },
      {
        "group": "Reference",
        "pages": [
          "reference/cli",
          "reference/core-api",
          "reference/policy-schema",
          "reference/mcp-protection-schema",
          "reference/errors"
        ]
      },
      {
        "group": "Help & FAQ",
        "pages": [
          "troubleshooting",
          "faq"
        ]
      }
    ]
  }
}
```

---

## 5. MDX AUTHORING & COMPONENT RULES

### Frontmatter (Required on all pages)
```mdx
---
title: "Page Title"
description: "Clear, concise one-sentence description for search and metadata."
icon: "shield-check" # Optional: valid Lucide icon name
---
```

### Component Guidelines
Use native Mintlify components exclusively. Never emit raw HTML tags where components exist:

- **`<Steps>` and `<Step>`**: Use for sequential tutorials and ordered procedures (e.g. Quickstart, installation).
- **`<CardGroup>` and `<Card>`**: Use for landing pages, feature overviews, and navigation indexes.
- **`<Tabs>` and `<Tab>`**: Use for multi-environment, multi-language, or multi-client examples (e.g. Cursor vs Claude vs Antigravity).
- **`<CodeGroup>` and `<Code>`**: Use for side-by-side terminal commands, request/response pairs, or configuration examples.
- **Callouts (`<Tip>`, `<Note>`, `<Info>`, `<Warning>`, `<Danger>`, `<Check>`)**:
  - `<Tip>`: Best practice, productivity shortcut.
  - `<Note>`: Contextual detail or background explanation.
  - `<Warning>`: Potential footgun, configuration error, or breaking change.
  - `<Danger>`: Fail-closed denial, credential leakage risk, or unauthenticated tool exposure.
  - `<Check>`: Verified state, cryptographic assertion confirmation.
  - *Rule*: Never stack more than two callouts sequentially.

---

## 6. TECHNICAL ACCURACY & SECURITY INVARIANTS

All documentation must accurately represent Dmint's formal security model:

1. **Deterministic Fail-Closed Default**: If an agent requests an action not explicitly permitted by `ALLOW` or `APPROVAL_REQUIRED` rules in `policy.json`, Dmint rejects it immediately (`DENY`).
2. **Exact Request Binding**: Approval is cryptographically bound to the canonical RFC 8785 request fingerprint (tool, action, sorted arguments, environment epoch). Approving `update(id=1)` CANNOT authorize `update(id=2)`.
3. **Single-Use Consumption**: Once an approval is executed, it is atomically marked `CONSUMED`. Replaying the assertion fails closed immediately (`DMT_APPROVAL_CONSUMED`).
4. **Policy Provenance Invalidation**: Modifying `policy.json` changes its SHA-256 digest, automatically invalidating any pending or pre-approved records tied to previous policy epochs.
5. **Zero Direct SQL from Dashboard**: The human approval UI (`dmint dashboard`) never queries SQLite directly; it interacts solely through Core's public APIs (`list_pending`, `approve_pending`, `reject_pending`).

### Tone & Positioning Rules
- **Technically Rigorous**: Frame Dmint as a deterministic authorization primitive and runtime security boundary.
- **Do NOT Claim**: "Unhackable", "solves all AI security", "replaces IAM", or "prevents every prompt injection". Dmint enforces deterministic authorization at tool execution boundaries, regardless of how the agent arrived at the request.
- **Runnable Examples Only**: Every bash command, Python snippet, and JSON schema must be syntactically valid and tested against the live v1 releases.

---

## 7. LOCAL PREVIEW & VERIFICATION WORKFLOW

To verify documentation locally before pushing:

```bash
# Run local Mintlify development server:
npx mintlify dev

# Mintlify will start local preview at http://localhost:3000
```

### Validation Checklist Before Release
- [ ] Every page declared in `docs.json` navigation exists as a corresponding `.mdx` file.
- [ ] Frontmatter `title` and `description` are present on every `.mdx` file.
- [ ] Code blocks specify proper language tags (`bash`, `python`, `json`, `text`).
- [ ] Relative links between pages (`href="/quickstart"`) resolve cleanly without 404s.
- [ ] Copy-paste snippets in Quickstart and Integrations match the verified v1.0.1/v1.1.0 CLI flags.
