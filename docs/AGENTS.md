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
├── docs.json                   # Master Mintlify configuration (theme, colors, nav, links)
├── logo/
│   ├── light.svg               # Brand mark on dark backgrounds
│   └── dark.svg                # Brand mark on light backgrounds
├── favicon.svg                 # Browser tab favicon
├── index.mdx                   # Docs home / landing overview
├── introduction.mdx            # What is Dmint? Why deterministic control?
├── quickstart.mdx              # 5-minute hands-on tutorial (Zero to Protected Tool)
│
├── concepts/                   # Deep mental models & primitives
│   ├── overview.mdx            # How Dmint intercepts and decides
│   ├── capabilities.mdx        # Tool, action, resource, wildcards
│   ├── request-binding.mdx     # RFC 8785 canonicalization & SHA-256 fingerprinting
│   ├── approvals.mdx           # Lifecycle: Pending -> Ed25519 Signed -> Single-use Consumed
│   └── policies.mdx            # Policy structure, rule evaluation, fail-closed defaults
│
├── guides/                     # Task-oriented, step-by-step how-to guides
│   ├── protecting-mcp.mdx      # Wrapping MCP servers with dmint-mcp gateway
│   ├── authoring-policies.mdx  # Using dmint create-policy & create-mcp-policy
│   ├── agent-skills.mdx        # Installing AI agent skills with dmint install-skill
│   ├── python-integration.mdx  # Direct @dmint.protected decorator in backends
│   └── human-approvals.mdx     # Launching & using dmint dashboard
│
├── integrations/               # Environment & AI tool copy-paste setup guides
│   ├── cursor.mdx              # .cursor/mcp.json integration
│   ├── claude-code.mdx         # ~/.claude/ configuration & CLI flags
│   ├── antigravity.mdx         # Antigravity & Gemini CLI skill integration
│   └── custom-agents.mdx       # LangChain, CrewAI, AutoGen, custom Python agents
│
├── architecture/               # Security specifications & invariants
│   ├── deterministic-enforcement.mdx # Why probabilistic models cannot enforce policy
│   ├── security-invariants.mdx       # The 5 non-negotiable security invariants
│   └── threat-model.mdx              # SSRF, prompt injection, replay, loopback isolation
│
└── reference/                  # Complete technical reference manual
    ├── cli.mdx                 # dmint CLI commands, subcommands, and flags
    ├── policy-schema.mdx       # policy.json schema and validation constraints
    ├── mcp-protection-schema.mdx # mcp_protection.json format specification
    └── core-api.mdx            # Python dmint package classes, methods, and error codes
```

---

## 4. MASTER CONFIGURATION (`docs.json`) STANDARDS

Every configuration option in `docs.json` must adhere to Mintlify's modern schema:

```json
{
  "$schema": "https://mintlify.com/docs.json",
  "theme": "mint",
  "name": "Dmint",
  "colors": {
    "primary": "#10b981",
    "light": "#34d399",
    "dark": "#059669",
    "background": {
      "light": "#ffffff",
      "dark": "#090d11"
    }
  },
  "logo": {
    "light": "/logo/light.svg",
    "dark": "/logo/dark.svg",
    "href": "https://dmint.app"
  },
  "favicon": "/favicon.svg",
  "topbarLinks": [
    { "name": "GitHub", "url": "https://github.com/dmint-app" },
    { "name": "PyPI", "url": "https://pypi.org/project/dmint/" }
  ],
  "topbarCtaButton": {
    "name": "Quickstart",
    "url": "/quickstart"
  },
  "navigation": [
    {
      "group": "Get Started",
      "pages": ["index", "introduction", "quickstart"]
    },
    {
      "group": "Core Concepts",
      "pages": [
        "concepts/overview",
        "concepts/capabilities",
        "concepts/request-binding",
        "concepts/approvals",
        "concepts/policies"
      ]
    },
    {
      "group": "Guides",
      "pages": [
        "guides/protecting-mcp",
        "guides/authoring-policies",
        "guides/agent-skills",
        "guides/python-integration",
        "guides/human-approvals"
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
      "group": "Architecture & Security",
      "pages": [
        "architecture/deterministic-enforcement",
        "architecture/security-invariants",
        "architecture/threat-model"
      ]
    },
    {
      "group": "Reference",
      "pages": [
        "reference/cli",
        "reference/policy-schema",
        "reference/mcp-protection-schema",
        "reference/core-api"
      ]
    }
  ],
  "footerSocials": {
    "github": "https://github.com/dmint-app",
    "twitter": "https://x.com/dmint_app"
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
