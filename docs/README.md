# Dmint Documentation (`docs.dmint.app`)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Dmint Engine: v2.0.3](https://img.shields.io/badge/Dmint-v2.0.3-10b981.svg)](../pyproject.toml)
[![Framework: Holocron](https://img.shields.io/badge/Engine-Holocron%20%2F%20Vite-6366f1.svg)](https://holocron.so)
[![Deployment: Cloudflare Workers](https://img.shields.io/badge/Deploy-Cloudflare%20Workers-f38020.svg)](wrangler.jsonc)
[![Node: >=18](https://img.shields.io/badge/Node-%3E%3D18-339933.svg)](package.json)

> **The official developer documentation platform, architectural specifications, and interactive knowledge base for the [Dmint](https://github.com/dmint-app/dmint) deterministic AI-agent security ecosystem.**

Live Site: **[https://docs.dmint.app](https://docs.dmint.app)** &bull; Public Portal: **[https://dmint.app](https://dmint.app)**

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Tech Stack](#architecture--tech-stack)
- [Quick Start for Contributors](#quick-start-for-contributors)
- [Documentation Directory Structure](#documentation-directory-structure)
- [Documentation Sitemap](#documentation-sitemap)
- [MDX Authoring Guidelines](#mdx-authoring-guidelines)
  - [Required Frontmatter](#required-frontmatter)
  - [Component Usage](#component-usage)
  - [Supported Callouts](#supported-callouts)
  - [Code Snippet Conventions](#code-snippet-conventions)
- [Build & Deployment Pipeline](#build--deployment-pipeline)
  - [Local Production Preview](#local-production-preview)
  - [Cloudflare Workers Deployment](#cloudflare-workers-deployment)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This directory (`/docs`) hosts the authoritative technical documentation for **Dmint v2.0.3**. Dmint is a deterministic security authorization and enforcement engine that sits between autonomous AI agents and privileged tools (databases, shell environments, file systems, APIs).

The documentation site serves developers, security engineers, and DevOps teams evaluating, deploying, and integrating Dmint with AI coding assistants (Google Antigravity, Cursor, Claude Code) and agent frameworks (LangChain, CrewAI, AutoGen).

---

## Architecture & Tech Stack

The documentation platform is built for instant page transitions, server-side rendering, and high-performance global edge delivery:

| Layer | Technology | Purpose |
|---|---|---|
| **Engine** | [Holocron](https://holocron.so) + Vite 8 | React Server Components (RSC) and client hydration |
| **Runtime** | React 19 | UI components, tabs, search, and dynamic code highlighting |
| **Styling** | Custom Brand CSS (`global.css`) | Terminal-console aesthetic, emerald `#10b981` signal palette |
| **Hosting** | Cloudflare Workers (`docs-dmint-app`) | Zero-cold-start edge distribution and global asset caching |
| **Configuration** | `docs.json` | Single source of truth for navigation, branding, search, and metadata |

---

## Quick Start for Contributors

### Prerequisites

- **Node.js**: `v18.0.0` or higher (`v20+` or `v24+` recommended)
- **Package Manager**: `npm` (bundled with Node) or `bun`

### 1. Install Dependencies

From the repository root or the `docs/` directory:

```bash
cd docs
npm install
```

### 2. Launch Local Development Server

```bash
npm run dev
```

The live development server will start at:

```text
  VITE v8.3.0  ready in 280 ms

  ➜  Local:   http://localhost:3334/
  ➜  Network: use --host to expose
```

Changes made to `.mdx` files or `docs.json` update instantly via Vite Hot Module Replacement (HMR).

### 3. Build & Validate

Before submitting pull requests, run a full production build to ensure all MDX components, frontmatter, and routing links resolve cleanly:

```bash
npm run build
```

---

## Documentation Directory Structure

```text
docs/
├── docs.json                   # Master navigation, theming, metadata & search configuration
├── package.json                # Node dependencies & build scripts
├── vite.config.ts              # Vite & Holocron plugin bundler configuration
├── wrangler.jsonc              # Cloudflare Workers deployment & routing specification
├── global.css                  # Custom styling overrides (brand colors, logo filters)
├── favicon.svg                 # Brand icon
├── logo.svg                    # Brand wordmark (light theme)
├── logo-dark.svg               # Brand wordmark (dark theme)
├── AGENTS.md                   # Authoritative guidance for AI agents working in docs
├── LICENSE                     # Apache-2.0 open-source license
├── README.md                   # This documentation site manual
├── public/                     # Static assets served at domain root
│   ├── favicon.svg             # Favicon asset
│   ├── logo.svg                # Brand logo asset
│   ├── logo-dark.svg           # Dark mode logo asset
│   ├── llms.txt                # Structured overview & index for AI agents (llmstxt.org)
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
│   ├── python-integration.mdx  # @dmint.protect decorator for def, async def, class/static methods
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

## Documentation Sitemap

The documentation is organized into 8 Diátaxis-aligned core sections configured in `docs.json`:

| Group | Topic | Key Pages |
|---|---|---|
| **Get Started** | 60-second overview and 5-minute zero-to-enforced quickstart | `index`, `quickstart` |
| **Tutorials** | Hands-on, step-by-step learning projects with real code | `tutorials/protect-a-tool` |
| **Core Concepts** | Primitives, exact-request binding, approval lifecycle, and resource matching | `how-dmint-works`, `policies`, `request-binding`, `approvals`, `resources` |
| **How-To Guides** | Task-oriented recipes for Python, MCP gateway, approvals, and notifications | `python-integration`, `protecting-mcp`, `human-approvals`, `notifications`, `authoring-policies`, `agent-skills` |
| **Integrations** | Copy-paste setup recipes for modern agent environments | `cursor`, `claude-code`, `antigravity`, `custom-agents` |
| **Operations & Security** | Threat model, deployment boundaries, security proofs, and limitations | `deployment-model`, `security-model`, `known-limitations` |
| **Reference** | Exhaustive CLI flags, Python SDK APIs, JSON schemas, and DMT error catalog | `cli`, `core-api`, `policy-schema`, `mcp-protection-schema`, `errors` |
| **Help & FAQ** | Diagnostic troubleshooting index and candid architectural FAQ | `troubleshooting`, `faq` |

---

## MDX Authoring Guidelines

### Required Frontmatter

Every page **must** begin with valid YAML frontmatter specifying `title` and `description`. The `icon` attribute is optional and accepts Lucide icon names:

```mdx
---
title: "Exact Request Binding"
description: "How Dmint binds approvals to canonical RFC 8785 request fingerprints."
icon: "fingerprint"
---
```

### Component Usage

Use standard native components. Avoid writing raw HTML tags (`<div>`, `<button>`) when structured components exist:

- **`<CardGroup cols={2}>`** and **`<Card>`**: Index navigation, features, and key links.
- **`<Tabs>`** and **`<Tab>`**: Multi-environment examples (e.g. stdio vs. HTTP, Cursor vs. Claude Code).
- **`<Steps>`** and **`<Step>`**: Sequential procedures and tutorials.
- **`<CodeGroup>`**: Side-by-side commands, request/response payloads, or multi-language examples.

### Supported Callouts

Use only these verified callout components (unsupported tags like `<Important>` will cause build failures):

| Component | Intended Usage | Example |
|---|---|---|
| `<Tip>` | Productivity shortcuts, best practices | Recommended configuration patterns |
| `<Note>` | Informational context, non-critical background | Parameter defaults, version history |
| `<Warning>` | Potential security footguns, epoch mismatches | Replay defense, isolated deployment epochs |
| `<Danger>` | Critical security risks, unauthenticated exposure | Public port exposure, plaintext credentials |
| `<Check>` | Validation confirmations, successful state | Cryptographic assertion verified |

### Code Snippet Conventions

To preserve technical consistency with Dmint v2.0.3, follow these conventions in all documentation:

- **Package Installation**: Always show the single unified package:
  ```bash
  pip install "dmint[all]"
  ```
- **CLI Commands**: Refer to the unified executable `dmint` (not legacy `dmint-cli`):
  ```bash
  dmint create-policy -f access.md -o policy.json -y
  dmint verify-policy policy.json
  dmint dashboard --db-path ./approvals.sqlite3
  ```
- **MCP Gateway**: Use the `dmint-mcp` entry point or `python -m dmint.mcp`:
  ```bash
  dmint-mcp run --config mcp_protection.json
  ```
- **Python Imports**: Import directly from `dmint` or `dmint.core`:
```python
from dmint import Dmint, Policy, SQLiteApprovalStore
from dmint.models import TrustedContext
```

---

## Build & Deployment Pipeline

### Local Production Preview

To test the compiled production artifacts locally using Node.js:

```bash
# 1. Compile client bundles and RSC SSR engine:
npm run build

# 2. Start the local production server:
npm start
```

### Cloudflare Workers Deployment

The documentation site is deployed to Cloudflare Workers via `wrangler`:

```bash
# Deploy to production:
npm run deploy

# Or manually via Wrangler:
npx wrangler deploy
```

Configuration in `wrangler.jsonc`:
- **Worker Name**: `docs-dmint-app`
- **Main Entrypoint**: `./dist/.holocron/rsc/index.js`
- **Client Assets**: `./dist/.holocron/client`
- **Asset Routing**: Single-Page Application (`single-page-application`)

---

## Contributing

We welcome contributions from the open-source community!

- **Fixing Typos or Clarifying Concepts**: Edit the relevant `.mdx` file directly and run `npm run build` to verify formatting.
- **Adding Integration Guides**: Place new guides in `integrations/<tool-name>.mdx` and register the page path in `docs.json` under the `Integrations` navigation group.
- **Reporting Security Issues**: Review our root [`SECURITY.md`](../SECURITY.md) for vulnerability disclosure procedures.

For monorepo development operations and testing rules, see the root [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`AGENTS.md`](../AGENTS.md).

---

## License

The Dmint documentation and brand assets are open-source and licensed under the [Apache-2.0 License](LICENSE).
