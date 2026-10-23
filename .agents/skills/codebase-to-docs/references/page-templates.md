# Page templates

Skeletons for each page type. The notation uses generic components (`<Steps>`, `<Tabs>`, `<Callout>`) so the structure is clear; translate them into the user's framework using `frameworks.md`. `acme` is a stand-in project name.

## Contents

1. Introduction
2. Installation / Quickstart
3. Concept page
4. Integration page
5. Guide (recipe)
6. Reference pages (config, CLI, API, env vars, errors)
7. Security model / threat model
8. Troubleshooting
9. FAQ
10. Migration and changelog
11. Docs map: ordering and navigation

---

## 1. Introduction

Purpose: let a reader decide in 60 seconds whether this project is for them.

```mdx
---
title: Introduction
description: What Acme does, the problem it solves, and when to use it.
---

Acme is a <what it is, one sentence, concrete>.

## The problem

<Two to four sentences in the reader's words: what breaks without this.>

## How it works

<A small diagram (flow or boundary) and 3-5 sentences describing the path a request takes.>

## What you get

- <capability 1, concrete and verifiable>
- <capability 2>
- <capability 3>

## When not to use Acme

<Honest list: non-goals, things better handled elsewhere. This builds trust.>

## Next steps

- [Quickstart](/docs/quickstart) - get a working result in 5 minutes
- [Concepts](/docs/concepts/...) - the ideas behind Acme
```

Source for this page: README opening, design notes, the invariants/guarantees the code actually enforces.

## 2. Installation / Quickstart

Purpose: the shortest path from nothing to a verified working result. This is the most important page in the set.

```mdx
---
title: Quickstart
description: Install Acme and protect your first call in under five minutes.
---

By the end of this page you will have <specific working result>.

## Prerequisites

- Python 3.10 or later (`python --version`)

<Steps>
<Step title="Install Acme">
<Tabs items={["pip", "uv", "poetry"]}>
  <Tab value="pip">```bash
pip install acme
```</Tab>
  <Tab value="uv">```bash
uv add acme
```</Tab>
  <Tab value="poetry">```bash
poetry add acme
```</Tab>
</Tabs>
</Step>

<Step title="Create <the main object>">
Create a file named `app.py`:

```python title="app.py"
<complete, imported, runnable code>
```
</Step>

<Step title="Run it">
```bash
python app.py
```

You should see:

```text
<real output>
```
</Step>
</Steps>

## Verify it works

<One command that proves the integration is live, with expected output. Include the failure case if it teaches something.>

## Next steps

- <Most common next task>
- <Second>
- <Reference link>
```

Rules: no more than 5 steps; if the reader needs a database or key, include the cheapest working option (for example SQLite) and link to production setup later; test every command in a clean environment.

## 3. Concept page

Purpose: build the mental model the reader needs to use the guides well.

```mdx
---
title: Approval lifecycle
description: How a request moves from pending to approved to consumed.
---

<One paragraph: the problem this concept solves, in plain words.>

## Definition

<Precise definition, 2-4 sentences. Use the exact terms from the code.>

## Example

```python title="example.py"
<smallest example that shows the concept>
```

<One paragraph: what to notice in the example.>

## How it works

<State machine, flow or table. Diagram where useful.>

| State | Meaning | Moves to |
| ----- | ------- | -------- |
| ...   | ...     | ...      |

## Guarantees and limits

<What the project promises about this concept and what it does not.>

## Related

- <links>
```

## 4. Integration page

Purpose: show how to connect the project to one external surface (a framework, client, runtime or protocol). Use one page per surface, with the same structure every time, so readers can compare quickly.

```mdx
---
title: Cursor
description: Protect MCP tools used by Cursor with Acme.
---

<One sentence: what this integration does.>

## Before you start

<Only what is specific to this integration, linked to the Quickstart for the rest.>

## Setup

<Steps>
  <Step title="Create the config">```jsonc title="mcp_protection.json"
<complete config>
```</Step>
  <Step title="Register it in <client>">```json title=".cursor/mcp.json"
<complete client config>
```</Step>
  <Step title="Confirm it is active">
<command or UI action, plus expected result>
  </Step>
</Steps>

## What happens at runtime

<Short description of the request path, and which decisions the reader will see.>

## Troubleshooting

<Two or three real failure modes for this integration with fixes.>
```

## 5. Guide (recipe)

Purpose: a task the reader wants to accomplish, end to end. Titles are verbs: "Require approval for destructive queries".

```mdx
---
title: Require approval for destructive queries
description: Pause UPDATE and DELETE calls until a human approves them.
---

<What you will build and why someone wants it, in two sentences.>

## Prerequisites

- Completed the [Quickstart](/docs/quickstart)

<Steps>
  <Step title="...">...</Step>
</Steps>

## Test it

<A command or script that triggers each outcome and the exact output for each.>

## Production notes

<Two to four bullets: what to change before shipping (storage, TTLs, secrets).>

## Next steps
```

Aim for 3-6 steps. If you need more, split into two guides.

## 6. Reference pages

Reference is exhaustive and generated from facts (the inventory), not prose memory. Pick the shape that fits.

**Configuration / options**

```mdx
## `approval_ttl`

<One sentence: what it controls.>

| Type | Default | Required |
| ---- | ------- | -------- |
| `timedelta` | `timedelta(minutes=30)` | No |

```python title="example.py"
<one realistic example>
```

<Edge cases: invalid values, interaction with other options.>
```

**CLI**: one section per command: synopsis block, a flags table (flag, default, description), one realistic example with output, exit codes.

**Python / JS API**: one section per public symbol: signature, parameters table, return value, raises/throws, a short example. Only document symbols that are part of the public surface (exported in `__all__` / `index`).

**Environment variables**: one table: name, default, effect, where it is read. Group by feature. Mark secrets.

**Errors**: one row per error type or code: name, when it is raised, how to fix, whether the call may be retried.

## 7. Security model / threat model

Purpose: let a security-minded reader decide whether to trust the project. Be precise and unglamorous. See `domain-playbooks.md` for what to cover for security tools. Shape:

```mdx
## What Acme protects against
| Threat | How Acme addresses it | Where enforced |

## What Acme does not protect against
<Explicit non-goals and residual risks.>

## Trust boundaries
<Diagram: what is trusted, what is not.>

## Guarantees
<Numbered invariants, each phrased as a testable statement and linked to the code or test that enforces it.>

## Hardening checklist
- [ ] <production setting 1 with link>

## Reporting a vulnerability
<Link to SECURITY.md or the contact process.>
```

## 8. Troubleshooting

Symptom, cause, fix. Use the exact error text as the heading so people find it by searching.

```mdx
## `AuthorizationError: no matching rule`

**Cause:** <why this happens>

**Fix:** <what to change, with a code block>
```

Source the entries from the code's raised errors, from issue trackers if available, and from what you hit while running the Quickstart yourself.

## 9. FAQ

Only real questions with short answers; link out for depth. Typical entries: how it differs from alternatives, performance impact, licensing, how to get help.

## 10. Migration and changelog

Migration guides: one page per breaking release, listing each change as before/after code with the reason. The changelog can embed or link the repository's `CHANGELOG.md`; do not rewrite history from memory.

## 11. Docs map: ordering and navigation

Order navigation from first-contact to deep-dive: Introduction, Quickstart, Concepts, Integrations, Guides, Security, Reference, Troubleshooting. Within each group, order by how often readers need the page, not alphabetically (except Reference, where alphabetical or by feature group is fine). Every page appears in the navigation file; the checker lists orphans.
