---
name: antigravity
description: >
  Use this skill whenever the user wants to convert a code repository into a Mintlify
  documentation site — this covers initial scaffolding, docs.json configuration, page
  architecture, section design, MDX authoring, component usage, navigation structure,
  theming, and deployment. Trigger this skill whenever the user mentions Mintlify, wants
  to generate docs from code, asks how to structure a documentation site, wants to add
  or redesign a docs section, or is working on any part of the antigravity docs pipeline.
  Also trigger when the user wants advice on what sections a good documentation site should
  have, how to write API reference pages, how to design a changelog, or how to style a
  Mintlify site to match a brand.
---

# Antigravity — Mintlify Documentation Site Skill

Antigravity converts a code repository into a polished, production-ready Mintlify
documentation site. This skill guides every decision: information architecture,
section design, MDX authoring, theming, and deployment.

---

## What is Mintlify?

Mintlify is a documentation platform where:
- Config lives in `docs.json` (or `mint.json` for older projects)
- Pages are `.mdx` files (Markdown + JSX components)
- Navigation, colors, fonts, and favicon are all declared in `docs.json`
- Mintlify provides a rich built-in component library (callouts, tabs, cards, code blocks, API references, etc.)
- Deployment is via the Mintlify GitHub app — push to main, docs update automatically

---

## Site Architecture

Every Mintlify site antigravity produces follows this structure:

```
docs/
├── docs.json              ← master config (nav, theme, socials)
├── index.mdx              ← landing / home page
├── quickstart.mdx         ← 5-minute get-started guide
├── introduction.mdx       ← what is this, why does it exist
│
├── concepts/              ← mental models, key ideas
│   └── *.mdx
│
├── guides/                ← task-oriented how-tos
│   └── *.mdx
│
├── api-reference/         ← endpoint docs (auto or manual)
│   ├── overview.mdx
│   └── *.mdx
│
├── configuration/         ← all config options, env vars
│   └── *.mdx
│
├── examples/              ← real, runnable examples
│   └── *.mdx
│
├── changelog/             ← version history
│   └── *.mdx
│
└── contributing.mdx       ← how to contribute / open source
```

---

## docs.json — Master Configuration

Always start here. Every site must have:

```json
{
  "$schema": "https://mintlify.com/docs.json",
  "theme": "mint",
  "name": "<Project Name>",
  "colors": {
    "primary": "<brand-primary>",
    "light": "<brand-light>",
    "dark": "<brand-dark>"
  },
  "logo": {
    "light": "/logo/light.svg",
    "dark": "/logo/dark.svg"
  },
  "favicon": "/favicon.svg",
  "topbarLinks": [
    { "name": "GitHub", "url": "https://github.com/<org>/<repo>" }
  ],
  "topbarCtaButton": {
    "name": "Get Started",
    "url": "/quickstart"
  },
  "navigation": [...],
  "footerSocials": {
    "github": "https://github.com/<org>/<repo>",
    "twitter": "https://twitter.com/<handle>"
  }
}
```

### Color Strategy
- `primary` — used for links, active nav, and CTA buttons. Make it the brand's main accent.
- `light` — slightly lighter variant for light-mode highlights.
- `dark` — slightly darker or more saturated variant for dark-mode highlights.
- Both `light` and `dark` logo variants should be provided so the site looks great in both modes.

> The model already knows the brand's colors and theme. Apply them consistently across docs.json and any custom CSS.

---

## Navigation Structure

Navigation is declared as an array of `NavigationGroup` objects. Use this exact anatomy:

```json
"navigation": [
  {
    "group": "Get Started",
    "pages": ["index", "introduction", "quickstart"]
  },
  {
    "group": "Core Concepts",
    "pages": ["concepts/overview", "concepts/<key-concept-1>", "concepts/<key-concept-2>"]
  },
  {
    "group": "Guides",
    "pages": [
      "guides/installation",
      "guides/configuration",
      "guides/advanced-usage"
    ]
  },
  {
    "group": "API Reference",
    "pages": [
      "api-reference/overview",
      "api-reference/<endpoint-1>",
      "api-reference/<endpoint-2>"
    ]
  },
  {
    "group": "Configuration",
    "pages": ["configuration/options", "configuration/env-vars"]
  },
  {
    "group": "Examples",
    "pages": ["examples/basic", "examples/advanced"]
  },
  {
    "group": "Resources",
    "pages": ["changelog", "contributing"]
  }
]
```

**Navigation rules:**
- "Get Started" always comes first
- Keep each group to 3–8 pages; split into sub-groups if larger
- Page paths in navigation omit the `.mdx` extension
- Nested groups use the `pages` key with nested objects (Mintlify supports one level of nesting)

---

## Required Sections & What Each Contains

### 1. Landing Page (`index.mdx`)
The "hero" of the docs. Must answer: *What is this? Why should I care?*

```mdx
---
title: "Project Name"
description: "One-sentence elevator pitch."
---

<Hero title="Project Name" description="What it does in plain English." />

## Key Features

<CardGroup cols={2}>
  <Card title="Feature 1" icon="bolt" href="/guides/feature-1">
    Short description of the benefit.
  </Card>
  <Card title="Feature 2" icon="shield" href="/guides/feature-2">
    Short description of the benefit.
  </Card>
</CardGroup>

## Quick Start

<Steps>
  <Step title="Install">...</Step>
  <Step title="Configure">...</Step>
  <Step title="Run">...</Step>
</Steps>
```

### 2. Introduction (`introduction.mdx`)
- What problem does this solve?
- Who is it for?
- How does it compare to alternatives?
- Architecture diagram if applicable

### 3. Quickstart (`quickstart.mdx`)
- Time estimate at the top: *"You'll be up and running in 5 minutes."*
- Prerequisites section
- Numbered steps using `<Steps>`
- Working code example at the end
- Link to "next steps" at the bottom

### 4. Core Concepts (`concepts/`)
One page per key mental model. Each concept page:
- Opens with a one-paragraph plain-English explanation
- Uses a diagram or illustration if the concept is spatial/relational
- Has a "Key Takeaways" callout at the bottom

### 5. Guides (`guides/`)
Task-oriented "how do I…" pages. Each guide:
- Title starts with a verb: *"Deploying to Production"*, *"Configuring Auth"*
- Has a prerequisites callout at the top
- Uses `<Steps>` for multi-step procedures
- Includes runnable code blocks with language tags
- Ends with troubleshooting tips or a "What's next" section

### 6. API Reference (`api-reference/`)
For REST APIs, use Mintlify's OpenAPI integration:
```json
// in docs.json
"openapi": ["openapi.yaml"]
```
For non-REST APIs or SDK method references, author pages manually:

```mdx
---
title: "methodName()"
description: "What this method does."
---

<ParamField path="param1" type="string" required>
  Description of param1.
</ParamField>

<ResponseField name="result" type="object">
  Description of the return value.
</ResponseField>

<CodeGroup>
  <Code title="Example">
    ```ts
    const result = await client.methodName({ param1: "value" });
    ```
  </Code>
</CodeGroup>
```

### 7. Configuration (`configuration/`)
- Full table of all config options (key, type, default, description)
- Environment variables table
- Example config file with annotations

```mdx
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `key`  | `string` | `""` | What it controls |
```

### 8. Examples (`examples/`)
- Real, copy-pasteable, runnable examples
- Annotate non-obvious lines with inline comments
- Show both minimal and advanced versions

### 9. Changelog (`changelog/`)
```mdx
---
title: "Changelog"
---

## v1.2.0 — 2024-01-15

<AccordionGroup>
  <Accordion title="New Features">
    - Added X
    - Added Y
  </Accordion>
  <Accordion title="Bug Fixes">
    - Fixed Z
  </Accordion>
</AccordionGroup>
```

### 10. Contributing (`contributing.mdx`)
- How to file a bug
- How to submit a PR
- Code style guide link
- Setup instructions for local dev

---

## MDX Authoring Rules

### Frontmatter (required on every page)
```mdx
---
title: "Page Title"           # shown in browser tab and nav
description: "One sentence."  # shown in search results and OG tags
icon: "rocket"                # optional, Lucide icon name
---
```

### Component Vocabulary
Use these Mintlify built-ins; never reinvent them with raw HTML:

| Component | When to use |
|-----------|-------------|
| `<Note>` | Non-critical tips |
| `<Warning>` | Things that can break something |
| `<Danger>` | Irreversible or destructive actions |
| `<Tip>` | Best practices and shortcuts |
| `<Info>` | Neutral, contextual information |
| `<Steps>` | Ordered procedures |
| `<Card>` + `<CardGroup>` | Feature grids, link collections |
| `<Tabs>` + `<Tab>` | Language variants, OS variants |
| `<AccordionGroup>` + `<Accordion>` | FAQ sections, changelogs |
| `<CodeGroup>` + `<Code>` | Multi-language code examples |
| `<ParamField>` | API parameter documentation |
| `<ResponseField>` | API response documentation |

### Code Blocks
Always include the language identifier:
````mdx
```typescript title="src/index.ts"
// code here
```
````

### Callout Usage
- Use `<Warning>` for breaking changes or destructive actions
- Use `<Note>` for "by the way" information
- Don't stack more than two callouts in a row

---

## Theming Reference

The model knows the brand's color palette and logo. When applying the theme:

1. Set `colors.primary` to the main brand accent
2. Provide both `logo.light` and `logo.dark` — the dark logo should work on white, the light logo on dark backgrounds
3. Custom CSS can be added via `"custom": { "css": "/custom.css" }` in docs.json for:
   - Custom font faces
   - Overriding Mintlify's default spacing
   - Custom hero components

---

## Repo-to-Docs Pipeline (How antigravity works)

When converting a code repo to docs:

1. **Scan the repo** — identify: README, existing docs/, API definitions, config files, source entry points, test files (for usage examples)
2. **Extract intent** — what does this project do? Who uses it? What are the main abstractions?
3. **Map to sections** — match source modules/packages to Concepts and API Reference pages
4. **Draft page skeletons** — create `.mdx` files with frontmatter and H2 section headers, leave content as `<!-- TODO -->` placeholders where you need more info
5. **Populate docs.json** — build the full navigation from the page map
6. **Fill pages** — write content section by section, starting with Quickstart (highest impact)
7. **Add components** — replace plain paragraphs with `<Steps>`, `<Card>`, `<Tabs>` etc. where they add clarity
8. **Review callouts** — every Warning and Danger callout must be earned; don't over-annotate
9. **Test navigation** — every page in docs.json must have a corresponding `.mdx` file

---

## Quality Checklist

Before considering any page done:

- [ ] Frontmatter has `title` and `description`
- [ ] Page answers one clear question
- [ ] Code examples are runnable, not pseudo-code
- [ ] No broken links in `href` or `url` props
- [ ] Callouts are appropriate (Warning ≠ Note)
- [ ] Page appears in `docs.json` navigation
- [ ] Dark/light mode looks correct (no hardcoded colors in MDX)

---

## Read These References When Needed

- `references/mintlify-components.md` — full component prop reference
- `references/docs-json-schema.md` — complete docs.json schema with all options
- `references/seo-and-metadata.md` — OG tags, sitemap, meta config

These are loaded on demand — only read them when working on that specific aspect.
