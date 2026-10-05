---
name: dmint-landing-page
description: Build or update the Dmint project's marketing/landing page (dmint.app) — an open-source, developer-facing, diagram-led page that explains Dmint's deterministic, fail-closed authorization gate for AI agent tool calls. Use this skill whenever the user asks to create, build, update, redesign, restyle, or add content to the Dmint landing page, hero, navbar, or site — even if they just say "the landing page," "dmint.app," or "the site" without repeating the design spec, since the spec lives here. Do NOT use this for the Dmint dashboard UI, docs site, or any other Dmint surface — landing page only.
---

# Dmint Landing Page

This skill encodes a fixed design system and content structure for one
specific page: the Dmint marketing/landing page. Apply it consistently
across every build or edit, unless the user explicitly asks to change
something in this conversation.

## What the page has to do

Dmint is an open-source project, not a funded SaaS product, and the page
should feel like one: precise, a little technical, confident without
selling. The central thing a visitor needs to leave understanding is a
*mechanism*, not a value proposition: an AI agent's tool call is
intercepted, checked against a policy deterministically (no LLM in that
decision), and only then allowed to run, denied, or routed to a human for
a cryptographically-bound approval. If a visitor can't redraw that flow
in their head after landing on the page, the page hasn't done its job —
prose claims about "security" without showing the actual gate don't land
for a developer audience skeptical of security-tool marketing.

That's why **diagrams carry the explanation, not paragraphs of text.**
Every major section pairs a short amount of writing with a real inline
SVG diagram showing the mechanism at that point in the story — not a
decorative icon, not a logo soup, an actual drawn request path with
labeled arrows. See "The diagrams" below before writing or editing any of
them.

## Before writing anything: ask for the logo

Dmint has its own logo. Never invent, generate, or sketch one. If the
working directory doesn't already contain a logo file, ask the user for
it before building the hero/navbar. A plain text wordmark is an
acceptable temporary stand-in only if the user says to use text for now.

## Information architecture

Don't reuse a visitor's or earlier draft's literal phrasing for nav items
or section names if it reads as a FAQ rather than a narrative — "Where is
the demo?" as a nav label, for instance, reads like a support ticket, not
a site. Instead, think about the actual story arc: problem → mechanism →
model → proof → how to start. The bundled skeleton uses this structure as
a sensible default, but treat it as a default to adapt, not a fixed script
— if the user has their own content priorities, restructure around those
while keeping the diagram-led approach. Content comes from the live docs
site (currently docs.dmint.app — fetch its pages, including the
`<page>.md` route for a clean markdown pull, rather than relying on
memory of what Dmint supports, since storage backends, webhook providers,
and CLI commands are the kind of detail that drifts from what's written
here) and should mirror whatever that site documents as current, not just
the sections below:

1. **Hero** — the one-line claim, plus the compact three-node request-flow
   diagram (agent → Dmint → tool) so the mechanism is visible before any
   scrolling happens at all.
2. **Overview / the problem** (`#overview`) — why this gate needs to
   exist, shown as a before/after comparison diagram (agent calling a
   tool directly, with nothing in between vs. the same call passing
   through Dmint). Per the diagramming approach below, the entire point
   of this diagram is the one arrow that's missing on one side and
   present on the other — don't dilute that by drawing more than is
   needed to make that comparison land.
3. **How it works** (`#how-it-works`) — the flagship diagram: request →
   canonicalize + hash → decision → three branches (allow / deny /
   approval required), where allow and an approved request both visibly
   reach the same "tool runs" box and deny visibly terminates. This is
   the page's single most important picture — it's the whole security
   argument in one image. Pair it with a genuine three-step sequence
   (request binding, deterministic policy evaluation, cryptographic
   approval) using numbered steps, since this content really is
   sequential — that's what earns the numbering (see frontend-design
   principles below).
4. **Capabilities / the permission model** (`#capabilities`) — a
   capability is (tool, action, resource), not a role — show the three
   inputs combining into one capability that gets matched against
   `policy.json`. This is what makes "deny by default" concrete: nothing
   is granted in bulk.
5. **Deterministic enforcement** (`#deterministic`) — the argument for
   *why* no model is in the decision path: a probabilistic guardrail can
   be swayed by what it reads, a compiled policy check can't. Reuses the
   two-row before/after pattern from Overview rather than inventing a new
   diagram shape.
6. **Protecting MCP servers** (`#mcp-proxy`) — the `dmint-mcp` gateway
   sitting in front of downstream MCP servers: tool aggregation, SSRF
   validation, and the same policy + approval check applied once, in
   front of every server it wraps.
7. **Storage** (`#storage`) — SQLite by default, PostgreSQL if needed,
   switched with one environment variable; Core is the only component
   that touches the database directly, which is the real security
   property worth drawing (not just "we support Postgres now").
8. **Webhooks / notifications** (`#webhooks`) — Slack/Discord/Teams
   notifications on `approval_required`, drawn with the new `.d-aux`
   dashed-line treatment (see "The diagrams") to make clear the webhook
   is a best-effort side-channel, not part of the authorization decision.
9. **A real example** (`#example`) — a short terminal transcript of one
   blocked call becoming an approved one, start to finish — including
   `dmint pending` and the approval command, so the CLI and the webhook
   notification both show up as part of one concrete story instead of
   staying abstract. Concrete and specific beats another diagram here;
   this is the one section that's prose/code, on purpose.
10. **CLI reference** (`#cli`) — a plain grid of the commands a user will
    actually type (`create-policy`, `create-mcp-policy`, `verify-policy`,
    `pending`, `approve`/`reject`, `dashboard`), one line of description
    each. Not numbered — this is a reference, not a sequence.
11. **Install** (`#install`) — minimal, a pip install and one CLI command.
    Resist the urge to oversell this section; developers want the
    command, not copy. To keep this section from going visually flat
    after the diagram-heavy top of the page, pair the install command
    with one small real artifact — a short `policy.json` snippet showing
    an actual rule (e.g. an `approval_required` rule on a destructive
    action) — rather than leaving it as bare prose next to a terminal
    block. That snippet is a second concrete thing to look at, not more
    explanation.
12. **Demo** (`#demo`) — space for the real demo video/recording once it
    exists. Keep this section genuinely empty of any real media until the
    recording exists; the bundled skeleton's placeholder is a drawn
    viewfinder frame (four corner brackets, a quiet "recording soon" with
    a pulsing dot reusing `.d-pulse`) rather than a fake video player —
    it signals "something will go here" without implying a video is
    already embedded.

## The navbar

The navbar holds exactly two things: the logo, and the theme toggle. No
link list — not even plainly-named ones. The page is short enough to
scroll, the sections already flow in a deliberate narrative order, and a
row of nav links is the one piece of template chrome this page doesn't
need; it would compete with the diagrams for being the thing that
explains the page. If the user asks for navigation back, add it as
in-content cross-references (the hero's CTA linking to Install, a "see
how it works" aside near the problem statement) rather than reintroducing
a persistent link bar — the goal is fewer things competing for attention
in that first standard-height unit, not restoring a menu.

### Theme toggle: an icon, not a labeled button

The toggle is a bare sun/moon icon button — no background box, no text
label, no border. Both icons live in the DOM at all times (`.icon-sun`,
`.icon-moon` inside the same `<button>`); CSS shows only the one matching
the current theme via `[data-theme]`, so there's no markup swap on click,
just an attribute change. Both icons use `stroke="currentColor"` so they
inherit `--text` automatically — never hardcode an icon color.

**Clicking it spreads the new theme outward from the icon itself**, across
the whole page, rather than an instant flat swap. This is built with the
View Transitions API (`document.startViewTransition`), animating an
expanding circular `clip-path` centered on the icon's position out to the
farthest corner of the viewport — `assets/theme.js` has the complete,
working implementation; use it as-is rather than re-deriving the circle
math each time. Two things matter about *why* it's built this way, so an
edit doesn't quietly break them:

- **It degrades to an instant swap, never a broken half-animation.**
  Browsers without View Transitions support, and anyone with
  `prefers-reduced-motion: reduce`, just get the theme change immediately.
  Don't add a hand-rolled animation fallback for those cases — instant is
  the correct fallback, not a lesser version of the effect.
- **The origin point is the icon's own center, not the raw mouse
  coordinates.** Keyboard activation (Enter/Space) fires a click event
  with no meaningful `clientX`/`clientY`, so computing the origin from the
  toggle's `getBoundingClientRect()` is what makes the effect work the
  same way for mouse and keyboard users. If the toggle ever moves
  elsewhere in a layout change, this still works without adjustment —
  don't hardcode a fixed pixel origin.

The toggle's `aria-label` always names the action the click will perform
("Switch to light theme" while dark is active, and vice versa) — update
the label alongside the theme, not just the icon, since a screen reader
user never sees which icon is showing.

## The footer

Unlike the navbar, the footer is where a link list belongs. By the time a
visitor reaches it, the page has already made its argument diagram by
diagram — wayfinding here doesn't compete with anything for attention,
which is exactly the reason the navbar doesn't carry one. Structure: the
wordmark and a one-line restatement of the thesis on the left, a few
short columns of real links (learn/docs/project — pointing at the page's
own sections plus the live docs site and GitHub/PyPI) on the right, and a
plain bottom line (license, a short closing line) underneath. Same rules
as everywhere else apply — background contrast (`--bg-alt`) for
separation, generous spacing, no border, no shadow.

## The diagrams

Hand-authored inline `<svg>` using native shapes (`rect`, `line`, `path`,
`text`) — no diagramming library, no external images. For every diagram:

- **Show the mechanism, not a label for it.** A box that says "Dmint"
  with nothing flowing in or out of it tells the visitor nothing a word
  wouldn't. Draw the request's actual path and label the arrows with what
  's happening on them (not just "→").
- **Color is semantic, not decorative.** Dmint's own three outcomes —
  allow, deny, approval-required — have fixed colors defined as CSS
  custom properties in `design-system.css` (`--allow` mint,
  `--deny` muted red, `--approval` amber) and SVG helper classes
  (`.d-allow`, `.d-deny`, `.d-approval` for strokes; the `-fill` variants
  for text/fills). Reuse these consistently everywhere a diagram shows
  one of those outcomes — don't introduce a new ad hoc color per diagram.
  Structural elements (nodes, connecting lines with no specific outcome)
  use `.d-node` / `.d-line`, which read from the page's theme variables
  (`--bg-alt`, `--line`, `--text`) so they work in both light and dark
  mode automatically.
- **The one motion idea on the page, reused.** A flowing-dash animation
  (`.d-flow`, defined once in `design-system.css`) represents a signal
  moving along a connector, and a slow pulse (`.d-pulse`) marks the node
  where the actual decision happens. These two classes are the *entire*
  animation vocabulary for the page — apply them to diagram elements,
  don't invent new animations per section, and don't add animation to
  anything that isn't illustrating something moving or deciding (no
  hover-grow on buttons, no scroll-reveal, no fade-ins). Both respect
  `prefers-reduced-motion` already via the stylesheet — don't duplicate
  that logic per diagram.
- **Size boxes with real margin around their text, not a tight fit.** A
  text label at this font size runs roughly (characters × 7.2px) for
  `.d-label` (12px) or (characters × 6.6px) for `.d-label--dim` (11px) —
  a box needs that plus at least ~40px of padding on top, not just
  "about as wide as the word looks." An earlier version of this page sized
  a box to roughly fit `delete_customer()` and the text ran outside the
  rectangle; check the arithmetic before shipping a new diagram, don't
  eyeball it.
- **A dashed, static `.d-aux` line is the one other line style on the
  page**, reserved for a best-effort side-channel that's explicitly not
  part of the critical decision path (webhook notifications, for
  instance) — it never gets `.d-flow`'s animation, specifically because
  looking inert is the point: it can drop silently, unlike the solid path
  it branches from. Don't use it for anything that's actually part of the
  authorization decision, even a boring part.
- **Size by `viewBox`**, scale with CSS (`figure svg { width: 100%; height:
  auto; }`, already set). Wide request-flow diagrams read left to right;
  don't force a diagram into a layout its content doesn't fit.
- **Every diagram is a `<figure>`** with `role="img"`, an `aria-label`
  stating the diagram's actual claim in one sentence, and a
  `<figcaption>` — the caption should say what to notice, not just
  restate the picture ("Deny is a dead end — that's the point of it" is a
  caption; "A diagram of allow, deny, and approval" is not).
- **Text in diagrams stays short** (a word or a few words per label) —
  explanation belongs in the surrounding prose or the figcaption, not
  crammed into the SVG.

`assets/page-skeleton.html` contains three fully worked, validated example
diagrams (the hero's compact flow, the overview's before/after, and the
flagship three-branch decision diagram in "How it works") — use these as
the concrete pattern to extend or adapt rather than inventing SVG
structure from scratch each time.

## Visual language

- **True rectangles, zero `border-radius`, zero `box-shadow`.** Every box
  is a sharp-cornered rectangle with no drop shadow. Separation between
  elements comes from background-color contrast (`--bg` vs `--bg-alt`)
  and generous whitespace, never a drawn border (a non-decorative
  `:focus-visible` outline for keyboard accessibility is the one
  exception — that's a functional indicator, not a layout device) and
  never a shadow.
- **Generous, even spacing.** Use the spacing scale in
  `design-system.css` (`--space-1` through `--space-7`) rather than ad
  hoc values — v1 of this page read as cramped because boxes didn't have
  enough breathing room; err toward more space, not less, especially
  around diagrams and between a heading and its body text.
- **Headings are plain text color** (`var(--text)`), not an accent color.
  The mint/amber/red palette is reserved for the three decision outcomes
  so that it still carries meaning wherever it shows up — if headings
  were mint too, the accent would mean "heading" half the time and
  "allow" the other half, and stop communicating either clearly.
- **No tracked-out ALL-CAPS labels, no middot-joined meta strings, no
  "→" appended to link text, no single-word-bolded headlines.** These
  read as generic AI-generated template chrome regardless of subject
  matter — see the frontend-design skill for the fuller list of defaults
  to avoid. The `.eyebrow` class in the stylesheet is deliberately plain
  lowercase, not tracked caps.
- **Numbered steps only where content is a genuine sequence.** The three
  steps in "How it works" (request binding → policy evaluation →
  cryptographic approval) are an actual sequence, so numbering them is
  earned. Don't add numbering to content that isn't sequential just for
  visual rhythm.

## Typography

Primarily monospace, in this priority order, loaded via Google Fonts
where available:

```css
font-family: 'Roboto Mono', 'Google Sans Code', 'Inconsolata', 'Fira Mono',
             ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
```

Verify `Google Sans Code` is actually loadable via Google Fonts at build
time before including it in the `<link>` tag (its public availability
has been limited) — if it isn't loadable, drop it from the `<link>` but
leave it in the CSS stack as a harmless fallback-skip.

## Color system

Defined once in `design-system.css`, same values in both themes:

| Token | Meaning | Value |
|---|---|---|
| `--allow` | allow / success / primary CTA | `#3ECFA0` (mint) |
| `--deny` | deny / blocked | `#E5484D` |
| `--approval` | approval required / human-in-the-loop | `#E8B339` |

Theme-dependent tokens (`--bg`, `--bg-alt`, `--text`, `--text-dim`,
`--line`) flip between dark mode (near-black background, off-white text)
and light mode (near-white background, near-black text) via
`data-theme="dark"|"light"` on `<html>`, set by inline script before
paint to avoid a flash of the wrong theme, with the user's explicit
toggle choice persisted in `localStorage`.

`::selection` uses mint background with fixed dark text
(`var(--on-allow)`), in both themes.

## Layout

- **Max content width 1140px**, centered, via the shared `.container`
  class — applied consistently across the navbar, hero, and every
  section, not just the hero.
- **Navbar + hero are one combined, standard-height unit** — not forced
  to fill the viewport. Flexbox for the navbar's internal row and for the
  hero's content stack.
- **Content sections size to their content**, not to a forced `100vh`
  — v1's hard-locked full-height-per-section rule produced awkward empty
  space around short sections. Let generous padding (`--space-7`) create
  rhythm between sections instead; it's fine for sections to be different
  heights.
- **CSS Grid for section-level/multi-item layout** (the `.split`
  two-column text+diagram layout, the `.steps` grid), **Flexbox for
  component-level arrangement** (navbar row, hero content stack, button
  groups).

## Bundled starting point

`assets/design-system.css` has the full token system, base type, layout
primitives, and the diagram theming/animation classes described above
(including `.d-aux`, the `.cmd-grid` reference-card grid, the
`.demo-frame` placeholder viewfinder, and the `.site-footer` styles),
ready to use as-is. `assets/theme.js` has the complete working theme
toggle (the spreading-circle transition and its fallback) — use it as-is,
see "Theme toggle" above for why its details matter. `assets/page-
skeleton.html` has the complete structural skeleton — navbar with the
icon toggle, hero, eleven content sections (the full default story arc
from "Information architecture" above, including seven worked diagrams),
and a footer — with realistic placeholder copy already in Dmint's voice,
sourced from the live docs site, and loads `theme.js` via a plain
`<script src="theme.js">`. Start from these files and adapt
content/structure to the specific request rather than rebuilding from
scratch; if the request only needs a subset of this story (say, just the
mechanism and install), trim sections rather than forcing all eleven in.

## When updating an existing build of this page

If a previous version of the page already exists in the project, edit it
in place rather than regenerating from the skeleton — preserve real
content, the real logo, and any sections added since — and apply the
rules above only to what's being changed, not as a reason to rewrite
working sections outside the request's scope.
