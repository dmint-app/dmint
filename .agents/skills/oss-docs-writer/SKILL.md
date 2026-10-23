---
name: oss-docs-writer
description: Plan, write, rewrite, and audit documentation for open-source projects, libraries, SDKs, CLIs, APIs, and developer tools so that a first-time user can succeed and a skeptical expert can trust it. Use this skill whenever the user mentions docs, documentation, README, quickstart, getting started, tutorial, how-to guide, concepts page, API or CLI reference, docs site, Mintlify, Docusaurus, MkDocs, Nextra, Starlight, or says their docs are bad, shallow, confusing, AI-generated, or "not like other OSS projects" — even if they only ask to improve one page. Also use it when the user wants to restructure a docs site, write a threat model or security page, write a migration guide or changelog, or prepare a project for launch.
---

# OSS Docs Writer

Documentation is a product, and its customer is a person who has never seen the project, is mildly impatient, and will leave after the first confusing minute. Good docs get that person to a working result fast, then give them a correct mental model, then give them every detail they will ever need. Most AI-written docs fail because they describe the project from the author's point of view: feature lists, adjectives, and no depth. This skill exists to prevent that.

## The two jobs of docs

1. **Get the reader to a working result** (the "aha" moment) in minutes.
2. **Build a correct mental model** so they can solve problems the docs never mention.

Every page serves one of these. If a page serves neither, delete it.

## Workflow

Work through these phases in order. Do not start writing pages until phases 0 to 2 are done, because rewriting a wrong structure is far more expensive than getting it right once.

### Phase 0: Collect ground truth

Docs that guess are worse than no docs. Gather facts from the project itself, in this order of trustworthiness: running code > tests > source > CLI `--help` > changelog > README > existing docs. Existing docs are the least trustworthy source, especially if they were AI-generated.

- Read the README, source layout, public API, config schema, error classes and messages, CLI entry points, tests, and `examples/`. Tests are the best source of realistic usage.
- Install and run the project in a clean environment when you have a shell. Run `--help` for every command. Capture real output.
- If you cannot run it (no shell, no repo), say so explicitly and mark every example as unverified in your handoff notes. Never present invented output as real.
- Run `python scripts/collect_facts.py <repo> --out facts.md` (add `--code-prefix XYZ_` for error codes) to collect version, scripts, CLI flags, environment variables, error codes and format identifiers with file and line. It is a static scan: still run `--help` and the quickstart yourself.
- Build a **facts ledger** (see `references/verification.md`): each claim you intend to write, with its source (file:line or command). A claim without a source does not go in the docs.
- Note anything that contradicts between sources (README says X, code does Y). Surface contradictions to the user instead of choosing silently.

### Phase 1: Know the reader

Infer from the repo first; ask the user only for what the repo cannot tell you. Ask at most four short questions in one message:

1. Who is the primary user, and what are they trying to get done when they find this project?
2. What is the one-sentence pitch, and what is the "aha" moment (the first result that makes the project click)?
3. What does the project deliberately not do, and what are the known limits or maturity status?
4. Who are the competing or adjacent tools a reader will compare it to?

Write down 2 or 3 reader personas, each with: what they already know, what they want, what they fear. A typical set: the evaluator (deciding in 5 minutes whether to use it), the integrator (wiring it into their app today), and the operator or reviewer (deploying it, auditing it, or being responsible when it breaks).

### Phase 2: Design the structure

Use the four-mode model (often called Diátaxis) because readers arrive in four different states of mind, and mixing them in one page is what makes docs feel bad:

| Mode | Reader's state | Page type | Test |
|---|---|---|---|
| Learning | "Teach me" | Tutorial / Quickstart | A beginner finishes with a working result, no decisions required |
| Doing | "Help me do X" | How-to guide | Solves one real task, assumes basic knowledge |
| Understanding | "Why does it work this way?" | Concept / Explanation | Builds a mental model, discusses trade-offs and alternatives |
| Looking up | "What exactly does this option do?" | Reference | Complete, accurate, scannable, no opinions |

Produce a **sitemap** before writing anything: for each page give its path, title, mode, reader persona, prerequisite pages, and the single outcome the reader gets. Show it to the user and get a go-ahead. A default sitemap for a developer tool is in `references/page-templates.md`.

Rules for the structure:
- One page, one job. If a title needs "and", split it.
- The first-time path must be linear: Overview → Quickstart → one real tutorial → Concepts. A newcomer should never have to choose between five doors.
- Navigation names describe tasks or nouns the reader would search for ("Require human approval for risky actions"), not internal architecture ("Gate subsystem").
- Reference pages are generated from or checked against code, not hand-typed from memory.

### Phase 3: Write the pages

Write in dependency order: overview, quickstart, concepts, how-to guides, reference, troubleshooting, security and limits, migration and changelog, contributing. Use the templates and quality bars in `references/page-templates.md` and the voice rules in `references/writing-style.md`. Read both before writing the first page.

What "in-depth" means in practice — every substantial page should contain these where relevant:

- **A complete, runnable example** in the first screen, with the exact expected output next to it.
- **The why**: the problem this solves, the trade-offs, and when not to use it.
- **Variations**: the two or three realistic ways people change the example.
- **Failure modes**: the real error messages a reader will see, what they mean, how to fix them.
- **Boundaries**: what is guaranteed, what is not, what the reader is still responsible for.
- **Next steps**: where to go after this page, chosen for the reader's likely next question.

Shallow patterns to avoid: pages that are only bullet lists; feature lists without code; "Overview" pages that describe the docs; concept pages that restate the README; reference pages with a description of "The name of the user".

### Phase 4: Verify

Nothing ships unverified. Follow `references/verification.md`:

- Run every code block and command, paste real output, and fix the doc (or report a bug in the project) when they disagree.
- Check every flag, option, default, error code, and limit against source or `--help`.
- Check every number (latency, size limits, versions) has a source or remove it.
- Run `python scripts/find_phantoms.py <docs> <src> --undocumented` to list names docs mention that the code does not contain (phantom names) and public names no doc mentions. Fix or remove every phantom; confirm each by reading the code before deleting.
- Run `python scripts/check_docs.py <docs-dir>` to catch broken links, skipped heading levels, untagged code fences, leftover TODOs, and marketing language.

### Phase 5: Test as a stranger

Walk the quickstart literally, as a person who knows nothing, copying commands exactly as written, on a clean setup if possible. Record every moment of hesitation: an undefined term, a missing prerequisite, an unclear next step, output that does not match. Fix each one, then repeat. Then tell the user to hand the quickstart to one real person who has never seen the project and watch them silently; the first place they stall is the next bug in the docs.

### Phase 6: Deliver

Deliver files in the project's existing docs format and folder layout (detect Mintlify `docs.json`, Docusaurus `sidebars.js`, MkDocs `mkdocs.yml`, Starlight, Nextra, or plain Markdown, and follow its conventions, including navigation config). End with a short handoff: what was written, what is verified and how, what is **unverified** and why, contradictions found in the code or old docs, and open questions for the maintainer. Do not bury unverified items.

## Non-negotiable rules, and why

1. **Every claim traces to a source.** Readers cannot tell a true claim from a false one, so a single wrong claim makes them distrust all the others. This matters most for security, performance, and compatibility claims.
2. **Show before telling.** A working example in the first screen proves the project works and gives the reader something to hold while the explanation arrives.
3. **Examples are real.** Runnable, copy-pasteable, with real output. If you cannot run it, mark it as a fragment or unverified; never fabricate output.
4. **Define on first use.** Every project term gets a one-line definition where it first appears, and a glossary entry. Experts skim past definitions; beginners cannot function without them.
5. **One name per concept.** Pick "approval", not "approval/grant/permit/ticket" in different pages. Inconsistent words read as different things.
6. **State limits and non-goals plainly.** Trust comes from honesty about what the project does not do. Put it in a visible place, not a footnote.
7. **No marketing language.** Replace adjectives with evidence (numbers, examples, comparisons) or delete them.
8. **Explain why, not only what.** A reader who knows only what to type is stuck the first time something differs; a reader who knows why can adapt.
9. **Respect the reader's time.** Short sentences, concrete nouns, descriptive headings, no throat-clearing. Depth means completeness, not word count.
10. **Do not edit source code to make docs true.** If docs and code disagree, report it; the maintainer decides which one is wrong.

## Auditing existing docs (including AI-written ones)

When docs already exist, audit before rewriting:

1. Read every page and score it: accurate? complete? right mode (tutorial vs reference)? first-timer friendly? Record the verdict in a table.
2. Test the quickstart exactly as written and record where it fails.
3. List claims that cannot be verified, contradictions with code, undefined terms, and pages that duplicate each other.
4. Keep what is accurate and well-structured; rewrite or delete the rest; do not preserve text out of politeness.
5. Share the audit table with the user before the rewrite, so they see why each decision was made.

Typical signs of weak AI-written docs: every page opens with a pitch; bullet lists where explanation should be; the same three adjectives everywhere; examples that use placeholder names and never show output; concept pages that repeat reference pages; no troubleshooting; no mention of limits.

## Quick recipe: rewriting weak, AI-written docs

1. `collect_facts.py` -> facts sheet. Run every `--help`. Run the old quickstart on a clean setup and note where it fails.
2. `find_phantoms.py old-docs src --undocumented` -> list of wrong names and missing topics. These are your first bug list.
3. Audit table (page | accurate? | right mode? | first-timer friendly? | verdict keep/rewrite/delete).
4. Sitemap from `references/page-templates.md`; show it to the user; get a go-ahead.
5. Write in this order: overview, quickstart (run it), concept for the core idea, trust/limits page, guides, generated reference, errors, troubleshooting.
6. `find_phantoms.py` and `check_docs.py --strict` on the result; stranger test on the quickstart; handoff report.

## Special cases

- **Security, auth, crypto, or infrastructure tools**: also read `references/security-library-docs.md`. These readers are skeptical and responsible for consequences, so threat models, guarantees versus non-goals, and deployment boundaries are first-class pages.
- **CLI tools**: generate reference from `--help` output; document exit codes, environment variables, config precedence, and every flag's default.
- **Libraries/SDKs**: every public function or class gets a signature, parameters with types and defaults, return value, raised errors, and a minimal example.
- **Multi-language SDKs**: use tabs for languages, and keep the example logic identical across tabs.
- **Pre-1.0 or beta projects**: say so on the first page, and say what may change.

## Output conventions

- Format: follow the project's existing format (MDX or Markdown). Frontmatter with `title` and `description` on every page; the description is a plain sentence a search result could show.
- Headings: one H1 per page; never skip levels; headings are sentences or noun phrases a reader would search for.
- Code blocks: always a language tag; shell commands show the prompt-free command, with output in a separate block; mark placeholders with `<ANGLE_BRACKETS>` and explain them.
- Callouts: use sparingly. Note for neutral context, Warning for things that can lose data or weaken security, and nothing else.
- Links: link the first mention of a concept to its page; use descriptive link text, never "click here".
- Length: a page may be long if each section earns its place; split when a page serves two readers.

## Reference files

- `references/page-templates.md` — default sitemap and a template plus quality bar for each page type. Read before writing any page.
- `references/writing-style.md` — voice, structure of explanations, banned patterns, before/after rewrites. Read before writing any page.
- `references/verification.md` — facts ledger, how to verify code, CLI, claims, and the stranger test. Read before Phase 4.
- `references/security-library-docs.md` — extra pages and rules for security-oriented projects.
- `references/example-dmint-sitemap.md` — a concrete plan (readers, sitemap, must-be-blunt pages, claims to avoid) for Dmint; use as a model for any project.
- `scripts/collect_facts.py` — gathers versions, scripts, flags, env vars, error codes from a repo.
- `scripts/find_phantoms.py` — finds names in docs that do not exist in the code, and public code names missing from docs.
- `scripts/check_docs.py` — automated linter for a docs folder (broken links, heading levels, code fences, markers, marketing words).
