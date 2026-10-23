---
name: codebase-to-docs
description: Turn a codebase into professional, copy-paste-first developer documentation in the style of better-auth, Stripe or Supabase docs - quickstart, concepts, integration guides, recipes, API/CLI/config reference, security model, troubleshooting. Grounds every claim in the actual source and verifies every code snippet. Make sure to use this skill whenever the user wants docs written, rewritten, audited or fixed for a repo, library, SDK, CLI, API, MCP server or agent tool - even if they only say "README", "docs site", "quickstart", "API reference", "developer docs", "my docs are bad / AI-generated / outdated", or just paste a GitHub URL and ask for documentation.
---

# Codebase to Docs

Produce developer documentation that a stranger can follow from zero to a working integration by copy-pasting, the way better-auth's docs work. The reader should never have to guess an import, a filename, an env var or what the output should look like.

Most AI-written docs fail in the same ways: they describe the project in marketing language instead of showing how to use it, they contain snippets with missing imports or invented APIs, they repeat the README in five places, and they claim things the code does not do. This skill avoids those failures by working from evidence (the source code) and by checking the result mechanically before handing it over.

## The bar

A page is done when all of these are true:

1. **Copy-paste complete.** Every code block runs as shown: imports included, filename stated, realistic values, and the expected output shown after commands. Anything the reader must change is marked and explained.
2. **Task-first.** Guides open with what the reader will have working at the end, then go straight to steps. Explanation lives in concept pages and short "why" notes, not in front of the first command.
3. **Grounded.** Every name, flag, default, env var and behavior on the page exists in the source at a pinned commit. If you cannot find it in the code, it does not go in the docs. The README, old docs, docstrings and comments are leads, never evidence.
4. **Verified more than once.** Every factual sentence has an entry in a claim ledger with exact evidence (file, lines, quote) and at least two different checks (reading, a test, running it, blind re-derivation). Scripts re-check the evidence mechanically, execute the snippets, and lint the wording. Anything that could not be checked is left out of the page and listed in the report. See `references/verification.md`.
5. **Honest and bounded.** Limits, non-goals and failure behavior are stated plainly. Claims say when they hold ("When no rule matches, `evaluate` returns `DENY`"), not how impressive they are. Words like "guarantee", "100%", "never", "secure" and "robust" do not appear unless a verified claim bounds them.
6. **Scannable.** Short sections, descriptive headings, tabs for variants (package managers, frameworks, databases), tables for reference data, and a "Next steps" block at the end.

## Workflow

Work through these phases in order. Keep a running `docs-plan.md` and, at the end, a short report (see "Final report").

### Phase 0: Get the code and pick the mode

Find the code on disk first: an uploaded zip or folder, the current working directory in a coding environment, or a path the user gives. The inventory script and the checker need a local checkout.

If the user only gave a GitHub URL and you have no filesystem access to the repo, say so briefly and work from what you can fetch (README, package manifest, key source files, existing docs) while asking for a zip or clone for the full treatment. Do not invent anything to fill the gap; mark those areas as unverified in the report.

Pin the commit: record `git rev-parse HEAD` (and whether the working tree is dirty). Every piece of evidence is read at that commit. If the code changes while you work, re-run the passes for every page whose sources changed.

Create a clean environment and install the package from the checkout (recipe in `references/verification.md`, section 11), because docs must be verified against what a reader will actually have. If you cannot install or run it, say so now and carry that limit through to the report.

Then decide the mode:

- **New docs**: no docs folder, or only a README. Build the full set.
- **Rewrite/audit**: a docs folder already exists. Read every existing page, compare it against the inventory and the code, and list what is wrong, stale, missing or duplicated before writing anything. Keep good pages, rewrite weak ones, delete dead ones, and keep URLs stable where possible (add redirects or notes if you must move a page).

### Phase 1: Inventory the codebase

Run the inventory script. It extracts the facts that docs most often get wrong: package name and version, install extras, entry points, public exports, CLI commands and flags, env vars, exception classes, existing docs framework, examples and tests.

```bash
python <skill-path>/scripts/inventory.py <repo-root> --out <workdir>/inventory
```

This writes `inventory.json` (used by the checkers) and `inventory.md` (read it). The script is a map of where to look, not proof: it analyses Python source in depth (AST), reads Node projects only at the `package.json` level, and detects docs tooling for any language. Its CLI and env-var detection are static hints; the real `--help` output and a real run are the authority. For anything it misses (Go, Rust, Java, config schemas, HTTP routes), read the source directly and add what you find to `docs-plan.md` under "Facts not captured by inventory".

### Phase 2: Read the code that matters

Read in this order, stopping when you can explain the project to a newcomer:

1. README, AGENTS.md / CONTRIBUTING / SECURITY, and any design notes. These hold intent, but verify their claims against code.
2. The package entry point (`__init__.py`, `index.ts`, `main.go`) and the public API surface.
3. **Tests and examples.** Tests are the best source of correct usage. Lift realistic usage from them, and use failing-path tests to document error behavior.
4. Config loading and defaults. Documented defaults must match what the code does.
5. The CLI definitions, for exact flags and help text. Run `<cli> --help` when you can.

Take notes on: the one-sentence job of the project, who uses it and how (the "integration surfaces", for example Python SDK, CLI, MCP gateway, framework plugin), the smallest end-to-end path that works, and the concepts a reader must hold in their head. Also note what the project does not do.

### Phase 3: Plan the docs

Write `docs-plan.md` containing:

- **Audience and entry points**: who reads these docs and what they arrive wanting to do.
- **Docs map**: each page with its type (see `references/page-templates.md`), one-line purpose, and the source files it draws from.
- **Quickstart path**: the single shortest route to a working result. This page gets the most care.
- **Variants** that need tabs (package managers, frameworks, databases, clients).
- **Gaps**: things you could not find or verify.

Default information architecture, which you adapt to the project (drop what does not apply, never pad):

```
Introduction            what it is, what it solves, when NOT to use it
Installation            one page, ends in a verified working state
Concepts                the 3-6 ideas the product is built on, one page each
Integrations            one page per surface: SDK, CLI, framework/MCP/client
Guides (recipes)        task-oriented, each ends with a working result
Security (if relevant)  threat model, guarantees, hardening checklist
Reference               config, CLI, API, env vars, errors - generated from facts
Troubleshooting & FAQ   symptom -> cause -> fix
Contributing, Changelog
```

If the user wants to review before you write, stop here and show the plan. Otherwise continue, because a good plan is cheap to revise later and long pages are not.

### Phase 4: Write the pages, ledger first

Before writing, read:

- `references/verification.md` (the evidence rules and the ledger format).
- `references/style-guide.md` for voice, structure and code-block rules.
- `references/page-templates.md` for the skeleton of each page type.
- `references/frameworks.md` for the exact components and file conventions of the user's docs framework. Detect it from the inventory (`docs_framework_guess`, `docs.json`, `mkdocs.yml`, `docusaurus.config.*`, `source.config.ts`, `_meta.js`, `.vitepress`). If an existing docs folder uses components, read two or three of its pages and match them exactly. Do not invent components the framework does not provide.
- `references/domain-playbooks.md` when the project is a security/auth library, an agent or MCP tool, an SDK, or a CLI. The playbooks list the pages, the checks and the caveats that readers of those projects expect.

Work page by page, in this order for each page:

1. List the facts the page needs (names, signatures, defaults, flags, env vars, errors, behaviors, limits). Find each in the code and write its ledger entry (file, lines, exact quote). Run the code where the fact is behavioral.
2. Only then write the prose, using only facts that have an entry. If you want to say something and have no entry, find the evidence or drop the sentence.
3. Take code from the source, tests or examples, then adapt and run it. Never write a snippet from memory of what the API "probably" looks like. Save the real output and paste it into the page.

Write the Quickstart first. If you cannot make a clean, short Quickstart, the project's first-run experience has a problem; note it in the report rather than papering over it.

Rules while writing:

- Name every code block's file (`title="policy.json"` or the framework's equivalent) so the reader knows where it goes. The verifier uses the title to build the files in order, so later blocks can use earlier ones.
- Show expected output after commands that print something, in a separate `text` block immediately after the command block, so the verifier can compare it with the real output. If output varies (ids, timestamps), mark the block with a `docs-check: skip <reason>` comment above it and say so in the text.
- Use one consistent set of example names across all pages (the same agent id, the same tool names, the same file names), so the pages read as one story.
- Reference pages are factual and exhaustive; guides are minimal and opinionated. Do not mix the two.
- Link the first mention of a concept to its page. Do not re-explain a concept on every page; link to it.
- Write bounded claims (see `verification.md`, section 9). State limits and non-goals next to the features they limit.
- Use the code's own terms and casing (take enum and parameter names from the inventory). Keep a short `glossary.json` of canonical term to banned variants if wording drifts; `check_docs.py --glossary` enforces it.
- A block that cannot be run as shown (needs the reader's credentials, a long-running server) gets a `docs-check: no-run <reason>` or `skip <reason>` comment on the line above the fence. Each one appears in the report.

### Phase 5: Verify, in four passes

Details, rules and recipes are in `references/verification.md`. Run the passes in order for every page and repeat all of them after the last edit; any edit invalidates earlier passes.

**Pass A, mechanical and static.**

```bash
python <skill-path>/scripts/check_ledger.py --repo <repo-root> --ledger <ledger-dir> --docs-dir <docs-dir>
python <skill-path>/scripts/check_docs.py <docs-dir> --inventory <workdir>/inventory/inventory.json --ledger <ledger-dir> --strict
```

The first re-reads every cited file and fails if a quote is not on the cited lines, if a verified claim lacks two different checks, or if the commit moved. The second checks frontmatter, headings, fences, links and anchors, parseability of python/json/toml/yaml blocks, names/flags/env vars/extras against the inventory, secrets, placeholders, hard-coded counts and versions, filler words, and absolute or vague wording (`guarantee`, `100%`, `never`, `secure`, ...). It also reports navigation orphans and public names no page mentions.

**Pass B, dynamic, in the clean environment.**

```bash
python <skill-path>/scripts/verify_snippets.py <docs-dir> --package <pkg> --cli <cli> --run
```

Imports every name the docs import, checks every documented flag and subcommand against the real `--help`, runs python blocks and documented CLI commands in a throwaway directory, and compares documented output blocks with real output. `--run` executes docs code, so use a clean venv or container. Then do what the script cannot: load each config example with the project's own loader, trigger each documented error and copy its real message, and run each integration against the real third-party package.

**Pass C, blind re-derivation.** Turn each factual sentence into a question, close the page, answer the questions from the code (and a run) alone, then compare. If a fresh subagent is available, give it only the repo and the questions. Every mismatch is a bug in the page. Procedure in `verification.md`, section 6. Security claims also need an adversarial attempt that tries to break the property and fails.

**Pass D, read it as a stranger.** Follow the Quickstart by hand from an empty directory, using only what the page shows. Anything you had to guess is a defect.

Treat `SKIP` results and `unverified` ledger entries as open items, not as passes: fix them, remove the sentence, or list them in the report.

Optionally generate AI-friendly exports, which developers increasingly feed to their coding agents (this only reformats text already on the pages):

```bash
python <skill-path>/scripts/build_llms_txt.py <docs-dir> --base-url https://docs.example.com --out <docs-dir>
```

### Phase 6: Deliver

Put the files where the project's docs live, in the framework's conventions (see `references/frameworks.md`), including its navigation file (`docs.json`, `meta.json`, `sidebars`, `mkdocs.yml`). When a presentation tool is available and the output is a set of files, present them (or a zip); otherwise tell the user exactly where the files are.

## Final report

End with a short report the user can act on, not a victory lap. Never write "everything is verified" without the evidence below.

- **Pages** created, rewritten, deleted (one line each), and the commit the docs were verified against.
- **Verification run**, with the summary line of each command: `check_ledger.py`, `check_docs.py --strict`, `verify_snippets.py --run`, the blind re-derivation pass (how many questions, how many mismatches found and fixed), and the by-hand Quickstart. State the environment (Python version, OS, installed package version).
- **Not verified**: every `SKIP`, `no-run`/`skip` directive, `unverified` ledger entry and external claim, each with the reason (no credentials, no network, cannot launch the client, ...). This list is the honest edge of the work.
- **Findings**: places where the README or old docs disagree with the code (both locations), possible bugs, confusing defaults, undocumented env vars, missing error messages. Source code was not changed.
- **Next steps**, such as running `check_docs.py --strict`, `verify_snippets.py --run` and `check_ledger.py` in CI so docs cannot drift from the code.

## Anti-patterns to avoid, and why

- **Marketing voice** ("powerful, seamless, robust"): readers skim past it and it signals that nothing concrete is coming. State the concrete behavior instead.
- **Snippets with `...` or missing imports**: they break the copy-paste promise and are the top reason developers abandon docs. If a block is a fragment of a larger file, say which file and show the surrounding lines that anchor it.
- **Duplicating the README across pages**: duplicated content drifts out of sync. One home per fact, links elsewhere.
- **Documenting the architecture before the first success**: readers need a win in five minutes, then context.
- **Inventing capabilities**: a documented feature that does not exist costs more trust than a missing one. When unsure, leave it out and list it as a gap.
- **Wall-of-text concept pages**: use a diagram (Mermaid or ASCII), a table or a small example every few paragraphs.
- **Trusting the README or old docs.** They are where wrong counts, versions and "supports X" lines come from. Verify against the code and say where they disagree.
- **Verifying only what you just wrote.** The writer confirms what the writer believes. Blind re-derivation and running the code exist to break that.
- **Declaring success after one pass.** An edit after a pass invalidates it. Re-run everything on the final text.
- **Leaving secrets or private URLs in examples**: use obvious placeholders, never anything that looks like a real credential.

## Bundled files

- `scripts/inventory.py` extracts facts from the repo: Python in depth, Node at manifest level, docs tooling for any language.
- `scripts/check_ledger.py` re-validates every evidence quote in the claim ledger and enforces multi-method verification.
- `scripts/check_docs.py` static checks: structure, links, snippet syntax, inventory cross-checks, wording lint, navigation.
- `scripts/verify_snippets.py` dynamic checks: real imports, real `--help`, optional execution and output comparison.
- `scripts/build_llms_txt.py` builds `llms.txt` and `llms-full.txt`.
- `scripts/_common.py` shared helpers.
- `references/verification.md` evidence rules, ledger format, the four passes. **Read before writing.**
- `references/style-guide.md`, `references/page-templates.md`, `references/frameworks.md`, `references/domain-playbooks.md` as described above.
