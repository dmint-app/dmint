# Style guide

Read this before writing any page. The goal is docs a developer can follow without thinking: calm, concrete and complete.

## Contents

- Voice
- Page anatomy
- Code blocks
- Commands and output
- Placeholders and secrets
- Variants and tabs
- Callouts
- Tables, diagrams, links
- Headings and titles
- Consistency
- Words to avoid

## Voice

- Address the reader as "you". Use the present tense and active voice. "Dmint blocks the call" rather than "the call will be blocked".
- Say what happens, not how impressive it is. "Returns `DENY` for any tool with no matching rule" beats "robust fail-safe protection".
- One idea per sentence. Keep paragraphs to 2-4 sentences.
- Be direct about limits. A reader who finds a limit by surprise stops trusting the rest.
- Avoid humour, hype, and rhetorical questions. Neutral and friendly is the register.
- Do not apologise or hedge ("you might want to maybe"). If something is optional, say "Optional:". If it is recommended, say why in one clause.

## Page anatomy

Every page has frontmatter with a `title` (what the page is, 2-5 words) and a `description` (one sentence, what the reader gets, under 160 characters).

Guides and quickstarts follow this shape:

1. One or two sentences: what you will build and what you will have at the end.
2. **Prerequisites** (only if real): a short list, each linked to where to get it.
3. **Steps**, each a verb phrase heading ("Install the package", "Create a policy", "Run the gateway"). Each step has: one sentence of context, a code block, and what the reader should see.
4. **Verify** (or "Test it"): a command that proves it works, with real expected output.
5. **Next steps**: 2-4 links to the logical follow-ups.

Concept pages: start with the problem the concept solves in plain words, then the definition, then a small example, then how it connects to neighbouring concepts. End with "Related" links.

Reference pages: lead with a one-line summary, then a table or definition list, then examples for the non-obvious entries. Alphabetical or by importance, but say which.

Keep pages between roughly 300 and 1,200 words. If a page grows beyond that, it is probably two pages.

## Code blocks

- Always include a language tag. Use `bash` for commands, `text` for output, `jsonc` when a JSON example contains comments.
- Always name the file the block belongs to, using the framework's title syntax (see `frameworks.md`). If a block is a command, no filename is needed.
- Blocks are complete and runnable. Include imports. Include the entry-point call. A reader who pastes the block into the named file and runs it should see the documented result.
- When you show an edit to an existing file, show enough surrounding lines for the reader to find the location, and mark the new lines with the framework's highlight syntax or a `# new` comment. State "your existing config" explicitly when you elide the rest. Never use a bare `...` inside code.
- Prefer realistic values: `"data-analyst-agent"`, not `"foo"`. Keep the same example domain across all pages.
- Keep blocks short enough to read at a glance (under about 40 lines). If longer, split into steps or link to a full example in the repo.
- Do not put a shell prompt (`$ `) in front of commands. It breaks copy-paste.
- One command per line, or a single multi-line command with `\` continuations. Do not mix commands and their output in one block; show output in a separate `text` block.

## Commands and output

After any command that prints something meaningful, show the real output. Run it to get it; do not guess. If output includes timestamps, ids or paths that vary, say so ("Your ID will differ") and show a representative sample.

State the exit behavior when it matters ("exits with status 1 if the policy is invalid").

## Placeholders and secrets

- Use angle brackets for values the reader must supply: `<your-database-url>`. Right after the block, say where to get each placeholder.
- Never use anything that resembles a real credential format (for example an `sk-` style key or a webhook URL with a plausible token). Use `<api-key>` for keys, and `postgresql://user:password@localhost:5432/dbname` for connection strings.
- Tell readers how to store secrets properly (env var or secret manager) the first time a secret appears, and link to that page after.
- Generate-secret commands are welcome: `openssl rand -base64 32`.

## Variants and tabs

When the same step differs by tool, use tabs rather than prose branches. Standard tab groups:

- Package managers: npm, pnpm, yarn, bun (JS) or pip, uv, poetry (Python). Order by popularity for the ecosystem.
- Frameworks or clients: one tab each, same structure inside every tab.
- Databases or backends.

Rules: the default tab is the most common choice; every tab contains a complete block, not a diff against another tab; do not hide critical information (like a required env var) inside only one tab without a note outside the tabs.

## Callouts

Use sparingly, at most two per page. Pick by meaning:

- **Note**: neutral extra context the reader may need.
- **Tip**: an optional improvement.
- **Warning**: data loss, security risk, or a step that breaks things if skipped.

If everything is a warning, nothing is. Put the critical thing in the main text and use the callout for emphasis.

## Tables, diagrams, links

- Tables for reference data: options, flags, env vars, error codes. Columns for name, type, default, description. Keep descriptions to one sentence.
- A diagram earns its place when it shows flow or boundaries (request path, trust boundary, state machine). Use Mermaid if the framework renders it, ASCII otherwise. Add a one-sentence caption saying what to notice.
- Link the first mention of a concept or reference item on a page. Use descriptive link text ("the policy reference"), never "click here". Use relative or root-relative internal links that the checker can resolve.

## Headings and titles

- Sentence case. Verb-first for tasks ("Protect an MCP server"), noun phrases for concepts and reference ("Approval lifecycle").
- Do not skip heading levels. One H1 (the title) per page, or none if the framework renders the title from frontmatter.
- Headings are anchors people link to; keep them stable and unique within a page.

## Consistency

- Use one name for each thing everywhere. If the code calls it `approval_ttl`, the docs call it `approval_ttl`, not "approval timeout" in one place and "expiry" in another.
- Match the code's casing for identifiers, and format them as inline code.
- Use the product name as the project writes it (check the README and package metadata).
- Version numbers and counts ("968 tests", "24 pages") rot quickly; avoid them unless generated.

## Words to avoid

These add nothing, or sound like filler. The checker warns on them.

`simply`, `just`, `easily`, `obviously`, `of course`, `seamless(ly)`, `robust`, `powerful`, `cutting-edge`, `state-of-the-art`, `game-changing`, `leverage`, `utilize`, `delve`, `comprehensive`, `in today's`, `it's important to note`, `it is worth noting`, `blazing fast`, `world-class`, `enterprise-grade` (unless defined).

Absolute and vague words need a verified, bounded claim behind them or a rewrite: `guarantee`, `100%`, `zero`, `never`, `always`, `impossible`, `cannot be bypassed`, `eliminates`, `prevents all`, `secure`, `safe`. Say what happens and when ("When no rule matches, `evaluate` returns `DENY`") instead. `check_docs.py` flags these and accepts an exemption only as `lint-ok: claim=<ledger-id>` pointing at a verified entry. See `verification.md`, section 9.

"Simply" and "just" are especially harmful: if the step fails for the reader, the word makes them feel stupid.
