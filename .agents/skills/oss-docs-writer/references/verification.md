# Verifying docs

Contents:
1. The facts ledger
2. Verifying code examples
3. Verifying CLI and config reference
4. Verifying claims (security, performance, compatibility)
5. Automated lint
6. The stranger test
7. Handoff report

Docs lose trust through wrong details, not through missing ones. Verification is therefore part of the writing, not an optional extra.

---

## 1. The facts ledger

Keep a ledger as you work (a scratch file, not shipped). One row per claim you intend to publish.

| Claim | Page | Source (file:line, command, or test) | Status |
|---|---|---|---|
| "Approvals expire after 1 hour by default" | concepts/approvals | `src/.../approvals.py:88` | verified |
| "Decision takes under 1 ms" | index | none | REMOVE or measure |

Status values: **verified** (read in code or ran it), **tested** (a project test asserts it), **unverified** (kept only if flagged), **remove**.

Rules:
- A claim with no source is removed or measured, never softened into vague wording.
- When two sources disagree, record both and ask the maintainer; do not pick.
- Re-check the ledger whenever the code changes during the session.

## 2. Verifying code examples

If you have a shell:
1. Create a clean environment (`python -m venv`, a temp directory, or a fresh container).
2. Install the project the way the quickstart says to.
3. Run every code block in order, exactly as written, including the commands that set up files.
4. Capture real output and paste it into the docs. Trim only noise, and mark trimming with `...`.
5. If an example fails, fix the example. If it fails because of a bug in the project, report it to the user and do not paper over it.
6. For long-lived docs, suggest the maintainer add the examples to CI (for example, doctest, pytest-markdown-docs, or a script that extracts and runs fenced blocks).

If you do not have a shell:
- State at the top of your handoff that no example was executed.
- Mark each example "unverified" in the ledger.
- Prefer examples taken directly from the project's tests or `examples/` folder, and cite them.
- Never invent output. If you must show output, take it from tests or existing verified docs, or leave the output block out and say so.

Examples must also be realistic: named after real scenarios, not `foo`, `bar`, `my_function`. Use the same scenario across the quickstart, tutorial, and concept pages so the reader builds on one picture.

## 3. Verifying CLI and config reference

- Run `<tool> --help` and `<tool> <command> --help` for every command and copy the flags, defaults, and descriptions from the output. Do not retype from memory.
- Check exit codes by running commands that should succeed and fail, and echo `$?`.
- For config, read the schema or validation code. Record each option's type, default, allowed values, and the error raised on a bad value. Try one invalid value per option class to confirm the real error text.
- Check environment variables by grepping the source (`os.environ`, `process.env`).
- Check in both directions: every flag in the code appears in the docs; every flag in the docs exists in the code.
- For library APIs, import the package and use `help()` or `inspect.signature` to confirm signatures, or read the type stubs.

## 4. Verifying claims

**Security claims.** Write them as precise statements with assumptions: "A request approved for arguments A cannot be executed with arguments B, because the approval stores a SHA-256 hash of the canonical request." Cite the test that proves it. Avoid absolutes. Always pair a guarantee with its boundary (what must also be true about the deployment).

**Performance claims.** Include the measurement, the hardware, and how to reproduce it, or remove the claim. Distinguish in-process computation from operations that touch disk or network.

**Compatibility claims.** Check the versions in the package metadata and CI matrix. Do not list a version you have not seen tested.

**Comparisons with other tools.** Only state what you have checked in their current docs, link the source, and describe differences without disparagement. When unsure, describe what your project does and let the reader compare.

**"First", "only", "best", "better than".** Remove unless you can prove it. They age badly and invite hostile scrutiny.

## 5. Automated lint

Run the bundled linter on the docs folder:

```bash
python scripts/check_docs.py path/to/docs
python scripts/check_docs.py path/to/docs --strict   # warnings become failures
```

It checks: broken relative links, duplicate H1, skipped heading levels, code fences with no language, leftover TODO/FIXME/lorem markers, missing frontmatter title or description, marketing and condescending words, and suspiciously short or very long pages. Treat its output as a floor, not a ceiling; it cannot tell you whether an explanation is clear.

## 6. The stranger test

Ask: can someone who has never seen the project reach the "aha" using only the quickstart?

Run it yourself as a literal-minded newcomer:
- Use only the page. Do not rely on anything you learned elsewhere in the session.
- Copy each command exactly. Note every place you had to guess.
- Record each stall: undefined term, missing prerequisite, output mismatch, ambiguous instruction, a step that assumes a tool is installed.
- Fix each stall in the doc and repeat from the top.

Then recommend the maintainer give the quickstart to one real stranger, watch silently, and write down where they pause. Two sessions with strangers find more problems than any amount of review.

Further checks for the whole site:
- Pick three tasks a user would search for ("how do I rotate keys?", "what does error X mean?", "does it work with Y?") and confirm each can be answered in under a minute from the navigation or search.
- Read the site as the skeptical reviewer: is each guarantee paired with its limits? Is there a place to report a vulnerability or bug?
- Search the docs for every project term and confirm each is defined at first use and in the glossary.

## 7. Handoff report

End every docs task with a short report to the maintainer:

- **Delivered:** files created or changed, in the project's docs structure.
- **Verified:** what was run or read, and how (commands, test names).
- **Unverified:** each item, why, and what the maintainer must check.
- **Contradictions:** places where code, old docs, and README disagree.
- **Bugs found:** problems in the project discovered while documenting.
- **Open questions:** decisions only the maintainer can make (supported versions, naming, maturity claims).
- **Suggested follow-ups:** CI for examples, a docs preview deploy, a feedback link on each page.
