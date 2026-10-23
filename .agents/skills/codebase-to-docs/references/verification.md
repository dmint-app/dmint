# Verification protocol

Read this before writing the first page and again before the final report. The goal is documentation in which every factual sentence has been checked against the code more than once, by different methods, and in which anything that could not be checked is said out loud instead of being written as fact.

## Contents

1. The rule
2. Evidence hierarchy
3. The claim ledger
4. How to verify each kind of claim
5. The passes (A to D) and when to repeat them
6. Pass C in detail: blind re-derivation
7. When sources disagree
8. What cannot be verified
9. Writing bounded claims
10. Numbers, versions and generated facts
11. Clean environment recipe
12. Definition of done

## 1. The rule

No factual sentence goes into a page unless it has a ledger entry with evidence that was re-checked after the page's last edit. A factual sentence is anything the reader could act on or be misled by: a name, a signature, a default, a flag, an env var, an error message, a behavior, a limit, a supported version, a security property, a number.

Sentences that are not factual claims (a heading, a transition, "Next, create a file") need no entry. If you are unsure whether a sentence is a claim, treat it as one.

Unverified is not false. When a fact cannot be verified, leave it out of the page and list it in the final report under "Unverified". Do not soften it with "usually" or "typically": a hedge on an unchecked fact is still an unchecked fact.

## 2. Evidence hierarchy

Strongest first. Stronger evidence overrides weaker evidence when they disagree.

1. **Executed behavior** in a clean environment at the pinned commit: a command you ran, the output you got.
2. **Source code** at that commit: the exact lines that implement the behavior.
3. **Tests**: they show what the maintainers intend and are good for realistic usage. A test can be wrong, outdated or skipped, so a test alone is not enough for a claim.
4. **Docstrings and comments**: leads only. They drift from the code.
5. **README, existing docs, CHANGELOG, commit messages, issue text**: leads only. Never evidence. Hard-coded counts, versions and "supports X" lines in these files are the most common source of wrong docs.
6. **Your own memory of how libraries like this usually work**: not evidence at all.

External facts about other systems (a client's config file location, a cloud API) are evidence only when fetched from the vendor's own current documentation during this task, with the URL and date recorded.

## 3. The claim ledger

One JSON Lines file per page, stored outside the published docs (for example `docs-work/claims/quickstart.jsonl`, or `docs/.claims/` if the docs toolchain ignores dotfolders; confirm that the build ignores it). One fact per line. Never combine two facts in one entry: if one half is wrong you want the entry to say which.

First line records the commit the evidence was read at:

```json
{"_meta": {"repo_sha": "<output of git rev-parse HEAD>"}}
```

Then one entry per claim:

```json
{"id": "qs-03", "page": "docs/quickstart.mdx", "claim": "A call with no matching rule is denied", "kind": "behavior", "evidence": [{"path": "src/pkg/policy.py", "lines": "41-46", "quote": "return Decision.DENY"}], "checks": ["read", "test", "run"], "status": "verified"}
```

| Field | Meaning |
| ----- | ------- |
| `id` | Unique, stable (`<page>-<n>`). Docs can reference it in `lint-ok: claim=<id>`. |
| `page` | Path of the page the claim appears on, relative to the repo root. |
| `claim` | The fact in one plain sentence, close to the docs wording. |
| `kind` | `api`, `cli`, `config`, `env`, `behavior`, `security`, `compat`, `number`, `link`, `external`, `other`. |
| `evidence` | List. File evidence: `{path, lines, quote}` where `quote` is exact text from those lines. Command evidence: `{command, quote}` where `quote` is text from the output. External evidence: `{url, quote, retrieved}`. |
| `checks` | The methods actually used: `read` (read the source), `test` (an existing test exercises it), `run` (you executed it), `rederive` (pass C), `computed` (a script produced the value), `external` (vendor docs). Record only what you did. |
| `status` | `verified`, `unverified` or `contradicted`. |

Keep quotes short (one line where possible) and exact. `scripts/check_ledger.py` re-reads every cited file and fails when the quote is not on the cited lines, so stale or invented evidence is caught mechanically. It cannot judge whether the quote supports the claim; passes A and C do that.

Rules the script enforces for `verified`: at least two different check methods; behavior, security, cli, api, config and number claims need at least one dynamic method (`run`, `test`, `computed`); security claims need three methods including `rederive`.

## 4. How to verify each kind of claim

| Kind | How |
| ---- | --- |
| `api` (names, signatures, defaults, return types, exceptions) | Read the definition. Confirm at runtime with `inspect.signature` or one real call. Take the public import path from `__init__.py` / `__all__`, then `python -c "from pkg import Name"`. Do not copy defaults from docstrings. |
| `cli` (commands, flags, defaults, exit codes) | Run `<cli> --help` and `<cli> <sub> --help`. Run the command and note the exit status (`echo $?`). Static AST hints in the inventory are leads only. |
| `config` (keys, types, defaults, validation, precedence) | Find where the config is parsed; read each default there; load the example with the project's own loader; try one invalid value and record the real error. Precedence claims (flag over env over file) need a test or run per link in the chain. |
| `env` | Find every read of the variable; note default and parsing; run once with it set and once unset. |
| `behavior` | Locate the code path, find or write a test that exercises it, run an example, and record the real output. |
| `security` | Everything for `behavior`, plus an adversarial attempt: a throwaway script (never published) that tries to violate the claimed property and shows it is refused. Also state the preconditions the property depends on. See `domain-playbooks.md`. |
| `compat` (Python/Node versions, OS, framework versions) | Read the package metadata (`requires-python`, `engines`) and the CI matrix. Write "declared to support" unless CI or your run covers it. A claim of "works with X" needs a run against X. |
| `number` (limits, timeouts, TTLs, counts, sizes) | Read the constant or compute it with a script. Never type a number from memory or copy it from a README. |
| `link` | `scripts/check_docs.py` resolves internal links and anchors. |
| `external` | Fetch the vendor's current documentation, quote it, record URL and retrieval date. If you cannot fetch it, do not document it. |

## 5. The passes

Run in this order. **Any edit to a page, its code, or its ledger invalidates every pass for that page**: re-run all of them after the last edit, not just the one that found the problem.

**Pass A: mechanical, static.**

```bash
python <skill-path>/scripts/check_ledger.py --repo <repo> --ledger <ledger-dir> --docs-dir <docs-dir>
python <skill-path>/scripts/check_docs.py <docs-dir> --inventory <workdir>/inventory/inventory.json --ledger <ledger-dir> --strict
```

Fix every ERROR. Resolve every WARN by rewriting, removing, or (for absolute/vague/count wording only) adding `lint-ok: claim=<id>` that points at a verified ledger entry. Never add a `lint-ok` to make a warning disappear.

**Pass B: dynamic.** In a clean environment (section 11), with the package installed from the checkout:

```bash
python <skill-path>/scripts/verify_snippets.py <docs-dir> --package <pkg> --cli <cli> --run
```

Every python block, documented CLI line and documented output block must execute and match. Read the summary: `PASS (static)` means names exist, `PASS (executed)` means it ran, `SKIP` means nobody checked it. List every SKIP in the report. Go beyond the script for things it cannot do: load every config example with the project's own loader, exercise each documented error and copy its real message, run each integration against the real third-party package at the version you state.

**Pass C: blind re-derivation.** Section 6. This is the pass that catches a sentence that is well-formed, linked to real code and still wrong.

**Pass D: final read.** Read each page top to bottom as a stranger who has only the page and a terminal. Execute the Quickstart by hand, in order, in a fresh directory, pasting only what the page shows. Anything you had to guess is a bug in the page.

## 6. Pass C in detail: blind re-derivation

Writers confirm what they already believe. To break that, answer the questions from the code without looking at the page.

1. From the finished page, write every factual sentence as a question in a scratch file (`What does evaluate return when no rule matches?`, `What is the default of approval_ttl?`, `Which flags does verify accept?`). Leave out the answers and the wording of the page.
2. Close the page. If you have a way to run an independent reviewer (a fresh subagent with only the repo and the questions), hand it the questions and the checkout and nothing else. If not, work from the questions alone and do not open the page or the ledger.
3. Answer each question from the source and from a command you run. Write each answer with `file:line`.
4. Only now compare answers with the page. Every mismatch, even a small wording difference that changes meaning (`may` versus `will`, `any` versus `each`, `or` versus `and`), becomes `status: contradicted`. Fix the page, not the answer, unless the answer was wrong.
5. Add `rederive` to `checks` for each claim that matched.

For any claim about security, also write the adversarial attempt described in section 4 during this pass.

## 7. When sources disagree

The code at the pinned commit wins over the README, docs, docstrings and comments. Then:

- Write the page from the code's behavior.
- Record the discrepancy in the report under "Findings" with both locations ("README says X; `file:line` does Y").
- Do not edit source code to make the docs true, and do not document the behavior the README promises.
- If the code looks like a bug (a documented invariant is not enforced, a default contradicts the stated intent), report it as a possible bug, document only what actually happens, and ask the maintainer which is intended.

If a test and the code disagree, run the code and report both.

## 8. What cannot be verified

Say so in the report instead of writing around it. Typical cases: services needing credentials or network when the sandbox has none; behavior on an OS or version you cannot run; performance and scale; third-party clients you cannot launch; anything depending on data or state you do not have. For each, state what you did verify (for example "read the code path, could not run it") and either leave the sentence out or ask the maintainer to confirm.

## 9. Writing bounded claims

A bounded claim states the condition and the mechanism. An unbounded claim states an outcome and hopes.

| Instead of | Write |
| ---------- | ----- |
| "Dmint secures your agents" | "Dmint evaluates each tool call that passes through `protect()` against your policy and returns ALLOW, DENY or APPROVAL_REQUIRED." (only if verified) |
| "Prevents prompt injection" | Say what the code does to a call regardless of how the model was prompted, and what it does not inspect. |
| "Always denies unknown tools" | "When no rule matches, `evaluate` returns `DENY` (`policy.py:46`)." |
| "Works offline" | "Evaluation makes no network calls" only after you ran it with the network disabled or read every call site. |
| "Tamper-proof logs" | "Each entry includes a hash of the previous entry; `<command>` reports a break in the chain." State what it cannot detect (for example truncation of the tail). |
| "Fast", "lightweight" | Delete, or give a measured number with the command and machine that produced it. |

Never write `guarantee`, `100%`, `zero`, `never`, `always`, `impossible`, `cannot be bypassed`, `secure` or `safe` without a verified ledger entry that bounds it. `check_docs.py` flags these.

State limits and non-goals with the same care as features. A limit found by the reader is worse than a limit stated by you.

## 10. Numbers, versions and generated facts

Do not hand-type counts (tests, files, rules, pages), version numbers or sizes. Either compute them with a command at build time, link to the source of truth, or leave them out. Install instructions should not pin the package version unless the guide is about a specific release; `pip install pkg` is correct for the reader's today, `pip install pkg==1.2.3` is correct only until the next release.

## 11. Clean environment recipe

Docs must work for someone who has only the package, so verify with only the package.

```bash
python -m venv /tmp/docs-venv && . /tmp/docs-venv/bin/activate
pip install -e "<repo>[<extras the pages use>]"     # or install the built wheel
cd "$(mktemp -d)"                                    # run snippets here, not in the repo
```

Record Python version, OS and the installed package version in the report. If the package cannot be installed (no network for dependencies, missing credentials), say so: pass B then only covers what can be imported, and the report must say which pages were not executed.

## 12. Definition of done

A page is done when all of these are true after the last edit:

- Every factual sentence has a `verified` ledger entry; `check_ledger.py` passes.
- `check_docs.py --strict` passes with no unexplained exemptions.
- `verify_snippets.py --run` passes, every SKIP is listed in the report, and the Quickstart was also followed by hand.
- Pass C found no mismatches on the final text.
- No count, version or absolute word remains without a bounded, evidenced claim.
- Limits, non-goals and failure behavior are on the page.

The final report states which of these were done, with the command output summaries, and lists everything that was not.
