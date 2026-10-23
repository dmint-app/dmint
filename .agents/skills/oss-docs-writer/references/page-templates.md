# Page templates and quality bars

Contents:
1. Default sitemap for a developer tool
2. Overview / landing page
3. Quickstart
4. Tutorial
5. How-to guide
6. Concept page
7. Reference page (library, CLI, config)
8. Troubleshooting / FAQ
9. Security and limits page
10. Migration guide and changelog
11. Glossary
12. Contributing

Each template lists what the page must contain and a quality bar: a test you can apply to decide whether the page is done.

---

## 1. Default sitemap for a developer tool

Adapt to the project; delete pages that have nothing real to say.

```
index                       Overview: what it is, who it is for, 60-second picture
quickstart                  Install and reach the "aha" in under 10 minutes
tutorials/
  build-your-first-<thing>  One realistic end-to-end walkthrough (20-30 min)
concepts/
  how-it-works              Architecture and the mental model, with a diagram
  <core-idea-1>             One page per idea the reader must understand
  <core-idea-2>
  design-decisions          Why it works this way, trade-offs, alternatives
guides/
  <task phrased as a verb>  One page per real task ("Protect an MCP server")
integrations/
  <tool or framework>       Copy-paste setups with verified steps
reference/
  cli                       Every command, flag, exit code, env var
  config / schema           Every option, type, default, validation rule
  api                       Every public function/class
  errors                    Every error code: cause, fix
operations/ (if deployed)
  deployment-model          Where each component runs and who can touch what
  security / threat-model   Guarantees, non-goals, attacker model
  upgrade-and-migration     Version-by-version changes
troubleshooting             Symptom -> cause -> fix
faq                         Real questions with direct answers
glossary                    Every project term, one line each
contributing                How to set up, test, propose changes
changelog                   Human-written release notes
```

First-timer path: index -> quickstart -> tutorial -> how-it-works. Everything else is reached by need.

---

## 2. Overview / landing page

**Reader:** the evaluator, deciding in about 5 minutes.

**Must contain, in this order:**
1. One sentence: what it is, in plain words, no adjectives.
2. The problem, shown through a concrete scenario (what goes wrong without it).
3. The smallest working example (5 to 15 lines) with its output.
4. How it works in one diagram or 5-step list.
5. Who it is for, and who should not use it.
6. Honest status: maturity, supported versions, what is not done yet.
7. Where to go next: a single recommended path plus a short list.

**Quality bar:** a stranger can answer, without clicking anything: What is this? Is it for me? Does it work? What does it not do?

**Common failure:** a wall of feature bullets with the same three adjectives.

---

## 3. Quickstart

**Reader:** impatient newcomer who wants a result.

**Template:**
```
# Quickstart
<1 sentence: what you will have at the end, and how long it takes>

## Before you start
Prerequisites with exact versions and how to check each one (`python --version`).

## 1. Install
<command> + expected output

## 2. <First action>
<command or code> + expected output
Why this works: <1 to 3 sentences>

## 3. <See it work / see it block / see the result>
<command or code> + expected output

## What you just did
<3 to 5 sentences that name each concept used, linked to concept pages>

## Next steps
<2 or 3 links, each with a reason>
```

**Quality bar:**
- Under 10 steps, no decisions, no optional branches.
- Every command is copy-pasteable and every command is followed by its real output.
- Works on a clean machine; prerequisites are checked, not assumed.
- Ends with a visible result the reader can point to.
- Includes the 2 or 3 most likely failures with fixes, right where they happen.

---

## 4. Tutorial

**Reader:** someone who finished the quickstart and wants to build something real.

Pick one realistic scenario (not "foo/bar"). Tell the reader what they will build, show the end result first, then build it in small steps where each step has a visible checkpoint ("run this; you should see ..."). Explain only what is needed at each step and link out for depth. Finish with a complete code listing and ideas for extending it.

**Quality bar:** a reader can stop after any step and still have something working.

---

## 5. How-to guide

**Reader:** knows the basics, has a specific goal.

**Template:**
```
# <Verb phrase: "Require approval for refunds over $100">
<When you need this, 1 or 2 sentences.>

## Prerequisites
## Steps
1. ... (each step: action, code, expected result)
## Verify it works
## Variations
## Troubleshooting for this task
## Related
```

**Quality bar:** solves exactly one goal; no teaching of fundamentals (link to concepts); has a "verify" step so the reader knows it worked.

---

## 6. Concept page

**Reader:** wants to understand, not do.

**Template:**
```
# <Noun: "Request binding">
<What it is in one plain sentence.>

## The problem
A concrete scenario where, without this idea, something goes wrong.

## How it works
Step-by-step, with a diagram or table. Use one running example throughout.

## Why it is designed this way
Trade-offs, alternatives considered, what was given up.

## What it guarantees, and what it does not
Explicit list of each.

## Common misunderstandings
## Related concepts and how-to guides
```

**Quality bar:** after reading, the reader can predict how the system behaves in a situation the page never mentioned. Contains at least one worked example with real values.

---

## 7. Reference page

**Reader:** knows what they want, needs exact facts.

**Rules:** complete, accurate, consistent structure, no narrative, no opinions. Generate from code or `--help` where possible so it cannot drift.

**Per CLI command:** synopsis, description, arguments and flags (name, type, default, required, description), environment variables, exit codes, examples (at least 2), related commands.

**Per config option:** name, type, default, allowed values, what it affects, example, validation errors it can produce.

**Per API item:** signature, parameters (type, default, meaning), return value, raised errors, thread-safety or side effects, minimal example.

**Per error code:** code, message text exactly as shown, when it occurs, how to fix, related option.

**Quality bar:** every item in the code appears in the reference, and every item in the reference exists in the code (check both directions).

---

## 8. Troubleshooting / FAQ

Organize by **symptom as the reader sees it**, using the exact error text so search engines and Ctrl+F find it:

```
### `<exact error message>`
**Cause:** ...
**Fix:** ... (commands)
**Why it happens:** ... (1 sentence, links to concept)
```

FAQ entries are real questions, answered in the first sentence, then explained. Include the hard ones ("Why not just use X?", "Is it safe for production?") with honest answers.

---

## 9. Security and limits page

See `security-library-docs.md` for the full guide. Minimum content: what is protected, from whom; what is not protected; assumptions about the deployment; how to report a vulnerability; known limitations.

---

## 10. Migration guide and changelog

**Changelog:** written for humans. Group by Added / Changed / Fixed / Security / Removed. Mark breaking changes at the top with what to do about them. Link to issues or commits.

**Migration guide per breaking release:** who is affected, what changed, why, step-by-step upgrade with before/after code, how to verify, and what happens if they do nothing (for example, old records fail closed).

---

## 11. Glossary

One entry per project term: the term, a one-sentence definition in plain words, a link to the page that explains it. Sorted alphabetically. Keep terms identical to those used in the docs.

---

## 12. Contributing

How to set up a dev environment (verified commands), how to run tests, code style and the commands to check it, how to propose changes, what makes a good issue or pull request, and where design decisions are discussed. Include a "good first issues" pointer if any exist.
