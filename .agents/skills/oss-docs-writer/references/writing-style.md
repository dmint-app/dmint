# Writing style for technical docs

Contents:
1. Voice
2. How to explain a concept
3. Sentence-level rules
4. Words and patterns to avoid
5. Before and after rewrites
6. Formatting rules that help or hurt

---

## 1. Voice

Write like a senior engineer explaining to a capable colleague who is new to this project: direct, concrete, a little informal, never salesy.

- Address the reader as "you". Use "we" only for the project team's decisions ("we chose X because...").
- Prefer active voice and present tense: "Dmint denies the call", not "the call will be denied by Dmint".
- Prefer plain verbs: use, run, set, return, reject. Avoid leverage, utilize, facilitate, enable.
- State things directly. If something is true, say it without hedging; if it is uncertain, say exactly what is uncertain and why.
- Be honest about rough edges. A docs page that admits a limitation earns more trust than ten pages of reassurance.

## 2. How to explain a concept

Use this pattern; it is the difference between shallow and deep docs.

1. **Name the problem first**, with a concrete scenario. ("An agent is allowed to issue refunds. A customer message tells it to refund $5,000 instead of $50.")
2. **Define the term in one plain sentence.**
3. **Walk through one running example** from start to finish, with real values. Reuse the same example across the page and, where possible, across the whole docs site.
4. **Show the mechanism**, not just the result: which step happens, in what order, what data moves.
5. **Say why it was designed this way** and what the alternatives cost.
6. **State the limits**: what it guarantees, what it does not.
7. **Anticipate the confusion**: "This is not the same as X."

Use analogies only after the precise explanation, and say where the analogy breaks.

## 3. Sentence-level rules

- One idea per sentence. Aim for under 25 words; split anything longer than 35.
- Put the important word at the end of the sentence or at the start of the paragraph; do not bury it in the middle.
- Lead each paragraph with its point. The reader who skims first sentences should still follow the page.
- Use concrete nouns and numbers: "rejects requests over 4 KB", not "limits large requests".
- Keep terms consistent. Once you call it an "approval", do not switch to "permission" or "grant" on the next page.
- Spell out acronyms at first use.
- Avoid pronouns with distant referents ("it", "this") at the start of a sentence if the referent is more than a sentence away.
- Use parallel structure in lists.

## 4. Words and patterns to avoid

**Marketing and filler adjectives** (replace with evidence or delete): powerful, robust, seamless, seamlessly, blazing, lightning-fast, cutting-edge, state-of-the-art, world-class, revolutionary, game-changing, next-generation, enterprise-grade, military-grade, battle-tested (unless you can show it), effortless, comprehensive, holistic, best-in-class, production-ready (unless defined and true).

**Condescending words**: simply, just, easily, obviously, of course, trivial, straightforward, "as you know". If it were easy, they would not need the docs.

**AI-sounding patterns**:
- "It's important to note that...", "It is worth mentioning...", "Note that" at the start of every paragraph
- "In today's fast-paced world...", "In the realm of...", "delve into", "dive into", "unlock the power of", "elevate", "supercharge", "navigate the landscape"
- Opening every page with a pitch paragraph
- Triplet adjectives ("fast, secure, and reliable")
- Sentences that restate the heading
- Summary sections that repeat the page instead of adding a next step
- Em-dash-heavy rhythm and "not just X, but Y" constructions used as filler
- Headings in Title Case Marketing Style ("Unlocking Seamless Security")

**Claims you cannot support**: "secure", "safe", "fast", "scalable", "zero overhead", "guaranteed", "prevents all", "impossible to bypass". Replace with a precise statement of what is checked and under which assumptions, plus a measurement or test reference.

## 5. Before and after rewrites

**Overview opening**
- Before: "Dmint is a powerful, enterprise-grade authorization engine that seamlessly secures your AI agents."
- After: "Dmint checks every tool call an AI agent makes against a policy file you wrote, before the tool runs. Each call is allowed, denied, or held until a person approves it."

**Feature bullet**
- Before: "Robust approval workflow."
- After: "An approval covers one exact request. If the agent changes a single argument, the approval no longer applies, and an approval can be used once."

**Concept intro**
- Before: "Request binding is an important security feature that ensures approvals are secure."
- After: "When a person approves a refund of $50 for order 123, that approval should not also authorize a refund of $5,000 for order 999. Request binding enforces this by tying each approval to a hash of the exact request."

**Quickstart step**
- Before: "Simply configure your policy and you're ready to go!"
- After: "Create `policy.json` with this content, then run `dmint verify-policy policy.json`. You should see `OK: 3 rules`."

**Limits**
- Before: "Dmint provides comprehensive protection against bypass attempts."
- After: "Dmint only checks calls that pass through it. If the agent can also run shell commands or use built-in editor tools, those calls are not checked unless you disable or route them. See Deployment model."

**Error documentation**
- Before: "If you encounter an error, check your configuration."
- After: "`DMT_RESOURCE_INVALID`: the resource in the request could not be normalized (for example it contains `..` that escapes the root). The call is denied. Fix the tool so it passes a clean path, or check the rule's `resource_kind`."

## 6. Formatting rules that help or hurt

- Use tables for comparisons and option lists; use bullet lists for parallel short items; use prose for explanation. Do not turn explanation into bullets, because bullets drop the reasoning that connects ideas.
- Use numbered lists only for ordered steps.
- Use bold for the one term being defined or a critical warning, not for emphasis everywhere.
- Use diagrams for flows with more than three actors or steps. Provide a text description for accessibility.
- Keep code blocks short enough to read at a glance; link to full examples for long ones. Show only the lines that matter, and mark omissions with a comment.
- Put the command and its output in separate blocks, labeled.
- Use headings that match what the reader would search for.
- Avoid emoji in headings and body text; they date the docs and clutter scanning.
