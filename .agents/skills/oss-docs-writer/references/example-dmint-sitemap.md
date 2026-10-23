# Worked example: a docs plan for Dmint

Dmint is a deterministic authorization layer for AI-agent tool calls: a policy file decides ALLOW, DENY or APPROVAL_REQUIRED before a tool runs; approvals are signed and bound to the exact request; there is a Python decorator, an MCP gateway/proxy, a CLI and a local dashboard.

Use this file as a model of how to turn the workflow in SKILL.md into a concrete plan, or as the actual plan if the project is Dmint. Every item marked **[re-verify]** comes from earlier audits of one specific commit; the code may have changed since. Confirm each against the current code and tests before writing it down as fact.

## 1. Readers

| Reader | Knows | Wants | Fears |
|---|---|---|---|
| Evaluator (solo dev or team lead) | Builds agents, knows MCP basics | Decide in 5 minutes if it fits | Another toy that gives false security |
| Integrator (web backend dev) | Python or TypeScript, FastAPI-style apps | Protect two or three risky tools today | Rewriting tools, async not supported |
| Operator / reviewer | Linux, deployment, security | Know exactly what runs where and what is trusted | Hidden bypass paths, key leaks |

## 2. Sitemap

```
index                         What Dmint is, who it is for, honest status (beta), 60-second picture
quickstart                    pip install, write a 3-rule policy, protect one function, see ALLOW / DENY / approval
tutorials/
  protect-a-refund-tool       Build "refunds over $100 need approval" end to end (decorator mode)
  protect-an-mcp-server       Put the gateway in front of an MCP server, hide and gate tools
concepts/
  how-dmint-works             The call path, the three decisions, one running example
  policies                    Rules, effects, deny-overrides, default-deny, evaluation order, AND semantics
  resources                   Resource kinds (path, url, host, identifier, exact, any), normalization, invalid = deny
  argument-constraints        Types, bounds, enums, patterns, required, additional properties; what patterns may do
  approvals                   Lifecycle states, request binding, single use, expiry, what invalidates one
  request-binding             What is hashed, canonical JSON, versioning; why changing one argument voids approval
  trust-model                 Who must not be able to read or write what (links to deployment-model)
guides/
  require-approval-for-risky-actions
  limit-arguments-with-constraints
  run-the-approval-dashboard
  send-approval-notifications    Slack / Discord / Teams, what is and is not in the message
  rotate-keys-and-issuers
  pin-your-policy-digest         [re-verify: implemented after the audit?]
  upgrade-and-migrate            Version-by-version; what old approvals do
reference/
  cli                          Every command, flag, exit code (generated from --help)
  policy-schema                Every field, type, default, validation error
  gateway-config               mcp_protection.json fields, trusted_issuers, transports
  python-api                   Dmint, Policy, Rule, decorator, store classes; signatures from the code
  errors                       Every DMT_ code: message, cause, fix
  environment-variables
  formats                      Canonical JSON, fingerprint domains, assertion layout, test vectors
operations/
  deployment-model             Components, users, secrets, isolation table; a tested reference setup
  security-model               Threat model, guarantees (with tests), non-goals, bypass paths
  known-limitations            Plain list, kept current
troubleshooting                Symptom -> cause -> fix, using exact error text
faq                            Real questions, direct answers (see section 5)
glossary
contributing
changelog
```

First-timer path: index -> quickstart -> protect-a-refund-tool -> how-dmint-works.

## 3. Pages that must exist and must be blunt

1. **deployment-model** (most important page). State, with a table, that Dmint protects only tool calls that pass through it, and that an agent running as the same OS user can read the signing key, edit `policy.json`, edit the approvals database, read the dashboard token and replace the MCP client config. Different OS user or container blocks these. Say which defenses rely only on file permissions. **[re-verify against the current attack results]**
2. **known-limitations.** Candidates, each to re-verify: rollback of an old database copy is not detected by row integrity checks; downstream MCP schema drift is not tracked unless a pin is configured; DNS rebinding window on remote MCP URLs unless IP pinning shipped; decorator support for async functions, methods and generators; policy pinning and remote loading status.
3. **security-model.** Each guarantee as: assumption, mechanism, test. For example, "approval cannot be reused with different arguments, because it stores a hash of the canonical request" with the test name. Include what Dmint does not do: it is not a content guardrail and does not check what the agent says.
4. **approvals.** The state machine as a table (pending, approved, consumed, expired, rejected, policy invalidated) with the function or command that causes each transition. Show the real retry flow: the call returns "approval required"; `dmint approve` signs and executes nothing; the host retries; the tool runs once.
5. **errors.** Every `DMT_*` code found with `collect_facts.py --code-prefix DMT_`, each with message text, cause and fix. Check both directions: every code in the code appears in docs, every documented code exists.

## 4. Claims to treat as traps (do not write unless proven)

- "Production-ready", "secure", "bulletproof": use maturity wording from the actual maturity decision.
- "Sub-millisecond": only for policy evaluation, with the measured number and hardware; approval operations are milliseconds because they touch disk.
- "RFC 8785": only if the canonicalization is byte-exact against a reference implementation, and say so with the test vectors file.
- "Supports FastAPI / async": only for what the decorator really supports now.
- "SQLite WAL mode": only if the code sets it.
- "All patterns evaluate in under N ms": only if a test proves a bound at the maximum input size.
- "Zero LLM in the decision path": true only for runtime evaluation; policy authoring commands may use an LLM. Say both.
- "Same as / better than" any other tool: remove.

## 5. FAQ questions to answer honestly

- Why not just use the permission prompts built into my coding agent?
- What happens if the agent edits the policy file?
- Is it safe to run the agent and Dmint as the same user? (No, and why.)
- Can an approval be replayed? Under what conditions?
- What does Dmint not protect against?
- How do I test a policy without running my tools?
- What do I do after upgrading, with old approvals in the database?

## 6. Writing order and checks

1. `collect_facts.py` on the repo, saved as the facts sheet; run every `--help`.
2. Write: index, quickstart (run it clean), how-dmint-works, approvals, policies, deployment-model, known-limitations.
3. Generate reference pages from code and `--help` output.
4. Write guides and the tutorial, running every command.
5. `find_phantoms.py docs src --undocumented` to remove names that do not exist and to find public names with no docs.
6. `check_docs.py docs --strict`.
7. Stranger test on the quickstart.
