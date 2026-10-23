# Domain playbooks

What readers of each kind of project expect, and where the claims are most likely to go wrong. Use alongside `page-templates.md` and `verification.md`. Every item below is something to **find in the code and verify**, not a statement to copy into docs.

## Contents

1. Security and authorization libraries
2. Agent tool-call authorization and MCP gateways
3. Integrations with other frameworks and clients
4. SDKs and libraries
5. CLIs
6. Web services and APIs
7. Keeping examples runnable over time

## 1. Security and authorization libraries

Readers here are deciding whether to trust you. They look for precision, limits and honesty before features.

**Pages to include:** Introduction (with "when not to use"), Quickstart, Concepts, Threat model, Guarantees and limits, Hardening checklist, Configuration reference, Error reference, Audit/logging (if any), Reporting a vulnerability (link the repo's own `SECURITY.md`; copy its contact method exactly).

**Write every security statement in this shape:**

> When *<precondition>*, *<component>* does *<observable behavior>*. It does not *<adjacent thing a reader might assume>*.

Example of the shape (not a claim about any project): "When a call goes through `protect()`, the engine evaluates the policy before the function runs. Calls that bypass `protect()` are not evaluated."

**Find and document these, each verified by reading and by running:**

- **Failure mode.** What happens when the policy is missing, malformed, or the store is unreachable: does the call proceed or stop? Trigger each failure and record the real behavior. Say "fails closed" or "fails open" only for the cases you triggered.
- **Default decision.** What happens when no rule matches. Verify with an empty policy.
- **Precedence.** What wins when rules conflict. Verify with a two-rule policy per ordering.
- **Trust boundary.** Which inputs the library treats as trusted (policy files, config, the process's own memory, the model's output) and which it validates. List what an attacker who controls each input could do, only as far as the code and tests establish.
- **Coverage assumptions.** The library can only judge calls that reach it. State how calls reach it (decorator, proxy, wrapper) and what happens to calls that do not.
- **Settings that weaken protection** (debug flags, permissive modes, disabled checks). Document each with the exact name, its default, and a warning. No copy-paste snippet may enable one silently.
- **Cryptography.** Name algorithms and key handling exactly as the code uses them. Say who generates, stores and rotates keys (often the reader). Never use phrases like "military grade". If a signature or hash chain is used, document how to verify it and what it does not detect.
- **Persistence.** Which store, where it lives by default, how migrations happen, what is lost if it is deleted. Do not say "SQLite" or "Postgres" for all cases if the code supports both; say which is the default and how to choose.
- **Secrets.** Where secrets are read from, whether they are logged, how to rotate. Use placeholder values that cannot be mistaken for real credentials.

**Verify security claims adversarially.** For each property, write a throwaway script that tries to break it using the library's own API (an unknown tool, a malformed argument, a replayed approval, an expired approval, a tampered record) and confirm it is refused with the documented error. Record the command and output as `run` evidence. Do not publish these scripts as bypass guides; publish the property, its preconditions and the error the caller sees.

## 2. Agent tool-call authorization and MCP gateways

The reader runs agents that call tools and wants to know exactly which calls will be allowed, blocked or paused for a human.

**Pages to include in addition to section 1:**

- **Concepts:** decision types (use the enum names and casing from the code), the policy/rule model, identity (how an agent or session is identified), the approval lifecycle (states, who can approve, expiry, single use), what is inspected in a call (tool name, arguments, which parts), what happens to responses, if anything.
- **Quickstart:** the shortest path to one allowed call, one denied call and, if the product has it, one approval, all from copy-paste, with real output.
- **One integration page per surface that exists in the code:** Python SDK/decorator, CLI, MCP proxy or gateway, each framework adapter that has code and tests. A surface with no code or tests is not documented as supported.
- **Recipes** with the exact policy and the exact outputs: allow read-only queries, require approval for destructive actions, deny a tool outright, restrict by argument values, run in dry-run or shadow mode (only if it exists).
- **Operations:** where decisions and audit records go, how to inspect them, how to run approvals in production, storage options, upgrade path.

**MCP specifics to verify:**

- Transports the code really implements (stdio, HTTP variants). Use the names and options from the code and `--help`, not from the MCP spec or memory.
- How the gateway starts and how a client connects: run it, connect with a real client or a small script, and record the output.
- What the gateway does with each MCP method it sees (tool calls, tool listing, anything else). Test each; do not generalize from tool calls to everything.
- What the model sees when a call is denied or paused (the real error or message), because developers write prompts and UIs around it.
- Client configuration files (Claude Desktop, Cursor, VS Code, Claude Code, others): file locations and JSON shapes belong to those clients and change. Treat them as `external` claims: fetch each vendor's current documentation, quote it in the ledger with URL and date, and run the setup if you can. If you cannot confirm a client's format, leave that client out and list it in the report. Do not write client configs from memory.
- Tool name and argument handling: how names are matched (exact, glob, namespaced), whether arguments are normalized before rules apply. Document the matching rules with examples from tests, each run.

**Phrases to avoid unless a verified entry bounds them:** "prevents prompt injection", "secures agents", "zero trust", "tamper-proof", "guarantees". Prefer the mechanism: what is evaluated, when, with what result, under which assumptions.

## 3. Integrations with other frameworks and clients

- Install the third-party package in the clean environment and run the integration against it. State the version you ran as "Tested with X 1.2" only if you did.
- If the integration needs no third-party package in the repo's tests, say it is untested rather than supported.
- Show the minimal working file for that framework, then the output.
- Link to the framework's own docs for their concepts; do not re-teach them.

## 4. SDKs and libraries

- Installation page ends with a one-line import check that you ran.
- Quickstart: construct, call, see output. Sync and async variants each get a verified block if both exist.
- Reference: one section per exported symbol (from `__all__` or the package index), with signature (verified at runtime), parameters, return value, raised exceptions with their real messages, a short example.
- Errors: a table of exception classes, when they are raised (cite the raise site), and what to do.
- Typing and versioning: Python versions from package metadata and CI; deprecations only if the code emits warnings or the changelog says so.

## 5. CLIs

- One section per command from the real `--help`, with synopsis, flags table, a worked example with output, and exit codes (run it and check `$?`).
- Config precedence (flags, env, file): verify each link by running.
- Show how the CLI behaves with no arguments and with a bad argument; copy the real error text into Troubleshooting.
- Shell completion, if present, only after running the setup command.

## 6. Web services and APIs

- Start the service and call each documented endpoint with `curl` against a local instance; paste real requests and responses with variable fields marked.
- Authentication: the exact header names and error responses seen.
- Pagination, rate limits and error shapes: only what you triggered.
- Provide an OpenAPI file only if the project already generates one; do not hand-write one from memory.

## 7. Keeping examples runnable over time

Recommend to the maintainer, in the report:

- Move complete examples into an `examples/` directory in the repo, include them in the docs from there, and run them in CI.
- Add `check_docs.py --strict` and `verify_snippets.py --run` as a CI job so docs fail the build when code and docs diverge.
- Commit the claim ledgers, and re-run `check_ledger.py` in CI so a code change that invalidates a cited line fails loudly.
