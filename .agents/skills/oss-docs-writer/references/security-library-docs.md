# Documenting security, auth, crypto, and infrastructure projects

Contents:
1. Who reads these docs
2. Pages these projects need
3. Threat model page
4. Guarantees and non-goals
5. Deployment model page
6. Cryptography and formats
7. Claims discipline
8. Vulnerability reporting and security policy
9. Failure and error documentation
10. Checklist

Readers of security documentation are skeptical, responsible for consequences, and quick to spot overclaiming. They will look for what the project does not protect against before trusting what it does. Honesty and precision are the product here.

---

## 1. Who reads these docs

- **The evaluator** wants to know within minutes: what problem, what guarantee, what it costs to adopt, what the catch is.
- **The integrator** wants a working, safe default setup, with the dangerous options clearly labeled.
- **The reviewer or auditor** wants a threat model, invariants, formats, and evidence (tests, audits, benchmarks).
- **The operator** wants to know what runs where, who holds which secret, how to rotate keys, and what happens when things fail.

## 2. Pages these projects need

In addition to the standard sitemap:

- `security/threat-model` — assets, attacker, assumptions, in-scope and out-of-scope threats
- `security/guarantees` — what is guaranteed, under which assumptions, and how it is tested
- `security/non-goals` — what the project does not do, stated bluntly
- `operations/deployment-model` — process, user, and network isolation requirements
- `operations/key-management` — generation, storage, permissions, rotation, revocation
- `reference/errors` — every denial or failure code with cause and fix
- `reference/formats` — wire formats, canonicalization, versioning
- `security/policy` (or `SECURITY.md`) — how to report vulnerabilities, supported versions, response expectations
- `security/audit-status` — independent reviews, internal audits, known open issues

## 3. Threat model page

Template:

```
# Threat model

## What this project protects
<the assets: e.g. the right to execute a privileged action>

## Who we defend against
<the attacker, with capabilities: e.g. a prompt-injected agent that controls tool names and arguments, can read files its OS user can read, can make network calls>

## Assumptions
<what must be true for the guarantees to hold: e.g. the agent process cannot read the approval signing key>

## In scope
<threats the project aims to stop, each with the mechanism that stops it>

## Out of scope
<threats the project does not address, each with a pointer to what to use instead>

## Attack walk-throughs
<3 to 6 concrete scenarios: attacker goal, steps, what the project does at each step, outcome>
```

Quality bar: a reviewer can find at least one limitation that surprised them and appreciated you for stating it.

## 4. Guarantees and non-goals

Write each guarantee as: **Under assumptions A, the project ensures P, because of mechanism M, verified by test T.**

Example: "Under the assumption that the approval database is not writable by the agent, an approval cannot be used for a request with different arguments, because the approval stores a hash of the exact canonical request and the hash is compared before execution. Verified by `tests/...::test_changed_argument_rejected`."

Write each non-goal as a plain sentence with a pointer: "Dmint does not check what an agent says, only what it does. Use a content guardrail for that." Also list **bypass paths**: any route by which an action can occur without passing through the project.

## 5. Deployment model page

This page prevents the most common real-world failure: a correct tool deployed in a way that defeats it. Cover:

- A diagram of components and trust boundaries: which process holds which secret, who can write which file or database.
- A table: component | runs as | can read | can write | must not be able to.
- Isolation requirements: separate OS users or containers for the untrusted process; no raw credentials in the untrusted process; no shell or config-write access if the guarantee depends on it.
- Network exposure: default bind addresses, what changes if exposed.
- A recommended reference deployment (a compose file or a systemd example) that has been tested.
- A "this setup defeats the protection" list: concrete misconfigurations that void the guarantees.

## 6. Cryptography and formats

For anything signed, hashed, or canonicalized, document so another team could reimplement it:

- Algorithm names and parameters; exact bytes signed or hashed; domain-separation strings and their versions.
- The canonicalization rules, with the standard it follows, any deviations or restrictions, and published test vectors.
- Versioning: how formats change, what happens to old data (for example, fails closed with a specific error).
- Key lifecycle: generation, storage permissions, rotation steps, what a compromised key lets an attacker do, how to revoke.

Provide test vectors as files in the repo and link them.

## 7. Claims discipline

- Never write "secure", "safe", "tamper-proof", "unbreakable", "prevents all attacks", "military-grade".
- Never claim an independent audit unless one happened and you link the report.
- Never claim a standard is implemented unless it is byte-exact and tested against a reference implementation; otherwise describe the actual rules and name them.
- Use "fails closed" only with a definition: what is the failure, what is the safe outcome.
- State the maturity honestly (beta, preview) and what has not been reviewed.
- Separate "implemented" from "planned". Planned items go in a roadmap, never in feature lists.

## 8. Vulnerability reporting and security policy

Include a visible page or `SECURITY.md` with: a private reporting channel (email or advisory link), what to include in a report, expected response time, supported versions, disclosure policy, and credit policy. A project with no way to report a vulnerability reads as not serious.

## 9. Failure and error documentation

Security tools fail closed, which means users meet denials often. Document each denial code with: the exact message, the common causes ranked by likelihood, how to tell them apart, and the fix. Include a "Why was my call denied?" page that shows how to read the decision and reason fields, and how to test a policy without running the tool.

## 10. Checklist

- [ ] Threat model with attacker capabilities, assumptions, in-scope, out-of-scope
- [ ] Each guarantee has assumption, mechanism, test
- [ ] Non-goals and bypass paths stated plainly
- [ ] Deployment model with isolation table and a tested reference setup
- [ ] Key management with rotation steps
- [ ] Formats and canonicalization documented with test vectors
- [ ] Every error code documented
- [ ] No unsupported absolute claims; no unverified performance numbers
- [ ] Vulnerability reporting path visible
- [ ] Maturity and audit status stated honestly
