# Dmint Development Roadmap & TODO

This document tracks completed milestones, the immediate **v0.1.0 release launch checklist**, and the multi-phase **Post-v0.1.0 Security Roadmap** for **Dmint** (`dmint.app`).

---

## 1. Immediate v0.1.0 Launch Checklist

- [x] **Core Engine:** 255/255 unit & security tests passing (`dmint-0.1.0`).
- [x] **MCP Proxy:** Real stdio transport with `ALLOW / DENY / APPROVAL_REQUIRED` gates.
- [x] **CLI Tooling:** `python3 -m dmint create-policy` and `compile-policy` with zero third-party dependencies.
- [x] **General Demo:** Operational Deployment Control demo with execution counters & attack scenario runner (`cli.py --demo`).
- [ ] **GitHub Push:** Push repository to `github.com/dmint-app/dmint`.
- [ ] **PyPI Release:** Publish package `dmint` v0.1.0.
- [ ] **Landing Page:** Deploy minimal documentation & landing site at `dmint.app`.

---

## 2. Post-v0.1.0 Security Backlog Roadmap

### Phase 1 — Inspection & Canonicalization

- [ ] Shell lexer / AST inspection (`shlex` / `bashlex`)
- [ ] Environment-variable expansion inside command arguments
- [ ] Fail-closed handling of `eval`, base64 payloads, or unparseable dynamic execution
- [ ] Path canonicalization (`pathlib.Path.resolve()`)
- [ ] Symlink traversal detection & target checking
- [ ] Glob / wildcard restriction rules (`pathStartsWith`, `pathIsSubpath`)

### Phase 2 — Network Security

- [ ] `ipInRange` condition operator
- [ ] CIDR allow/deny network policies
- [ ] Private / internal IP blocking (`127.0.0.1`, `10.0.0.0/8`, AWS metadata `169.254.169.254`)
- [ ] Domain / FQDN wildcard matching (`domainMatches`)
- [ ] DNS resolution before authorization
- [ ] DNS-rebinding protections
- [ ] SSRF defense layer

### Phase 3 — Database Security

- [ ] SQL AST inspection for raw query tool calls
- [ ] `DROP` / `TRUNCATE` / `ALTER` statement detection & blocking
- [ ] `DELETE` without `WHERE` clause detection
- [ ] SQL parameter-boundary enforcement

### Phase 4 — Advanced Policy Engine

- [ ] Rich typed condition operators
- [ ] `matchesRegex` operator
- [ ] `semanticVersionCompare` operator
- [ ] `jsonSchemaValid` operator
- [ ] JSON Schema argument validation
- [ ] Strong argument isolation

### Phase 5 — Enterprise Authorization

- [ ] Attribute-Based Access Control (ABAC)
- [ ] `agent_id` principal isolation
- [ ] `session_id` workflow isolation
- [ ] Environment-aware policies (`production` vs `staging`)
- [ ] Rate limiting & execution throttling
- [ ] Volumetric execution caps
- [ ] Time-based operational window authorization

### Phase 6 — Human Approval Lifecycle

- [ ] Persistent approval queue API
- [ ] Dual-control approvals (requiring 2 distinct sign-offs)
- [ ] Multi-party approvals
- [ ] Approval REST API endpoints
- [ ] OAuth2 / JWT authentication middleware
- [ ] Standalone Admin Web UI dashboard
- [ ] Webhook notifications
- [ ] Slack integration (one-click approval buttons)
- [ ] Microsoft Teams integration
- [ ] PagerDuty incident integration

### Phase 7 — MCP Security

- [ ] Dynamic `tools/list` discovery filtering
- [ ] Identity-aware tool discovery
- [ ] Tool capability isolation
- [ ] MCP-specific security policies

---

## 3. Long-Term Architectural Design

To maintain a lean, high-performance runtime core without dependency bloat, Dmint's modular structure will evolve into:

### Package Repositories
```text
dmint-app/
│
├── dmint          ← enforcement engine (core runtime & policy logic)
├── dmint-cli      ← CLI & policy authoring tools
├── dmint-mcp      ← MCP proxy server & gateway integration
└── dmint-skills   ← AI coding assistant skills
```

### Module Organization in `dmint` Core
```text
dmint/
├── policy/            ← Policy schemas & evaluation engine
├── authorization/     ← Deterministic ALLOW / DENY / APPROVAL_REQUIRED
├── inspection/        ← Security inspection engine
│   ├── shell/         ← Shell AST & command lexer
│   ├── path/          ← Path canonicalization & symlink resolution
│   ├── network/       ← CIDR & SSRF checks
│   └── sql/           ← SQL AST query safety
├── canonicalization/  ← RFC 8785 JCS request fingerprinting
├── schemas/           ← JSON Schema validation
├── approvals/         ← Atomic Ed25519 single-use approval store
└── security/          ← Cryptographic primitives & audit logging
```
