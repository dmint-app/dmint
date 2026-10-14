# Dmint Security Fixes Progress (Tier 2 & Tier 3)

## Group A (Small Fixes)
- [x] A1 Unclosed sqlite connections (storage/thread_safe.py context manager & close tracking)
- [x] A2 Dashboard: thaw_json on arguments rendering in routes.py with escaped keys/values
- [x] A3 Constrained DENY rules: reject constraints on DENY at load time & doc alignment
- [x] A4 Webhooks: sanitize @everyone, @here, links; truncate; SSRF guard; no redirects
- [x] A5 Host normalization: reject empty labels & repeated trailing dots; idempotence test; fuzz check
- [x] A6 Packaging: httpx2 audit; pyproject questionary/sqlalchemy bounds; py313 classifier; shims audit
- [x] A7 Docs code blocks: fix compilation errors in docs python fences & add validation test
- [x] A8 Fresh-process import isolation test; docs on integrity key & policy digest pin
- [x] Group A Gate: Full pytest, ruff, mypy, mutation harness, tag fix-A

## Group B (Product Features)
- [x] B1 Decorator mode: async def, methods (self/cls), reject generators, WeakKeyDictionary registry, TOCTOU
- [x] B2 SSRF: pin resolved IP to connection, reject trailing-dot / octal / hex IPs, cleanup dead ipv4_mapped
- [x] B3 Tool schema pinning: create-mcp-policy per-tool schema hash & gateway enforcement
- [x] B4 Postgres: 10-process consume race & K-21 tamper scenarios against Postgres store
- [x] Group B Gate: Full pytest, ruff, mypy, mutation harness, tag fix-B

## Group C (Coverage, Hygiene, CI)
- [ ] C1 Coverage: >=85% line+branch on security modules (keys.py, gateway.py, sql.py, etc.)
- [ ] C2 Policy authoring injection test: adversarial LLM prompt injection review step
- [ ] C3 CI: .github/workflows/ci.yml multi-python matrix (3.10, 3.12, 3.13) + mutation job
- [ ] C4 Final accuracy pass: audit docs/claims against measured numbers; generate FIX_REPORT.md
- [ ] Group C Gate: Tag fix-C & final report
