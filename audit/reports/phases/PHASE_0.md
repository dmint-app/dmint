# Phase 0: Baseline Verification Report

## Environment & Tooling
- Target Commit: `de708c6` (tag: `phase6c-final`)
- Host Python: Python 3.10.12 (clean virtualenv in `audit_scratch/venv` via `[E-001]`)
- Docker Engine: 29.7.2 (used for Python 3.12-slim and 3.13-slim test matrix)
- PostgreSQL: Local port 5432 verified accepting connections (Docker container `dmint-test-postgres`)
- Node.js: v24.21.0 available on host

## Evidence Summary
- **[E-001]**: Clean venv created and dependencies installed (`rc=0`, 38.64s).
- **[E-002]**: `pip check` passed (`rc=0`, "No broken requirements found.").
- **[E-003]**: Standard pytest suite baseline: **1158 passed**, 65 subtests passed, 0 failed, 0 skipped (`rc=0`, 82.94s).
- **[E-004]**: Optimized Python execution (`python -O -m pytest -q`): **1158 passed** (`rc=0`, 84.03s). Confirms runtime security invariants do not vanish under `-O`.
- **[E-005]**: `ruff check .` passed with 0 errors (`rc=0`).
- **[E-006]**: `ruff format --check .` failed (`rc=1`) on `tests/mcp/test_phase3_gateway_verifier.py:152`. Tracked files kept read-only per Rule 1.
- **[E-007]**: `mypy src/` passed with 0 errors (`rc=0`, 78 source files clean).
- **[E-008]**: Full branch coverage generated into `coverage.json` and compiled to `tables/coverage.md`. 27 security-critical modules have branch coverage < 90%.
- **[E-009]**: Python 3.10 execution with `-W error::DeprecationWarning`: **1158 passed**, 0 DeprecationWarnings (`rc=0`, 81.78s).
- **[E-010]**: Python 3.12 (Docker) execution with `-W error::DeprecationWarning`: **1158 passed**, 0 DeprecationWarnings (`rc=0`, 71.99s).
- **[E-011]**: Python 3.13 (Docker) execution with `-W error::DeprecationWarning`: **1158 passed**, 0 DeprecationWarnings (`rc=0`, 71.42s).
- **[E-012]**: `dmint --help` console entry point exited 0 (`rc=0`).
- **[E-013]**: `dmint-mcp --help` console entry point exited 0 (`rc=0`).
- **[E-014]**: `dmint-dashboard --help` console entry point exited 0 (`rc=0`).
