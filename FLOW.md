# Dmint — Developer Verification Flow (`FLOW.md`)

> **Step-by-step verification checklist to follow EVERY TIME you change any code, documentation, or configuration in Dmint.**
>
> Follow this flow in order before staging and committing your changes.

---

## 1. Quick Summary (The 6-Step Loop)

Every time you finish making changes, run these 6 steps from the `~/dmint` root directory:

```bash
# 1. Format code deterministically
ruff format .

# 2. Lint and check for syntax / rule errors
ruff check .

# 3. Type check all 71 source files
mypy src/

# 4. Run targeted tests for what you changed
PYTHONPATH=src pytest tests/<subsystem>/ -v

# 5. Run full test suite (must be 971 passed, 0 skipped, 0 failed)
PYTHONPATH=src pytest tests/ -q

# 6. Run pre-commit hooks manually across all files
pre-commit run --all-files
```

---

## 2. Universal Pre-Commit Flow (Step-by-Step)

Follow these steps in exact order before you run `git commit`:

### Step 1: Code Formatting
- **Why**: Keeps code style 100% clean and consistent. Pre-commit hooks will reject unformatted code.
- **Command**:
  ```bash
  ruff format .
  ```
- **Expected result**: `X files already formatted` (or `X files reformatted`). Zero errors.

### Step 2: Code Linting
- **Why**: Catches unused imports, undefined variables, syntax errors, and style violations.
- **Commands**:
  ```bash
  # Check for errors:
  ruff check .

  # Auto-fix safe errors if any:
  ruff check . --fix
  ```
- **Expected result**: `All checks passed!`

### Step 3: Type Checking with MyPy
- **Why**: Ensures all type hints are valid and Python type hints provide helpful editor autocomplete for developers.
- **Command**:
  ```bash
  mypy src/
  ```
- **Expected result**: `Success: no issues found in 71 source files`
- **Tips for writing type hints**:
  - Always add type annotations to new function arguments and return values:
    ```python
    def verify_request(request: ToolRequest, ttl_seconds: int = 300) -> bool: ...
    ```
  - For optional values, use `Type | None` (Python 3.10+):
    ```python
    agent_id: str | None = None
    ```
  - Use `collections.abc` or `typing` for complex types:
    ```python
    from collections.abc import Callable, Mapping, Sequence
    ```

### Step 4: Targeted Subsystem Tests
- **Why**: Gives you fast feedback on the specific module you modified before waiting for the full suite.
- **Command**: Run the specific test directory matching your changed folder (see Section 3 below).

### Step 5: Full Regression Test Suite
- **Why**: Guarantees your changes didn't accidentally break another subsystem or contract.
- **Command**:
  ```bash
  PYTHONPATH=src pytest tests/ -q
  ```
- **Expected result**: `971 passed, 0 failed, 0 skipped` (or higher if you added new tests).
- **Rule**: `skipTest()` is banned. No skipped tests allowed.

### Step 6: Pre-Commit Hook Check
- **Why**: Verifies trailing whitespace, end-of-file newlines, YAML/JSON/TOML syntax, and private key detection before git runs it.
- **Command**:
  ```bash
  pre-commit run --all-files
  ```
- **Expected result**: All hooks `Passed`.
- **Note**: `pre-commit` operates on git repositories. If git is not yet initialized in your environment, steps 1–5 (`ruff format`, `ruff check`, `mypy`, `pytest`) provide full lint, format, type, and test validation.

### Step 7: Documentation & Readme Check
- **Why**: If you added a new CLI flag, changed an API, or altered a command, documentation must be updated immediately so it never goes stale.
- Check: Did you add/change commands? Update `README.md` and `docs/reference/`.

### Step 8: Conventional Commit Message
- **Why**: `commitizen` enforces strict Conventional Commit message formats.
- **Format**: `<type>(<scope>): <short description in imperative present tense>`
- **Allowed types**:
  - `feat`: New feature or user-facing capability (e.g. `feat(cli): add --json output flag`)
  - `fix`: Bug fix (e.g. `fix(dashboard): correct approval card badge color`)
  - `docs`: Documentation updates only (e.g. `docs(quickstart): update installation guide`)
  - `test`: Adding or updating tests (e.g. `test(core): add replay attack regression test`)
  - `refactor`: Code change that neither fixes a bug nor adds a feature
  - `chore`: Build scripts, dependencies, pre-commit config, gitignore

### Step 9: Version Severity Assessment & User Permission Check
- **Why**: Semantic Versioning (`MAJOR.MINOR.PATCH`) communicates the risk and scope of each release to downstream users.
- **Severity Guidelines**:
  | Severity | SemVer Bump | Trigger Changes | Examples |
  |---|---|---|---|
  | **Low / Patch** | `2.0.0` &rarr; `2.0.1` | Bug fixes, documentation updates, internal refactoring, test additions, dependency maintenance. Backwards-compatible. | `fix(mcp): resolve subprocess timeout`<br>`docs: update quickstart guide` |
  | **Medium / Minor** | `2.0.0` &rarr; `2.1.0` | New backwards-compatible features, new CLI commands, new flags, new framework integrations, new policy operators. | `feat(cli): add interactive export wizard`<br>`feat(mcp): add streamable http transport` |
  | **High / Major** | `2.0.0` &rarr; `3.0.0` | Breaking changes, modified policy schema, changed cryptographic fingerprint algorithm, removed public APIs, architectural redesign. | `feat!(core): breaking change to policy condition schema` |

- **CRITICAL PROTOCOL (ALWAYS ASK PERMISSION)**:
  1. **Assess Severity**: Look at the changes made and classify them into Patch, Minor, or Major.
  2. **Propose to User**: Suggest the recommended new version with clear rationale, for example:
     > *"Based on the severity of these changes (new CLI options and bug fixes), I recommend bumping the version from `2.0.0` to `2.0.1` (Patch). Would you like me to update the version and changelog?"*
  3. **Wait for Explicit Permission**: **NEVER** edit version strings or release tags without the user's explicit approval.
  4. **When Approved, Synchronously Update All Canonical Locations**:
     - [ ] `pyproject.toml` (`version = "X.Y.Z"`) — Single source of truth
     - [ ] `src/dmint/version.py` (`__version__ = "X.Y.Z"`)
     - [ ] `src/dmint/core/__init__.py` (`__version__ = "X.Y.Z"`)
     - [ ] `CHANGELOG.md` (add release section with date and bulleted summary)
     - [ ] Rebuild and check package: `python3 -m build --no-isolation && twine check dist/*`

---

## 3. Folder-Specific Action Guides

When your change is focused on a specific folder or subsystem, follow these exact checklist items:

---

### A. When Changing `src/dmint/core/` (Core Engine)

`dmint.core` is the security authority for authorization, cryptographic signing, canonicalization, and SQLite storage.

- [ ] **Check Security Invariants**:
  1. *Fail-closed default*: Unknown actions must return `DENY`.
  2. *Exact request binding*: Fingerprint must use RFC 8785 canonicalization + SHA-256.
  3. *Single-use consumption*: Approval must be atomically marked `CONSUMED`.
  4. *Policy epoch*: Changing policy digest must invalidate old approvals.
  5. *Zero direct SQL outside Core*: Only export public APIs.
- [ ] **Run Core Tests**:
  ```bash
  PYTHONPATH=src pytest tests/core/ -v
  ```
- [ ] **Run Adversarial Tests**:
  ```bash
  PYTHONPATH=src pytest tests/core/test_security.py tests/core/test_consumption.py -v
  ```
- [ ] **Check Compatibility**:
  - Ensure compatibility shims in `src/dmint/approvals.py`, `src/dmint/canonicalize.py`, `src/dmint/enforcement.py` continue to work.

---

### B. When Changing `src/dmint/cli/` (CLI Commands & Wizards)

`dmint.cli` provides developer tooling (`dmint create-policy`, `verify-policy`, `dashboard`, `install-skill`).

- [ ] **Check CLI Help & Parsing**:
  - Run `--help` to verify command descriptions and options are readable:
    ```bash
    PYTHONPATH=src python3 -m dmint.cli --help
    PYTHONPATH=src python3 -m dmint.cli <command> --help
    ```
- [ ] **Check Documentation**:
  - If you added a new flag or command:
    - [ ] Update [src/dmint/cli/README.md](src/dmint/cli/README.md)
    - [ ] Update [docs/reference/cli.mdx](docs/reference/cli.mdx)
    - [ ] Update root [README.md](README.md) CLI section
- [ ] **Run CLI Tests**:
  ```bash
  PYTHONPATH=src pytest tests/cli/ -v
  ```

---

### C. When Changing `src/dmint/mcp/` (MCP Gateway & Proxy)

`dmint.mcp` is the transparent Model Context Protocol proxy and gateway (`dmint-mcp`).

- [ ] **Check Subprocess Path Safety**:
  - Subprocesses spawned by MCP stdio do not automatically inherit `PYTHONPATH`. Ensure `tests/mcp/proxy_entrypoint.py` and MCP loaders resolve paths self-contained.
- [ ] **Check Imports**:
  - **Rule**: Never import `from dmint.canonicalize import ...` inside `dmint.mcp`.
  - **Rule**: Always import `from dmint.core.canonicalize import ...` directly.
- [ ] **Check SSRF Protection**:
  - If touching network/HTTP transports, verify private IP and loopback filters remain active.
- [ ] **Run MCP Tests**:
  ```bash
  PYTHONPATH=src pytest tests/mcp/ -v
  ```

---

### D. When Changing `src/dmint/dashboard/` (Approval Dashboard)

`dmint.dashboard` is the local FastAPI human review interface (`dmint-dashboard`).

- [ ] **Check Security Invariant 5 (Zero Direct SQL)**:
  - The dashboard must **NEVER** import `sqlite3` or execute SQL strings.
  - All access must go through `CoreClient` public APIs (`list_pending`, `approve_pending`, `reject_pending`, `list_records`).
  - Automated security tests will fail if `sqlite3` or raw SQL is detected in the dashboard module.
- [ ] **Check Templates & UI**:
  - If you changed HTML strings, badges, or texts in `templates/`:
    - [ ] Check if `tests/dashboard/test_smoke.py` asserts on that string.
    - [ ] Check if `tests/dashboard/test_routes.py` asserts on that string.
    - [ ] Keep the 5-second polling JS functional and intact.
- [ ] **Run Dashboard Tests**:
  ```bash
  PYTHONPATH=src pytest tests/dashboard/ -v
  ```

---

### E. When Changing `src/dmint/skills/` (Installable Skills)

`dmint.skills` provides the `dmint-policy-manager` AI coding assistant skill.

- [ ] **Check Skill Content**:
  - Verify `src/dmint/skills/skills/dmint-policy-manager/SKILL.md` contains clear system prompt instructions.
- [ ] **Verify Skill Packaging**:
  - Ensure skill markdown files are included in package data (`pyproject.toml`).
- [ ] **Run Skills Tests**:
  ```bash
  PYTHONPATH=src pytest tests/skills/ -v
  ```

---

### F. When Changing `docs/` (Documentation Site)

`docs/` is the Holocron/Vite MDX documentation site deployed to Cloudflare Workers.

- [ ] **Check JSX Callout Components**:
  - **Allowed**: `<Note>`, `<Warning>`, `<Tip>`, `<Danger>`, `<Check>`.
  - **Banned**: `<Important>` (causes Vite build failure).
- [ ] **Check Frontmatter**:
  - Every `.mdx` file must start with valid YAML frontmatter containing `title:` and `description:`.
- [ ] **Validate Build Locally**:
  ```bash
  cd docs
  npm run build
  ```
  Must compile in ~2 seconds with zero errors.
- [ ] **Verify Navigation Links**:
  - If a new `.mdx` page was added, register its route in `docs/docs.json`.

---

### G. When Changing Packaging or Version (`pyproject.toml`)

- [ ] **Single Source of Truth**:
  - Update `version = "X.Y.Z"` in `pyproject.toml`.
  - Keep synchronized in `src/dmint/version.py` and `src/dmint/core/__init__.py`.
- [ ] **Build Package**:
  ```bash
  python3 -m build --no-isolation
  ```
- [ ] **Validate Distributions with Twine**:
  ```bash
  twine check dist/*
  ```
  Expected: `PASSED` for both `.whl` and `.tar.gz`.
- [ ] **Verify Editable Development Install**:
  ```bash
  pip install --no-build-isolation -e ".[all,dev]"
  ```
  Expected: Installs editable wheel cleanly without build-isolation errors.

---

## 4. Quick Command Reference Cheat Sheet

| Task | Command |
|---|---|
| **Format code** | `ruff format .` |
| **Lint code** | `ruff check .` |
| **Auto-fix lint** | `ruff check . --fix` |
| **Type check** | `mypy src/` |
| **Test Core** | `PYTHONPATH=src pytest tests/core/ -v` |
| **Test CLI** | `PYTHONPATH=src pytest tests/cli/ -v` |
| **Test MCP** | `PYTHONPATH=src pytest tests/mcp/ -v` |
| **Test Dashboard** | `PYTHONPATH=src pytest tests/dashboard/ -v` |
| **Test Skills** | `PYTHONPATH=src pytest tests/skills/ -v` |
| **Test Everything** | `PYTHONPATH=src pytest tests/ -q` |
| **Pre-commit check** | `pre-commit run --all-files` |
| **Build docs** | `cd docs && npm run build` |
| **Build wheel/sdist** | `python3 -m build --no-isolation` |
| **Check package** | `twine check dist/*` |

---

## 5. "Ready to Commit" Final Checklist

Before running `git commit`, confirm every box is checked:

- [ ] Code formatted with `ruff format .`
- [ ] Code linted with `ruff check .` (0 errors)
- [ ] Types checked with `mypy src/` (0 errors across 71 files)
- [ ] Subsystem tests pass for touched area
- [ ] Full test suite passes (`971 passed, 0 skipped`)
- [ ] Pre-commit hooks run cleanly (`pre-commit run --all-files`)
- [ ] If docs/commands changed, `README.md` and `docs/` are updated
- [ ] If docs touched, `npm run build` succeeds in `docs/`
- [ ] Assessed change severity (Patch / Minor / Major) and proposed version bump to user
- [ ] Explicit user permission obtained before changing any version strings
- [ ] Commit message follows Conventional Commits (`type(scope): summary`)
