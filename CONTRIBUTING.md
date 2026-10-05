# Contributing to Dmint

Thank you for your interest in contributing to **Dmint**! Dmint is an open-source, deterministic security enforcement layer for AI-agent tool execution.

We welcome contributions of all kinds: bug fixes, security hardening, new policy templates, integration guides, documentation improvements, and architectural enhancements.

---

## Code of Conduct

All contributors, maintainers, and community members are expected to adhere to our community standards:
- Be welcoming, inclusive, and respectful of differing viewpoints.
- Focus on what is best for the security and reliability of the project.
- Gracefully accept constructive criticism.
- Treat security concerns with utmost seriousness and report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

---

## Development Setup

### Prerequisites
- **Python 3.10+** (Python 3.10, 3.11, or 3.12)
- **Git**
- **pip** and **virtualenv**

### 1. Clone the Repository
```bash
git clone https://github.com/dmint-app/dmint.git
cd dmint
```

### 2. Set Up Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install in Editable Mode with All Development Tools
```bash
pip install --upgrade pip setuptools wheel
pip install -e ".[all,dev]"

# Or on older pip versions without upgrading pip:
# pip install --no-build-isolation -e ".[all,dev]"
```

This installs Dmint along with all subsystem dependencies (`mcp`, `dashboard`), test runners (`pytest`, `pytest-cov`), code quality tools (`ruff`, `mypy`), and release tools (`build`, `twine`, `pre-commit`, `commitizen`).

### 4. Install Git Pre-Commit Hooks
Dmint uses `pre-commit` to guarantee formatting, linting, and Conventional Commit message compliance before commits are accepted:

```bash
pre-commit install --hook-type pre-commit --hook-type commit-msg
```

---

## Commit Message Conventions

Dmint strictly enforces the **[Conventional Commits](https://www.conventionalcommits.org/)** specification via `commitizen`. Every commit message must follow this structure:

```text
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

### Allowed Types
| Type | Description | Example |
| :--- | :--- | :--- |
| `feat` | A new user-facing feature or API capability | `feat(mcp): add streamable http authorization headers` |
| `fix` | A bug fix or security patch | `fix(core): prevent sqlite lock timeout on concurrent consume` |
| `docs` | Documentation, READMEs, docstrings | `docs(readme): add mcp proxy client configuration` |
| `test` | Adding, refactoring, or updating tests | `test(cli): add version consistency test across submodules` |
| `refactor` | Code restructuring with no behavioral change | `refactor(authority): streamline ed25519 key verification` |
| `perf` | Performance improvement | `perf(canonicalize): optimize frozen json dict hashing` |
| `ci` | CI/CD workflows, GitHub Actions, scripts | `ci(github): add ruff format check to test pipeline` |
| `chore` | Maintenance tasks, dependencies, packaging | `chore(deps): bump ruff to 0.6.9` |

### Scopes (Optional but Recommended)
- `core`: Core policy evaluation, hashing, canonicalization, SQLite store
- `mcp`: MCP proxy, gateway, transports, SSRF defenses
- `cli`: CLI commands, policy compilation, wizard, verify
- `dashboard`: Web UI, FastAPI routes, approval templates
- `skills`: Bundled agent skills, system prompts
- `packaging`: pyproject.toml, wheels, builds

---

## Code Quality & Standards

Before opening a pull request, all checks must pass locally.

### 1. Code Formatting (Prettier for Python)
Dmint uses **Ruff Formatter** for deterministic, PEP 8 / Black-compatible formatting:
```bash
# Check formatting without modifying files
ruff format --check .

# Auto-format all files
ruff format .
```

### 2. Linting & Auto-fix (ESLint for Python)
Dmint uses **Ruff Linter** for fast AST-based static analysis:
```bash
# Run linter
ruff check .

# Automatically apply safe fixes
ruff check --fix .
```

### 3. Strict Static Type Checking (PEP 561 / Mypy)
All source code in `src/` must be 100% type-annotated and pass strict type checking with zero errors or warnings:
```bash
PYTHONPATH=src mypy src/
```

### 4. Running the Test Suite
Dmint maintains over 890 automated tests covering unit tests, security invariants, concurrency, and end-to-end flows.

```bash
# Run all tests
PYTHONPATH=src pytest -v tests/

# Run individual subsystem test suites
PYTHONPATH=src pytest tests/core/
PYTHONPATH=src pytest tests/mcp/
PYTHONPATH=src pytest tests/cli/
PYTHONPATH=src pytest tests/dashboard/
PYTHONPATH=src pytest tests/skills/
```

### 5. Packaging & Local Wheel Verification
Verify that source distributions (`.tar.gz`) and wheels (`.whl`) build cleanly and install in an isolated environment:
```bash
# Build packages
python3 -m build --no-isolation
twine check dist/*

# Test-install the wheel in an isolated venv:
python3 -m venv /tmp/test-env
source /tmp/test-env/bin/activate
pip install "dist/dmint-2.0.0-py3-none-any.whl[all]"
dmint --version
dmint --help
deactivate
rm -rf /tmp/test-env
```

### 6. Testing Documentation Locally
When editing `.mdx` files or documentation configuration in `docs/`:
```bash
cd docs
npm install
npm run dev    # Starts hot-reloading dev server at http://localhost:3334
npm run build  # Validates full production bundle
```

For the complete step-by-step developer checklist before committing, see [`FLOW.md`](FLOW.md).

---

## Security Invariants to Maintain

Any pull request modifying core authorization or transport code **must preserve these five core invariants**:

1. **Deterministic Execution**: Authorization decisions (`ALLOW`, `DENY`, `APPROVAL_REQUIRED`) must remain purely deterministic. Never introduce stochastic LLM calls or external network dependencies into the critical authorization path.
2. **Fail-Closed Default**: Any request that is unrecognized, malformed, missing credentials, or not explicitly covered by an `ALLOW` rule must evaluate to `DENY`.
3. **Exact Request Binding**: Requests must be canonicalized via RFC 8785 JSON Canonicalization Scheme (JCS) and fingerprinted with domain-separated SHA-256 digests. Any mutation in arguments or context must invalidate approval assertions.
4. **Single-Use Replay Protection**: Approvals must transition atomically (`PENDING` $\to$ `APPROVED` $\to$ `CONSUMED`) in SQLite storage to prevent race conditions and replay attacks.
5. **Zero Secret Leakage**: Plaintext tokens, API keys, passwords, and authorization codes must never appear in logs, exception strings, or generated policy files.

---

## Pull Request Lifecycle

1. **Branch Naming**: Use descriptive branch names prefixed with the change type:
   - `feat/streamable-http-mcp`
   - `fix/sqlite-concurrent-consume`
   - `docs/policy-wizard-guide`
2. **Work in Progress**: Feel free to open a Draft PR early to solicit architectural feedback.
3. **Tests Required**: Every feature or bug fix must include corresponding tests in `tests/`.
4. **CI Checks**: Ensure all GitHub Actions workflows pass:
   - Multi-version testing on Python 3.10, 3.11, 3.12
   - Ruff linting and formatting check
   - Mypy static type checking
   - Twine package verification
5. **Code Review**: A maintainer will review your pull request against Dmint's security invariant matrix.
