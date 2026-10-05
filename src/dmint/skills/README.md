# `dmint.skills`

Official AI agent skills and system prompt assets for Dmint security policy management.

`dmint.skills` bundles instructions and templates that teach AI coding assistants (Cursor, Claude Code, Antigravity, Gemini CLI) how to author and maintain least-privilege Dmint security policies through natural conversation.

---

## Installation

Included by default in the base `dmint` distribution:

```bash
pip install dmint
```

To install the skill directly into your AI coding assistant's workspace:

```bash
dmint install-skill -y
# Installs to: .agents/skills/dmint-policy-manager/
```

---

## Python API Usage

```python
from dmint.skills import (
    load_policy_manager_skill,
    get_skill_path,
    DMINT_POLICY_SYSTEM_PROMPT,
)

# Load the full skill markdown text programmatically
skill_markdown = load_policy_manager_skill()
print(f"Loaded skill ({len(skill_markdown)} characters)")

# Locate the bundled skill asset path on disk
path = get_skill_path("dmint-policy-manager")
print(f"Skill directory: {path}")
```

---

## Core Principles Taught to Agents

The bundled `dmint-policy-manager` skill teaches AI assistants to:
1. **Enforce Least Privilege by Default**: Operations not explicitly required must evaluate to `DENY`.
2. **Never Hand-Edit Raw JSON**: Author human-readable security requirements in `access.md` and compile them using `dmint create-policy`.
3. **Mandatory Offline Verification**: Run `dmint verify-policy` to catch schema errors and potential secret leaks before committing.
4. **Preserve Boundaries**: Understand that LLMs draft policies at development time, but never evaluate authorization at runtime.
