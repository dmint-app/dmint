# Security Policy

Dmint is a deterministic authorization and policy enforcement engine designed specifically to protect sensitive infrastructure from unauthorized AI agent actions. Because Dmint sits directly in the critical execution path, we treat security vulnerabilities with the highest priority.

---

## Supported Versions

Only the latest major and minor release receive active security updates, vulnerability patches, and backports.

| Version | Status | Security Patches |
| :--- | :--- | :--- |
| **`2.0.x`** | **Active (Latest)** | :white_check_mark: Supported |
| `1.x.x` | Deprecated (Replaced by v2.0 Monorepo) | :x: Unsupported (Upgrade to 2.0.0+) |
| `< 1.0.0` | EOL / Experimental | :x: Unsupported |

---

## Threat Model & Security Boundaries

Dmint provides a tamper-evident, deterministic boundary between an AI agent and execution environments.

### What Dmint Protects Against
1. **Adversarial Prompt Injection & Tool Jailbreaks**: An AI agent manipulated via prompt injection into calling destructive tools (e.g. `DROP TABLE`, `rm -rf`, `cloud.delete_instance`) is blocked before the tool call reaches downstream execution.
2. **Unauthorized Scope Escalation**: Agents cannot access tools, actions, or resources outside the declarative policy definition.
3. **Parameter Tampering & Replay Attacks**: Request parameters are bound to cryptographic signatures using RFC 8785 canonicalization. Modifying even a single character in arguments invalidates the approval token.
4. **SSRF & Metadata Exfiltration (MCP Transports)**: The MCP gateway rigorously inspects target URLs, resolving DNS and blocking:
   - Loopback interfaces (`127.0.0.0/8`, `::1`)
   - Private RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
   - Cloud instance metadata endpoints (`http://169.254.169.254`)
   - Non-standard IP encodings (octal, hex, dword representations)
   - DNS rebinding attacks via socket address pinning
5. **Approval Re-use & Concurrency Races**: Approval records in SQLite transition atomically (`PENDING` $\to$ `APPROVED` $\to$ `CONSUMED`). An approval token can only be consumed once.

### Out of Scope
- Compromised host operating system, root access, or physical hardware tampering.
- Tampering with the Python interpreter memory space from within the same trusted host process.
- Social engineering of human approvers outside the cryptographic assertions.

---

## Cryptographic Standards & Design

Dmint adheres to rigorous cryptographic specifications:

| Component | Standard / Algorithm | Specification |
| :--- | :--- | :--- |
| **Canonicalization** | RFC 8785 (JSON Canonicalization Scheme - JCS) | Guarantees identical byte sequences regardless of whitespace or dictionary key ordering. |
| **Request Hashing** | SHA-256 with Domain Separation | Domain: `b"dmint/request-binding/v1\x00"` |
| **Policy Digest** | SHA-256 with Domain Separation | Domain: `b"dmint/policy-digest/v1\x00"` |
| **Approval Signatures** | Ed25519 (EdDSA over Curve25519) | Fast, deterministic public-key signatures resistant to side-channel and timing attacks. |
| **Storage State Machine** | SQLite WAL mode with Immediate Transactions | Guarantees atomic, serialized state transitions without approval token replay. |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

If you discover or suspect a security vulnerability in Dmint, please report it privately:

1. **GitHub Private Vulnerability Advisory (Preferred)**:
   - Go to the **Security** tab of the [`dmint-app/dmint`](https://github.com/dmint-app/dmint) repository.
   - Click **Report a vulnerability** to open a confidential advisory draft.
2. **Email Disclosure**:
   - Send full technical details to: **`security@dmint.app`** 

### What to Include in Your Report
To help us triage and resolve the issue quickly, please provide:
- A concise summary of the vulnerability and its potential impact.
- The affected component(s) (`dmint.core`, `dmint.mcp`, `dmint.cli`, `dmint.dashboard`, `dmint.skills`).
- Step-by-step reproduction instructions or a minimal Proof-of-Concept (PoC) script.
- Any observed failure of Dmint's security invariants (e.g. bypass of `DENY`, SSRF bypass, replay of approval).
- Suggested remediation or patch, if known.

---

## Vulnerability Handling & Response Process

We follow responsible disclosure principles and commit to the following response timeline:

1. **Initial Acknowledgment**: Within **24–48 hours** of receiving the report.
2. **Triage & Assessment**: Within **72 hours**, confirming reproducibility and assigning a CVSS severity score.
3. **Patch Development & Testing**: We will develop and test a fix in a private branch, sharing the patch with the reporter for verification.
4. **Release & Advisory**: We will publish a patched release on PyPI and GitHub, followed by a public Security Advisory crediting the finder (unless anonymity is requested).
5. **Disclosure Window**: We adhere to a 90-day responsible disclosure window before public disclosure, or earlier upon mutual agreement once patches are deployed.
