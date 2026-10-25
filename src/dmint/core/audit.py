"""Tamper-evident, level-aware structured audit logging engine for Dmint.

Features:
- Industry-standard log levels (DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50)
  configurable via DMINT_LOG_LEVEL or explicit min_level.
- Cryptographic SHA-256 hash chaining (prev_hash -> entry_hash) over RFC 8785 (JCS)
  canonicalized JSON payloads with domain separation (b"dmint/audit-log/v1\\x00").
- Automatic credential, API key, and database DSN redaction before persistence.
- Thread-safe and multiprocess-safe atomic JSONL appends via POSIX fcntl advisory locks
  plus automatic size-bounded rotation.
- Seamless bridge to Python's standard `logging.getLogger("dmint.audit")`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import threading
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

from .canonicalize import canonicalize_bytes
from .redaction import SENSITIVE_PARAM_NAMES, redact_database_url

AUDIT_DOMAIN_PREFIX = b"dmint/audit-log/v1\x00"
GENESIS_PREV_HASH = "0" * 64
DEFAULT_MAX_AUDIT_BYTES = 10 * 1024 * 1024  # 10 MB per log file
DEFAULT_BACKUP_COUNT = 5

LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,        # 10
    "INFO": logging.INFO,          # 20
    "WARN": logging.WARNING,       # 30
    "WARNING": logging.WARNING,    # 30
    "ERROR": logging.ERROR,        # 40
    "CRITICAL": logging.CRITICAL,  # 50
}

_SECRET_VALUE_RE = re.compile(
    r"(?i)(sk-[a-z0-9_-]{12,}|ghp_[a-z0-9]{16,}|akia[a-z0-9]{12,}|bearer\s+[a-z0-9._~+/=-]{10,})"
)

_std_logger = logging.getLogger("dmint.audit")
_std_logger.addHandler(logging.NullHandler())
_std_logger.propagate = False
_thread_lock = threading.Lock()


def parse_log_level(level: str | int | None, default: str = "INFO") -> tuple[str, int]:
    """Normalize a log level name or integer into (canonical_name, numeric_value)."""
    if isinstance(level, int):
        for name, val in LEVEL_MAP.items():
            if val == level and name != "WARN":
                return name, val
        return ("DEBUG", 10) if level < 20 else ("INFO", 20)
    raw = str(level or os.environ.get("DMINT_LOG_LEVEL") or default).strip().upper()
    if raw == "WARN":
        raw = "WARNING"
    if raw not in LEVEL_MAP:
        raise ValueError(
            f"Invalid log level '{level}'. Expected one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
        )
    return raw, LEVEL_MAP[raw]


def level_for_decision(
    decision: str,
    *,
    code: str = "",
    shadow_would_block: bool = False,
) -> str:
    """Determine the canonical audit log level for a given decision and status code."""
    dec_upper = decision.upper()
    code_upper = (code or "").upper()

    if any(
        kw in code_upper
        for kw in (
            "SIGNATURE_INVALID",
            "FINGERPRINT_MISMATCH",
            "INTEGRITY_VIOLATION",
            "APPROVAL_CONSUMED",
            "SCHEMA_MISMATCH",
            "SSRF",
            "TAMPER",
        )
    ):
        return "CRITICAL"
    if shadow_would_block:
        return "WARNING"
    if dec_upper == "DENY":
        return "ERROR"
    if dec_upper in ("APPROVAL_REQUIRED", "REJECTED"):
        return "WARNING"
    if dec_upper in ("ALLOW", "APPROVED", "CONSUMED"):
        return "INFO"
    return "DEBUG"


def redact_audit_value(value: Any, *, _depth: int = 0) -> Any:
    """Recursively scrub secrets, tokens, passwords, and DSNs from audit payloads."""
    if _depth > 8:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        scrubbed = redact_database_url(value)
        scrubbed = _SECRET_VALUE_RE.sub("[REDACTED_SECRET]", scrubbed)
        if len(scrubbed) > 2048:
            return scrubbed[:2048] + "...[truncated]"
        return scrubbed
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            k_str = str(k)
            if k_str.lower() in SENSITIVE_PARAM_NAMES or any(
                s in k_str.lower() for s in ("secret", "password", "token", "api_key", "private_key")
            ):
                out[k_str] = "[REDACTED]"
            else:
                out[k_str] = redact_audit_value(v, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_audit_value(item, _depth=_depth + 1) for item in list(value)[:50]]
    return str(value)[:512]


def compute_audit_entry_hash(entry_without_hash: Mapping[str, Any]) -> str:
    """Compute the domain-separated SHA-256 hash over an RFC 8785 canonicalized audit entry."""
    payload = {k: v for k, v in entry_without_hash.items() if k != "entry_hash"}
    canonical = canonicalize_bytes(payload)
    return hashlib.sha256(AUDIT_DOMAIN_PREFIX + canonical).hexdigest()


@dataclass(frozen=True)
class AuditVerificationResult:
    """Result of verifying a tamper-evident audit log hash chain."""

    valid: bool
    total_entries: int
    head_hash: str
    broken_at_seq: int | None = None
    broken_at_line: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "total_entries": self.total_entries,
            "head_hash": self.head_hash,
            "broken_at_seq": self.broken_at_seq,
            "broken_at_line": self.broken_at_line,
            "error": self.error,
        }


def resolve_default_audit_log_path(workspace_dir: str | Path | None = None) -> Path:
    """Resolve the active audit.jsonl path from environment or workspace directory."""
    env_path = os.environ.get("DMINT_AUDIT_LOG") or os.environ.get("DMINT_LOG_FILE")
    if env_path:
        return Path(env_path).resolve()
    base = Path(workspace_dir).resolve() if workspace_dir else Path.cwd().resolve()
    return base / ".dmint" / "audit.jsonl"


class AuditLogger:
    """Tamper-evident, level-filtered JSONL audit logger with SHA-256 hash chaining."""

    def __init__(
        self,
        log_path: str | Path | None = None,
        *,
        min_level: str | int | None = None,
        max_bytes: int = DEFAULT_MAX_AUDIT_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
        enabled: bool | None = None,
    ) -> None:
        self.log_path = Path(log_path).resolve() if log_path else resolve_default_audit_log_path()
        self.min_level_name, self.min_level_num = parse_log_level(min_level)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        if enabled is None:
            env_disabled = os.environ.get("DMINT_AUDIT_DISABLED", "").strip().lower() in ("1", "true", "yes")
            self.enabled = not env_disabled
        else:
            self.enabled = enabled

    def _rotate_if_needed_locked(self) -> None:
        """Rotate audit.jsonl if it exceeds max_bytes (called while holding lock)."""
        if not self.log_path.exists() or self.max_bytes <= 0:
            return
        try:
            if self.log_path.stat().st_size < self.max_bytes:
                return
            for idx in range(self.backup_count, 0, -1):
                src = self.log_path.with_suffix(f".jsonl.{idx}")
                dst = self.log_path.with_suffix(f".jsonl.{idx + 1}")
                if src.exists():
                    if idx == self.backup_count:
                        src.unlink(missing_ok=True)
                    else:
                        src.replace(dst)
            self.log_path.replace(self.log_path.with_suffix(".jsonl.1"))
        except Exception:
            pass

    def _read_last_entry_locked(self) -> tuple[int, str]:
        """Return (last_seq, last_entry_hash) from the tail of the log file."""
        if not self.log_path.exists():
            return 0, GENESIS_PREV_HASH
        try:
            with self.log_path.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return 0, GENESIS_PREV_HASH
                read_len = min(size, 16384)
                f.seek(size - read_len)
                lines = [ln.strip() for ln in f.read().decode("utf-8", errors="replace").splitlines() if ln.strip()]
                if not lines:
                    return 0, GENESIS_PREV_HASH
                last_obj = json.loads(lines[-1])
                return int(last_obj.get("seq", len(lines))), str(last_obj.get("entry_hash", GENESIS_PREV_HASH))
        except Exception:
            return 0, GENESIS_PREV_HASH

    def log_event(
        self,
        *,
        decision: str,
        tool: str,
        action: str,
        resource: str | None = None,
        code: str = "",
        harness: str = "sdk",
        agent_id: str = "default",
        event_type: str = "tool_evaluation",
        level: str | None = None,
        mode: str = "enforce",
        shadow_would_block: bool = False,
        approval_id: str | None = None,
        latency_ms: float | None = None,
        arguments: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Record a structured audit event if its level meets or exceeds min_level."""
        if not self.enabled:
            return None

        eff_level_name = (
            parse_log_level(level)[0]
            if level is not None
            else level_for_decision(decision, code=code, shadow_would_block=shadow_would_block)
        )
        _, eff_level_num = parse_log_level(eff_level_name)

        # Respect configured minimum log level
        active_min_name, active_min_num = parse_log_level(os.environ.get("DMINT_LOG_LEVEL") or self.min_level_name)
        if eff_level_num < active_min_num:
            return None

        now = timestamp or datetime.now(timezone.utc)
        ts_str = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        clean_details: dict[str, Any] = {}
        if details:
            clean_details.update(redact_audit_value(details))
        # At DEBUG level (or when explicitly provided in details), include redacted arguments snapshot
        if arguments is not None and (active_min_num <= logging.DEBUG or eff_level_num >= logging.WARNING):
            clean_details["arguments"] = redact_audit_value(arguments)

        with _thread_lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self.log_path.with_suffix(".lock")
            lock_fd = lock_path.open("a+", encoding="utf-8")
            try:
                if fcntl is not None:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                self._rotate_if_needed_locked()
                last_seq, prev_hash = self._read_last_entry_locked()
                seq = last_seq + 1

                entry_core: dict[str, Any] = {
                    "seq": seq,
                    "timestamp": ts_str,
                    "level": eff_level_name,
                    "event_type": event_type,
                    "decision": decision.upper(),
                    "code": code or ("DMT_ALLOWED" if decision.upper() == "ALLOW" else "DMT_EVENT"),
                    "harness": harness,
                    "agent_id": agent_id,
                    "tool": tool,
                    "action": action,
                    "resource": redact_audit_value(resource) if isinstance(resource, str) else None,
                    "mode": mode,
                    "shadow_would_block": bool(shadow_would_block),
                    "approval_id": approval_id,
                    "latency_ms": round(float(latency_ms), 3) if latency_ms is not None else 0.0,
                    "details": clean_details,
                    "prev_hash": prev_hash,
                }
                entry_hash = compute_audit_entry_hash(entry_core)
                full_entry = {**entry_core, "entry_hash": entry_hash}

                line = json.dumps(full_entry, separators=(",", ":"), sort_keys=False) + "\n"
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
            finally:
                if fcntl is not None:
                    try:
                        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                lock_fd.close()

        # Also emit to Python's standard logging hierarchy for external log collectors
        _std_logger.log(
            eff_level_num,
            "[%s] %s.%s resource=%r code=%s mode=%s hash=%s",
            full_entry["decision"],
            tool,
            action,
            full_entry["resource"],
            full_entry["code"],
            mode,
            full_entry["entry_hash"][:12],
        )
        return full_entry


def verify_audit_chain(log_path: str | Path | None = None) -> AuditVerificationResult:
    """Verify the cryptographic SHA-256 hash chain and sequence integrity of an audit.jsonl file."""
    path = Path(log_path).resolve() if log_path else resolve_default_audit_log_path()
    if not path.exists():
        return AuditVerificationResult(valid=True, total_entries=0, head_hash=GENESIS_PREV_HASH)

    expected_prev = GENESIS_PREV_HASH
    expected_seq = 1
    total = 0

    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        return AuditVerificationResult(
            valid=False,
            total_entries=0,
            head_hash=GENESIS_PREV_HASH,
            broken_at_line=1,
            error=f"Could not read audit log: {exc}",
        )

    for line_no, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception as exc:
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                head_hash=expected_prev,
                broken_at_seq=expected_seq,
                broken_at_line=line_no,
                error=f"Malformed JSON at line {line_no}: {exc}",
            )

        seq = obj.get("seq")
        if seq != expected_seq:
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                head_hash=expected_prev,
                broken_at_seq=expected_seq,
                broken_at_line=line_no,
                error=f"Sequence gap or reordering at line {line_no}: expected seq={expected_seq}, found seq={seq}",
            )

        prev_hash = obj.get("prev_hash")
        if prev_hash != expected_prev:
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                head_hash=expected_prev,
                broken_at_seq=seq,
                broken_at_line=line_no,
                error=(
                    f"Broken prev_hash link at seq #{seq} (line {line_no}): "
                    f"expected {expected_prev[:12]}..., found {str(prev_hash)[:12]}..."
                ),
            )

        recorded_hash = obj.get("entry_hash")
        computed_hash = compute_audit_entry_hash(obj)
        if recorded_hash != computed_hash:
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                head_hash=expected_prev,
                broken_at_seq=seq,
                broken_at_line=line_no,
                error=(
                    f"Tampered entry payload at seq #{seq} (line {line_no}): "
                    f"recorded hash {str(recorded_hash)[:12]}... != computed {computed_hash[:12]}..."
                ),
            )

        expected_prev = computed_hash
        expected_seq += 1
        total += 1

    return AuditVerificationResult(valid=True, total_entries=total, head_hash=expected_prev)


def read_audit_entries(
    log_path: str | Path | None = None,
    *,
    min_level: str | None = None,
    decision: str | None = None,
    tool: str | None = None,
    harness: str | None = None,
    agent_id: str | None = None,
    mode: str | None = None,
    search: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Read and filter structured audit entries from audit.jsonl."""
    path = Path(log_path).resolve() if log_path else resolve_default_audit_log_path()
    if not path.exists():
        return []

    min_num = parse_log_level(min_level)[1] if min_level else 0
    dec_filter = decision.strip().upper() if decision else None
    tool_filter = tool.strip().lower() if tool else None
    harness_filter = harness.strip().lower() if harness else None
    agent_filter = agent_id.strip().lower() if agent_id else None
    mode_filter = mode.strip().lower() if mode else None
    search_filter = search.strip().lower() if search else None

    matched: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            continue

        if min_num:
            _, entry_num = parse_log_level(obj.get("level", "INFO"))
            if entry_num < min_num:
                continue
        if dec_filter and str(obj.get("decision", "")).upper() != dec_filter:
            continue
        if tool_filter:
            cap = f"{obj.get('tool', '')}.{obj.get('action', '')}".lower()
            if tool_filter not in cap and tool_filter != str(obj.get("tool", "")).lower():
                continue
        if harness_filter and str(obj.get("harness", "")).lower() != harness_filter:
            continue
        if agent_filter and str(obj.get("agent_id", "")).lower() != agent_filter:
            continue
        if mode_filter and str(obj.get("mode", "enforce")).lower() != mode_filter:
            continue
        if search_filter:
            haystack = json.dumps(obj).lower()
            if search_filter not in haystack:
                continue

        matched.append(obj)

    if limit is not None and limit > 0:
        return matched[-limit:]
    return matched


def summarize_audit_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate statistics over a list of audit log entries."""
    by_decision: dict[str, int] = {}
    by_level: dict[str, int] = {}
    by_harness: dict[str, int] = {}
    by_capability: dict[str, int] = {}
    denied_resources: dict[str, int] = {}
    shadow_blocks = 0

    for e in entries:
        dec = str(e.get("decision", "UNKNOWN")).upper()
        lvl = str(e.get("level", "INFO")).upper()
        har = str(e.get("harness", "unknown"))
        cap = f"{e.get('tool', '')}.{e.get('action', '')}"

        by_decision[dec] = by_decision.get(dec, 0) + 1
        by_level[lvl] = by_level.get(lvl, 0) + 1
        by_harness[har] = by_harness.get(har, 0) + 1
        by_capability[cap] = by_capability.get(cap, 0) + 1
        if e.get("shadow_would_block"):
            shadow_blocks += 1
        if dec == "DENY" or e.get("shadow_would_block"):
            res = str(e.get("resource") or "(none)")
            denied_resources[res] = denied_resources.get(res, 0) + 1

    return {
        "total_events": len(entries),
        "by_decision": by_decision,
        "by_level": by_level,
        "by_harness": by_harness,
        "top_capabilities": dict(sorted(by_capability.items(), key=lambda kv: -kv[1])[:10]),
        "top_blocked_resources": dict(sorted(denied_resources.items(), key=lambda kv: -kv[1])[:10]),
        "shadow_would_block_count": shadow_blocks,
    }


def learn_policy_from_audit_logs(
    log_path: str | Path | None = None,
    *,
    include_baseline_denies: bool = True,
) -> list[dict[str, Any]]:
    """Synthesize a least-privilege list of policy rules from observed audit.jsonl events.

    Safety invariants:
    - Destructive commands (rm -rf, sudo, mkfs, drop_*) and secret paths (.env*, *.key, *.pem, /etc/**)
      are NEVER learned as ALLOW; they are always emitted as explicit DENY rules.
    - Mutating operations (git push, docker, write_file, delete_file, refund, update_*, delete_*)
      are emitted as APPROVAL_REQUIRED.
    - Safe read-only operations observed in the session are emitted as scoped ALLOW rules.
    """
    entries = read_audit_entries(log_path, limit=0)
    rules: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str, str]] = set()

    def _add_rule(effect: str, tool: str, action: str, resource: str, resource_kind: str | None = None) -> None:
        key = (effect, tool, action, resource)
        if key in seen_keys:
            return
        seen_keys.add(key)
        r: dict[str, Any] = {
            "effect": effect,
            "tool": tool,
            "action": action,
            "resource": resource,
        }
        if resource != "*" and resource_kind:
            r["resource_kind"] = resource_kind
        elif resource != "*" and ("/" in resource or "**" in resource):
            r["resource_kind"] = "path"
        rules.append(r)

    if include_baseline_denies:
        _add_rule("deny", "filesystem", "read_file", "**/.env*", "path")
        _add_rule("deny", "filesystem", "write_file", "**/.env*", "path")
        _add_rule("deny", "filesystem", "read_file", "**/*.key", "path")
        _add_rule("deny", "filesystem", "write_file", "**/.dmint/**", "path")
        _add_rule("deny", "shell", "execute", "rm -rf /")
        _add_rule("deny", "shell", "execute", "sudo *")

    destructive_tokens = (
        "rm -rf", "sudo ", "mkfs", "dd if=", "> /dev/", "| sh", "| bash",
        ".env", ".key", ".pem", "/etc/passwd", "/etc/shadow", ".dmint/",
        "drop_", "destroy", "terminate", "delete_account", "wipe",
    )
    mutating_tokens = (
        "git push", "git reset --hard", "docker ", "kubectl ", "terraform ",
        "npm install", "pip install", "curl ", "wget ",
        "write_file", "delete_file", "edit", "write", "apply_patch",
        "refund", "transfer", "payout", "update", "delete", "insert", "create",
    )

    for e in entries:
        if e.get("event_type") == "approval_lifecycle":
            continue
        tool = str(e.get("tool") or "").strip()
        action = str(e.get("action") or "").strip()
        if not tool or not action:
            continue
        res = str(e.get("resource") if e.get("resource") is not None else "*").strip() or "*"
        combined = f"{tool}.{action} {res}".lower()

        if any(tok in combined for tok in destructive_tokens):
            _add_rule("deny", tool, action, res)
        elif any(tok in combined for tok in mutating_tokens):
            _add_rule("approval_required", tool, action, res)
        else:
            _add_rule("allow", tool, action, res)

    return rules
