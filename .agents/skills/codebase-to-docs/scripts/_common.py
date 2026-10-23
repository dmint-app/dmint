"""Shared helpers for the codebase-to-docs scripts. Standard library only."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

DOC_SUFFIXES = {".md", ".mdx"}
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", ".tox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", ".next", ".turbo", ".astro", ".cache",
}


def is_skipped(parts) -> bool:
    return any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts)


def iter_doc_files(root) -> Iterator[Path]:
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in DOC_SUFFIXES and not is_skipped(p.relative_to(root).parts):
            yield p


# --------------------------------------------------------------------------- fences

FENCE_OPEN = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")


def scan_fences(lines: list[str]):
    """Yield (start_idx, end_idx, indent, info, closed) for each fenced block.

    Body is lines[start_idx+1:end_idx]; the closing fence (if any) is lines[end_idx].
    """
    i = 0
    while i < len(lines):
        m = FENCE_OPEN.match(lines[i])
        if m and not (m["fence"][0] == "`" and "`" in m["info"]):
            fence = m["fence"]
            closer = re.compile(r"^[ \t]*" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*$")
            j = i + 1
            while j < len(lines) and not closer.match(lines[j]):
                j += 1
            yield i, j, m["indent"], m["info"].strip(), j < len(lines)
            i = j + 1
        else:
            i += 1


@dataclass
class Block:
    path: Path
    line: int  # 1-based line of the opening fence
    lang: str
    info: str
    code: str
    closed: bool
    directive: str | None = None  # docs-check directive found just above the fence
    directive_reason: str = ""


DIRECTIVE = re.compile(r"docs-check:\s*(skip|no-run|expect-error)\b\s*(.*?)\s*(?:-->|\*/\}|$)")


def extract_blocks(path) -> list[Block]:
    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[Block] = []
    for start, end, indent, info, closed in scan_fences(lines):
        body = [(raw[len(indent):] if raw.startswith(indent) else raw.lstrip()) for raw in lines[start + 1:end]]
        lang = re.split(r"[\s{(\[=]", info, maxsplit=1)[0].lower() if info else ""
        directive, reason = None, ""
        for back in (1, 2):  # directive must sit on one of the two lines above the fence
            if start - back >= 0:
                d = DIRECTIVE.search(lines[start - back])
                if d:
                    directive, reason = d.group(1), d.group(2).strip()
                    break
        out.append(Block(path, start + 1, lang, info, "\n".join(body), closed, directive, reason))
    return out


def prose_lines(text: str, keep_inline_code: bool = False) -> list[tuple[int, str]]:
    """[(lineno, text)] with fenced blocks blanked (and inline code blanked unless kept)."""
    lines = text.splitlines()
    masked: set[int] = set()
    for start, end, *_ in scan_fences(lines):
        masked.update(range(start, min(end, len(lines) - 1) + 1))
    out = []
    for idx, raw in enumerate(lines):
        if idx in masked:
            out.append((idx + 1, ""))
        elif keep_inline_code:
            out.append((idx + 1, raw))
        else:
            out.append((idx + 1, re.sub(r"`[^`\n]*`", lambda m: " " * len(m.group(0)), raw)))
    return out


# --------------------------------------------------------------------------- headings & frontmatter

HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
EXPLICIT_ID = re.compile(r"(?:\[#([\w.-]+)\]|\{#([\w.-]+)\})\s*$")


def slugify(text: str) -> str:
    text = EXPLICIT_ID.sub("", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").replace("*", "")
    text = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return text.replace(" ", "-")


def headings(text: str) -> list[tuple[int, int, str]]:
    """[(lineno, level, raw_heading_text)] outside code fences and frontmatter."""
    _, _, fm_lines = split_frontmatter(text)
    out = []
    for lineno, line in prose_lines(text, keep_inline_code=True):
        if lineno <= fm_lines:
            continue
        m = HEADING.match(line)
        if m:
            out.append((lineno, len(m.group(1)), re.sub(r"\s+#+\s*$", "", m.group(2))))
    return out


def heading_ids(text: str) -> set[str]:
    ids: set[str] = set()
    seen: dict[str, int] = {}
    for _, _, raw in headings(text):
        explicit = EXPLICIT_ID.search(raw)
        if explicit:
            ids.add(explicit.group(1) or explicit.group(2))
        slug = slugify(raw)
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        ids.add(slug if n == 0 else f"{slug}-{n}")
    return ids


def split_frontmatter(text: str):
    """Return (frontmatter_text | None, body, number_of_lines_used_by_frontmatter)."""
    if text.startswith("---"):
        m = re.match(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)", text, re.S)
        if m:
            return m.group(1), text[m.end():], m.group(0).count("\n")
    return None, text, 0


# --------------------------------------------------------------------------- reporting

class Reporter:
    ORDER = ["ERROR", "WARN", "INFO", "SKIP", "PASS"]

    def __init__(self) -> None:
        self.items: list[tuple[str, str, str]] = []

    def add(self, level: str, where: str, msg: str) -> None:
        self.items.append((level, where, msg))

    def count(self, level: str) -> int:
        return sum(1 for lv, _, _ in self.items if lv == level)

    def print(self, show_pass: bool = False, show_info: bool = True) -> None:
        for level in self.ORDER:
            if level == "PASS" and not show_pass:
                continue
            if level == "INFO" and not show_info:
                continue
            for lv, where, msg in self.items:
                if lv == level:
                    print(f"{lv:<5} {where}: {msg}")

    def summary(self) -> str:
        return "  ".join(f"{lv}={self.count(lv)}" for lv in self.ORDER if self.count(lv))


# --------------------------------------------------------------------------- claim ledger

def load_ledger(path):
    """Load ledger JSONL file(s). Returns (records_by_id, meta, errors).

    A ledger is one JSON object per line. A line {"_meta": {...}} carries repo-level metadata.
    """
    import json
    path = Path(path)
    files = sorted(path.rglob("*.jsonl")) if path.is_dir() else [path]
    records, meta, errors = {}, {}, []
    for f in files:
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"{f}:{n}: invalid JSON ({e.msg})")
                continue
            if "_meta" in obj:
                meta.update(obj["_meta"])
                continue
            obj["_where"] = f"{f}:{n}"
            if obj.get("id") in records:
                errors.append(f"{f}:{n}: duplicate claim id '{obj.get('id')}'")
            records[obj.get("id")] = obj
    return records, meta, errors
