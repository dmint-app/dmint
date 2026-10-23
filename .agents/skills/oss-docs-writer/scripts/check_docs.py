#!/usr/bin/env python3
"""Lint a docs folder (Markdown / MDX) for common quality problems.

Usage:
    python check_docs.py DOCS_DIR [--strict] [--no-frontmatter-check]

Checks:
  errors   : broken relative links, duplicate H1, leftover TODO/FIXME/lorem markers
  warnings : skipped heading levels, code fences without a language,
             missing frontmatter title/description, marketing or condescending
             words, very short or very long pages, "click here" link text,
             missing alt text on images

Exit code is 1 if any error is found (or any warning with --strict).
This is a floor, not a ceiling: it cannot judge whether an explanation is clear.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DOC_SUFFIXES = {".md", ".mdx"}

MARKETING_WORDS = [
    "powerful",
    "robust",
    "seamless",
    "seamlessly",
    "blazing",
    "lightning-fast",
    "cutting-edge",
    "state-of-the-art",
    "world-class",
    "revolutionary",
    "game-changing",
    "game changing",
    "next-generation",
    "enterprise-grade",
    "military-grade",
    "battle-tested",
    "effortless",
    "effortlessly",
    "best-in-class",
    "supercharge",
    "unlock the power",
    "delve",
    "holistic",
    "turnkey",
    "bulletproof",
    "unbreakable",
    "tamper-proof",
]
CONDESCENDING_WORDS = ["simply", "just", "easy", "easily", "obviously", "trivial", "trivially", "straightforward"]
FILLER_PHRASES = [
    "it's important to note",
    "it is important to note",
    "it is worth mentioning",
    "it's worth mentioning",
    "in today's",
    "in the realm of",
    "dive into",
    "deep dive",
]
MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|TBD|lorem ipsum)\b", re.IGNORECASE)

FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})(.*)$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
LINK_RE = re.compile(r"(?<!\!)\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")


@dataclass
class Finding:
    level: str  # "error" or "warning"
    path: Path
    line: int
    message: str


@dataclass
class Page:
    path: Path
    lines: list[str]
    frontmatter: dict[str, str] = field(default_factory=dict)
    body_start: int = 0  # 0-based index of first body line


def parse_frontmatter(lines: list[str]) -> tuple[dict[str, str], int]:
    if not lines or lines[0].strip() != "---":
        return {}, 0
    data: dict[str, str] = {}
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return data, i + 1
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", lines[i])
        if m:
            data[m.group(1)] = m.group(2).strip().strip("\"'")
    return {}, 0  # unterminated frontmatter: treat as none


def collect_pages(root: Path) -> list[Page]:
    pages = []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() in DOC_SUFFIXES and not any(
            part in {"node_modules", ".git", ".venv", "venv"} or (part.startswith(".") and part != ".")
            for part in path.parts
        ):
            if path.name in {"README.md", "AGENTS.md"} and path.parent == root:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            fm, start = parse_frontmatter(lines)
            pages.append(Page(path, lines, fm, start))
    return pages


def resolve_link(root: Path, page: Path, target: str) -> bool:
    """Return True if a local link target exists. External/anchor links return True."""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("#"):
        return True
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return True
    base = root if target.startswith("/") else page.parent
    candidate = (base / target.lstrip("/")).resolve()
    options = [candidate]
    for suffix in DOC_SUFFIXES:
        options.append(candidate.with_name(candidate.name + suffix))
        options.append(candidate / f"index{suffix}")
        options.append(candidate / f"README{suffix}")
    return any(p.exists() for p in options)


def word_pattern(words: list[str]) -> re.Pattern[str]:
    return re.compile(r"\b(" + "|".join(re.escape(w) for w in words) + r")\b", re.IGNORECASE)


def check_page(root: Path, page: Page, check_fm: bool) -> list[Finding]:
    findings: list[Finding] = []
    marketing = word_pattern(MARKETING_WORDS)
    condescending = word_pattern(CONDESCENDING_WORDS)
    filler = word_pattern(FILLER_PHRASES)

    if check_fm:
        if not page.frontmatter.get("title"):
            findings.append(Finding("warning", page.path, 1, "missing frontmatter 'title'"))
        if not page.frontmatter.get("description"):
            findings.append(Finding("warning", page.path, 1, "missing frontmatter 'description'"))

    in_fence = False
    fence_char = ""
    h1_count = 0
    prev_level = 0
    body_line_count = 0

    for idx in range(page.body_start, len(page.lines)):
        line = page.lines[idx]
        lineno = idx + 1

        fence = FENCE_RE.match(line)
        if fence:
            marker, info = fence.group(2), fence.group(3).strip()
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                if not info:
                    findings.append(Finding("warning", page.path, lineno, "code fence has no language tag"))
            elif marker[0] == fence_char and not info:
                in_fence = False
            continue
        if in_fence:
            continue

        if line.strip():
            body_line_count += 1

        heading = HEADING_RE.match(line)
        if heading:
            level = len(heading.group(1))
            if level == 1:
                h1_count += 1
                if h1_count > 1:
                    findings.append(Finding("error", page.path, lineno, "more than one H1 on the page"))
            if prev_level and level > prev_level + 1:
                findings.append(Finding("warning", page.path, lineno, f"heading jumps from H{prev_level} to H{level}"))
            prev_level = level

        prose = INLINE_CODE_RE.sub("", line)

        if MARKER_RE.search(prose):
            findings.append(Finding("error", page.path, lineno, f"leftover marker: {MARKER_RE.search(prose).group(0)}"))

        for m in marketing.finditer(prose):
            findings.append(
                Finding("warning", page.path, lineno, f"marketing word '{m.group(0)}': replace with evidence or delete")
            )
        for m in condescending.finditer(prose):
            # "just" is common in legitimate phrases like "just after"; still worth a look
            findings.append(Finding("warning", page.path, lineno, f"condescending word '{m.group(0)}'"))
        for m in filler.finditer(prose):
            findings.append(Finding("warning", page.path, lineno, f"filler phrase '{m.group(0)}'"))

        for m in LINK_RE.finditer(line):
            text, target = m.group(1).strip(), m.group(2)
            if text.lower() in {"click here", "here", "link", "this link", "read more"}:
                findings.append(Finding("warning", page.path, lineno, f"non-descriptive link text '{text}'"))
            if not resolve_link(root, page.path, target):
                findings.append(Finding("error", page.path, lineno, f"broken link: {target}"))

        for m in IMAGE_RE.finditer(line):
            if not m.group(1).strip():
                findings.append(Finding("warning", page.path, lineno, "image has no alt text"))
            if not resolve_link(root, page.path, m.group(2)):
                findings.append(Finding("error", page.path, lineno, f"broken image path: {m.group(2)}"))

    if in_fence:
        findings.append(Finding("error", page.path, len(page.lines), "unclosed code fence"))
    if body_line_count < 12 and page.path.stem.lower() not in {"index", "readme"}:
        findings.append(
            Finding("warning", page.path, 1, f"very short page ({body_line_count} non-empty lines): is it a real page?")
        )
    if body_line_count > 700:
        findings.append(
            Finding("warning", page.path, 1, f"very long page ({body_line_count} lines): consider splitting")
        )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint a docs folder.")
    parser.add_argument("docs_dir", type=Path)
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument("--no-frontmatter-check", action="store_true")
    args = parser.parse_args()

    root = args.docs_dir.resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    pages = collect_pages(root)
    if not pages:
        print(f"No .md or .mdx files found under {root}")
        return 2

    findings: list[Finding] = []
    for page in pages:
        findings.extend(check_page(root, page, not args.no_frontmatter_check))

    for f in findings:
        rel = f.path.relative_to(root)
        print(f"{f.level.upper():7} {rel}:{f.line}: {f.message}")

    errors = sum(1 for f in findings if f.level == "error")
    warnings = sum(1 for f in findings if f.level == "warning")
    print(f"\nChecked {len(pages)} pages: {errors} errors, {warnings} warnings")

    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
