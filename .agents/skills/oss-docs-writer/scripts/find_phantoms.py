#!/usr/bin/env python3
"""Find "phantom" names in docs: identifiers, CLI flags, env vars, error codes and
file paths that docs mention in `backticks` but that do not appear in the source.
Optionally list public names in the code that no doc mentions.

Usage:
    python find_phantoms.py DOCS_DIR SRC_DIR [--root REPO_ROOT]
                            [--undocumented] [--ignore NAME ...] [--fail]

  DOCS_DIR   folder (or file) with .md/.mdx docs; README.md can be passed as a file
  SRC_DIR    folder with source code to search (repeat with --extra-src)
  --root     repo root used to resolve file paths mentioned in docs (default: parent of SRC_DIR)
  --undocumented  also list public Python names / CLI flags / env vars never mentioned in docs
  --fail     exit 1 if any phantom is found (default: informational, exit 0)

What counts as a candidate token (inside inline `code` spans, outside fenced blocks):
  CLI flags (--flag), ENV_VARS and ERROR_CODES (UPPER_SNAKE), snake_case names,
  CamelCase names, dotted paths (a.b.c), and file paths (dir/file.ext).
A token is a phantom if neither the token nor (for dotted paths) its last part
appears anywhere in the source text. This is a text search, so it has false
positives (names built dynamically) and false negatives (a name that exists but
means something else). Treat the output as a to-check list, not a verdict.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

DOC_SUFFIXES = {".md", ".mdx"}
SRC_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".cs",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".cfg",
    ".ini",
    ".sh",
    ".txt",
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".overview_scratch",
}

FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
SPAN_RE = re.compile(r"`([^`\n]+)`")

FLAG_RE = re.compile(r"^--[a-zA-Z0-9][a-zA-Z0-9-]*$")
UPPER_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
SNAKE_RE = re.compile(r"^[a-z_][a-z0-9]*(?:_[a-z0-9]+)+$")
CAMEL_RE = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+$")
DOTTED_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
PATH_RE = re.compile(r"^(?:\./|\.\./)?[\w.-]+(?:/[\w.-]+)+\.[A-Za-z0-9]{1,5}$")
CALL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)\(.*\)$")

# words that look like identifiers but are generic
COMMON = {
    "e.g",
    "i.e",
    "etc.",
    "node.js",
    "next.js",
    "vue.js",
    "package.json",
    "pyproject.toml",
    "readme.md",
    "setup.py",
    "requirements.txt",
    "__init__",
    "__main__",
    "__name__",
    "__version__",
    "true",
    "false",
    "none",
    "null",
}


def iter_files(root: Path, suffixes: set[str]):
    if root.is_file():
        if root.suffix.lower() in suffixes:
            yield root
        return
    for p in sorted(root.rglob("*")):
        if (
            p.is_file()
            and p.suffix.lower() in suffixes
            and not any(part in SKIP_DIRS or part.startswith("audit") for part in p.parts)
        ):
            yield p


def doc_spans(path: Path):
    """Yield (line_number, token) for inline code spans outside fenced blocks."""
    in_fence, marker = False, ""
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        m = FENCE_RE.match(line)
        if m:
            if not in_fence:
                in_fence, marker = True, m.group(1)[0]
            elif m.group(1)[0] == marker:
                in_fence = False
            continue
        if in_fence:
            continue
        for sm in SPAN_RE.finditer(line):
            yield n, sm.group(1).strip()


def classify(token: str):
    """Return (kind, key_to_search, fallback_key) or None if not a candidate."""
    t = token.strip().rstrip(",.;:")
    if not t or " " in t or len(t) < 4 or t.lower() in COMMON:
        return None
    call = CALL_RE.match(t)
    if call:
        t = call.group(1)
    if FLAG_RE.match(t):
        return "flag", t, t.lstrip("-")
    if UPPER_RE.match(t):
        return "constant", t, None
    if PATH_RE.match(t):
        return "path", t, None
    if DOTTED_RE.match(t):
        last = t.rsplit(".", 1)[1]
        if last.lower() in {"py", "js", "ts", "md", "json", "toml", "yaml", "yml", "txt", "mdx", "html", "css"}:
            return None  # file name like config.yaml
        return "dotted", t, last if len(last) >= 4 else None
    if SNAKE_RE.match(t):
        return "snake", t, None
    if CAMEL_RE.match(t):
        return "camel", t, None
    return None


def build_corpus(src_roots: list[Path]) -> str:
    chunks = []
    for root in src_roots:
        for f in iter_files(root, SRC_SUFFIXES):
            try:
                chunks.append(f.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    return "\n".join(chunks)


def public_python_names(src_roots: list[Path]) -> set[str]:
    names: set[str] = set()
    for root in src_roots:
        for f in iter_files(root, {".py"}):
            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
            except SyntaxError:
                continue
            for node in tree.body:
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_") and len(node.name) >= 5:
                        names.add(node.name)
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description="Find names in docs that do not exist in the code.")
    ap.add_argument("docs", type=Path)
    ap.add_argument("src", type=Path)
    ap.add_argument("--extra-src", type=Path, action="append", default=[])
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--undocumented", action="store_true")
    ap.add_argument("--ignore", nargs="*", default=[])
    ap.add_argument("--fail", action="store_true")
    args = ap.parse_args()

    src_roots = [args.src.resolve(), *[p.resolve() for p in args.extra_src]]
    root = (args.root or args.src.resolve().parent).resolve()
    corpus = build_corpus(src_roots)
    if not corpus:
        print(f"error: no source text found under {args.src}", file=sys.stderr)
        return 2

    docs_files = list(iter_files(args.docs.resolve(), DOC_SUFFIXES))
    if not docs_files:
        print(f"error: no .md/.mdx files under {args.docs}", file=sys.stderr)
        return 2

    ignore = set(args.ignore)
    seen_in_docs: set[str] = set()
    phantoms: dict[str, dict] = {}
    checked = 0

    for doc in docs_files:
        for lineno, token in doc_spans(doc):
            cls = classify(token)
            if not cls:
                continue
            kind, key, fallback = cls
            if key in ignore:
                continue
            seen_in_docs.add(key)
            if fallback:
                seen_in_docs.add(fallback)
            checked += 1

            if kind == "path":
                clean = key.lstrip("./")
                exists = (root / clean).exists() or (doc.parent / key).exists() or clean in corpus
                if exists:
                    continue
            else:
                if key in corpus or (fallback and fallback in corpus):
                    continue
            entry = phantoms.setdefault(key, {"kind": kind, "where": [], "count": 0})
            entry["count"] += 1
            if len(entry["where"]) < 3:
                try:
                    rel = doc.relative_to(root)
                except ValueError:
                    rel = doc
                entry["where"].append(f"{rel}:{lineno}")

    print(f"Checked {checked} candidate names from {len(docs_files)} doc files against the source.\n")
    if phantoms:
        print(f"PHANTOM CANDIDATES ({len(phantoms)}): mentioned in docs, not found in source")
        by_kind = defaultdict(list)
        for key, e in phantoms.items():
            by_kind[e["kind"]].append((key, e))
        for kind in ("flag", "constant", "path", "dotted", "snake", "camel"):
            if kind not in by_kind:
                continue
            print(f"\n  [{kind}]")
            for key, e in sorted(by_kind[kind]):
                print(f"   - {key}  (x{e['count']})  {', '.join(e['where'])}")
    else:
        print("No phantom names found.")

    if args.undocumented:
        print("\nPUBLIC NAMES NEVER MENTIONED IN DOCS (informational)")
        docs_text = "\n".join(d.read_text(encoding="utf-8", errors="replace") for d in docs_files)
        py_names = sorted(n for n in public_python_names(src_roots) if n not in docs_text)
        flags = sorted(
            f
            for f in {f for f in re.findall(r"""["'](--[a-zA-Z0-9][a-zA-Z0-9-]{2,})["']""", corpus)}
            if f not in docs_text
        )
        envs = sorted(
            e
            for e in {
                e
                for e in re.findall(
                    r"""(?:environ(?:\.get)?\s*[\[(]\s*|getenv\s*\(\s*|process\.env\.|process\.env\[\s*)["']?([A-Z][A-Z0-9_]{3,})""",
                    corpus,
                )
            }
            if e not in docs_text
        )
        for title, items in (
            ("Python classes/functions", py_names),
            ("CLI flags", flags),
            ("Environment variables", envs),
        ):
            print(f"\n  [{title}] {len(items)}")
            for i in items[:60]:
                print(f"   - {i}")
            if len(items) > 60:
                print(f"   ... and {len(items) - 60} more")

    return 1 if (args.fail and phantoms) else 0


if __name__ == "__main__":
    sys.exit(main())
