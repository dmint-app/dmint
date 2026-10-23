#!/usr/bin/env python3
"""Collect ground-truth facts from a repository so docs are written from code, not memory.

Usage:
    python collect_facts.py REPO_DIR [--out facts.md] [--code-prefix DMT_]
                            [--include-tests] [--src DIR ...]

Writes a Markdown fact sheet with: project metadata (pyproject.toml / package.json),
console scripts, CLI flags (argparse / click / typer), environment variables,
error-code-like constants, version strings and format identifiers, git info, and an
inventory of docs files. Every item lists the file (and line) where it was found,
so each fact can go straight into the docs "facts ledger".

It is a static text scan: it cannot see values built dynamically. For CLI
behavior, still run `<tool> --help` and read the real output.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

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
    ".tox",
    "site-packages",
}
CODE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".rb", ".java", ".kt"}

FLAG_PATTERNS = [
    re.compile(r"""add_argument\(\s*((?:["']-{1,2}[A-Za-z0-9][\w-]*["']\s*,?\s*)+)"""),
    re.compile(r"""(?:click\.)?(?:option|argument)\(\s*((?:["']-{1,2}[A-Za-z0-9][\w-]*["']\s*,?\s*)+)"""),
    re.compile(r"""\.option\(\s*["'](-{1,2}[A-Za-z0-9][\w-]*(?:[ ,|]+-{1,2}[A-Za-z0-9][\w-]*)*)"""),
]
ENV_PATTERNS = [
    re.compile(r"""os\.environ(?:\.get)?\s*[\[(]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""os\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)"""),
    re.compile(r"""process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    re.compile(r"""\b_?[A-Z_]*ENV[A-Z_]*\s*=\s*["']([A-Z][A-Z0-9_]{3,})["']"""),
]
VERSION_PATTERNS = [
    re.compile(r"""__version__\s*=\s*["']([^"']+)["']"""),
    re.compile(r"""\bVERSION\s*[:=]\s*["']([0-9][^"']*)["']"""),
    re.compile(r"""["']([A-Za-z][\w-]*(?:/[\w.-]+)+/v\d+)["']"""),  # format ids like name/thing/v2
    re.compile(r"""(?:SCHEMA|CREDENTIAL|RECORD|BINDING|FORMAT)_VERSION\s*[:=]\s*["']([^"']+)["']"""),
]


def walk(root: Path, suffixes: set[str], include_tests: bool):
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in suffixes:
            continue
        parts = set(p.parts)
        if parts & SKIP_DIRS or any(x.startswith("audit") for x in p.parts):
            continue
        if not include_tests and ({"tests", "test", "__tests__"} & parts or p.name.startswith("test_")):
            continue
        yield p


def run(cmd: list[str], cwd: Path) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=30)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def scan(root: Path, files, regexes, group=1):
    found: dict[str, list[str]] = defaultdict(list)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rx in regexes:
            for m in rx.finditer(text):
                val = m.group(group)
                line = text.count("\n", 0, m.start()) + 1
                loc = f"{f.relative_to(root)}:{line}"
                if loc not in found[val]:
                    found[val].append(loc)
    return found


def project_metadata(root: Path) -> list[str]:
    out: list[str] = []
    pp = root / "pyproject.toml"
    if pp.exists() and tomllib:
        try:
            data = tomllib.loads(pp.read_text(encoding="utf-8"))
            proj = data.get("project", {})
            out.append(
                f"- Python project `{proj.get('name', '?')}` version **{proj.get('version', 'dynamic/unknown')}** (pyproject.toml)"
            )
            if proj.get("requires-python"):
                out.append(f"- requires-python: `{proj['requires-python']}`")
            cls = [
                c
                for c in proj.get("classifiers", [])
                if "Programming Language :: Python ::" in c or "Development Status" in c or "License" in c
            ]
            if cls:
                out.append("- classifiers: " + "; ".join(f"`{c.split(' :: ', 1)[-1]}`" for c in cls))
            if proj.get("license"):
                out.append(f"- license field: `{proj['license']}`")
            scripts = proj.get("scripts", {})
            if scripts:
                out.append("- console scripts: " + ", ".join(f"`{k}` -> `{v}`" for k, v in scripts.items()))
            deps = proj.get("dependencies", [])
            out.append(f"- dependencies ({len(deps)}): " + (", ".join(f"`{d}`" for d in deps) if deps else "none"))
            for extra, items in (proj.get("optional-dependencies") or {}).items():
                out.append(f"- extra `{extra}`: " + ", ".join(f"`{d}`" for d in items))
            unbounded = [d for d in deps if "<" not in d and "==" not in d and "~=" not in d]
            if unbounded:
                out.append("- dependencies with no upper bound: " + ", ".join(f"`{d}`" for d in unbounded))
        except Exception as exc:
            out.append(f"- could not parse pyproject.toml: {exc}")
    elif pp.exists():
        out.append("- pyproject.toml present (tomllib unavailable; use Python 3.11+ for details)")
    pj = root / "package.json"
    if pj.exists():
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
            out.append(
                f"- Node package `{data.get('name', '?')}` version **{data.get('version', '?')}** (package.json)"
            )
            if data.get("license"):
                out.append(f"- license: `{data['license']}`")
            if data.get("engines"):
                out.append(f"- engines: `{data['engines']}`")
            if data.get("bin"):
                out.append(f"- bin: `{data['bin']}`")
            if data.get("scripts"):
                out.append("- npm scripts: " + ", ".join(f"`{k}`" for k in data["scripts"]))
            deps = data.get("dependencies", {})
            out.append(
                f"- dependencies ({len(deps)}): "
                + (", ".join(f"`{k}@{v}`" for k, v in deps.items()) if deps else "none")
            )
        except Exception as exc:
            out.append(f"- could not parse package.json: {exc}")
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        lic = root / name
        if lic.exists():
            first = next((line.strip() for line in lic.read_text(errors="ignore").splitlines() if line.strip()), "")
            out.append(f"- {name} starts with: `{first[:80]}`")
            break
    return out or ["- no pyproject.toml or package.json found"]


def fmt_found(found: dict[str, list[str]], limit_loc: int = 2) -> list[str]:
    return [
        f"- `{k}`: " + ", ".join(f"`{v}`" for v in locs[:limit_loc]) + (" ..." if len(locs) > limit_loc else "")
        for k, locs in sorted(found.items())
    ] or ["- none found"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect ground-truth facts from a repo.")
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--code-prefix", default=None, help="prefix of error-code constants, e.g. DMT_")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--src", type=Path, action="append", default=[], help="limit source scan to these folders")
    args = ap.parse_args()

    root = args.repo.resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    roots = [p.resolve() for p in args.src] or [root]
    files = [f for r in roots for f in walk(r, CODE_SUFFIXES, args.include_tests)]

    lines: list[str] = ["# Facts collected from the repository", ""]
    head = run(["git", "rev-parse", "--short", "HEAD"], root)
    if head:
        lines += [
            "## Git",
            f"- HEAD: `{head}`",
            f"- date: {run(['git', 'log', '-1', '--format=%cI'], root)}",
            "- tags (newest first): "
            + (
                ", ".join(f"`{t}`" for t in run(["git", "tag", "--sort=-creatordate"], root).splitlines()[:8]) or "none"
            ),
            f"- working tree: {'clean' if not run(['git', 'status', '--porcelain'], root) else 'has uncommitted changes'}",
            "",
        ]

    lines += ["## Project metadata", *project_metadata(root), ""]

    flags: dict[str, list[str]] = defaultdict(list)
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for rx in FLAG_PATTERNS:
            for m in rx.finditer(text):
                for flag in re.findall(r"-{1,2}[A-Za-z0-9][\w-]*", m.group(1)):
                    loc = f"{f.relative_to(root)}:{text.count(chr(10), 0, m.start()) + 1}"
                    if loc not in flags[flag]:
                        flags[flag].append(loc)
    lines += [f"## CLI flags found in code ({len(flags)})", *fmt_found(flags), ""]

    envs = scan(root, files, ENV_PATTERNS)
    lines += [f"## Environment variables read by the code ({len(envs)})", *fmt_found(envs), ""]

    if args.code_prefix:
        rx = re.compile(r"""["'](""" + re.escape(args.code_prefix) + r"""[A-Z0-9_]+)["']""")
        codes = scan(root, files, [rx])
        lines += [f"## Error codes / constants with prefix `{args.code_prefix}` ({len(codes)})", *fmt_found(codes), ""]

    versions = scan(root, files, VERSION_PATTERNS)
    lines += [f"## Version strings and format identifiers ({len(versions)})", *fmt_found(versions, 3), ""]

    docs = [
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in {".md", ".mdx"}
        and not (set(p.parts) & SKIP_DIRS)
        and not any(x.startswith("audit") for x in p.parts)
    ]
    lines += [f"## Docs inventory ({len(docs)} markdown files)"]
    by_dir: dict[str, int] = defaultdict(int)
    for d in docs:
        by_dir[str(d.parent.relative_to(root))] += 1
    lines += [f"- `{k}/`: {v} file(s)" for k, v in sorted(by_dir.items())[:30]]
    lines += [
        "",
        "## Not collected here (do these by running commands)",
        "- Run `<tool> --help` and `<tool> <subcommand> --help` for every command and copy real output.",
        "- Run the quickstart on a clean machine and capture real output.",
        "- Read tests for realistic usage examples.",
    ]

    text_out = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text_out, encoding="utf-8")
        print(f"wrote {args.out} ({len(lines)} lines)")
    else:
        print(text_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
