#!/usr/bin/env python3
"""Static, offline checks for a docs folder. Nothing is imported or executed.

Usage:
    python check_docs.py <docs-dir> [--inventory inventory.json] [--ledger <file-or-dir>]
                         [--glossary glossary.json] [--require-frontmatter title,description|none]
                         [--strict]

Checks: frontmatter, heading structure, code fences, internal links and anchors,
syntax of python/json/toml/yaml blocks, placeholders (TODO...), secret-looking strings,
overclaiming and filler language, hard-coded counts/versions, glossary terms,
navigation orphans (docs.json, meta.json, mkdocs.yml). With --inventory it also checks
names, CLI flags/subcommands, env vars and pip extras against the source.

Exit status 1 if any ERROR (or any WARN with --strict). A static pass proves a page is
well-formed. It does NOT prove a snippet works: use verify_snippets.py for that.

Exempting a flagged absolute/vague/count term: put `lint-ok: claim=<ledger-id>` on the same
or previous line (inside an HTML/MDX comment). The id must exist in --ledger with
status "verified". Filler/hype words cannot be exempted: rewrite them.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore

sys.path.insert(0, str(Path(__file__).parent))
from _common import (
    Reporter,
    extract_blocks,
    heading_ids,
    headings,
    iter_doc_files,
    load_ledger,  # noqa: E402
    prose_lines,
    split_frontmatter,
)

ABSOLUTE = [
    r"guarantee[sd]?",
    r"100\s?%",
    r"zero",
    r"impossible",
    r"unbreakable",
    r"bulletproof",
    r"foolproof",
    r"tamper[- ]?proof",
    r"military[- ]grade",
    r"(?:completely|fully|totally|absolutely|entirely) (?:secure|safe|protected)",
    r"prevents? (?:all|every|any)",
    r"(?:all|any|every) attacks?",
    r"eliminates?",
    r"never",
    r"always",
    r"cannot be (?:bypassed|tampered|circumvented|forged)",
    r"immune",
    r"no way to",
]
VAGUE = [r"secure[sd]?", r"safe(?:ly)?"]
HYPE = [
    r"seamless(?:ly)?",
    r"robust",
    r"powerful",
    r"cutting[- ]edge",
    r"state[- ]of[- ]the[- ]art",
    r"game[- ]chang\w+",
    r"blazing[- ]fast",
    r"world[- ]class",
    r"enterprise[- ]grade",
    r"production[- ]ready",
    r"battle[- ]tested",
    r"best[- ]in[- ]class",
    r"next[- ]gen",
    r"supercharge[sd]?",
    r"effortless(?:ly)?",
    r"comprehensive",
    r"leverag\w+",
    r"utili[sz]\w+",
    r"delve",
    r"in today's",
    r"it'?s important to note",
    r"it is worth noting",
]
CRUTCH = [r"simply", r"just", r"easily", r"easy", r"obviously", r"of course"]
COUNT_RE = re.compile(
    r"\b\d[\d,]*\+?\s+(?:passing\s+)?(?:tests?|files?|pages?|commands?|rules?|invariants?|modules?|tools?|"
    r"integrations?|endpoints?|checks?|policies|packages?|source files?)\b",
    re.I,
)
VERSION_RE = re.compile(r"(?<![\w.-])v?\d+\.\d+\.\d+(?:[-+][\w.]+)?(?![\w.-])")
VERSION_OK_FILES = re.compile(r"changelog|migration|release|upgrad|history", re.I)
PLACEHOLDER_RE = re.compile(r"\b(TODO|TBD|FIXME|XXX|WIP)\b|lorem ipsum|coming soon", re.I)
PLACEHOLDER_CASE = re.compile(r"\b(TODO|TBD|FIXME|XXX|WIP)\b")
SECRET_RES = [
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "API-key-looking string (sk-...)"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/\w{20,}"), "real-looking Slack webhook URL"),
]
LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
LINT_OK = re.compile(r"lint-ok:\s*claim=([\w.-]+)")


def compile_terms(words):
    return re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % "|".join(words), re.I)


ABS_RE, VAGUE_RE, HYPE_RE, CRUTCH_RE = map(compile_terms, (ABSOLUTE, VAGUE, HYPE, CRUTCH))


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


class Checker:
    def __init__(self, docs: Path, args):
        self.docs = docs
        self.args = args
        self.rep = Reporter()
        self.anchor_cache: dict[Path, set[str]] = {}
        self.inv = json.loads(Path(args.inventory).read_text(encoding="utf-8")) if args.inventory else None
        self.ledger = None
        if args.ledger:
            self.ledger, _, errs = load_ledger(args.ledger)
            for e in errs:
                self.rep.add("ERROR", "ledger", e)
        self.glossary = json.loads(Path(args.glossary).read_text(encoding="utf-8")) if args.glossary else {}
        self.required_fm = (
            []
            if args.require_frontmatter.lower() == "none"
            else [k.strip() for k in args.require_frontmatter.split(",") if k.strip()]
        )
        self.all_text = ""
        self._prepare_inventory()

    # ------------------------------------------------------------------ inventory facts
    def _prepare_inventory(self):
        self.pkg_exports: dict[str, set[str]] = {}
        self.pkg_known: set[str] = set()
        self.extras: set[str] = set()
        self.project_name = None
        self.cli_names: set[str] = set()
        self.cli_subs: set[str] = set()
        self.cli_flags: set[str] = set()
        self.env_known: set[str] = set()
        self.env_prefixes: set[str] = set()
        if not self.inv:
            return
        for m in self.inv["modules"]:
            self.pkg_known.add(m["module"])
            names = set(m["all"] or [])
            for r in m["reexports"]:
                names |= {n["as"] or n["name"] for n in r["names"]}
            names |= {c["name"] for c in m["classes"]} | {f["name"] for f in m["functions"]}
            names |= set(m["constants"])
            self.pkg_exports[m["module"]] = names
        pp = self.inv.get("project") or {}
        self.project_name = norm(pp["name"]) if pp.get("name") else None
        self.extras = {norm(k) for k in (pp.get("optional_dependencies") or {})}
        self.cli_names = set((pp.get("scripts") or {}).keys())
        for c in self.inv["cli"]:
            if c["kind"] == "subcommand" or (c["kind"] in {"command", "group"} and c.get("name")):
                self.cli_subs.add(c["name"])
            for n in c.get("names") or []:
                if n.startswith("-"):
                    self.cli_flags.add(n)
        self.env_known = {e["name"] for e in self.inv["env_vars"]}
        self.env_prefixes = {n.split("_")[0] + "_" for n in self.env_known if "_" in n}

    # ------------------------------------------------------------------ per-file
    def check_file(self, path: Path):
        rel = path.name if path == self.docs else path.relative_to(self.docs).as_posix()
        text = path.read_text(encoding="utf-8")
        self.all_text += "\n" + text
        fm, body, fm_lines = split_frontmatter(text)
        where = lambda n: f"{rel}:{n}"  # noqa: E731

        if self.required_fm:
            keys = set(re.findall(r"^([A-Za-z_][\w-]*)\s*:", fm or "", re.M))
            missing = [k for k in self.required_fm if k not in keys]
            if fm is None:
                self.rep.add("ERROR", where(1), f"no frontmatter (required keys: {', '.join(self.required_fm)})")
            elif missing:
                self.rep.add("ERROR", where(1), f"frontmatter missing: {', '.join(missing)}")
            elif "description" in self.required_fm:
                d = re.search(r"^description\s*:\s*(.+)$", fm, re.M)
                if d and len(d.group(1).strip("\"' ")) > 160:
                    self.rep.add("WARN", where(1), "description longer than 160 characters")

        self.check_headings(text, rel, fm)
        self.check_fences_and_blocks(path, rel)
        self.check_links(path, text, rel)
        self.check_prose(text, rel)
        self.check_inventory_refs(text, rel)

    def check_headings(self, text, rel, fm):
        hs = headings(text)
        prev = 0
        h1s = [h for h in hs if h[1] == 1]
        for lineno, level, raw in hs:
            if prev and level > prev + 1:
                self.rep.add("WARN", f"{rel}:{lineno}", f"heading level jumps from h{prev} to h{level}: {raw!r}")
            prev = level
        if len(h1s) > 1:
            self.rep.add("WARN", f"{rel}:{h1s[1][0]}", "more than one h1")
        if h1s and fm and re.search(r"^title\s*:", fm, re.M):
            self.rep.add("WARN", f"{rel}:{h1s[0][0]}", "h1 in body duplicates the frontmatter title")
        seen = {}
        for lineno, level, raw in hs:
            key = (level, raw.lower())
            if key in seen:
                self.rep.add(
                    "WARN", f"{rel}:{lineno}", f"duplicate heading {raw!r} (first at line {seen[key]}); anchors collide"
                )
            seen.setdefault(key, lineno)

    def check_fences_and_blocks(self, path, rel):
        for b in extract_blocks(path):
            w = f"{rel}:{b.line}"
            if not b.closed:
                self.rep.add("ERROR", w, "unclosed code fence")
                continue
            if not b.lang:
                self.rep.add("WARN", w, "code fence has no language tag")
            if b.directive == "skip":
                if not b.directive_reason:
                    self.rep.add("WARN", w, "docs-check: skip needs a reason")
                self.rep.add("INFO", w, f"block skipped by directive: {b.directive_reason or '(no reason)'}")
                continue
            self.parse_block(b, w)
            if self.inv and b.lang in {"bash", "sh", "shell", "zsh", "console"}:
                self.check_shell_block(b, w)

    def parse_block(self, b, w):
        lang, code = b.lang, b.code
        try:
            if lang in {"python", "py", "python3"}:
                tree = ast.parse(code)
                self.check_python_imports(tree, w)
            elif lang == "json":
                json.loads(code)
            elif lang == "toml" and tomllib:
                tomllib.loads(code)
            elif lang in {"yaml", "yml"}:
                try:
                    import yaml  # type: ignore
                except ModuleNotFoundError:
                    self.rep.add("SKIP", w, "yaml block not parsed (PyYAML not installed)")
                    return
                list(yaml.safe_load_all(code))
        except SyntaxError as e:
            self.rep.add("ERROR", w, f"python syntax error: {e.msg} (block line {e.lineno})")
        except json.JSONDecodeError as e:
            self.rep.add("ERROR", w, f"invalid JSON: {e.msg} (block line {e.lineno}); use ```jsonc if it has comments")
        except Exception as e:  # toml / yaml parse errors
            self.rep.add("ERROR", w, f"{lang} parse error: {str(e).splitlines()[0]}")

    def check_python_imports(self, tree, w):
        if not self.inv:
            return
        tops = {m.split(".")[0] for m in self.pkg_known}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module
                and node.module.split(".")[0] in tops
            ):
                if node.module not in self.pkg_exports:
                    self.rep.add("WARN", w, f"module '{node.module}' not found in inventory")
                    continue
                for a in node.names:
                    if (
                        a.name != "*"
                        and a.name not in self.pkg_exports[node.module]
                        and f"{node.module}.{a.name}" not in self.pkg_known
                    ):
                        self.rep.add(
                            "WARN",
                            w,
                            f"'{a.name}' not found in '{node.module}' per inventory (verify with verify_snippets.py)",
                        )
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in tops and a.name not in self.pkg_known:
                        self.rep.add("WARN", w, f"module '{a.name}' not found in inventory")

    def check_shell_block(self, b, w):
        console = b.lang == "console"
        for off, line in enumerate(b.code.splitlines()):
            s = line.strip()
            if console:
                if not s.startswith("$ "):
                    continue
                s = s[2:]
            if not s or s.startswith("#"):
                continue
            tokens = re.findall(r"""(?:[^\s"']+|"[^"]*"|'[^']*')+""", s)
            for i, t in enumerate(tokens):
                if t in self.cli_names:
                    rest = tokens[i + 1 :]
                    first = next((x for x in rest if not x.startswith("-")), None)
                    if self.cli_subs and first and rest and rest[0] == first and first not in self.cli_subs:
                        self.rep.add(
                            "WARN", f"{w}+{off + 1}", f"'{t} {first}': '{first}' is not a subcommand found in source"
                        )
                    for x in rest:
                        flag = x.split("=")[0]
                        if (
                            flag.startswith("--")
                            and self.cli_flags
                            and flag not in self.cli_flags
                            and flag != "--help"
                            and flag != "--version"
                        ):
                            self.rep.add(
                                "WARN",
                                f"{w}+{off + 1}",
                                f"flag '{flag}' not defined in any CLI definition found in source",
                            )
                    break

    # ------------------------------------------------------------------ links
    def anchors_of(self, p: Path):
        if p not in self.anchor_cache:
            self.anchor_cache[p] = heading_ids(p.read_text(encoding="utf-8"))
        return self.anchor_cache[p]

    def resolve(self, src: Path, target: str):
        path_part, _, anchor = target.partition("#")
        path_part = path_part.split("?")[0]
        if not path_part:
            return src, anchor, "self"
        rooted = path_part.startswith("/")
        rels = [path_part.lstrip("/")] if rooted else [path_part]
        if rooted and rels[0].startswith("docs/"):
            rels.append(rels[0][5:])
        bases = [self.docs] if rooted else [src.parent]
        for base in bases:
            for r in rels:
                full = base / r
                for c in (
                    full,
                    Path(str(full) + ".md"),
                    Path(str(full) + ".mdx"),
                    full / "index.md",
                    full / "index.mdx",
                ):
                    if c.is_file():
                        return c, anchor, "ok"
        return None, anchor, "rooted" if rooted else "relative"

    def check_links(self, path, text, rel):
        for lineno, line in prose_lines(text):
            for m in LINK_RE.finditer(line):
                target = m.group(1)
                if re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", target, re.I):
                    continue  # external: not checked offline
                found, anchor, state = self.resolve(path, target)
                if found is None:
                    level = "WARN" if state == "rooted" else "ERROR"
                    self.rep.add(
                        level,
                        f"{rel}:{lineno}",
                        f"link target not found: {target}"
                        + (" (site-root link; confirm the route exists)" if state == "rooted" else ""),
                    )
                elif anchor and found.suffix.lower() in {".md", ".mdx"} and anchor not in self.anchors_of(found):
                    self.rep.add(
                        "ERROR",
                        f"{rel}:{lineno}",
                        f"anchor #{anchor} not found in {found.name} "
                        "(slug rules differ per site generator; confirm in the built site)",
                    )

    # ------------------------------------------------------------------ prose lint
    def exempt(self, lines, idx, label):
        ids = []
        for j in (idx, idx - 1):
            if 0 <= j < len(lines):
                ids += LINT_OK.findall(lines[j])
        if not ids:
            return False
        if self.ledger is None:
            self.rep.add("WARN", "lint-ok", f"exemption for {label!r} cannot be verified without --ledger")
            return True
        for cid in ids:
            rec = self.ledger.get(cid)
            if not rec or rec.get("status") != "verified":
                self.rep.add("ERROR", "lint-ok", f"claim '{cid}' is missing or not verified in the ledger")
                return False
        return True

    def check_prose(self, text, rel):
        raw_lines = text.splitlines()
        base_name = Path(rel).name
        for lineno, line in prose_lines(text):
            if not line.strip():
                continue
            idx = lineno - 1
            for m in ABS_RE.finditer(line):
                if not self.exempt(raw_lines, idx, m.group(0)):
                    self.rep.add(
                        "WARN",
                        f"{rel}:{lineno}",
                        f"absolute wording '{m.group(0)}': needs a verified ledger entry "
                        "(lint-ok: claim=<id>) or a bounded rewrite ('when X, Y')",
                    )
            for m in VAGUE_RE.finditer(line):
                if not self.exempt(raw_lines, idx, m.group(0)):
                    self.rep.add("WARN", f"{rel}:{lineno}", f"'{m.group(0)}' is vague: say secure/safe against what")
            for m in HYPE_RE.finditer(line):
                self.rep.add(
                    "WARN", f"{rel}:{lineno}", f"filler/hype word '{m.group(0)}': state the concrete behavior instead"
                )
            for m in CRUTCH_RE.finditer(line):
                self.rep.add("WARN", f"{rel}:{lineno}", f"crutch word '{m.group(0)}'")
            for m in COUNT_RE.finditer(line):
                if not self.exempt(raw_lines, idx, m.group(0)):
                    self.rep.add(
                        "WARN",
                        f"{rel}:{lineno}",
                        f"hard-coded count '{m.group(0)}': generate it from code or remove it",
                    )
            if not VERSION_OK_FILES.search(base_name):
                for m in VERSION_RE.finditer(line):
                    if not self.exempt(raw_lines, idx, m.group(0)):
                        self.rep.add(
                            "WARN",
                            f"{rel}:{lineno}",
                            f"hard-coded version '{m.group(0)}': it will go stale; "
                            "use install commands without pins or generate it",
                        )
            for term_ok, variants in self.glossary.items():
                for v in variants:
                    if re.search(r"(?<![\w-])" + re.escape(v) + r"(?![\w-])", line):
                        self.rep.add("ERROR", f"{rel}:{lineno}", f"use '{term_ok}' instead of '{v}'")
        # placeholders and secrets are checked everywhere, including code
        for lineno, line in enumerate(raw_lines, 1):
            if PLACEHOLDER_CASE.search(line) or re.search(r"lorem ipsum|coming soon", line, re.I):
                self.rep.add("ERROR", f"{rel}:{lineno}", "placeholder text (TODO/TBD/coming soon...)")
            for rx, label in SECRET_RES:
                if rx.search(line):
                    self.rep.add("ERROR", f"{rel}:{lineno}", f"{label}: use an obvious placeholder")

    # ------------------------------------------------------------------ inventory references in prose
    def check_inventory_refs(self, text, rel):
        if not self.inv:
            return
        if self.project_name:
            for m in re.finditer(r"(?<![\w-])([A-Za-z0-9_.-]+)\[([A-Za-z0-9_.,\s-]+)\]", text):
                if norm(m.group(1)) == self.project_name:
                    for extra in (e.strip() for e in m.group(2).split(",")):
                        if extra and norm(extra) not in self.extras:
                            line = text[: m.start()].count("\n") + 1
                            self.rep.add(
                                "ERROR",
                                f"{rel}:{line}",
                                f"extra '{extra}' is not defined in pyproject.toml "
                                f"(defined: {', '.join(sorted(self.extras)) or 'none'})",
                            )
        for prefix in sorted(self.env_prefixes):
            for m in re.finditer(r"\b(%s[A-Z0-9_]+)\b" % re.escape(prefix), text):
                if m.group(1) not in self.env_known:
                    line = text[: m.start()].count("\n") + 1
                    self.rep.add("WARN", f"{rel}:{line}", f"env var {m.group(1)} not found in source/.env.example")

    # ------------------------------------------------------------------ whole-docs checks
    def coverage(self):
        if not self.inv:
            return
        exported = set()
        for m in self.inv["modules"]:
            if m["is_package_init"] and m["all"]:
                exported |= set(m["all"])
        missing = sorted(n for n in exported if not re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", self.all_text))
        if missing:
            self.rep.add("INFO", "coverage", f"exported names no page mentions: {', '.join(missing[:40])}")
        scripts = sorted(s for s in self.cli_names if s not in self.all_text)
        if scripts:
            self.rep.add("INFO", "coverage", f"console scripts no page mentions: {', '.join(scripts)}")
        envs = sorted(
            e["name"]
            for e in self.inv["env_vars"]
            if e["form"] in {"call", "subscript"} and e["name"] not in self.all_text
        )
        if envs:
            self.rep.add(
                "INFO", "coverage", f"env vars read in code that no page mentions: {', '.join(sorted(set(envs)))}"
            )

    def navigation(self, pages):
        routes = {p.relative_to(self.docs).with_suffix("").as_posix() for p in pages}
        routes |= {r.rsplit("/index", 1)[0] for r in routes if r.endswith("/index")}
        done = False
        for base in (self.docs, self.docs.parent):
            dj = base / "docs.json"
            if dj.is_file():
                done = True
                try:
                    data = json.loads(dj.read_text(encoding="utf-8"))
                except json.JSONDecodeError as e:
                    self.rep.add("ERROR", str(dj), f"invalid JSON: {e.msg}")
                    break
                listed: set[str] = set()

                def walk(o):
                    if isinstance(o, dict):
                        for k, v in o.items():
                            if k == "pages" and isinstance(v, list):
                                for it in v:
                                    if isinstance(it, str):
                                        listed.add(it.strip("/"))
                                    else:
                                        walk(it)
                            else:
                                walk(v)
                    elif isinstance(o, list):
                        for it in o:
                            walk(it)

                walk(data.get("navigation", data))
                prefix = "" if base == self.docs else self.docs.name + "/"
                for entry in sorted(listed):
                    e = entry[len(prefix) :] if prefix and entry.startswith(prefix) else entry
                    if e not in routes:
                        self.rep.add("ERROR", str(dj.name), f"navigation entry '{entry}' has no page")
                for r in sorted(routes - {x[len(prefix) :] if prefix and x.startswith(prefix) else x for x in listed}):
                    self.rep.add("WARN", r, "page is not listed in docs.json navigation")
                break
        for meta in sorted(self.docs.rglob("meta.json")):
            done = True
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                self.rep.add("ERROR", str(meta), f"invalid JSON: {e.msg}")
                continue
            if isinstance(data.get("pages"), list):
                d = meta.parent
                names = {x for x in data["pages"] if isinstance(x, str) and not x.startswith(("---", "...", "!", "["))}
                for n in sorted(names):
                    if (
                        not any((d / (n + s)).exists() for s in ("", ".md", ".mdx"))
                        and not (d / n / "index.mdx").exists()
                    ):
                        self.rep.add("ERROR", str(meta.relative_to(self.docs)), f"pages entry '{n}' has no file")
                present = {p.stem for p in d.glob("*.md*")} | {p.name for p in d.iterdir() if p.is_dir()}
                for n in sorted(present - names - {"index"}):
                    self.rep.add("WARN", str(meta.relative_to(self.docs)), f"'{n}' exists but is not listed in pages")
        if not done:
            self.rep.add(
                "INFO",
                "navigation",
                "no docs.json or meta.json found; navigation not checked (mkdocs/sidebars/_meta: compare by hand)",
            )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("docs_dir")
    ap.add_argument("--inventory")
    ap.add_argument("--ledger")
    ap.add_argument("--glossary")
    ap.add_argument("--require-frontmatter", default="title,description")
    ap.add_argument("--strict", action="store_true", help="treat WARN as failure")
    ap.add_argument("--quiet", action="store_true", help="hide INFO lines")
    a = ap.parse_args()
    docs = Path(a.docs_dir).resolve()
    if not docs.exists():
        sys.exit(f"not found: {docs}")
    c = Checker(docs, a)
    pages = list(iter_doc_files(docs))
    for p in pages:
        c.check_file(p)
    c.coverage()
    if docs.is_dir():
        c.navigation(pages)
    c.rep.print(show_info=not a.quiet)
    print(f"\n{len(pages)} page(s) checked. {c.rep.summary() or 'no findings'}")
    print("Static checks only: nothing was imported or executed. Run verify_snippets.py for that.")
    failed = c.rep.count("ERROR") > 0 or (a.strict and c.rep.count("WARN") > 0)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
