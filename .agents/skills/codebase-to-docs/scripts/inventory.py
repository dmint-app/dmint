#!/usr/bin/env python3
"""Extract a factual inventory of a repository straight from its files.

Usage:
    python inventory.py <repo-root> --out <dir> [--package NAME ...] [--env-prefix PREFIX_ ...]

Writes <dir>/inventory.json (machine-readable, used by check_docs.py) and
<dir>/inventory.md (human-readable map).

What this is: a *map of where to look*. Everything is read from files (AST, TOML, JSON);
nothing comes from memory or existing docs. What it is not: proof. Docs sentences still
need evidence per references/verification.md.

Depth: Python is analysed in detail (AST). Node is manifest-level only (package.json).
Other languages: only docs/CI/manifest detection; read the source yourself.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
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
from _common import is_skipped, iter_doc_files  # noqa: E402

NON_PACKAGE_DIRS = {"tests", "test", "docs", "doc", "scripts", "examples", "benchmarks", "build", "dist"}
ENUM_BASES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}
ENV_CALLS = {"os.environ.get", "os.getenv", "environ.get", "getenv"}
DOC_CONFIGS = [
    "mkdocs.yml", "mkdocs.yaml", "docusaurus.config.js", "docusaurus.config.ts", "sidebars.js",
    "sidebars.ts", "astro.config.mjs", "astro.config.ts", "docs.json", "mint.json", "conf.py",
    "book.toml", "source.config.ts", "meta.json", "_meta.js", "_meta.json",
    "vitepress.config.ts", "vitepress.config.js", "next.config.js", "next.config.mjs",
]


def clip(s, n=200):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def rel(p: Path, root: Path) -> str:
    return p.relative_to(root).as_posix()


def git_info(root: Path):
    def run(*args):
        try:
            r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=15)
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None
    sha = run("rev-parse", "HEAD")
    if not sha:
        return None
    return {"sha": sha, "describe": run("describe", "--tags", "--always"), "dirty": bool(run("status", "--porcelain"))}


# --------------------------------------------------------------------------- python analysis

def doc1(node):
    d = ast.get_docstring(node)
    return d.strip().splitlines()[0] if d and d.strip() else None


def signature(node):
    kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    return f"{kind} {node.name}({ast.unparse(node.args)}){ret}"


def func_info(node):
    return {
        "name": node.name, "line": node.lineno, "signature": clip(signature(node), 400),
        "decorators": [clip(ast.unparse(d), 120) for d in node.decorator_list], "doc": doc1(node),
    }


def class_info(node):
    bases = [ast.unparse(b) for b in node.bases]
    info = {
        "name": node.name, "line": node.lineno, "bases": bases, "doc": doc1(node),
        "decorators": [clip(ast.unparse(d), 120) for d in node.decorator_list],
        "is_enum": any(b.split(".")[-1] in ENUM_BASES for b in bases),
        "attributes": [], "methods": [],
    }
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            info["attributes"].append({
                "name": item.target.id, "annotation": clip(ast.unparse(item.annotation)),
                "default": clip(ast.unparse(item.value)) if item.value else None, "line": item.lineno})
        elif isinstance(item, ast.Assign):
            for t in item.targets:
                if isinstance(t, ast.Name):
                    info["attributes"].append({"name": t.id, "annotation": None,
                                               "default": clip(ast.unparse(item.value)), "line": item.lineno})
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not item.name.startswith("_") or item.name == "__init__":
                info["methods"].append(func_info(item))
    return info


def is_str(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            v = k.value
            return v.value if isinstance(v, ast.Constant) else clip(ast.unparse(v))
    return None


class Collector(ast.NodeVisitor):
    """Collects raise sites, env-var reads and CLI definitions across one module."""

    def __init__(self, env_regex):
        self.stack: list[str] = []
        self.raises, self.env, self.cli = [], [], []
        self.env_regex = env_regex

    def scope(self):
        return ".".join(self.stack) or "<module>"

    def _enter(self, node):
        self.stack.append(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                name = ast.unparse(target)
                last = name.split(".")[-1]
                if "." in name and last in {"command", "group"}:
                    first = dec.args[0].value if isinstance(dec, ast.Call) and dec.args and is_str(dec.args[0]) else None
                    self.cli.append({"framework": "click/typer", "kind": last, "function": node.name,
                                     "name": first or (kw(dec, "name") if isinstance(dec, ast.Call) else None),
                                     "help": kw(dec, "help") if isinstance(dec, ast.Call) else None,
                                     "line": node.lineno})
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _enter

    def visit_Raise(self, node):
        exc = node.exc
        if exc is None:
            name, msg = "(re-raise)", None
        elif isinstance(exc, ast.Call):
            name = ast.unparse(exc.func)
            msg = clip(ast.unparse(exc.args[0]), 300) if exc.args else None
        else:
            name, msg = ast.unparse(exc), None
        self.raises.append({"exception": name, "message": msg, "line": node.lineno, "in": self.scope()})
        self.generic_visit(node)

    def visit_Call(self, node):
        fname = ast.unparse(node.func)
        last = fname.split(".")[-1]
        if fname in ENV_CALLS and node.args and is_str(node.args[0]):
            default = clip(ast.unparse(node.args[1])) if len(node.args) > 1 else kw(node, "default")
            self.env.append({"name": node.args[0].value, "default": default, "form": "call",
                             "line": node.lineno, "in": self.scope()})
        elif last == "add_parser" and node.args and is_str(node.args[0]):
            self.cli.append({"framework": "argparse", "kind": "subcommand", "name": node.args[0].value,
                             "help": kw(node, "help"), "line": node.lineno})
        elif last == "add_argument":
            self.cli.append({"framework": "argparse", "kind": "argument",
                             "names": [a.value for a in node.args if is_str(a)], "help": kw(node, "help"),
                             "default": kw(node, "default"), "required": kw(node, "required"),
                             "action": kw(node, "action"), "choices": kw(node, "choices"), "line": node.lineno})
        elif last == "ArgumentParser":
            self.cli.append({"framework": "argparse", "kind": "parser", "prog": kw(node, "prog"),
                             "description": kw(node, "description"), "line": node.lineno})
        elif last in {"option", "argument", "Option", "Argument"} and (
                fname.split(".")[0] in {"click", "typer"} or fname in {"option", "argument"}):
            self.cli.append({"framework": "click/typer", "kind": last.lower(),
                             "names": [a.value for a in node.args if is_str(a)], "help": kw(node, "help"),
                             "default": kw(node, "default"), "line": node.lineno})
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if ast.unparse(node.value) in {"os.environ", "environ"} and is_str(node.slice):
            self.env.append({"name": node.slice.value, "default": None, "form": "subscript",
                             "line": node.lineno, "in": self.scope()})
        self.generic_visit(node)

    def visit_Constant(self, node):
        if self.env_regex and isinstance(node.value, str) and self.env_regex.fullmatch(node.value):
            self.env.append({"name": node.value, "default": None, "form": "literal",
                             "line": node.lineno, "in": self.scope()})


def str_list(value):
    if isinstance(value, (ast.List, ast.Tuple)) and all(is_str(e) for e in value.elts):
        return [e.value for e in value.elts], False
    return None, True


def analyze_module(path: Path, root: Path, base: Path, env_regex):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    parts = list(path.relative_to(base).with_suffix("").parts)
    is_init = parts[-1] == "__init__"
    if is_init:
        parts = parts[:-1]
    mod = {"module": ".".join(parts), "file": rel(path, root), "is_package_init": is_init, "doc": doc1(tree),
           "all": None, "all_dynamic": False, "constants": {}, "reexports": [], "classes": [],
           "functions": [], "exception_classes": []}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "__all__":
                    mod["all"], mod["all_dynamic"] = str_list(node.value)
                elif isinstance(t, ast.Name) and t.id == "__version__":
                    mod["constants"]["__version__"] = clip(ast.unparse(node.value))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == "__all__":
            mod["all_dynamic"] = True
        elif isinstance(node, ast.ImportFrom) and is_init:
            mod["reexports"].append({"from": "." * node.level + (node.module or ""), "line": node.lineno,
                                     "names": [{"name": a.name, "as": a.asname} for a in node.names]})
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            ci = class_info(node)
            mod["classes"].append(ci)
            if any(re.search(r"(Error|Exception|Warning)$", b.split(".")[-1]) for b in ci["bases"]):
                mod["exception_classes"].append({"name": node.name, "bases": ci["bases"], "line": node.lineno,
                                                 "doc": ci["doc"]})
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            mod["functions"].append(func_info(node))
    col = Collector(env_regex)
    col.visit(tree)
    return mod, col


def discover_packages(root: Path, names):
    found = []
    for base in (root / "src", root):
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if (d.is_dir() and (d / "__init__.py").exists() and d.name not in NON_PACKAGE_DIRS
                    and not d.name.startswith(".") and (not names or d.name in names)):
                if all(d != f[1] for f in found):
                    found.append((base, d))
    return found


def read_pyproject(root: Path):
    p = root / "pyproject.toml"
    if not p.exists() or tomllib is None:
        return None
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    proj = data.get("project", {})
    return {"file": "pyproject.toml", "name": proj.get("name"), "version": proj.get("version"),
            "dynamic": proj.get("dynamic"), "requires_python": proj.get("requires-python"),
            "dependencies": proj.get("dependencies", []),
            "optional_dependencies": proj.get("optional-dependencies", {}),
            "scripts": proj.get("scripts", {}), "license": proj.get("license"),
            "build_backend": data.get("build-system", {}).get("build-backend")}


def index_tests(root: Path, errors):
    out = {}
    for d in ("tests", "test"):
        base = root / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if is_skipped(p.relative_to(root).parts) or not (p.name.startswith("test_") or p.name.endswith("_test.py")):
                continue
            try:
                tree = ast.parse(p.read_text(encoding="utf-8"))
            except Exception as e:
                errors.append(f"{rel(p, root)}: {e}")
                continue
            names = []
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                    names.append(f"{node.name}:{node.lineno}")
                elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                    names += [f"{node.name}.{i.name}:{i.lineno}" for i in node.body
                              if isinstance(i, (ast.FunctionDef, ast.AsyncFunctionDef)) and i.name.startswith("test")]
            out[rel(p, root)] = names[:300]
    return out


# --------------------------------------------------------------------------- other facts

def node_manifest(root: Path):
    p = root / "package.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        return {"file": "package.json", "error": str(e)}
    keep = {k: d.get(k) for k in ("name", "version", "bin", "main", "module", "types", "exports", "engines", "type", "license")}
    keep.update({"file": "package.json", "scripts": d.get("scripts", {}),
                 "dependencies": sorted(d.get("dependencies", {})), "devDependencies": sorted(d.get("devDependencies", {}))})
    return keep


def docs_info(root: Path):
    configs, pkgs = [], []
    bases = [root] + [root / n for n in ("docs", "doc", "website", "documentation") if (root / n).is_dir()]
    for b in bases:
        for name in DOC_CONFIGS:
            if (b / name).exists():
                configs.append(rel(b / name, root))
        if b != root and (b / "package.json").exists():
            try:
                d = json.loads((b / "package.json").read_text(encoding="utf-8"))
                pkgs.append({"file": rel(b / "package.json", root), "scripts": d.get("scripts", {}),
                             "dependencies": sorted(d.get("dependencies", {})),
                             "devDependencies": sorted(d.get("devDependencies", {}))})
            except Exception:
                pass
    for meta in sorted(root.glob("**/content/docs/**/meta.json")):
        if not is_skipped(meta.relative_to(root).parts):
            configs.append(rel(meta, root))
    guess = "plain markdown"
    names = " ".join(c.split("/")[-1] for c in configs) + " " + json.dumps(pkgs)
    for needle, label in [("docs.json", "docs.json-based (Mintlify or compatible)"), ("mint.json", "Mintlify"),
                          ("source.config.ts", "Fumadocs"), ("fumadocs", "Fumadocs"), ("docusaurus", "Docusaurus"),
                          ("mkdocs", "MkDocs"), ("vitepress", "VitePress"), ("nextra", "Nextra"),
                          ("starlight", "Starlight"), ("holocron", "Holocron (check its docs)")]:
        if needle in names:
            guess = label
            break
    files = []
    docs_dir = next((root / n for n in ("docs", "doc", "documentation") if (root / n).is_dir()), None)
    if docs_dir:
        files = [rel(p, root) for p in iter_doc_files(docs_dir)][:500]
    return {"docs_framework_guess": guess, "config_files": configs, "package_jsons": pkgs,
            "docs_dir": rel(docs_dir, root) if docs_dir else None, "doc_files": files,
            "root_markdown": sorted(p.name for p in root.glob("*.md"))}


def ci_info(root: Path):
    out = []
    wf = root / ".github" / "workflows"
    if wf.is_dir():
        for p in sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))):
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"python-version|node-version|matrix:", line):
                    out.append({"file": rel(p, root), "line": n, "text": line.strip()})
    return out[:60]


def env_example(root: Path):
    out = []
    for name in (".env.example", ".env.sample", ".env.template"):
        p = root / name
        if p.exists():
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                m = re.match(r"^\s*(#\s*)?([A-Z][A-Z0-9_]+)\s*=", line)
                if m:
                    out.append({"name": m.group(2), "file": name, "line": n, "commented_out": bool(m.group(1))})
    return out


# --------------------------------------------------------------------------- markdown rendering

def render_md(inv) -> str:
    L = ["# Inventory", "", f"Root: `{inv['root']}`", ""]
    if inv["git"]:
        L += [f"Commit: `{inv['git']['sha']}` ({inv['git']['describe']}){' - WORKING TREE DIRTY' if inv['git']['dirty'] else ''}", ""]
    pp = inv["project"]
    if pp:
        L += ["## Project metadata (pyproject.toml)", "", f"- name: `{pp['name']}`", f"- version: `{pp['version']}`"
              + (f" (dynamic: {pp['dynamic']})" if pp.get("dynamic") else ""),
              f"- requires-python: `{pp['requires_python']}`", f"- build backend: `{pp['build_backend']}`", ""]
        if pp["optional_dependencies"]:
            L += ["### Extras", ""] + [f"- `{k}`: {', '.join(v)}" for k, v in pp["optional_dependencies"].items()] + [""]
        if pp["scripts"]:
            L += ["### Console scripts", ""] + [f"- `{k}` -> `{v}`" for k, v in pp["scripts"].items()] + [""]
    if inv["node"]:
        L += ["## Node manifest (package.json)", "", "```json", json.dumps(inv["node"], indent=2)[:3000], "```", ""]
    L += ["## Python modules", ""]
    for m in inv["modules"]:
        L.append(f"### `{m['module']}`  ({m['file']})")
        if m["doc"]:
            L.append(f"_{m['doc']}_")
        if m["all"] is not None:
            L.append(f"- `__all__`: {', '.join(m['all'])}")
        elif m["all_dynamic"]:
            L.append("- `__all__` is built dynamically: read the file")
        for r in m["reexports"]:
            L.append(f"- re-exports from `{r['from']}` (line {r['line']}): " + ", ".join(n["as"] or n["name"] for n in r["names"]))
        for c in m["classes"]:
            L.append(f"- class `{c['name']}({', '.join(c['bases'])})` :{c['line']}"
                     + (f" - {c['doc']}" if c["doc"] else "")
                     + (" [enum: " + ", ".join(a["name"] for a in c["attributes"]) + "]" if c["is_enum"] else ""))
            for me in c["methods"]:
                L.append(f"  - `{me['signature']}` :{me['line']}")
        for f in m["functions"]:
            L.append(f"- `{f['signature']}` :{f['line']}")
        L.append("")
    if inv["env_vars"]:
        L += ["## Environment variables", "", "| name | default | form | file:line |", "| --- | --- | --- | --- |"]
        L += [f"| `{e['name']}` | {e.get('default')} | {e['form']} | {e['file']}:{e['line']} |" for e in inv["env_vars"]] + [""]
    if inv["cli"]:
        L += ["## CLI definitions (static hints; confirm with `<cli> --help`)", ""]
        for c in inv["cli"]:
            L.append(f"- {c['framework']} {c['kind']} {c.get('name') or c.get('names') or c.get('prog') or ''} "
                     f"({c['file']}:{c['line']})" + (f" - {c['help']}" if c.get("help") else ""))
        L.append("")
    if inv["raises"]:
        L += ["## Raise sites", "", "| exception | message | in | file:line |", "| --- | --- | --- | --- |"]
        L += [f"| `{r['exception']}` | {(r['message'] or '').replace('|', chr(92) + '|')} | {r['in']} | {r['file']}:{r['line']} |"
              for r in inv["raises"] if r["exception"] != "(re-raise)"] + [""]
    d = inv["docs"]
    L += ["## Docs tooling", "", f"- framework guess: **{d['docs_framework_guess']}**",
          f"- config files: {', '.join(d['config_files']) or 'none'}", f"- docs dir: {d['docs_dir']}",
          f"- doc pages found: {len(d['doc_files'])}", f"- root markdown: {', '.join(d['root_markdown'])}", ""]
    if inv["ci"]:
        L += ["## CI matrix lines", ""] + [f"- {c['file']}:{c['line']}: `{c['text']}`" for c in inv["ci"]] + [""]
    L += ["## Tests (names only; usage examples live here)", ""]
    L += [f"- `{f}`: {len(n)} tests" for f, n in inv["tests"].items()] + [""]
    if inv["parse_errors"]:
        L += ["## Parse errors (files not analysed)", ""] + [f"- {e}" for e in inv["parse_errors"]] + [""]
    L += ["---", "This is a map, not proof. See references/verification.md for how a fact becomes a documented claim."]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--out", required=True)
    ap.add_argument("--package", action="append", default=[], help="restrict to these top-level package names")
    ap.add_argument("--env-prefix", action="append", default=[],
                    help="also report string literals that look like env vars with this prefix (e.g. MYAPP_)")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    env_regex = re.compile("(?:%s)[A-Z0-9_]+" % "|".join(map(re.escape, a.env_prefix))) if a.env_prefix else None

    modules, raises, env_vars, cli = [], [], [], []
    for base, pkg in discover_packages(root, a.package):
        for p in sorted(pkg.rglob("*.py")):
            if is_skipped(p.relative_to(root).parts):
                continue
            try:
                mod, col = analyze_module(p, root, base, env_regex)
            except Exception as e:
                errors.append(f"{rel(p, root)}: {type(e).__name__}: {e}")
                continue
            modules.append(mod)
            f = rel(p, root)
            raises += [{**r, "file": f} for r in col.raises]
            env_vars += [{**e, "file": f} for e in col.env]
            cli += [{**c, "file": f} for c in col.cli]
    for e in env_example(root):
        env_vars.append({"name": e["name"], "default": None, "form": "env_example", "file": e["file"], "line": e["line"],
                         "in": "commented out" if e["commented_out"] else ""})
    seen, uniq = set(), []
    for e in env_vars:
        k = (e["name"], e["form"], e["file"], e["line"])
        if k not in seen:
            seen.add(k)
            uniq.append(e)

    inv = {"generated_by": "codebase-to-docs/scripts/inventory.py", "root": str(root), "git": git_info(root),
           "project": read_pyproject(root), "node": node_manifest(root), "modules": modules, "env_vars": uniq,
           "cli": cli, "raises": raises, "tests": index_tests(root, errors), "docs": docs_info(root),
           "ci": ci_info(root), "parse_errors": errors,
           "limits": ["Namespace packages (no __init__.py) are not discovered",
                      "CLI definitions are static AST hints; the --help output is the authority",
                      "Env vars read via helper functions or settings classes are not detected"]}
    (out / "inventory.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
    (out / "inventory.md").write_text(render_md(inv), encoding="utf-8")
    print(f"modules={len(modules)} env_vars={len({e['name'] for e in uniq})} cli_defs={len(cli)} "
          f"raise_sites={len(raises)} test_files={len(inv['tests'])} parse_errors={len(errors)} -> {out}/inventory.{{json,md}}")


if __name__ == "__main__":
    main()
