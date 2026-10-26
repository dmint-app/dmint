#!/usr/bin/env python3
"""Verify docs code blocks against the REAL installed code. Imports and (optionally) executes.

Usage:
    python verify_snippets.py <docs-dir> --package NAME [--package NAME2] [--cli NAME[=COMMAND]]
                              [--pythonpath DIR] [--run] [--timeout 30] [--json report.json]

    --package     top-level package(s) the docs import; they must be importable.
    --cli         CLI executable(s) documented. NAME=COMMAND maps a name to how to launch it when it is
                  not installed, e.g.  --cli "toyguard=python -m toyguard.cli".
    --pythonpath  extra sys.path / PYTHONPATH entries (e.g. src) when the package is not pip-installed.
    --run         EXECUTE python blocks and documented CLI commands in a throwaway directory.
                  This runs code from the docs on this machine: use a clean venv / container.

What is checked without --run: python syntax; every `import` / `from x import y` / `pkg.attr`
against the real modules; every `--flag` and subcommand in documented CLI lines against the real
`--help` output.
With --run: python blocks run (a block with title="x.py" is saved and run as x.py; titled non-python
blocks are saved as files so later blocks can use them); documented CLI lines run; a `text`/`output`
block right after a run block is compared with the real output.

Result levels: PASS (static) means "names exist"; PASS (executed) means "it ran". They are reported
separately on purpose. SKIP is never a pass. Exit status 1 if anything FAILs.

Per-block directives (a comment on one of the two lines above the fence), each with a reason:
    <!-- docs-check: skip <reason> -->      {/* docs-check: no-run <reason> */}
    <!-- docs-check: expect-error <reason> -->   (the block is supposed to fail)
"""

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import extract_blocks, iter_doc_files  # noqa: E402

SHELL = {"bash", "sh", "shell", "zsh", "console", "shell-session", "terminal"}
PYTHON = {"python", "py", "python3"}
OUTPUT = {"text", "output", "plaintext", "txt"}
TITLE_RE = re.compile(r"""title\s*=\s*["']([^"']+)["']|\[([^\]\s]+\.[A-Za-z0-9]+)\]""")
NOT_INSTALLED = object()


class Result:
    def __init__(self, status, level, where, msg, output=None):
        self.status, self.level, self.where, self.msg, self.output = status, level, where, msg, output


class Verifier:
    def __init__(self, args):
        self.a = args
        self.results: list[Result] = []
        self.pkgs = set(args.package)
        self.cli: dict[str, list[str]] = {}
        for spec in args.cli:
            name, _, cmd = spec.partition("=")
            self.cli[name] = shlex.split(cmd) if cmd else [name]
        self.help_cache: dict[tuple, object] = {}
        self.warned_cli: set[str] = set()
        self.env = os.environ.copy()
        extra = [str(Path(p).resolve()) for p in args.pythonpath]
        for p in extra:
            sys.path.insert(0, p)
        if extra:
            self.env["PYTHONPATH"] = os.pathsep.join(
                extra + ([self.env["PYTHONPATH"]] if self.env.get("PYTHONPATH") else [])
            )
        self.env["COLUMNS"] = "250"
        self.env["NO_COLOR"] = "1"

    def add(self, status, level, where, msg, output=None):
        self.results.append(Result(status, level, where, msg, output))

    # ------------------------------------------------------------------ python
    def check_python_static(self, b, where):
        try:
            tree = ast.parse(b.code)
        except SyntaxError as e:
            self.add("FAIL", "static", where, f"python syntax error: {e.msg} (block line {e.lineno})")
            return False
        problems, warns = [], []
        aliases: dict[str, object] = {}
        stdlib = getattr(sys, "stdlib_module_names", set())

        def load(name):
            top = name.split(".")[0]
            if top in self.pkgs or top in stdlib:
                try:
                    return importlib.import_module(name)
                except Exception as e:  # noqa: BLE001
                    problems.append(f"cannot import '{name}': {type(e).__name__}: {e}")
                    return None
            if importlib.util.find_spec(top) is None:
                warns.append(f"third-party module '{top}' is not installed here: not verified")
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    mod = load(a.name)
                    if mod is not None:
                        aliases[a.asname or a.name.split(".")[0]] = (
                            importlib.import_module(a.name.split(".")[0]) if not a.asname else mod
                        )
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mod = load(node.module)
                if mod is not None:
                    for a in node.names:
                        if a.name != "*" and not hasattr(mod, a.name):
                            try:
                                importlib.import_module(f"{node.module}.{a.name}")
                            except Exception:  # noqa: BLE001
                                problems.append(f"'{a.name}' cannot be imported from '{node.module}'")
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
                mod = aliases[node.value.id]
                if not hasattr(mod, node.attr):
                    try:
                        importlib.import_module(f"{mod.__name__}.{node.attr}")
                    except Exception:  # noqa: BLE001
                        problems.append(f"'{node.value.id}.{node.attr}' does not exist on module '{mod.__name__}'")
        for p in problems:
            self.add("FAIL", "static", where, p)
        for w in sorted(set(warns)):
            self.add("WARN", "static", where, w)
        if not problems:
            self.add("PASS", "static", where, "syntax OK; imports and module attributes exist (not executed)")
        return not problems

    # ------------------------------------------------------------------ cli
    def help_text(self, cli, chain):
        key = (cli, tuple(chain))
        if key in self.help_cache:
            return self.help_cache[key]
        try:
            r = subprocess.run(
                [*self.cli[cli], *chain, "--help"], capture_output=True, text=True, timeout=self.a.timeout, env=self.env
            )
            out = (r.stdout + r.stderr) if r.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            out = NOT_INSTALLED
        self.help_cache[key] = out
        return out

    @staticmethod
    def has_word(text, token):
        return re.search(r"(?<![\w-])" + re.escape(token) + r"(?![\w-])", text) is not None

    def check_cli_line(self, tokens, where):
        cli = tokens[0]
        top = self.help_text(cli, [])
        if top is NOT_INSTALLED or top is None:
            if cli not in self.warned_cli:
                self.warned_cli.add(cli)
                self.add(
                    "SKIP",
                    "static",
                    where,
                    f"cannot run `{' '.join(self.cli[cli])} --help`; CLI lines for '{cli}' NOT verified",
                )
            return
        args = tokens[1:]
        chain, helps, parent, i = [], [top], top, 0
        while i < len(args) and not args[i].startswith("-") and self.has_word(parent, args[i]):
            nxt = self.help_text(cli, chain + [args[i]])
            if nxt in (None, NOT_INSTALLED):
                break
            chain.append(args[i])
            helps.append(nxt)
            parent = nxt
            i += 1
        bad = []
        if (
            i < len(args)
            and not args[i].startswith("-")
            and len(args) > i
            and chain == []
            and re.search(r"\{[\w,-]+\}|commands?:", top, re.I)
        ):
            bad.append(f"'{args[i]}' is not a subcommand of '{cli}'")
        for t in args:
            if t.startswith("-") and t not in {"-", "--"} and not re.fullmatch(r"-\d+(\.\d+)?", t):
                flag = t.split("=")[0]
                if not any(self.has_word(h, flag) for h in helps):
                    bad.append(f"flag '{flag}' not in `{cli} {' '.join(chain)} --help`".replace("  ", " "))
        if bad:
            for m in bad:
                self.add("FAIL", "static", where, m)
        else:
            self.add(
                "PASS",
                "static",
                where,
                f"`{cli} {' '.join(chain)}`: subcommands/flags exist in --help (positional args not checked)",
            )

    # ------------------------------------------------------------------ run
    def run_cmd(self, cmd, cwd, env):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=self.a.timeout, cwd=cwd, env=env)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {self.a.timeout}s"
        except FileNotFoundError as e:
            return 127, "", str(e)

    def process_page(self, path: Path, rel: str):
        blocks = extract_blocks(path)
        workdir = Path(tempfile.mkdtemp(prefix="docs-verify-"))
        env = dict(self.env)
        last_output = None  # (index, stdout) of the previous executed block
        for idx, b in enumerate(blocks):
            where = f"{rel}:{b.line}"
            if not b.closed:
                self.add("FAIL", "static", where, "unclosed code fence")
                continue
            if b.directive == "skip":
                self.add("SKIP", "static", where, f"skipped by directive: {b.directive_reason or '(no reason given)'}")
                last_output = None
                continue
            title_m = TITLE_RE.search(b.info)
            title = (title_m.group(1) or title_m.group(2)) if title_m else None
            expect_err = b.directive == "expect-error"
            norun = b.directive == "no-run"
            produced = None

            if b.lang in PYTHON:
                ok = self.check_python_static(b, where)
                if ok and self.a.run and not norun:
                    fname = title or "snippet.py"
                    target = workdir / fname
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(b.code, encoding="utf-8")
                    code, out, err = self.run_cmd([sys.executable, str(target)], workdir, env)
                    if (code != 0) != expect_err:
                        self.add(
                            "FAIL",
                            "executed",
                            where,
                            f"exit code {code}"
                            + (" (expected failure)" if expect_err else "")
                            + f": {(err or out).strip().splitlines()[-1] if (err or out).strip() else ''}",
                        )
                    else:
                        self.add(
                            "PASS",
                            "executed",
                            where,
                            "ran" + (" and failed as documented" if expect_err else f" (exit {code})"),
                            output=out,
                        )
                        produced = out
                elif ok and self.a.run and norun:
                    self.add(
                        "SKIP", "executed", where, f"no-run directive: {b.directive_reason or '(no reason given)'}"
                    )
            elif b.lang in SHELL:
                produced = self.process_shell(b, where, workdir, env, expect_err, norun)
            elif b.lang in OUTPUT and self.a.run and last_output is not None and idx > 0 and last_output[0] == idx - 1:
                self.compare_output(b, where, last_output[1])
            else:
                if title and b.lang not in OUTPUT:
                    pass  # saved below
                if b.lang == "json":
                    try:
                        json.loads(b.code)
                        self.add(
                            "PASS", "static", where, "valid JSON (shape not validated against the project's own loader)"
                        )
                    except json.JSONDecodeError as e:
                        self.add("FAIL", "static", where, f"invalid JSON: {e.msg} (block line {e.lineno})")
                elif b.lang in OUTPUT:
                    self.add(
                        "SKIP",
                        "static",
                        where,
                        "output block not compared with real output (needs --run and a run block right before it)",
                    )
                else:
                    self.add("SKIP", "static", where, f"language '{b.lang or 'none'}' is not verified by this script")
            if title and b.lang not in PYTHON and self.a.run:
                t = workdir / title
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_text(b.code, encoding="utf-8")
            last_output = (idx, produced) if produced is not None else None

    def process_shell(self, b, where, workdir, env, expect_err, norun):
        console = b.lang in {"console", "shell-session"}
        collected = []
        for off, line in enumerate(b.code.splitlines()):
            s = line.strip()
            if console:
                if not s.startswith("$ "):
                    continue
                s = s[2:]
            if not s or s.startswith("#"):
                continue
            w = f"{where}+{off + 1}"
            if s.startswith("export "):
                m = re.match(r"export\s+([A-Za-z_]\w*)=(.*)$", s)
                if m:
                    env[m.group(1)] = shlex.split(m.group(2))[0] if m.group(2) else ""
                continue
            try:
                tokens = shlex.split(s, comments=True)
            except ValueError:
                self.add("WARN", "static", w, "could not parse shell line (heredoc/continuation?): not verified")
                continue
            lead = {}
            while tokens and re.fullmatch(r"[A-Za-z_]\w*=.*", tokens[0]):
                k, _, v = tokens.pop(0).partition("=")
                lead[k] = v
            if (
                tokens
                and tokens[0] in {"python", "python3"}
                and len(tokens) > 1
                and not tokens[1].startswith("-")
                and (workdir / tokens[1]).is_file()
            ):
                if self.a.run and not norun and not any(x in s for x in ("|", "&&", "||", ";", ">", "<", "$(", "`")):
                    code, out, err = self.run_cmd([sys.executable, *tokens[1:]], workdir, {**env, **lead})
                    if (code != 0) != expect_err:
                        self.add(
                            "FAIL",
                            "executed",
                            w,
                            f"exit code {code}"
                            + f": {(err or out).strip().splitlines()[-1] if (err or out).strip() else ''}",
                        )
                    else:
                        self.add("PASS", "executed", w, f"ran {tokens[1]} (exit {code})", output=out)
                        collected.append(out)
                continue
            if not tokens or tokens[0] not in self.cli:
                continue
            if any(x in s for x in ("|", "&&", "||", ";", ">", "<", "$(", "`")):
                self.add("SKIP", "static", w, "compound shell line not verified")
                continue
            self.check_cli_line(tokens, w)
            if self.a.run and not norun:
                cmd = [*self.cli[tokens[0]], *tokens[1:]]
                code, out, err = self.run_cmd(cmd, workdir, {**env, **lead})
                if (code != 0) != expect_err:
                    self.add(
                        "FAIL",
                        "executed",
                        w,
                        f"exit code {code}"
                        + (" (expected failure)" if expect_err else "")
                        + f": {(err or out).strip().splitlines()[-1] if (err or out).strip() else ''}",
                    )
                else:
                    self.add("PASS", "executed", w, f"ran (exit {code})", output=out)
                    collected.append(out)
        return "".join(collected) if collected else None

    def compare_output(self, b, where, actual):
        norm = lambda s: [ln.rstrip() for ln in s.strip().splitlines()]  # noqa: E731
        want, got = norm(b.code), norm(actual)
        if want == got:
            self.add("PASS", "executed", where, "documented output matches the real output")
            return
        for i, (x, y) in enumerate(zip(want + [None] * len(got), got + [None] * len(want))):
            if x != y:
                self.add(
                    "FAIL",
                    "executed",
                    where,
                    f"documented output differs at output line {i + 1}: documented {x!r}, real {y!r}",
                )
                return

    # ------------------------------------------------------------------ driver
    def check_packages_importable(self):
        for p in sorted(self.pkgs):
            try:
                mod = importlib.import_module(p)
                self.add(
                    "PASS", "static", f"package {p}", f"importable (version attr: {getattr(mod, '__version__', 'n/a')})"
                )
            except Exception as e:  # noqa: BLE001
                self.add(
                    "FAIL",
                    "static",
                    f"package {p}",
                    f"cannot import: {type(e).__name__}: {e}. Install the package "
                    "(pip install -e .) or pass --pythonpath. Nothing below can be trusted until this passes.",
                )

    def run(self):
        docs = Path(self.a.docs_dir).resolve()
        self.check_packages_importable()
        for p in iter_doc_files(docs):
            self.process_page(p, p.relative_to(docs).as_posix() if docs.is_dir() else p.name)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("docs_dir")
    ap.add_argument("--package", action="append", default=[], required=True)
    ap.add_argument("--cli", action="append", default=[])
    ap.add_argument("--pythonpath", action="append", default=[])
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--json")
    ap.add_argument("--show-pass", action="store_true")
    a = ap.parse_args()
    v = Verifier(a)
    v.run()
    order = {"FAIL": 0, "WARN": 1, "SKIP": 2, "PASS": 3}
    for r in sorted(v.results, key=lambda r: order[r.status]):
        if r.status == "PASS" and not a.show_pass:
            continue
        print(f"{r.status:<4} [{r.level}] {r.where}: {r.msg}")
    c = Counter((r.status, r.level) for r in v.results)
    print("\nSummary:")
    for st in ("FAIL", "WARN", "SKIP", "PASS"):
        print(f"  {st:<4} static={c[(st, 'static')]}  executed={c[(st, 'executed')]}")
    if not a.run:
        print("\nNothing was executed (no --run). PASS(static) only means names and flags exist.")
    if any(r.status == "SKIP" for r in v.results):
        print("SKIP entries are NOT verified. List them in the final report.")
    if a.json:
        Path(a.json).write_text(json.dumps([r.__dict__ for r in v.results], indent=2), encoding="utf-8")
    sys.exit(1 if c[("FAIL", "static")] + c[("FAIL", "executed")] else 0)


if __name__ == "__main__":
    main()
