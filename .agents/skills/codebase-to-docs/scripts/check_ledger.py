#!/usr/bin/env python3
"""Validate a claim ledger: every documented fact must point at evidence that still exists.

Usage:
    python check_ledger.py --repo <repo-root> --ledger <file.jsonl | dir> [--docs-dir <docs>]
                           [--slack N] [--rerun]

Ledger format: JSON Lines, one claim per line (see references/verification.md). Optional first line:
    {"_meta": {"repo_sha": "<git sha the evidence was read at>"}}
Claim:
    {"id": "qs-03", "page": "docs/quickstart.mdx", "claim": "Unmatched calls are denied", "kind": "behavior",
     "evidence": [{"path": "src/x/policy.py", "lines": "30-33", "quote": "return Decision.DENY"}],
     "checks": ["read", "test", "run"], "status": "verified"}
Evidence kinds: file {path, lines, quote} | command {command, quote} | external {url, quote, retrieved}.

What is enforced mechanically:
  * each file evidence: the file exists inside the repo, the line range exists, and the quote is
    really in those lines (whitespace-insensitive). Stale or invented evidence fails.
  * status "verified" needs >= 2 distinct check methods; behavior/security/cli/api/config/number
    claims need at least one dynamic method (run, test or computed); security claims need >= 3
    methods including rederive; external claims need a url evidence with a retrieved date.
  * "contradicted" claims fail; "unverified" claims are listed (they must not be in the docs as fact).
  * the repo HEAD still matches _meta.repo_sha (otherwise evidence may have drifted).
What is NOT enforced: that the quote really supports the claim, and that the docs sentence says
what the claim says. Those are the blind re-derivation pass's job.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import Reporter, iter_doc_files, load_ledger  # noqa: E402

KINDS = {"api", "cli", "config", "env", "behavior", "security", "compat", "number", "link", "external", "other"}
METHODS = {"read", "test", "run", "rederive", "computed", "external"}
DYNAMIC_KINDS = {"behavior", "security", "cli", "api", "config", "number"}
DYNAMIC_METHODS = {"run", "test", "computed"}
STATUSES = {"verified", "unverified", "contradicted"}


def squash(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def git(repo: Path, *args):
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:  # noqa: BLE001
        return None


def parse_lines(spec):
    m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", str(spec))
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2) or a)
    return (a, b) if 1 <= a <= b else None


def check_evidence(rep, repo, cid, i, ev, slack, rerun, counters):
    w = f"{cid}.evidence[{i}]"
    if not isinstance(ev, dict) or not ev.get("quote", "").strip():
        rep.add("ERROR", w, "evidence needs a non-empty 'quote'")
        return
    quote = squash(ev["quote"])
    if "path" in ev:
        p = (repo / ev["path"]).resolve()
        if repo not in p.parents and p != repo:
            rep.add("ERROR", w, f"path escapes the repo: {ev['path']}")
            return
        if not p.is_file():
            rep.add("ERROR", w, f"file not found: {ev['path']}")
            return
        rng = parse_lines(ev.get("lines", ""))
        if not rng:
            rep.add("ERROR", w, f"bad 'lines' value {ev.get('lines')!r} (use 'N' or 'N-M')")
            return
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if rng[1] > len(lines):
            rep.add("ERROR", w, f"{ev['path']} has {len(lines)} lines; evidence cites {ev['lines']}")
            return
        lo, hi = max(1, rng[0] - slack), min(len(lines), rng[1] + slack)
        if quote in squash(" ".join(lines[lo - 1 : hi])):
            counters["file_ok"] += 1
        else:
            rep.add(
                "ERROR",
                w,
                f"quote not found in {ev['path']}:{ev['lines']}"
                + (f" (±{slack})" if slack else "")
                + " - evidence is stale or wrong",
            )
    elif "command" in ev:
        counters["command"] += 1
        if rerun:
            try:
                r = subprocess.run(shlex.split(ev["command"]), capture_output=True, text=True, timeout=60, cwd=repo)
                if quote not in squash(r.stdout + " " + r.stderr):
                    rep.add("ERROR", w, f"quote not found in output of `{ev['command']}`")
                else:
                    counters["cmd_ok"] += 1
            except Exception as e:  # noqa: BLE001
                rep.add("ERROR", w, f"could not run `{ev['command']}`: {e}")
        else:
            counters["cmd_skipped"] += 1
    elif "url" in ev:
        counters["external"] += 1
        if not ev.get("retrieved"):
            rep.add("ERROR", w, "external evidence needs a 'retrieved' date (YYYY-MM-DD)")
    else:
        rep.add("ERROR", w, "evidence needs one of: path+lines, command, url")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--docs-dir")
    ap.add_argument("--slack", type=int, default=0, help="allow the quote within N lines of the cited range")
    ap.add_argument("--rerun", action="store_true", help="re-run command evidence (executes commands from the ledger)")
    a = ap.parse_args()
    repo = Path(a.repo).resolve()
    rep = Reporter()
    records, meta, errors = load_ledger(a.ledger)
    for e in errors:
        rep.add("ERROR", "ledger", e)

    head = git(repo, "rev-parse", "HEAD")
    if meta.get("repo_sha") and head and meta["repo_sha"] != head:
        rep.add(
            "WARN",
            "ledger",
            f"repo HEAD {head[:10]} differs from ledger repo_sha {meta['repo_sha'][:10]}: "
            "evidence may have drifted; re-run all passes for pages whose sources changed",
        )
    if not meta.get("repo_sha"):
        rep.add("WARN", "ledger", "no _meta.repo_sha recorded: cannot tell which commit the evidence was read at")
    if head and git(repo, "status", "--porcelain"):
        rep.add("INFO", "repo", "working tree has uncommitted changes: evidence may not match any commit")

    counters = {"file_ok": 0, "command": 0, "cmd_ok": 0, "cmd_skipped": 0, "external": 0}
    status_count = {s: 0 for s in STATUSES}
    for cid, r in records.items():
        for field in ("id", "page", "claim", "kind", "evidence", "checks", "status"):
            if field not in r or r[field] in (None, "", []):
                if not (field in ("evidence", "checks") and r.get("status") == "unverified"):
                    rep.add("ERROR", str(cid), f"missing field '{field}'")
        kind, status = r.get("kind"), r.get("status")
        if kind not in KINDS:
            rep.add("ERROR", str(cid), f"kind {kind!r} not in {sorted(KINDS)}")
        if status not in STATUSES:
            rep.add("ERROR", str(cid), f"status {status!r} not in {sorted(STATUSES)}")
            continue
        status_count[status] += 1
        methods = set(r.get("checks") or [])
        for m in methods - METHODS:
            rep.add("ERROR", str(cid), f"unknown check method '{m}' (allowed: {sorted(METHODS)})")
        page = r.get("page")
        if page and not (repo / page).is_file():
            rep.add("ERROR", str(cid), f"page not found: {page}")
        for i, ev in enumerate(r.get("evidence") or []):
            check_evidence(rep, repo, cid, i, ev, a.slack, a.rerun, counters)
        if status == "contradicted":
            rep.add(
                "ERROR", str(cid), f"claim is contradicted by the code: fix or remove it from {page} - {r.get('claim')}"
            )
        elif status == "unverified":
            rep.add("WARN", str(cid), f"unverified: must not appear in the docs as fact ({page}): {r.get('claim')}")
        elif status == "verified":
            if not r.get("evidence"):
                rep.add("ERROR", str(cid), "verified claim has no evidence")
            if len(methods) < 2:
                rep.add("ERROR", str(cid), f"verified needs >= 2 distinct check methods, has {sorted(methods)}")
            if kind in DYNAMIC_KINDS and not (methods & DYNAMIC_METHODS):
                rep.add(
                    "ERROR", str(cid), f"{kind} claims need a dynamic check (run/test/computed), has {sorted(methods)}"
                )
            if kind == "security" and (len(methods) < 3 or "rederive" not in methods):
                rep.add("ERROR", str(cid), "security claims need >= 3 methods including 'rederive'")
            if kind == "external" and not any("url" in e for e in (r.get("evidence") or []) if isinstance(e, dict)):
                rep.add("ERROR", str(cid), "external claims need url evidence")

    if a.docs_dir:
        docs = Path(a.docs_dir).resolve()
        covered = {(repo / r["page"]).resolve() for r in records.values() if r.get("page")}
        for p in iter_doc_files(docs):
            if p.resolve() not in covered:
                rep.add("WARN", str(p.relative_to(repo) if repo in p.parents else p), "page has no ledger entries")

    rep.print(show_info=True)
    print(
        f"\n{len(records)} claim(s): "
        + ", ".join(f"{k}={v}" for k, v in status_count.items())
        + f"; file evidence re-checked OK={counters['file_ok']}; command evidence={counters['command']} "
        f"(re-run OK={counters['cmd_ok']}, not re-run={counters['cmd_skipped']}); external (manual)={counters['external']}"
    )
    if counters["cmd_skipped"]:
        print("Command evidence was not re-run (use --rerun in a safe environment).")
    if counters["external"]:
        print("External evidence cannot be checked offline: re-fetch those URLs before release.")
    print(rep.summary() or "no findings")
    sys.exit(1 if rep.count("ERROR") else 0)


if __name__ == "__main__":
    main()
