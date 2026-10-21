#!/usr/bin/env python3
import csv
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

repo = pathlib.Path(os.environ.get("AUDIT_REPO", ".")).resolve()
if "AUDIT_RUN" in os.environ:
    run = pathlib.Path(os.environ["AUDIT_RUN"]).resolve()
else:
    run = repo / "audit" / "results"
run.mkdir(parents=True, exist_ok=True)

mutations_path = (
    pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else (pathlib.Path(__file__).with_name("mutations.json"))
)
muts = json.loads(mutations_path.read_text(encoding="utf-8"))

ignore = shutil.ignore_patterns(
    ".git",
    "audit",
    "audit_*",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "*.egg-info",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
)
rows = []
for m in muts:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="mut_"))
    try:
        dst = tmp / "r"
        shutil.copytree(repo, dst, ignore=ignore, symlinks=True)
        f = dst / m["file"]
        src = f.read_text(encoding="utf-8")
        if src.count(m["find"]) != 1:
            rows.append([m["id"], m["file"], "NOT_APPLIED", f"find string occurs {src.count(m['find'])}x", ""])
            continue
        f.write_text(src.replace(m["find"], m["replace"]), encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(dst / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
        try:
            p = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-x",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "-o",
                    "cache_dir=/tmp/.pytest_cache",
                    *m["tests"],
                ],
                cwd=dst,
                env=env,
                capture_output=True,
                text=True,
                timeout=int(os.environ.get("MUT_TIMEOUT", "300")),
            )
            status = "KILLED" if p.returncode == 1 else "SURVIVED" if p.returncode == 0 else "ERROR"
            tail = (p.stdout + p.stderr).strip().splitlines()[-1:]
        except subprocess.TimeoutExpired:
            status, tail = "KILLED_TIMEOUT", ["timeout"]
        rows.append([m["id"], m["file"], status, m["find"][:60] + " -> " + m["replace"][:60], tail[0] if tail else ""])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(rows[-1][:3], flush=True)

try:
    with open(run / "mutants.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "file", "status", "mutation", "last_line"])
        w.writerows(rows)
except OSError as exc:
    print(f"Warning: could not write mutants.csv to {run}: {exc}", file=sys.stderr)

survived = [r for r in rows if r[2] not in ("KILLED", "KILLED_TIMEOUT")]
if survived:
    print(f"\n[!] Mutation testing failed: {len(survived)} mutants survived or errored:", file=sys.stderr)
    for s in survived:
        print(f"  {s[0]} ({s[1]}): {s[2]}", file=sys.stderr)
    sys.exit(1)
print(f"\n✓ All {len(rows)} mutants killed successfully.")
