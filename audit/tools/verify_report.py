#!/usr/bin/env python3
import json
import os
import pathlib
import re
import sys

repo = pathlib.Path(os.environ.get("AUDIT_REPO", ".")).resolve()
if "AUDIT_RUN" in os.environ:
    run = pathlib.Path(os.environ["AUDIT_RUN"]).resolve()
else:
    run = repo / "audit" / "reports"

report_file = (
    (run / "AUDIT_REPORT.md") if (run / "AUDIT_REPORT.md").exists() else (repo / "audit/reports/AUDIT_REPORT.md")
)
report = report_file.read_text(encoding="utf-8")

evidence_file = run / "evidence.jsonl"
if evidence_file.exists():
    evidence = {json.loads(line)["id"] for line in evidence_file.read_text().splitlines() if line.strip()}
else:
    evidence = set()

problems = []
for n, line in enumerate(report.splitlines(), 1):
    for m in re.finditer(r"\b((?:src|tests|docs)/[\w./-]+\.(?:py|mdx|md|json|toml|html))(?::(\d+))?", line):
        p = repo / m.group(1).rstrip(".")
        if not p.exists():
            problems.append(f"{n}: missing path {m.group(1)}")
            continue
        if m.group(2):
            total = len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
            if int(m.group(2)) > total:
                problems.append(f"{n}: {m.group(1)}:{m.group(2)} beyond EOF ({total} lines)")
    for e in re.findall(r"\bE-\d+\b", line):
        if evidence and e not in evidence:
            problems.append(f"{n}: unknown evidence id {e}")
    if (
        line.lstrip().startswith("|")
        and re.search(r"\b(REAL|BLOCKED|SUCCEEDED|FIXED|KILLED|SURVIVED|PARTIAL|BROKEN)\b", line)
        and not re.search(r"\bE-\d+\b", line)
        and "Verdict" not in line
        and "---" not in line
    ):
        problems.append(f"{n}: verdict row without evidence id: {line[:90]}")

print("\n".join(problems) or "OK: no problems")
sys.exit(1 if problems else 0)
