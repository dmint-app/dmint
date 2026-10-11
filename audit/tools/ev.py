#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import time

repo = pathlib.Path(os.environ.get("AUDIT_REPO", ".")).resolve()
if "AUDIT_RUN" in os.environ:
    run = pathlib.Path(os.environ["AUDIT_RUN"]).resolve()
else:
    run = repo / "audit" / "results"
run.mkdir(parents=True, exist_ok=True)

eid, label = sys.argv[1], sys.argv[2]
cmd = sys.argv[sys.argv.index("--") + 1 :]
timeout = int(os.environ.get("EV_TIMEOUT", "120"))


def txt(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


start = time.time()
try:
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    rc, out, err, timed_out = p.returncode, txt(p.stdout), txt(p.stderr), False
except subprocess.TimeoutExpired as e:
    rc, out, err, timed_out = -9, txt(e.stdout), txt(e.stderr), True

(run / "logs").mkdir(exist_ok=True)
(run / "logs" / f"{eid}.log").write_text(
    f"$ {' '.join(cmd)}\nrc={rc} timeout={timed_out}\n--- stdout ---\n{out}\n--- stderr ---\n{err}\n"
)
rec = {
    "id": eid,
    "label": label,
    "cmd": cmd,
    "rc": rc,
    "timeout": timed_out,
    "seconds": round(time.time() - start, 2),
}
with open(run / "evidence.jsonl", "a", encoding="utf-8") as f:
    f.write(json.dumps(rec) + "\n")
print(f"[{eid}] {label} rc={rc} timeout={timed_out} {rec['seconds']}s")
print("\n".join((out + err).splitlines()[:10]))
