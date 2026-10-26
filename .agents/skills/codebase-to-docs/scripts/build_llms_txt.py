#!/usr/bin/env python3
"""Build llms.txt (index) and llms-full.txt (all pages concatenated) from a docs folder.

Usage:
    python build_llms_txt.py <docs-dir> --base-url https://docs.example.com --out <dir>
                             [--title "Project"] [--summary "One sentence."] [--url-suffix .md]

URLs are base-url + the page's path without extension ("index" pages map to their folder).
That matches most docs sites; if yours differs, use --url-suffix or fix the links by hand.
Page order follows docs.json navigation when present, otherwise index first, then alphabetical.
Only text already in the pages is used: nothing is generated or summarised.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import headings, iter_doc_files, split_frontmatter  # noqa: E402


def fm_value(fm, key):
    m = re.search(rf"^{key}\s*:\s*(.+)$", fm or "", re.M)
    return m.group(1).strip().strip("\"'") if m else None


def nav_order(docs: Path):
    for base in (docs, docs.parent):
        f = base / "docs.json"
        if f.is_file():
            order = []

            def walk(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if k == "pages" and isinstance(v, list):
                            for it in v:
                                order.append(it.strip("/")) if isinstance(it, str) else walk(it)
                        else:
                            walk(v)
                elif isinstance(o, list):
                    for it in o:
                        walk(it)

            try:
                walk(json.loads(f.read_text(encoding="utf-8")).get("navigation", {}))
            except json.JSONDecodeError:
                return []
            return order
    return []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("docs_dir")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--title")
    ap.add_argument("--summary", default="")
    ap.add_argument("--url-suffix", default="")
    a = ap.parse_args()
    docs = Path(a.docs_dir).resolve()
    pages = []
    for p in iter_doc_files(docs):
        text = p.read_text(encoding="utf-8")
        fm, body, _ = split_frontmatter(text)
        route = p.relative_to(docs).with_suffix("").as_posix()
        if route == "index":
            route = ""
        elif route.endswith("/index"):
            route = route[: -len("/index")]
        h1 = next((raw for _, lvl, raw in headings(body) if lvl == 1), None)
        pages.append(
            {
                "route": route,
                "key": p.relative_to(docs).with_suffix("").as_posix(),
                "title": fm_value(fm, "title") or h1 or p.stem,
                "desc": fm_value(fm, "description") or "",
                "body": body.strip(),
            }
        )
    order = nav_order(docs)
    rank = {k: i for i, k in enumerate(order)}
    pages.sort(key=lambda x: (rank.get(x["key"], len(rank) + 1), x["key"] != "index", x["key"]))
    base = a.base_url.rstrip("/")
    url = lambda p: f"{base}/{p['route']}{a.url_suffix}".rstrip("/") if p["route"] else base  # noqa: E731
    title = a.title or "Documentation"
    idx = [f"# {title}", ""] + ([f"> {a.summary}", ""] if a.summary else []) + ["## Docs", ""]
    idx += [f"- [{p['title']}]({url(p)})" + (f": {p['desc']}" if p["desc"] else "") for p in pages]
    full = [f"# {title}", ""] + ([f"> {a.summary}", ""] if a.summary else [])
    for p in pages:
        full += ["---", "", f"# {p['title']}", f"Source: {url(p)}", "", p["body"], ""]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "llms.txt").write_text("\n".join(idx) + "\n", encoding="utf-8")
    (out / "llms-full.txt").write_text("\n".join(full) + "\n", encoding="utf-8")
    print(f"{len(pages)} page(s) -> {out}/llms.txt, {out}/llms-full.txt")


if __name__ == "__main__":
    main()
