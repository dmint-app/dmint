"""Test that all fenced python code blocks in docs/ and README.md compile cleanly."""

from pathlib import Path
import re
import pytest


def test_docs_python_blocks_compile():
    repo_root = Path(__file__).resolve().parent.parent.parent
    docs_dir = repo_root / "docs"
    readme_file = repo_root / "README.md"

    doc_files = [
        p
        for p in docs_dir.rglob("*")
        if p.suffix in (".md", ".mdx") and "node_modules" not in p.parts and ".agents" not in p.parts
    ]
    if readme_file.exists():
        doc_files.append(readme_file)

    pattern = re.compile(r"```(?:python|py)\b[^\n]*\n(.*?)```", re.DOTALL)
    total_blocks = 0
    errors = []

    for file_path in sorted(doc_files):
        text = file_path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            total_blocks += 1
            code = match.group(1)
            line_no = text[: match.start()].count("\n") + 1
            rel_path = file_path.relative_to(repo_root)
            try:
                compile(code, f"{rel_path}:{line_no}", "exec")
            except SyntaxError as err:
                errors.append(f"{rel_path}:{line_no}: {err.msg}")

    assert total_blocks > 0, "Expected to find python code blocks in docs"
    assert not errors, f"Syntax errors in documentation python blocks:\n" + "\n".join(errors)
