#!/usr/bin/env python3
"""Static, fail-closed quality and attack-surface audit for the Python artifact."""
from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {"__pycache__", ".git", ".hg", ".svn"}
PRODUCTION_ROOTS = {ROOT / "src", ROOT / "checker"}


def dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def line_count(text: str) -> int:
    return sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in text.splitlines())


def main() -> None:
    files = [
        path
        for path in ROOT.rglob("*.py")
        if not any(part in EXCLUDED_PARTS for part in path.parts)
    ]
    dangerous: list[dict[str, Any]] = []
    production_asserts: list[dict[str, Any]] = []
    bare_excepts: list[dict[str, Any]] = []
    todo_markers: list[dict[str, Any]] = []
    stats = {"files": 0, "logical_lines": 0, "functions": 0, "classes": 0, "tests": 0}
    forbidden_calls = {
        "eval",
        "exec",
        "os.system",
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
        "yaml.load",
    }

    for path in sorted(files):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        try:
            tree = ast.parse(text, filename=relative)
        except SyntaxError as error:
            dangerous.append({"file": relative, "line": error.lineno, "kind": "syntax-error", "detail": str(error)})
            continue
        stats["files"] += 1
        stats["logical_lines"] += line_count(text)
        stats["functions"] += sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))
        stats["classes"] += sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
        if relative.startswith("tests/"):
            stats["tests"] += sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
                for node in ast.walk(tree)
            )
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT and re.search(
                r"\b(?:TODO|FIXME|XXX)\b", token.string, flags=re.I
            ):
                todo_markers.append({"file": relative, "line": token.start[0]})
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and any(path.is_relative_to(root) for root in PRODUCTION_ROOTS):
                production_asserts.append({"file": relative, "line": node.lineno})
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                bare_excepts.append({"file": relative, "line": node.lineno})
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            if name in forbidden_calls:
                dangerous.append({"file": relative, "line": node.lineno, "kind": "forbidden-call", "detail": name})
            if name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}:
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        dangerous.append({"file": relative, "line": node.lineno, "kind": "shell-true", "detail": name})

    status = "PASS" if not dangerous and not production_asserts and not bare_excepts and not todo_markers else "FAIL"
    report = {
        "status": status,
        "statistics": stats,
        "dangerous_calls": dangerous,
        "production_asserts": production_asserts,
        "bare_excepts": bare_excepts,
        "todo_markers": todo_markers,
        "scope": "All distributed Python files; asserts are prohibited in src/ and checker/ because -O removes them.",
    }
    audit = ROOT / "audit"
    audit.mkdir(exist_ok=True)
    (audit / "code-quality-audit.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
