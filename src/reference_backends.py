"""Two small, executable-syntax reference lowerings for event traces.

These are deliberately independent of the certificate checker.  They turn the
bounded event language into concrete Python source without executing that
source.  A separate extractor in ``checker/source_extract.py`` recovers the
trace from syntax alone.
"""
from __future__ import annotations

import ast
import json
import re
from typing import Any, Iterable

Record = dict[str, Any]
_EVIDENCE_KEYS = {"origin", "obligations", "occurrence"}
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _evidence(event: Record) -> Record:
    result: Record = {
        "origin": event["origin"],
        "obligations": list(event.get("obligations", [])),
    }
    if "occurrence" in event:
        result["occurrence"] = list(event["occurrence"])
    return result


def _payload(event: Record) -> Record:
    return {
        key: value
        for key, value in sorted(event.items())
        if key not in _EVIDENCE_KEYS and key != "op"
    }


def _comment(event: Record) -> str:
    return "# cg-evidence " + json.dumps(
        _evidence(event), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _call_name(event: Record) -> str:
    op = event.get("op")
    if not isinstance(op, str) or not _NAME.fullmatch(op):
        raise ValueError(f"event operation is not a safe identifier: {op!r}")
    return f"cg_{op}"


def lower_template(events: Iterable[Record]) -> str:
    """Lower by deterministic string templating."""
    lines: list[str] = []
    for event in events:
        arguments = ", ".join(
            f"{key}={value!r}" for key, value in _payload(event).items()
        )
        lines.extend((_comment(event), f"{_call_name(event)}({arguments})"))
    return "\n".join(lines) + ("\n" if lines else "")


def _literal(value: Any) -> ast.expr:
    # ``ast.Constant`` cannot directly contain lists/dicts.  Parsing repr gives
    # a compact, deterministic literal while still avoiding code execution.
    expression = ast.parse(repr(value), mode="eval").body
    if not isinstance(
        expression,
        (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.UnaryOp),
    ):
        raise ValueError(f"unsupported literal payload: {value!r}")
    return expression


def lower_ast(events: Iterable[Record]) -> str:
    """Lower through Python's AST and unparser, preserving evidence comments."""
    lines: list[str] = []
    for event in events:
        call = ast.Call(
            func=ast.Name(id=_call_name(event), ctx=ast.Load()),
            args=[],
            keywords=[
                ast.keyword(arg=key, value=_literal(value))
                for key, value in _payload(event).items()
            ],
        )
        statement = ast.Expr(value=call)
        ast.fix_missing_locations(statement)
        lines.extend((_comment(event), ast.unparse(statement)))
    return "\n".join(lines) + ("\n" if lines else "")
