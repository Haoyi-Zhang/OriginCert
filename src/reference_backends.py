"""Two structurally distinct, syntax-only reference encodings for event traces.

The call backend emits one restricted Python call per event with adjacent JSON
metadata.  The record backend emits one module-level literal table.  Neither
backend executes generated source.  Paired decoders in ``checker/source_extract``
recover the complete event records from the two different surface syntaxes.
"""
from __future__ import annotations

import ast
import json
import math
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


def _record(event: Record) -> Record:
    operation = event.get("op")
    if not isinstance(operation, str) or not operation:
        raise ValueError(f"event operation is invalid: {operation!r}")
    record: Record = {"op": operation}
    record.update(_payload(event))
    record.update(_evidence(event))
    return record


def _comment(event: Record) -> str:
    return "# cg-evidence " + json.dumps(
        _evidence(event), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _call_name(event: Record) -> str:
    operation = event.get("op")
    if not isinstance(operation, str) or not _NAME.fullmatch(operation):
        raise ValueError(f"event operation is not a safe identifier: {operation!r}")
    return f"cg_{operation}"


def _json_literal(value: Any) -> ast.expr:
    """Build a Python AST expression for strict JSON data only."""
    if value is None or type(value) in (str, bool, int):
        return ast.Constant(value=value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return ast.Constant(value=value)
    if type(value) is list:
        return ast.List(elts=[_json_literal(item) for item in value], ctx=ast.Load())
    if type(value) is dict:
        if not all(type(key) is str for key in value):
            raise ValueError("JSON object keys must be strings")
        return ast.Dict(
            keys=[ast.Constant(value=key) for key in value],
            values=[_json_literal(item) for item in value.values()],
        )
    raise ValueError(f"unsupported non-JSON literal: {value!r}")


def lower_template(events: Iterable[Record]) -> str:
    """Lower by deterministic call-statement templating plus evidence comments."""
    lines: list[str] = []
    for event in events:
        arguments = ", ".join(
            f"{key}={value!r}" for key, value in _payload(event).items()
        )
        lines.extend((_comment(event), f"{_call_name(event)}({arguments})"))
    return "\n".join(lines) + ("\n" if lines else "")


def lower_ast(events: Iterable[Record]) -> str:
    """Lower through an AST-built literal trace table.

    This surface form is intentionally different from ``lower_template``: all
    event and evidence fields live in a single ``TRACE_EVENTS`` list of literal
    dictionaries, with no call statements and no evidence comments.
    """
    records = [_record(event) for event in events]
    assignment = ast.Assign(
        targets=[ast.Name(id="TRACE_EVENTS", ctx=ast.Store())],
        value=ast.List(
            elts=[_json_literal(record) for record in records],
            ctx=ast.Load(),
        ),
    )
    module = ast.Module(body=[assignment], type_ignores=[])
    ast.fix_missing_locations(module)
    return ast.unparse(module) + "\n"
