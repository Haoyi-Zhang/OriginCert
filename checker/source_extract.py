"""Independent syntax-only extraction for the reference source backends."""
from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from typing import Any

Record = dict[str, Any]
_PREFIX = "# cg-evidence "
_CALL = re.compile(r"^cg_([A-Za-z_][A-Za-z0-9_]*)$")


class SourceExtractionError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> Record:
    result: Record = {}
    for key, value in pairs:
        if key in result:
            raise SourceExtractionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _metadata(source: str) -> dict[int, Record]:
    comments: list[tuple[int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                comments.append((token.start[0], token.string))
    except (tokenize.TokenError, IndentationError) as error:
        raise SourceExtractionError(str(error)) from error

    metadata: dict[int, Record] = {}
    lines = source.splitlines()
    for line_number, comment in comments:
        if not comment.startswith(_PREFIX):
            raise SourceExtractionError(f"unexpected comment at line {line_number}")
        try:
            value = json.loads(
                comment[len(_PREFIX) :],
                object_pairs_hook=_strict_object,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    SourceExtractionError(f"non-finite JSON value {item!r}")
                ),
            )
        except (json.JSONDecodeError, TypeError) as error:
            raise SourceExtractionError(f"invalid evidence JSON at line {line_number}") from error
        if not isinstance(value, dict):
            raise SourceExtractionError("evidence metadata must be an object")
        allowed = {"origin", "obligations", "occurrence"}
        if set(value) - allowed or not {"origin", "obligations"} <= set(value):
            raise SourceExtractionError("evidence metadata has an invalid field set")
        if not isinstance(value["origin"], str) or not value["origin"]:
            raise SourceExtractionError("origin must be a non-empty string")
        if not isinstance(value["obligations"], list) or not all(
            isinstance(item, str) and item for item in value["obligations"]
        ):
            raise SourceExtractionError("obligations must be a string list")
        if "occurrence" in value and (
            not isinstance(value["occurrence"], list)
            or not all(isinstance(item, int) and item >= 0 for item in value["occurrence"])
        ):
            raise SourceExtractionError("occurrence must be a non-negative integer list")
        target = line_number + 1
        while target <= len(lines) and not lines[target - 1].strip():
            target += 1
        if target in metadata:
            raise SourceExtractionError("multiple evidence comments for one statement")
        metadata[target] = value
    return metadata


def extract_events(source: str) -> list[Record]:
    """Recover an event trace from accepted Python call syntax.

    The source is parsed, never imported or executed.  Each statement must be a
    single ``cg_<operation>(keyword=<literal>, ...)`` call immediately preceded
    by one evidence comment.
    """
    try:
        module = ast.parse(source, mode="exec")
    except SyntaxError as error:
        raise SourceExtractionError(str(error)) from error
    evidence = _metadata(source)
    if len(evidence) != len(module.body):
        raise SourceExtractionError("every generated statement needs exactly one evidence comment")

    events: list[Record] = []
    used_lines: set[int] = set()
    for statement in module.body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            raise SourceExtractionError("only expression-call statements are allowed")
        call = statement.value
        if call.args or not isinstance(call.func, ast.Name):
            raise SourceExtractionError("calls must use a direct name and keyword arguments only")
        match = _CALL.fullmatch(call.func.id)
        if not match:
            raise SourceExtractionError(f"unsupported generated call {call.func.id!r}")
        if statement.lineno not in evidence:
            raise SourceExtractionError("missing evidence comment")
        used_lines.add(statement.lineno)
        event: Record = {"op": match.group(1)}
        for keyword in call.keywords:
            if keyword.arg is None or keyword.arg in event:
                raise SourceExtractionError("duplicate or expanded keyword argument")
            try:
                value = ast.literal_eval(keyword.value)
            except (ValueError, TypeError) as error:
                raise SourceExtractionError("event payload must use literals only") from error
            event[keyword.arg] = value
        for key, value in evidence[statement.lineno].items():
            if key in event:
                raise SourceExtractionError(f"evidence field {key!r} collides with payload")
            event[key] = value
        events.append(event)
    if used_lines != set(evidence):
        raise SourceExtractionError("orphan evidence comment")
    return events
