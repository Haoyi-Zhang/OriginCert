"""Independent syntax-only decoders for the two reference source encodings."""
from __future__ import annotations

import ast
import io
import json
import math
import re
import tokenize
from typing import Any

Record = dict[str, Any]
_PREFIX = "# cg-evidence "
_CALL = re.compile(r"^cg_([A-Za-z_][A-Za-z0-9_]*)$")
_OPERATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SourceExtractionError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> Record:
    result: Record = {}
    for key, value in pairs:
        if key in result:
            raise SourceExtractionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _tokens(source: str) -> list[tokenize.TokenInfo]:
    try:
        return list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError) as error:
        raise SourceExtractionError(str(error)) from error


def _metadata(source: str) -> dict[int, Record]:
    comments = [
        (token.start[0], token.string)
        for token in _tokens(source)
        if token.type == tokenize.COMMENT
    ]
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
            raise SourceExtractionError(
                f"invalid evidence JSON at line {line_number}"
            ) from error
        if not isinstance(value, dict):
            raise SourceExtractionError("evidence metadata must be an object")
        allowed = {"origin", "obligations", "occurrence"}
        if set(value) - allowed or not {"origin", "obligations"} <= set(value):
            raise SourceExtractionError("evidence metadata has an invalid field set")
        target = line_number + 1
        while target <= len(lines) and not lines[target - 1].strip():
            target += 1
        if target in metadata:
            raise SourceExtractionError("multiple evidence comments for one statement")
        metadata[target] = value
    return metadata


def _decode_json_expression(node: ast.expr) -> Any:
    """Decode strict JSON data while retaining duplicate-key detection."""
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None or type(value) in (str, bool, int):
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise SourceExtractionError("non-finite literal")
            return value
        raise SourceExtractionError("payload literal is not JSON data")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        value = _decode_json_expression(node.operand)
        if type(value) not in (int, float):
            raise SourceExtractionError("unary sign requires a JSON number")
        result = -value if isinstance(node.op, ast.USub) else value
        if type(result) is float and not math.isfinite(result):
            raise SourceExtractionError("non-finite literal")
        return result
    if isinstance(node, ast.List):
        return [_decode_json_expression(item) for item in node.elts]
    if isinstance(node, ast.Dict):
        result: Record = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            if key_node is None:
                raise SourceExtractionError("expanded dictionary entries are not allowed")
            key = _decode_json_expression(key_node)
            if type(key) is not str:
                raise SourceExtractionError("JSON object keys must be strings")
            if key in result:
                raise SourceExtractionError(f"duplicate literal object key {key!r}")
            result[key] = _decode_json_expression(value_node)
        return result
    raise SourceExtractionError("payload expression is not strict JSON literal syntax")


def _validate_event(event: Any) -> Record:
    if not isinstance(event, dict):
        raise SourceExtractionError("event record must be an object")
    if not all(type(key) is str for key in event):
        raise SourceExtractionError("event keys must be strings")
    required = {"op", "origin", "obligations"}
    if not required <= set(event):
        raise SourceExtractionError("event record is missing required evidence fields")
    operation = event["op"]
    if not isinstance(operation, str) or not _OPERATION.fullmatch(operation):
        raise SourceExtractionError("event operation must be a non-empty identifier")
    if not isinstance(event["origin"], str) or not event["origin"]:
        raise SourceExtractionError("origin must be a non-empty string")
    obligations = event["obligations"]
    if (
        not isinstance(obligations, list)
        or not all(isinstance(item, str) and item for item in obligations)
        or len(set(obligations)) != len(obligations)
    ):
        raise SourceExtractionError("obligations must be a duplicate-free string list")
    if "occurrence" in event:
        occurrence = event["occurrence"]
        if (
            not isinstance(occurrence, list)
            or not occurrence
            or not all(type(item) is int and 0 <= item <= 3 for item in occurrence)
        ):
            raise SourceExtractionError(
                "occurrence must be a nonempty list of exact integers from 0 through 3"
            )
    # Re-encode every nested value through the strict AST-independent JSON walk.
    def inspect(value: Any) -> None:
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float:
            if not math.isfinite(value):
                raise SourceExtractionError("non-finite JSON value")
            return
        if type(value) is list:
            for item in value:
                inspect(item)
            return
        if type(value) is dict:
            if not all(type(key) is str for key in value):
                raise SourceExtractionError("JSON object keys must be strings")
            for item in value.values():
                inspect(item)
            return
        raise SourceExtractionError("event contains a non-JSON value")

    inspect(event)
    return event


def extract_call_events(source: str) -> list[Record]:
    """Recover events from restricted call statements and evidence comments."""
    try:
        module = ast.parse(source, mode="exec")
    except SyntaxError as error:
        raise SourceExtractionError(str(error)) from error
    evidence = _metadata(source)
    if len(evidence) != len(module.body):
        raise SourceExtractionError(
            "every generated statement needs exactly one evidence comment"
        )

    events: list[Record] = []
    used_lines: set[int] = set()
    for statement in module.body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            raise SourceExtractionError("only expression-call statements are allowed")
        call = statement.value
        if call.args or not isinstance(call.func, ast.Name):
            raise SourceExtractionError(
                "calls must use a direct name and keyword arguments only"
            )
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
            event[keyword.arg] = _decode_json_expression(keyword.value)
        for key, value in evidence[statement.lineno].items():
            if key in event:
                raise SourceExtractionError(
                    f"evidence field {key!r} collides with payload"
                )
            event[key] = value
        events.append(_validate_event(event))
    if used_lines != set(evidence):
        raise SourceExtractionError("orphan evidence comment")
    return events


def extract_record_events(source: str) -> list[Record]:
    """Recover events from one literal ``TRACE_EVENTS`` module assignment."""
    if any(token.type == tokenize.COMMENT for token in _tokens(source)):
        raise SourceExtractionError("record-table syntax does not admit comments")
    try:
        module = ast.parse(source, mode="exec")
    except SyntaxError as error:
        raise SourceExtractionError(str(error)) from error
    if len(module.body) != 1 or not isinstance(module.body[0], ast.Assign):
        raise SourceExtractionError("record-table source must contain one assignment")
    statement = module.body[0]
    if (
        len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or statement.targets[0].id != "TRACE_EVENTS"
    ):
        raise SourceExtractionError("record table must be assigned to TRACE_EVENTS")
    value = _decode_json_expression(statement.value)
    if not isinstance(value, list):
        raise SourceExtractionError("TRACE_EVENTS must be a literal list")
    return [_validate_event(event) for event in value]


def extract_events(source: str) -> list[Record]:
    """Backward-compatible name for the call-statement decoder."""
    return extract_call_events(source)
