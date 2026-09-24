from __future__ import annotations

import ast
import json
from typing import Any

Json = dict[str, Any]

# These records capture only the source-to-sink mechanisms stated in the public
# advisories.  The models below are independently written, bounded abstractions;
# they do not contain or execute vendor code.
ANCHORS: dict[str, Json] = {
    "python-model-factory": {
        "project": "datamodel-code-generator",
        "record": "GHSA-386q-5hp3-95m9",
        "cve": "CVE-2026-54653",
        "surface": "schema default_factory to generated Python expression",
        "channel": "python_factory",
        "obligation": "CWE-94-PY-FACTORY",
        "protection": "factory_allowlist",
        "mitigation": "reject expressions outside a fixed constructor allowlist",
    },
    "php-sdk-literal": {
        "project": "Microsoft Kiota PHP generator",
        "record": "GHSA-jqwh-526h-c92j",
        "cve": "CVE-2026-59859",
        "surface": "OpenAPI text to PHP double-quoted literal",
        "channel": "php_double_quote",
        "obligation": "CWE-94-PHP-LITERAL",
        "protection": "php_dollar_escape",
        "mitigation": "escape dollar signs after common quoted-literal escaping",
    },
    "typescript-mock-const": {
        "project": "Orval mock generator",
        "record": "GHSA-f456-rf33-4626",
        "cve": "CVE-2026-24132",
        "surface": "OpenAPI const to generated TypeScript expression",
        "channel": "typescript_const",
        "obligation": "CWE-94-TS-CONST",
        "protection": "json_serialize",
        "mitigation": "serialize a const value as data rather than splice it as code",
    },
}


def _python_value(assignment: Json) -> str:
    if not assignment["untrusted"]:
        return {"pydantic": "dict", "dataclass": "list", "msgspec": "set"}[assignment["model_kind"]]
    return {
        "pydantic": "sentinel_factory()",
        "dataclass": "(lambda: 0)",
        "msgspec": "tuple()",
    }[assignment["model_kind"]]


def _python_safe(rendered: str) -> bool:
    if rendered == "schema rejected":
        return True
    try:
        module = ast.parse(rendered)
    except (SyntaxError, ValueError):
        return False
    if len(module.body) != 1:
        return False
    expression = module.body[0]
    if not isinstance(expression, ast.Expr) or not isinstance(expression.value, ast.Call):
        return False
    call = expression.value
    keyword = next((item for item in call.keywords if item.arg == "default_factory"), None)
    return isinstance(keyword.value, ast.Name) and keyword.value.id in {"dict", "list", "set"} if keyword else False


def _php_value(assignment: Json) -> str:
    if not assignment["untrusted"]:
        return {"description": "plain text", "default": "default value", "wire_name": "wire_name"}[
            assignment["literal_site"]
        ]
    return {
        "description": "${sentinel}",
        "default": "$sentinel",
        "wire_name": "{$sentinel}",
    }[assignment["literal_site"]]


def _php_escape_common(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _has_unescaped_dollar(value: str) -> bool:
    for index, char in enumerate(value):
        if char != "$":
            continue
        slashes = 0
        cursor = index - 1
        while cursor >= 0 and value[cursor] == "\\":
            slashes += 1
            cursor -= 1
        if slashes % 2 == 0:
            return True
    return False


def _php_safe(rendered: str) -> bool:
    if len(rendered) < 2 or not rendered.startswith('"') or not rendered.endswith('"'):
        return False
    return not _has_unescaped_dollar(rendered[1:-1])


def _typescript_value(assignment: Json) -> Any:
    if not assignment["untrusted"]:
        return {"string": "ordinary", "number": 7, "object": {"ok": True}}[assignment["const_kind"]]
    return {
        "string": "sentinel_call()",
        "number": "0); sentinel_call(); (0",
        "object": "({get value(){return sentinel_call()}})",
    }[assignment["const_kind"]]


def _typescript_safe(rendered: str) -> bool:
    prefix = "export const value = "
    if not rendered.startswith(prefix) or not rendered.endswith(";"):
        return False
    expression = rendered[len(prefix) : -1]
    try:
        json.loads(expression)
    except json.JSONDecodeError:
        return False
    return True


def render(anchor_id: str, patched: bool, assignment: Json) -> Json:
    """Render and inspect one bounded advisory-derived source-to-sink model.

    The returned safety judgment is syntactic and intentionally mechanism-specific.
    No generated text is executed.
    """
    if anchor_id == "python-model-factory":
        value = _python_value(assignment)
        if patched and value not in {"dict", "list", "set"}:
            rendered = "schema rejected"
            rejected = True
        else:
            rendered = f"Field(default_factory={value})"
            rejected = False
        safe = _python_safe(rendered)
    elif anchor_id == "php-sdk-literal":
        value = _php_value(assignment)
        escaped = _php_escape_common(value)
        if patched:
            escaped = escaped.replace("$", "\\$")
        rendered = f'"{escaped}"'
        rejected = False
        safe = _php_safe(rendered)
    elif anchor_id == "typescript-mock-const":
        value = _typescript_value(assignment)
        expression = (
            json.dumps(value, sort_keys=True, separators=(",", ":"))
            if patched or not assignment["untrusted"]
            else str(value)
        )
        rendered = f"export const value = {expression};"
        rejected = False
        safe = _typescript_safe(rendered)
    else:
        raise ValueError(f"unknown historical anchor: {anchor_id}")
    return {
        "anchor": anchor_id,
        "patched": patched,
        "input_untrusted": bool(assignment["untrusted"]),
        "rejected": rejected,
        "rendered": rendered,
        "safe": safe,
    }


def classify(anchor_id: str, patched: bool, assignments: list[Json]) -> str:
    return "rejected" if any(not render(anchor_id, patched, item)["safe"] for item in assignments) else "accepted"
