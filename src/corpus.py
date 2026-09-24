from __future__ import annotations

import argparse
import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import validate_case
from .historical_models import ANCHORS

Json = dict[str, Any]

CATALOG: Json = {
    "name": "CWE-derived bounded trace obligations",
    "obligations": [
        {"id": "CWE-89", "trigger": {"op": "sink", "channel": "sql"},
         "rule": {"kind": "protection", "requires": ["sql_parameter"]}},
        {"id": "CWE-79", "trigger": {"op": "sink", "channel": "html"},
         "rule": {"kind": "protection", "requires": ["html_escape"]}},
        {"id": "CWE-78", "trigger": {"op": "sink", "channel": "shell"},
         "rule": {"kind": "protection", "requires": ["argv_exec"]}},
        {"id": "CWE-22", "trigger": {"op": "sink", "channel": "path"},
         "rule": {"kind": "protection", "requires": ["path_normalize", "base_confine"]}},
        {"id": "CWE-862", "trigger": {"op": "privileged"},
         "rule": {"kind": "preceded", "capability_field": "capability"}},
        {"id": "CWE-330", "trigger": {"op": "token"},
         "rule": {"kind": "strong_rng", "source_field": "source"}},
        {"id": "CWE-798", "trigger": {"op": "credential_use"},
         "rule": {"kind": "protection", "requires": ["external_secret"]}},
        {"id": "GEN-PY-FACTORY", "cwe": "CWE-94",
         "trigger": {"op": "sink", "channel": "python_factory"},
         "rule": {"kind": "protection", "requires": ["factory_allowlist"]}},
        {"id": "GEN-PHP-LITERAL", "cwe": "CWE-94",
         "trigger": {"op": "sink", "channel": "php_double_quote"},
         "rule": {"kind": "protection", "requires": ["php_dollar_escape"]}},
        {"id": "GEN-TS-CONST", "cwe": "CWE-94",
         "trigger": {"op": "sink", "channel": "typescript_const"},
         "rule": {"kind": "protection", "requires": ["json_serialize"]}},
    ],
}

SCHEMAS: dict[str, Json] = {
    "web": {"fields": [
        {"name": "mode", "domain": ["normal", "legacy", "bulk"]},
        {"name": "admin", "domain": [False, True]},
        {"name": "feature", "domain": [False, True]},
        {"name": "replicas", "domain": [1, 2]},
    ]},
    "automation": {"fields": [
        {"name": "runner", "domain": ["direct", "compat", "batch"]},
        {"name": "remote", "domain": [False, True]},
        {"name": "strict", "domain": [False, True]},
        {"name": "jobs", "domain": [1, 2]},
    ]},
    "service": {"fields": [
        {"name": "profile", "domain": ["standard", "migration", "recovery"]},
        {"name": "elevated", "domain": [False, True]},
        {"name": "debug", "domain": [False, True]},
        {"name": "replicas", "domain": [1, 2]},
    ]},
}

HISTORICAL_SCHEMAS: dict[str, Json] = {
    "python-model-factory": {"fields": [
        {"name": "model_kind", "domain": ["pydantic", "dataclass", "msgspec"]},
        {"name": "untrusted", "domain": [False, True]},
        {"name": "strict", "domain": [False, True]},
        {"name": "fields", "domain": [1, 2]},
    ]},
    "php-sdk-literal": {"fields": [
        {"name": "literal_site", "domain": ["description", "default", "wire_name"]},
        {"name": "untrusted", "domain": [False, True]},
        {"name": "nullable", "domain": [False, True]},
        {"name": "copies", "domain": [1, 2]},
    ]},
    "typescript-mock-const": {"fields": [
        {"name": "const_kind", "domain": ["string", "number", "object"]},
        {"name": "untrusted", "domain": [False, True]},
        {"name": "mock", "domain": [False, True]},
        {"name": "copies", "domain": [1, 2]},
    ]},
}


CONDITIONS: dict[str, list[list[tuple[str, Any]]]] = {
    "web": [
        [("mode", "legacy")],
        [("feature", True)],
        [("mode", "bulk"), ("admin", True)],
        [("feature", True), ("admin", True)],
    ],
    "automation": [
        [("runner", "compat")],
        [("remote", True)],
        [("runner", "batch"), ("strict", False)],
        [("remote", True), ("strict", False)],
    ],
    "service": [
        [("profile", "migration")],
        [("debug", True)],
        [("profile", "recovery"), ("elevated", True)],
        [("debug", True), ("elevated", True)],
    ],
}


@dataclass
class Builder:
    prefix: str
    number: int = 0

    def identity(self, tag: str) -> str:
        self.number += 1
        return f"{self.prefix}-{tag}-{self.number:02d}"

    def emit(self, event: Json, obligations: list[str] | None = None, tag: str = "emit",
             origin_override: str | None = None) -> Json:
        node: Json = {"kind": "emit", "node": self.identity(tag), "event": event,
                      "declared_obligations": list(obligations or [])}
        if origin_override is not None:
            node["origin_override"] = origin_override
        return node

    def seq(self, children: list[Json], tag: str = "seq") -> Json:
        return {"kind": "seq", "node": self.identity(tag), "children": children}

    def branch(self, field: str, equals: Any, yes: Json, no: Json, tag: str = "if") -> Json:
        return {"kind": "if", "node": self.identity(tag),
                "condition": {"field": field, "equals": equals}, "then": yes, "else": no}

    def repeat(self, count_field: str, body: Json, tag: str = "repeat") -> Json:
        return {"kind": "repeat", "node": self.identity(tag), "count_field": count_field, "body": body}


def fresh_clone(builder: Builder, node: Json, tag: str = "clone") -> Json:
    kind = node["kind"]
    cloned: Json = {"kind": kind, "node": builder.identity(tag)}
    if kind == "seq":
        cloned["children"] = [fresh_clone(builder, child, tag) for child in node["children"]]
    elif kind == "if":
        cloned["condition"] = copy.deepcopy(node["condition"])
        cloned["then"] = fresh_clone(builder, node["then"], tag)
        cloned["else"] = fresh_clone(builder, node["else"], tag)
    elif kind == "repeat":
        cloned["count_field"] = node["count_field"]
        cloned["body"] = fresh_clone(builder, node["body"], tag)
    else:
        cloned["event"] = copy.deepcopy(node["event"])
        cloned["declared_obligations"] = list(node.get("declared_obligations", []))
        if "origin_override" in node:
            cloned["origin_override"] = node["origin_override"]
    return cloned


def guard(builder: Builder, conditions: list[tuple[str, Any]], selected: Json, other: Json) -> Json:
    result = fresh_clone(builder, selected, tag="selected-clone")
    for field, value in reversed(conditions):
        result = builder.branch(field, value, result, fresh_clone(builder, other, tag="other-clone"), tag="guard")
    return result


def fault_mode(local: int) -> str:
    """Balanced 36-case partition for each constructed subtype."""
    if local < 18:
        return "safe"
    if local < 28:
        return "semantic"
    if local < 32:
        return "coverage"
    return "origin"


def declared_for(cwe: str, fault: str, variant: int) -> list[str]:
    """Return an exact, missing, or spuriously enlarged declaration set."""
    if fault != "coverage":
        return [cwe]
    if variant == 0:
        return []
    extra = next(item["id"] for item in CATALOG["obligations"] if item["id"] != cwe)
    return [cwe, extra]


def rewrite_origin_override(node: Json, replacement: str) -> int:
    """Replace every negative-fixture origin marker and return the number changed."""
    kind = node["kind"]
    changed = 0
    if kind == "emit":
        if "origin_override" in node:
            node["origin_override"] = replacement
            changed += 1
    elif kind == "seq":
        for child in node["children"]:
            changed += rewrite_origin_override(child, replacement)
    elif kind == "if":
        changed += rewrite_origin_override(node["then"], replacement)
        changed += rewrite_origin_override(node["else"], replacement)
    else:
        changed += rewrite_origin_override(node["body"], replacement)
    return changed


def fault_detail(fault: str, variant: int) -> str:
    if fault == "safe":
        return "none"
    if fault == "semantic":
        return "monitor-violation"
    if fault == "coverage":
        return "missing-obligation" if variant == 0 else "spurious-obligation"
    return "nonexistent-origin" if variant == 0 else "wrong-existing-origin"


def secured_flow(builder: Builder, cwe: str, channel: str, protection_names: list[str],
                 count_field: str, fault: str, variant: int) -> tuple[Json, Json]:
    source = builder.emit({"op": "source", "target": "user", "input": "request"}, tag="source")
    current = "user"
    protections: list[Json] = []
    for index, protection in enumerate(protection_names):
        target = f"safe{index}"
        protections.append(builder.emit({"op": "protect", "target": target, "source": current,
                                         "protection": protection}, tag="protect"))
        current = target
    good_sink = builder.emit({"op": "sink", "channel": channel, "source": current}, [cwe], tag="sink-good")
    good = builder.seq([source] + protections + [builder.repeat(count_field, good_sink, tag="repeat-good")], tag="good")

    bad_source = builder.emit({"op": "source", "target": "user", "input": "request"}, tag="source-bad")
    bad_protections: list[Json] = []
    bad_current = "user"
    keep = protections if fault != "semantic" else protections[:-1]
    for index, original in enumerate(keep):
        event = copy.deepcopy(original["event"])
        event["source"] = bad_current
        event["target"] = f"bad_safe{index}"
        bad_current = event["target"]
        bad_protections.append(builder.emit(event, tag="protect-bad"))
    obligations = declared_for(cwe, fault, variant)
    origin = "absent-generator-node" if fault == "origin" else None
    bad_sink = builder.emit({"op": "sink", "channel": channel, "source": bad_current}, obligations,
                            tag="sink-selected", origin_override=origin)
    bad = builder.seq([bad_source] + bad_protections + [builder.repeat(count_field, bad_sink, tag="repeat-selected")],
                      tag="selected")
    if fault == "safe":
        # A distinct but secure selected path makes the partition non-trivial.
        extra = builder.emit({"op": "protect", "target": "safe_extra", "source": current,
                              "protection": protection_names[-1]}, tag="protect-extra")
        safe_sink = builder.emit({"op": "sink", "channel": channel, "source": "safe_extra"}, [cwe], tag="sink-extra")
        bad = builder.seq([copy.deepcopy(source)] + copy.deepcopy(protections) + [extra,
                          builder.repeat(count_field, safe_sink, tag="repeat-extra")], tag="selected-safe")
    return good, bad


def authorization_flow(builder: Builder, count_field: str, fault: str, variant: int) -> tuple[Json, Json]:
    check = builder.emit({"op": "check", "capability": "admin"}, tag="check")
    privileged = builder.emit({"op": "privileged", "capability": "admin"}, ["CWE-862"], tag="privileged-good")
    good = builder.seq([check, builder.repeat(count_field, privileged, tag="repeat-good")], tag="good")
    selected_check = [] if fault == "semantic" else [builder.emit({"op": "check", "capability": "admin"}, tag="check-selected")]
    obligations = declared_for("CWE-862", fault, variant)
    origin = "absent-generator-node" if fault == "origin" else None
    selected_privileged = builder.emit({"op": "privileged", "capability": "admin"}, obligations,
                                       tag="privileged-selected", origin_override=origin)
    selected = builder.seq(selected_check + [builder.repeat(count_field, selected_privileged, tag="repeat-selected")],
                           tag="selected")
    if fault == "safe":
        selected = builder.seq([builder.emit({"op": "check", "capability": "admin"}, tag="check-safe"),
                                builder.emit({"op": "noop"}, tag="audit-safe"),
                                builder.repeat(count_field,
                                               builder.emit({"op": "privileged", "capability": "admin"}, ["CWE-862"],
                                                            tag="privileged-safe"), tag="repeat-safe")], tag="selected-safe")
    return good, selected


def token_flow(builder: Builder, count_field: str, fault: str, variant: int) -> tuple[Json, Json]:
    rng = builder.emit({"op": "rng", "target": "entropy", "strength": "strong"}, tag="rng")
    token = builder.emit({"op": "token", "source": "entropy"}, ["CWE-330"], tag="token-good")
    good = builder.seq([rng, builder.repeat(count_field, token, tag="repeat-good")], tag="good")
    strength = "weak" if fault == "semantic" else "strong"
    selected_rng = builder.emit({"op": "rng", "target": "entropy", "strength": strength}, tag="rng-selected")
    obligations = declared_for("CWE-330", fault, variant)
    origin = "absent-generator-node" if fault == "origin" else None
    selected_token = builder.emit({"op": "token", "source": "entropy"}, obligations,
                                  tag="token-selected", origin_override=origin)
    selected = builder.seq([selected_rng, builder.repeat(count_field, selected_token, tag="repeat-selected")], tag="selected")
    if fault == "safe":
        selected = builder.seq([selected_rng, builder.emit({"op": "noop"}, tag="audit-safe"),
                                builder.repeat(count_field,
                                               builder.emit({"op": "token", "source": "entropy"}, ["CWE-330"],
                                                            tag="token-safe"), tag="repeat-safe")], tag="selected-safe")
    return good, selected


def credential_flow(builder: Builder, count_field: str, fault: str, variant: int) -> tuple[Json, Json]:
    source = builder.emit({"op": "source", "target": "secret", "input": "environment"}, tag="secret-source")
    external = builder.emit({"op": "protect", "target": "bound_secret", "source": "secret",
                             "protection": "external_secret"}, tag="secret-bind")
    use = builder.emit({"op": "credential_use", "source": "bound_secret"}, ["CWE-798"], tag="credential-good")
    good = builder.seq([source, external, builder.repeat(count_field, use, tag="repeat-good")], tag="good")
    selected_source = builder.emit({"op": "source", "target": "secret", "input": "environment"}, tag="secret-source-selected")
    selected_nodes: list[Json] = [selected_source]
    selected_value = "secret"
    if fault != "semantic":
        selected_nodes.append(builder.emit({"op": "protect", "target": "bound_secret", "source": "secret",
                                            "protection": "external_secret"}, tag="secret-bind-selected"))
        selected_value = "bound_secret"
    obligations = declared_for("CWE-798", fault, variant)
    origin = "absent-generator-node" if fault == "origin" else None
    selected_use = builder.emit({"op": "credential_use", "source": selected_value}, obligations,
                                tag="credential-selected", origin_override=origin)
    selected_nodes.append(builder.repeat(count_field, selected_use, tag="repeat-selected"))
    selected = builder.seq(selected_nodes, tag="selected")
    if fault == "safe":
        selected = builder.seq([copy.deepcopy(source), copy.deepcopy(external), builder.emit({"op": "noop"}, tag="audit-safe"),
                                builder.repeat(count_field,
                                               builder.emit({"op": "credential_use", "source": "bound_secret"}, ["CWE-798"],
                                                            tag="credential-safe"), tag="repeat-safe")], tag="selected-safe")
    return good, selected


def historical_flow(builder: Builder, anchor_id: str, patched: bool) -> Json:
    anchor = ANCHORS[anchor_id]
    schema = HISTORICAL_SCHEMAS[anchor_id]
    count_field = schema["fields"][-1]["name"]
    obligation = {
        "python-model-factory": "GEN-PY-FACTORY",
        "php-sdk-literal": "GEN-PHP-LITERAL",
        "typescript-mock-const": "GEN-TS-CONST",
    }[anchor_id]

    def source(tag: str) -> Json:
        return builder.emit({"op": "source", "target": "schema_value", "input": "schema"}, tag=tag)

    def safe_sink(tag: str) -> Json:
        protected = builder.emit(
            {"op": "protect", "target": "safe_value", "source": "schema_value",
             "protection": anchor["protection"]},
            tag=f"{tag}-protect",
        )
        sink = builder.emit(
            {"op": "sink", "channel": anchor["channel"], "source": "safe_value"},
            [obligation],
            tag=f"{tag}-sink",
        )
        return builder.seq([source(f"{tag}-source"), protected,
                            builder.repeat(count_field, sink, tag=f"{tag}-repeat")], tag=f"{tag}-seq")

    ordinary = safe_sink("ordinary")
    if patched and anchor_id == "python-model-factory":
        # The advisory-derived patched model rejects a non-allowlisted expression
        # before emitting a Python factory expression.
        selected = builder.seq([
            source("selected-source"),
            builder.emit({"op": "reject_input", "reason": "factory_allowlist"}, tag="selected-reject"),
        ], tag="selected-seq")
    elif patched:
        selected = safe_sink("selected")
    else:
        raw_sink = builder.emit(
            {"op": "sink", "channel": anchor["channel"], "source": "schema_value"},
            [obligation],
            tag="selected-sink",
        )
        selected = builder.seq([
            source("selected-source"),
            builder.repeat(count_field, raw_sink, tag="selected-repeat"),
        ], tag="selected-seq")

    return builder.branch("untrusted", True, selected, ordinary, tag="untrusted-guard")


def reshape_historical(builder: Builder, anchor_id: str, root: Json, local: int) -> Json:
    """Give the three advisory families distinct, semantics-preserving outer controls."""
    variant = local % 6
    schema = HISTORICAL_SCHEMAS[anchor_id]
    flag = schema["fields"][2]["name"]
    selector = schema["fields"][0]
    count_field = schema["fields"][3]["name"]
    if anchor_id == "python-model-factory":
        if variant == 0:
            return root
        if variant == 1:
            return builder.seq([builder.emit({"op": "noop"}, tag="prelude"), root], tag="root-seq")
        if variant == 2:
            return builder.branch(flag, True, root, fresh_clone(builder, root, "strict-clone"), tag="strict-outer")
        if variant == 3:
            return builder.branch(selector["name"], selector["domain"][0], root,
                                  fresh_clone(builder, root, "model-clone"), tag="model-outer")
        if variant == 4:
            return builder.seq([root, builder.emit({"op": "noop"}, tag="epilogue")], tag="root-seq")
        return builder.repeat(count_field, root, tag="outer-repeat")
    if anchor_id == "php-sdk-literal":
        if variant in {0, 1}:
            return builder.repeat(count_field, root, tag="outer-repeat") if variant else root
        if variant in {2, 3}:
            return builder.branch(flag, variant == 2, root, fresh_clone(builder, root, "nullable-clone"), tag="nullable-outer")
        if variant == 4:
            return builder.seq([builder.emit({"op": "noop"}, tag="quote-mode"), root], tag="writer-seq")
        return builder.branch(selector["name"], selector["domain"][2], fresh_clone(builder, root, "wire-clone"), root,
                              tag="site-outer")
    if variant == 0:
        return builder.seq([root, builder.emit({"op": "noop"}, tag="handler-end")], tag="mock-seq")
    if variant == 1:
        return builder.branch(flag, True, root, fresh_clone(builder, root, "mock-clone"), tag="mock-outer")
    if variant == 2:
        return builder.branch(selector["name"], selector["domain"][1], root,
                              fresh_clone(builder, root, "const-clone"), tag="const-outer")
    if variant == 3:
        return builder.repeat(count_field, root, tag="outer-repeat")
    if variant == 4:
        return builder.seq([builder.emit({"op": "noop"}, tag="faker-start"), root,
                            builder.emit({"op": "noop"}, tag="faker-end")], tag="mock-seq")
    return root


def make_historical_case(anchor_id: str, local: int) -> Json:
    anchor = ANCHORS[anchor_id]
    family = {
        "python-model-factory": "python-model",
        "php-sdk-literal": "php-sdk",
        "typescript-mock-const": "typescript-mock",
    }[anchor_id]
    patched = local < 6
    case_id = f"{family}-{local + 1:03d}"
    builder = Builder(case_id)
    generator = historical_flow(builder, anchor_id, patched)
    generator = reshape_historical(builder, anchor_id, generator, local)
    case: Json = {
        "case_id": case_id,
        "family": family,
        "subtype": anchor_id,
        "corpus_source": "public-advisory-abstraction",
        "fault_kind": "safe" if patched else "semantic",
        "fault_detail": "advisory-patched" if patched else "advisory-vulnerable",
        "expected": "accepted" if patched else "rejected",
        "schema": copy.deepcopy(HISTORICAL_SCHEMAS[anchor_id]),
        "catalog": copy.deepcopy(CATALOG),
        "generator": generator,
        "historical_model": {
            "anchor": anchor_id,
            "state": "patched" if patched else "vulnerable",
            "record": anchor["record"],
            "cve": anchor["cve"],
            "scope": "independent bounded source-to-sink model; not vendor-code execution",
        },
    }
    validate_case(case)
    return case


def make_case(family: str, subtype: str, local: int) -> Json:
    case_id = f"{family}-{subtype}-{local + 1:03d}"
    builder = Builder(case_id)
    fault = fault_mode(local)
    variant = local % 2
    count_field = "jobs" if family == "automation" else "replicas"
    if subtype == "sql":
        good, selected = secured_flow(builder, "CWE-89", "sql", ["sql_parameter"], count_field, fault, variant)
    elif subtype == "html":
        good, selected = secured_flow(builder, "CWE-79", "html", ["html_escape"], count_field, fault, variant)
    elif subtype == "shell":
        good, selected = secured_flow(builder, "CWE-78", "shell", ["argv_exec"], count_field, fault, variant)
    elif subtype == "path":
        good, selected = secured_flow(builder, "CWE-22", "path", ["path_normalize", "base_confine"], count_field, fault, variant)
    elif subtype == "auth":
        good, selected = authorization_flow(builder, count_field, fault, variant)
    elif subtype == "token":
        good, selected = token_flow(builder, count_field, fault, variant)
    elif subtype == "credential":
        good, selected = credential_flow(builder, count_field, fault, variant)
    else:
        raise ValueError(subtype)
    conditions = CONDITIONS[family][local % len(CONDITIONS[family])]
    generator = guard(builder, conditions, selected, good)
    if fault == "origin" and variant == 1:
        changed = rewrite_origin_override(generator, generator["node"])
        if changed == 0:
            raise AssertionError(f"{case_id}: expected an origin fixture marker")
    case: Json = {
        "case_id": case_id,
        "family": family,
        "subtype": subtype,
        "corpus_source": "constructed",
        "fault_kind": fault,
        "fault_detail": fault_detail(fault, variant),
        "expected": "accepted" if fault == "safe" else "rejected",
        "schema": copy.deepcopy(SCHEMAS[family]),
        "catalog": copy.deepcopy(CATALOG),
        "generator": generator,
    }
    validate_case(case)
    return case


def generate_cases() -> list[Json]:
    plan = {
        "web": ["sql", "html", "auth"],
        "automation": ["shell", "path", "auth"],
        "service": ["token", "credential", "auth"],
    }
    cases: list[Json] = []
    for family, subtypes in plan.items():
        for subtype in subtypes:
            for local in range(36):
                cases.append(make_case(family, subtype, local))
    for anchor_id in ANCHORS:
        for local in range(12):
            cases.append(make_historical_case(anchor_id, local))
    if len(cases) != 360:
        raise AssertionError(f"expected 360 cases, built {len(cases)}")
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the frozen 360-case bounded-generator corpus.")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = generate_cases()
    for case in cases:
        path = args.output / f"{case['case_id']}.json"
        with path.open("w", encoding="utf-8") as handle:
            json.dump(case, handle, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
    manifest = [
        {
            key: case.get(key)
            for key in ("case_id", "family", "subtype", "corpus_source", "fault_kind", "fault_detail", "expected")
        }
        for case in cases
    ]
    with (args.output / "manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        handle.write("\n")
    print(f"wrote {len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
