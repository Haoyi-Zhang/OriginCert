from __future__ import annotations

import copy
import itertools
import json
import math
from dataclasses import dataclass
from typing import Any, Iterable

Json = dict[str, Any]
Occurrence = tuple[int, ...]

MAX_ASSIGNMENTS = 256
MAX_GENERATOR_NODES = 2_000
MAX_GENERATOR_DEPTH = 256
MAX_TRACE_EVENTS = 4_096
MAX_REPEAT_COUNT = 4
MAX_TRAVERSAL_STEPS = 2_000_000

EVENT_FIELDS: dict[str, tuple[set[str], set[str]]] = {
    "source": ({"target"}, {"input"}),
    "protect": ({"target", "source", "protection"}, set()),
    "sink": ({"channel", "source"}, set()),
    "check": ({"capability"}, set()),
    "privileged": ({"capability"}, set()),
    "rng": ({"target", "strength"}, set()),
    "token": ({"source"}, set()),
    "credential_use": ({"source"}, set()),
    "literal_secret": ({"name"}, set()),
    "reject_input": ({"reason"}, set()),
    "noop": (set(), set()),
}
RESERVED_EVENT_FIELDS = {"origin", "obligations", "occurrence"}

CASE_REQUIRED_FIELDS = {"case_id", "family", "schema", "catalog", "generator"}
CASE_OPTIONAL_FIELDS = {
    "subtype",
    "corpus_source",
    "historical_model",
    "expected",
    "fault_kind",
    "fault_detail",
}
SUBJECT_OPTIONAL_FIELDS = {"subtype", "corpus_source", "historical_model"}


class ModelError(ValueError):
    """Raised when a case is outside the frozen bounded language."""


def _exact_keys(value: Json, required: set[str], optional: set[str], label: str) -> None:
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise ModelError(f"{label} is missing {sorted(missing)!r}")
    if extra:
        raise ModelError(f"{label} has unknown fields {sorted(extra)!r}")


def validate_json_value(value: Any, label: str = "value") -> None:
    """Validate the in-memory value against strict finite JSON data types."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ModelError(f"{label} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelError(f"{label} contains a non-string object key")
            validate_json_value(item, f"{label}.{key}")
        return
    raise ModelError(f"{label} contains a non-JSON value of type {type(value).__name__}")


def canonical_json(value: Any) -> str:
    validate_json_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def same_json_value(left: Any, right: Any) -> bool:
    """Compare values using JSON identity rather than Python bool/int equality."""
    return canonical_json(left) == canonical_json(right)


def validate_event_template(event: Any) -> None:
    if not isinstance(event, dict):
        raise ModelError("emit.event must be an object")
    validate_json_value(event, "emit.event")
    op = event.get("op")
    if not isinstance(op, str) or op not in EVENT_FIELDS:
        raise ModelError(f"unsupported event operation: {op!r}")
    if RESERVED_EVENT_FIELDS & set(event):
        raise ModelError("event templates may not predeclare origin, obligations, or occurrence")
    required, optional = EVENT_FIELDS[op]
    supplied = set(event) - {"op"}
    if not required.issubset(supplied) or not supplied.issubset(required | optional):
        raise ModelError(f"event {op!r} has invalid operation-specific fields")
    for name in supplied:
        if not isinstance(event[name], str) or not event[name]:
            raise ModelError(f"event {op!r} field {name!r} must be a non-empty string")
    if op == "rng" and event["strength"] not in {"weak", "strong"}:
        raise ModelError("rng strength must be weak or strong")


def field_names(schema: Json) -> list[str]:
    if not isinstance(schema, dict):
        raise ModelError("schema must be an object")
    _exact_keys(schema, {"fields"}, set(), "schema")
    fields = schema["fields"]
    if not isinstance(fields, list) or not fields:
        raise ModelError("schema.fields must be a non-empty list")
    names: list[str] = []
    assignment_count = 1
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            raise ModelError("every field must be an object")
        _exact_keys(field, {"name", "domain"}, set(), f"schema.fields[{index}]")
        name = field["name"]
        domain = field["domain"]
        if not isinstance(name, str) or not name or name in names:
            raise ModelError("field names must be unique non-empty strings")
        if not isinstance(domain, list) or not domain:
            raise ModelError(f"field {name} must have a finite non-empty domain")
        for value_index, value in enumerate(domain):
            validate_json_value(value, f"field {name} domain[{value_index}]")
        if len({canonical_json(value) for value in domain}) != len(domain):
            raise ModelError(f"field {name} contains duplicate JSON values")
        assignment_count *= len(domain)
        if assignment_count > MAX_ASSIGNMENTS:
            raise ModelError(f"schema exceeds the {MAX_ASSIGNMENTS}-assignment bound")
        names.append(name)
    return names


def domains(schema: Json) -> dict[str, list[Any]]:
    field_names(schema)
    return {field["name"]: copy.deepcopy(field["domain"]) for field in schema["fields"]}


def raw_assignments(schema: Json) -> list[Json]:
    ds = domains(schema)
    names = list(ds)
    return [
        dict(zip(names, copy.deepcopy(values), strict=True))
        for values in itertools.product(*(ds[name] for name in names))
    ]


def assignment_rank(schema: Json, assignment: Json) -> tuple[Any, ...]:
    ds = domains(schema)
    if not isinstance(assignment, dict) or set(assignment) != set(ds):
        raise ModelError("assignment fields do not match schema")
    validate_json_value(assignment, "assignment")
    positions: list[int] = []
    for name, domain in ds.items():
        matches = [index for index, value in enumerate(domain) if same_json_value(value, assignment[name])]
        if len(matches) != 1:
            raise ModelError(f"assignment value for {name} is outside its domain")
        positions.append(matches[0])
    non_default = sum(index != 0 for index in positions)
    return (non_default, sum(positions), tuple(positions), canonical_json(assignment))


def canonical_assignments(schema: Json) -> list[Json]:
    return sorted(raw_assignments(schema), key=lambda item: assignment_rank(schema, item))


def input_size(schema: Json, assignment: Json) -> int:
    return int(assignment_rank(schema, assignment)[0])


def all_node_ids(node: Json) -> set[str]:
    ids: set[str] = set()

    def visit(current: Any, depth: int) -> None:
        if not isinstance(current, dict):
            raise ModelError("generator nodes must be objects")
        if depth > MAX_GENERATOR_DEPTH:
            raise ModelError(f"generator exceeds the depth bound of {MAX_GENERATOR_DEPTH}")
        node_id = current.get("node")
        kind = current.get("kind")
        if not isinstance(node_id, str) or not node_id or node_id in ids:
            raise ModelError("generator node identifiers must be unique non-empty strings")
        if kind not in {"seq", "if", "repeat", "emit"}:
            raise ModelError(f"unsupported generator node kind: {kind!r}")
        ids.add(node_id)
        if len(ids) > MAX_GENERATOR_NODES:
            raise ModelError(f"generator exceeds the node bound of {MAX_GENERATOR_NODES}")

        if kind == "seq":
            _exact_keys(current, {"node", "kind", "children"}, set(), f"seq node {node_id}")
            children = current["children"]
            if not isinstance(children, list):
                raise ModelError("seq.children must be a list")
            for child in children:
                visit(child, depth + 1)
        elif kind == "if":
            _exact_keys(current, {"node", "kind", "condition", "then", "else"}, set(), f"if node {node_id}")
            condition = current["condition"]
            if not isinstance(condition, dict):
                raise ModelError("if.condition must be an object")
            _exact_keys(condition, {"field", "equals"}, set(), f"condition at {node_id}")
            if not isinstance(condition["field"], str) or not condition["field"]:
                raise ModelError("if.condition.field must be a non-empty string")
            validate_json_value(condition["equals"], f"condition at {node_id}.equals")
            visit(current["then"], depth + 1)
            visit(current["else"], depth + 1)
        elif kind == "repeat":
            _exact_keys(current, {"node", "kind", "count_field", "body"}, set(), f"repeat node {node_id}")
            if not isinstance(current["count_field"], str) or not current["count_field"]:
                raise ModelError("repeat.count_field must be a non-empty string")
            visit(current["body"], depth + 1)
        else:
            _exact_keys(
                current,
                {"node", "kind", "event"},
                {"declared_obligations", "origin_override"},
                f"emit node {node_id}",
            )
            validate_event_template(current["event"])
            declared = current.get("declared_obligations", [])
            if (
                not isinstance(declared, list)
                or any(not isinstance(item, str) or not item for item in declared)
                or len(set(declared)) != len(declared)
            ):
                raise ModelError("declared obligations must be unique non-empty strings")
            if "origin_override" in current and (
                not isinstance(current["origin_override"], str) or not current["origin_override"]
            ):
                raise ModelError("origin override must be a non-empty string")

    visit(node, 1)
    return ids


def _validate_historical_model(value: Any) -> None:
    if not isinstance(value, dict):
        raise ModelError("historical_model must be an object")
    _exact_keys(value, {"anchor", "state", "record", "cve", "scope"}, set(), "historical_model")
    for key, item in value.items():
        if not isinstance(item, str) or not item:
            raise ModelError(f"historical_model.{key} must be a non-empty string")
    if value["state"] not in {"patched", "vulnerable"}:
        raise ModelError("historical_model.state must be patched or vulnerable")


def _validate_rule(rule: Any, oid: str, trigger_allowed: set[str]) -> None:
    if not isinstance(rule, dict):
        raise ModelError(f"obligation {oid} has no rule")
    kind = rule.get("kind")
    if kind == "protection":
        _exact_keys(rule, {"kind", "requires"}, {"source_field"}, f"rule for {oid}")
        requires = rule["requires"]
        if (
            not isinstance(requires, list)
            or not requires
            or any(not isinstance(item, str) or not item for item in requires)
            or len(set(requires)) != len(requires)
        ):
            raise ModelError(f"obligation {oid} has invalid required protections")
        source_field = rule.get("source_field", "source")
        if not isinstance(source_field, str) or not source_field or source_field not in trigger_allowed:
            raise ModelError(f"obligation {oid} has an invalid source field")
    elif kind == "preceded":
        _exact_keys(rule, {"kind"}, {"capability_field"}, f"rule for {oid}")
        capability_field = rule.get("capability_field", "capability")
        if not isinstance(capability_field, str) or not capability_field or capability_field not in trigger_allowed:
            raise ModelError(f"obligation {oid} has an invalid capability field")
    elif kind == "strong_rng":
        _exact_keys(rule, {"kind"}, {"source_field"}, f"rule for {oid}")
        source_field = rule.get("source_field", "source")
        if not isinstance(source_field, str) or not source_field or source_field not in trigger_allowed:
            raise ModelError(f"obligation {oid} has an invalid source field")
    elif kind == "forbid":
        _exact_keys(rule, {"kind"}, {"message"}, f"rule for {oid}")
        if "message" in rule and (not isinstance(rule["message"], str) or not rule["message"]):
            raise ModelError(f"obligation {oid} has an invalid message")
    else:
        raise ModelError(f"obligation {oid} has an unsupported rule")



def _emission_flags(root: Json) -> tuple[dict[str, bool], int]:
    """Summarize whether each subtree can emit, visiting each static node once."""
    flags: dict[str, bool] = {}
    visited = 0

    def visit(node: Json) -> bool:
        nonlocal visited
        visited += 1
        kind = node["kind"]
        if kind == "emit":
            emits = True
        elif kind == "seq":
            child_flags = [visit(child) for child in node["children"]]
            emits = any(child_flags)
        elif kind == "if":
            then_emits = visit(node["then"])
            else_emits = visit(node["else"])
            emits = then_emits or else_emits
        else:
            emits = visit(node["body"])
        flags[node["node"]] = emits
        return emits

    visit(root)
    return flags, visited


def _charge_work(counter: list[int], amount: int = 1) -> None:
    counter[0] += amount
    if counter[0] > MAX_TRAVERSAL_STEPS:
        raise ModelError(
            f"generator execution exceeds the {MAX_TRAVERSAL_STEPS}-step traversal bound"
        )


def _trace_event_count(
    node: Json,
    assignment: Json,
    remaining: int = MAX_TRACE_EVENTS,
    *,
    emission_flags: dict[str, bool] | None = None,
    work: list[int] | None = None,
) -> int:
    if emission_flags is None:
        emission_flags, _ = _emission_flags(node)
    if work is None:
        work = [0]
    _charge_work(work)
    if not emission_flags[node["node"]]:
        return 0
    kind = node["kind"]
    if kind == "emit":
        return 1
    if kind == "seq":
        total = 0
        for child in node["children"]:
            total += _trace_event_count(
                child, assignment, remaining - total,
                emission_flags=emission_flags, work=work
            )
            if total > remaining:
                return total
        return total
    if kind == "if":
        condition = node["condition"]
        branch = node["then"] if same_json_value(assignment[condition["field"]], condition["equals"]) else node["else"]
        return _trace_event_count(
            branch, assignment, remaining, emission_flags=emission_flags, work=work
        )
    count = assignment[node["count_field"]]
    total = 0
    for _ in range(count):
        total += _trace_event_count(
            node["body"], assignment, remaining - total,
            emission_flags=emission_flags, work=work
        )
        if total > remaining:
            return total
    return total


def validate_case(case: Json) -> None:
    if not isinstance(case, dict):
        raise ModelError("case must be an object")
    validate_json_value(case, "case")
    _exact_keys(case, CASE_REQUIRED_FIELDS, CASE_OPTIONAL_FIELDS, "case")
    for key in ("case_id", "family"):
        if not isinstance(case[key], str) or not case[key]:
            raise ModelError(f"{key} must be a non-empty string")
    for key in ("subtype", "corpus_source", "fault_kind", "fault_detail"):
        if key in case and (not isinstance(case[key], str) or not case[key]):
            raise ModelError(f"{key} must be a non-empty string")
    if "expected" in case and case["expected"] not in {"accepted", "rejected"}:
        raise ModelError("expected must be accepted or rejected when present")
    if "historical_model" in case:
        _validate_historical_model(case["historical_model"])

    ds = domains(case["schema"])
    ids = all_node_ids(case["generator"])

    catalog = case["catalog"]
    if not isinstance(catalog, dict):
        raise ModelError("catalog must be an object")
    _exact_keys(catalog, {"obligations"}, {"name"}, "catalog")
    if "name" in catalog and (not isinstance(catalog["name"], str) or not catalog["name"]):
        raise ModelError("catalog.name must be a non-empty string")
    obligations = catalog["obligations"]
    if not isinstance(obligations, list) or not obligations:
        raise ModelError("catalog.obligations must be a non-empty list")
    seen: set[str] = set()
    for index, obligation in enumerate(obligations):
        if not isinstance(obligation, dict):
            raise ModelError("obligation must be an object")
        _exact_keys(obligation, {"id", "trigger", "rule"}, {"cwe"}, f"obligation[{index}]")
        oid = obligation["id"]
        trigger = obligation["trigger"]
        if not isinstance(oid, str) or not oid or oid in seen:
            raise ModelError("obligation ids must be unique non-empty strings")
        if "cwe" in obligation and (not isinstance(obligation["cwe"], str) or not obligation["cwe"]):
            raise ModelError(f"obligation {oid} has an invalid CWE label")
        if not isinstance(trigger, dict):
            raise ModelError(f"obligation {oid} needs a trigger object")
        operation = trigger.get("op")
        if not isinstance(operation, str) or operation not in EVENT_FIELDS:
            raise ModelError(f"obligation {oid} needs a trigger operation")
        trigger_allowed = {"op"} | EVENT_FIELDS[operation][0] | EVENT_FIELDS[operation][1]
        if not set(trigger).issubset(trigger_allowed):
            raise ModelError(f"obligation {oid} trigger uses a field absent from its event operation")
        for key, value in trigger.items():
            if not isinstance(key, str) or not key:
                raise ModelError(f"obligation {oid} has an invalid trigger field")
            if key != "op" and (not isinstance(value, str) or not value):
                raise ModelError(f"obligation {oid} has an invalid trigger value")
        _validate_rule(obligation["rule"], oid, trigger_allowed)
        seen.add(oid)

    names = set(ds)

    def check_refs(node: Json) -> None:
        kind = node["kind"]
        if kind == "seq":
            for child in node["children"]:
                check_refs(child)
        elif kind == "if":
            field = node["condition"]["field"]
            if field not in names or not any(
                same_json_value(node["condition"]["equals"], value) for value in ds[field]
            ):
                raise ModelError("if condition is outside the schema")
            check_refs(node["then"])
            check_refs(node["else"])
        elif kind == "repeat":
            field = node["count_field"]
            if field not in names or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > MAX_REPEAT_COUNT
                for value in ds[field]
            ):
                raise ModelError(
                    f"repeat fields must have integer domains between zero and {MAX_REPEAT_COUNT}"
                )
            check_refs(node["body"])
        else:
            unknown = set(node.get("declared_obligations", [])) - seen
            if unknown:
                raise ModelError(f"emit node {node['node']} declares unknown obligations {sorted(unknown)!r}")

    check_refs(case["generator"])
    assignments = raw_assignments(case["schema"])
    if len(assignments) > MAX_ASSIGNMENTS:
        raise ModelError(f"schema exceeds the frozen {MAX_ASSIGNMENTS}-assignment bound")
    emission_flags, _ = _emission_flags(case["generator"])
    for assignment in assignments:
        if _trace_event_count(
            case["generator"], assignment, emission_flags=emission_flags, work=[0]
        ) > MAX_TRACE_EVENTS:
            raise ModelError(f"generator exceeds the {MAX_TRACE_EVENTS}-event trace bound")
    _ = ids


def event_with_origin(node: Json, occurrence: Occurrence = ()) -> Json:
    """Return a public event with the generator's claimed origin and declarations."""
    event = copy.deepcopy(node["event"])
    event["origin"] = node.get("origin_override", node["node"])
    event["obligations"] = list(node.get("declared_obligations", []))
    if occurrence:
        event["occurrence"] = list(occurrence)
    return event


def execute_concrete_evidence(node: Json, assignment: Json) -> tuple[list[Json], list[str]]:
    """Execute a generator and retain the actual emit node for each public event."""
    output: list[Json] = []
    emitters: list[str] = []
    emission_flags, _ = _emission_flags(node)
    work = [0]

    def run(current: Json, occurrence: Occurrence = ()) -> None:
        _charge_work(work)
        if not emission_flags[current["node"]]:
            return
        kind = current["kind"]
        if kind == "seq":
            for child in current["children"]:
                run(child, occurrence)
        elif kind == "if":
            condition = current["condition"]
            branch = (
                current["then"]
                if same_json_value(assignment[condition["field"]], condition["equals"])
                else current["else"]
            )
            run(branch, occurrence)
        elif kind == "repeat":
            count = assignment[current["count_field"]]
            for index in range(count):
                run(current["body"], occurrence + (index,))
        else:
            if len(output) >= MAX_TRACE_EVENTS:
                raise ModelError(f"execution exceeds the {MAX_TRACE_EVENTS}-event trace bound")
            output.append(event_with_origin(current, occurrence))
            emitters.append(current["node"])

    run(node)
    return output, emitters


def execute_concrete(node: Json, assignment: Json) -> list[Json]:
    return execute_concrete_evidence(node, assignment)[0]


@dataclass(frozen=True)
class SymbolicPath:
    cube: dict[str, tuple[Any, ...]]
    events: tuple[str, ...]


def symbolic_paths(case: Json) -> list[tuple[Json, list[Json], list[str]]]:
    validate_case(case)
    ds = domains(case["schema"])
    initial = [({name: tuple(values) for name, values in ds.items()}, [], [])]
    emission_flags, _ = _emission_flags(case["generator"])
    work = [0]

    def walk(
        node: Json,
        states: list[tuple[dict[str, tuple[Any, ...]], list[Json], list[str]]],
        occurrence: Occurrence = (),
    ) -> list[tuple[dict[str, tuple[Any, ...]], list[Json], list[str]]]:
        _charge_work(work, max(1, len(states)))
        if not emission_flags[node["node"]]:
            return states
        kind = node["kind"]
        if kind == "emit":
            output = []
            for cube, events, emitters in states:
                if len(events) >= MAX_TRACE_EVENTS:
                    raise ModelError(f"symbolic execution exceeds the {MAX_TRACE_EVENTS}-event trace bound")
                output.append((cube, events + [event_with_origin(node, occurrence)], emitters + [node["node"]]))
            return output
        if kind == "seq":
            result = states
            for child in node["children"]:
                result = walk(child, result, occurrence)
            return result
        if kind == "if":
            condition = node["condition"]
            field = condition["field"]
            target = condition["equals"]
            output: list[tuple[dict[str, tuple[Any, ...]], list[Json], list[str]]] = []
            for cube, events, emitters in states:
                yes = tuple(value for value in cube[field] if same_json_value(value, target))
                no = tuple(value for value in cube[field] if not same_json_value(value, target))
                if yes:
                    next_cube = dict(cube)
                    next_cube[field] = yes
                    output.extend(walk(node["then"], [(next_cube, list(events), list(emitters))], occurrence))
                if no:
                    next_cube = dict(cube)
                    next_cube[field] = no
                    output.extend(walk(node["else"], [(next_cube, list(events), list(emitters))], occurrence))
            return output

        output = []
        field = node["count_field"]
        for cube, events, emitters in states:
            for count in cube[field]:
                next_cube = dict(cube)
                next_cube[field] = (count,)
                branch_states = [(next_cube, list(events), list(emitters))]
                for index in range(count):
                    branch_states = walk(node["body"], branch_states, occurrence + (index,))
                output.extend(branch_states)
        return output

    raw = walk(case["generator"], initial)
    return merge_equivalent_paths(case["schema"], raw)


def cube_key(schema: Json, cube: dict[str, Iterable[Any]]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    ds = domains(schema)
    return tuple((name, tuple(canonical_json(value) for value in cube[name])) for name in ds)


def merge_equivalent_paths(
    schema: Json,
    paths: list[tuple[dict[str, tuple[Any, ...]], list[Json], list[str]]],
) -> list[tuple[Json, list[Json], list[str]]]:
    ds = domains(schema)
    working = [(dict(cube), list(events), list(emitters)) for cube, events, emitters in paths]
    changed = True
    while changed:
        changed = False
        for i in range(len(working)):
            cube_a, events_a, emitters_a = working[i]
            sig_a = canonical_json({"events": events_a, "emitters": emitters_a})
            for j in range(i + 1, len(working)):
                cube_b, events_b, emitters_b = working[j]
                if canonical_json({"events": events_b, "emitters": emitters_b}) != sig_a:
                    continue
                differing = [
                    name
                    for name in ds
                    if tuple(canonical_json(value) for value in cube_a[name])
                    != tuple(canonical_json(value) for value in cube_b[name])
                ]
                if len(differing) != 1:
                    continue
                name = differing[0]
                set_a = {canonical_json(value) for value in cube_a[name]}
                set_b = {canonical_json(value) for value in cube_b[name]}
                if set_a & set_b:
                    continue
                union = [value for value in ds[name] if canonical_json(value) in set_a | set_b]
                merged = dict(cube_a)
                merged[name] = tuple(union)
                working[i] = (merged, events_a, emitters_a)
                del working[j]
                changed = True
                break
            if changed:
                break
    working.sort(key=lambda item: cube_key(schema, item[0]))
    return [({name: list(cube[name]) for name in ds}, events, emitters) for cube, events, emitters in working]


def trigger_matches(event: Json, trigger: Json) -> bool:
    return all(key in event and same_json_value(event[key], value) for key, value in trigger.items())


def required_obligations(catalog: Json, event: Json) -> list[str]:
    return sorted(
        obligation["id"]
        for obligation in catalog["obligations"]
        if trigger_matches(event, obligation["trigger"])
    )


def compact_state(protections: dict[str, set[str]], checks: set[str], strong_rng: set[str]) -> Json:
    return {
        "protections": {name: sorted(values) for name, values in sorted(protections.items()) if values},
        "checks": sorted(checks),
        "strong_rng": sorted(strong_rng),
    }


def analyze_events(catalog: Json, emitters: list[str], events: list[Json]) -> tuple[list[Json], list[Json]]:
    protections: dict[str, set[str]] = {}
    checks: set[str] = set()
    strong_rng: set[str] = set()
    steps: list[Json] = []
    violations: list[Json] = []
    by_id = {item["id"]: item for item in catalog["obligations"]}
    if len(emitters) != len(events):
        raise ModelError("emitter sequence length does not match event trace")

    for index, event in enumerate(events):
        before = compact_state(protections, checks, strong_rng)
        local: list[Json] = []
        origin = event.get("origin")
        emitter = emitters[index]
        if origin != emitter:
            local.append(
                {
                    "kind": "origin",
                    "obligation": None,
                    "event_index": index,
                    "prefix_length": index + 1,
                    "detail": f"origin {origin!r} does not match emit node {emitter!r}",
                }
            )
        required = required_obligations(catalog, event)
        declarations = event.get("obligations", [])
        if (
            not isinstance(declarations, list)
            or any(not isinstance(item, str) or not item for item in declarations)
            or len(set(declarations)) != len(declarations)
        ):
            raise ModelError("event obligation declaration is malformed")
        declared = sorted(declarations)
        if declared != required:
            local.append(
                {
                    "kind": "coverage",
                    "obligation": required[0] if required else None,
                    "event_index": index,
                    "prefix_length": index + 1,
                    "detail": f"declared obligations {declared!r} do not equal required obligations {required!r}",
                }
            )

        # Rules are evaluated against the state before the current event.  This
        # makes "preceded", "protected", and "strong" mean established earlier,
        # rather than allowing a triggering event to satisfy itself.
        for oid in required:
            rule = by_id[oid]["rule"]
            kind = rule["kind"]
            unsafe = False
            detail = ""
            if kind == "protection":
                source = event.get(rule.get("source_field", "source"))
                required_protections = set(rule["requires"])
                present = protections.get(source, set())
                unsafe = not required_protections.issubset(present)
                detail = f"value {source!r} has {sorted(present)!r}, needs {sorted(required_protections)!r}"
            elif kind == "preceded":
                capability = event.get(rule.get("capability_field", "capability"))
                unsafe = capability not in checks
                detail = f"capability {capability!r} was not checked"
            elif kind == "strong_rng":
                source = event.get(rule.get("source_field", "source"))
                unsafe = source not in strong_rng
                detail = f"random source {source!r} is not strong"
            elif kind == "forbid":
                unsafe = True
                detail = rule.get("message", "forbidden event")
            if unsafe:
                local.append(
                    {
                        "kind": "safety",
                        "obligation": oid,
                        "event_index": index,
                        "prefix_length": index + 1,
                        "detail": detail,
                    }
                )

        op = event["op"]
        if op == "source":
            target = event["target"]
            protections[target] = set()
            strong_rng.discard(target)
        elif op == "protect":
            target = event["target"]
            source = event["source"]
            source_is_strong = source in strong_rng
            protections[target] = set(protections.get(source, set())) | {event["protection"]}
            if source_is_strong:
                strong_rng.add(target)
            else:
                strong_rng.discard(target)
        elif op == "check":
            checks.add(event["capability"])
        elif op == "rng":
            target = event["target"]
            protections[target] = set()
            if event["strength"] == "strong":
                strong_rng.add(target)
            else:
                strong_rng.discard(target)

        violations.extend(local)
        steps.append(
            {
                "event_index": index,
                "before": before,
                "after": compact_state(protections, checks, strong_rng),
                "violations": local,
            }
        )
    return steps, violations


def _occurrence_suffix(event: Json) -> str:
    occurrence = event.get("occurrence")
    if occurrence is None:
        return ""
    return "[" + ".".join(str(index) for index in occurrence) + "]"


def render_program(events: list[Json]) -> list[str]:
    lines: list[str] = []
    for event in events:
        op = event["op"]
        occurrence = _occurrence_suffix(event)
        if op == "source":
            text = f"{event['target']}{occurrence} = input({event.get('input', 'request')})"
        elif op == "protect":
            text = f"{event['target']}{occurrence} = {event['protection']}({event['source']})"
        elif op == "sink":
            text = f"{event['channel']}_sink({event['source']})"
        elif op == "check":
            text = f"require({event['capability']})"
        elif op == "privileged":
            text = f"privileged({event['capability']})"
        elif op == "rng":
            text = f"{event['target']}{occurrence} = rng({event['strength']})"
        elif op == "token":
            text = f"token({event['source']})"
        elif op == "credential_use":
            text = f"credential_use({event['source']})"
        elif op == "literal_secret":
            text = f"credential_literal({event['name']})"
        elif op == "reject_input":
            text = f"reject_input({event['reason']})"
        else:
            text = f"{op}()"
        lines.append(text)
    return lines


def first_violation(case: Json, assignment: Json) -> tuple[list[Json], list[str], list[Json], list[Json]]:
    events, emitters = execute_concrete_evidence(case["generator"], assignment)
    steps, violations = analyze_events(case["catalog"], emitters, events)
    return events, render_program(events), steps, violations


def cube_assignments(schema: Json, cube: Json) -> list[Json]:
    ds = domains(schema)
    if not isinstance(cube, dict) or set(cube) != set(ds):
        raise ModelError("cube fields do not match schema")
    dimensions: list[list[Any]] = []
    for name, domain in ds.items():
        allowed = cube[name]
        if not isinstance(allowed, list) or not allowed:
            raise ModelError("cube dimensions must be non-empty lists")
        if len({canonical_json(value) for value in allowed}) != len(allowed):
            raise ModelError("cube contains duplicate values")
        if any(not any(same_json_value(value, item) for item in domain) for value in allowed):
            raise ModelError("cube contains an out-of-domain value")
        expected_order = [
            item for item in domain if any(same_json_value(item, value) for value in allowed)
        ]
        if [canonical_json(value) for value in allowed] != [canonical_json(value) for value in expected_order]:
            raise ModelError("cube values are not in schema order")
        dimensions.append(allowed)
    names = list(ds)
    return [
        dict(zip(names, copy.deepcopy(values), strict=True))
        for values in itertools.product(*dimensions)
    ]
