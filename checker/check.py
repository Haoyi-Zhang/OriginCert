from __future__ import annotations

import argparse
import copy
import itertools
import json
import math
from pathlib import Path
from typing import Any

Record = dict[str, Any]
Occurrence = tuple[int, ...]

MAX_ASSIGNMENTS = 256
MAX_GENERATOR_NODES = 2_000
MAX_GENERATOR_DEPTH = 256
MAX_TRACE_EVENTS = 4_096
MAX_REPEAT_COUNT = 4
MAX_TRAVERSAL_STEPS = 2_000_000
MAX_JSON_BYTES = 64 * 1024 * 1024

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


class CheckFailure(Exception):
    """Raised when a serialized certificate or counterexample fails replay."""


def demand(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def exact_keys(value: Record, required: set[str], optional: set[str], label: str) -> None:
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    demand(not missing, f"{label} is missing {sorted(missing)!r}")
    demand(not extra, f"{label} has unknown fields {sorted(extra)!r}")


def inspect_json_value(value: Any, label: str = "value") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        demand(math.isfinite(value), f"{label} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            inspect_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            demand(isinstance(key, str), f"{label} contains a non-string object key")
            inspect_json_value(item, f"{label}.{key}")
        return
    raise CheckFailure(f"{label} contains a non-JSON value of type {type(value).__name__}")


def packed(value: Any) -> str:
    inspect_json_value(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise CheckFailure(f"value is not strict JSON: {error}") from error


def same_value(left: Any, right: Any) -> bool:
    return packed(left) == packed(right)


def inspect_event(event: Any) -> None:
    demand(isinstance(event, dict), "emit event is not an object")
    inspect_json_value(event, "emit event")
    operation = event.get("op")
    demand(isinstance(operation, str) and operation in EVENT_FIELDS, f"unsupported event operation {operation!r}")
    demand(not (RESERVED_EVENT_FIELDS & set(event)), "event template contains a reserved evidence field")
    required, optional = EVENT_FIELDS[operation]
    supplied = set(event) - {"op"}
    demand(required.issubset(supplied), f"event {operation!r} is missing an operation-specific field")
    demand(supplied.issubset(required | optional), f"event {operation!r} has an unknown operation-specific field")
    demand(
        all(isinstance(event[name], str) and event[name] for name in supplied),
        f"event {operation!r} has a non-string or empty field",
    )
    if operation == "rng":
        demand(event["strength"] in {"weak", "strong"}, "rng strength must be weak or strong")


def inspect_public_event(event: Any) -> None:
    demand(isinstance(event, dict), "serialized event is not an object")
    inspect_json_value(event, "serialized event")
    operation = event.get("op")
    demand(isinstance(operation, str) and operation in EVENT_FIELDS, f"unsupported event operation {operation!r}")
    required, optional = EVENT_FIELDS[operation]
    exact_keys(
        event,
        {"op", "origin", "obligations"} | required,
        optional | {"occurrence"},
        "serialized event",
    )
    demand(isinstance(event["origin"], str) and event["origin"], "serialized event has an invalid origin")
    declarations = event["obligations"]
    demand(
        isinstance(declarations, list)
        and all(isinstance(item, str) and item for item in declarations)
        and len(set(declarations)) == len(declarations),
        "event obligation declaration is malformed",
    )
    for name in required | (set(event) & optional):
        demand(isinstance(event[name], str) and event[name], f"event field {name!r} is invalid")
    if operation == "rng":
        demand(event["strength"] in {"weak", "strong"}, "rng strength must be weak or strong")
    if "occurrence" in event:
        occurrence = event["occurrence"]
        demand(
            isinstance(occurrence, list)
            and bool(occurrence)
            and all(
                isinstance(index, int)
                and not isinstance(index, bool)
                and 0 <= index < MAX_REPEAT_COUNT
                for index in occurrence
            ),
            "event occurrence must be a non-empty repeat-index path",
        )


def schema_domains(schema: Record) -> tuple[list[str], dict[str, list[Any]]]:
    demand(isinstance(schema, dict), "schema is not an object")
    exact_keys(schema, {"fields"}, set(), "schema")
    fields = schema["fields"]
    demand(isinstance(fields, list) and fields, "schema.fields must be non-empty")
    names: list[str] = []
    domains: dict[str, list[Any]] = {}
    assignment_count = 1
    for index, field in enumerate(fields):
        demand(isinstance(field, dict), "schema field is not an object")
        exact_keys(field, {"name", "domain"}, set(), f"schema.fields[{index}]")
        name = field["name"]
        domain = field["domain"]
        demand(isinstance(name, str) and name and name not in domains, "invalid or duplicate field name")
        demand(isinstance(domain, list) and domain, f"field {name!r} has no finite domain")
        for value_index, value in enumerate(domain):
            inspect_json_value(value, f"field {name!r} domain[{value_index}]")
        demand(
            len({packed(value) for value in domain}) == len(domain),
            f"field {name!r} has duplicate JSON values",
        )
        assignment_count *= len(domain)
        demand(
            assignment_count <= MAX_ASSIGNMENTS,
            f"schema exceeds the {MAX_ASSIGNMENTS}-assignment bound",
        )
        names.append(name)
        domains[name] = copy.deepcopy(domain)
    return names, domains


def rank(schema: Record, assignment: Record) -> tuple[Any, ...]:
    names, domains = schema_domains(schema)
    demand(isinstance(assignment, dict) and set(assignment) == set(names), "assignment fields do not match schema")
    inspect_json_value(assignment, "assignment")
    positions: list[int] = []
    for name in names:
        indices = [index for index, value in enumerate(domains[name]) if same_value(value, assignment[name])]
        demand(len(indices) == 1, f"assignment value for {name!r} is outside its domain")
        positions.append(indices[0])
    return (
        sum(position != 0 for position in positions),
        sum(positions),
        tuple(positions),
        packed(assignment),
    )


def assignment_list(schema: Record, *, structural_order: bool) -> list[Record]:
    names, domains = schema_domains(schema)
    assignments = [
        dict(zip(names, copy.deepcopy(values), strict=True))
        for values in itertools.product(*(domains[name] for name in names))
    ]
    if structural_order:
        assignments.sort(key=lambda assignment: rank(schema, assignment))
    return assignments


def inspect_tree(root: Record, schema: Record) -> set[str]:
    names, domains = schema_domains(schema)
    identities: set[str] = set()

    def visit(node: Any, depth: int) -> None:
        demand(isinstance(node, dict), "generator node is not an object")
        demand(depth <= MAX_GENERATOR_DEPTH, f"generator exceeds the depth bound of {MAX_GENERATOR_DEPTH}")
        identity = node.get("node")
        kind = node.get("kind")
        demand(isinstance(identity, str) and identity and identity not in identities, "invalid or duplicate node identity")
        demand(kind in {"seq", "if", "repeat", "emit"}, f"unsupported generator node kind {kind!r}")
        identities.add(identity)
        demand(len(identities) <= MAX_GENERATOR_NODES, f"generator exceeds the node bound of {MAX_GENERATOR_NODES}")

        if kind == "seq":
            exact_keys(node, {"node", "kind", "children"}, set(), f"seq node {identity}")
            children = node["children"]
            demand(isinstance(children, list), "sequence children must be a list")
            for child in children:
                visit(child, depth + 1)
            return

        if kind == "if":
            exact_keys(node, {"node", "kind", "condition", "then", "else"}, set(), f"if node {identity}")
            condition = node["condition"]
            demand(isinstance(condition, dict), "conditional must contain an object condition")
            exact_keys(condition, {"field", "equals"}, set(), f"condition at {identity}")
            field = condition["field"]
            demand(isinstance(field, str) and field, "conditional field is invalid")
            inspect_json_value(condition["equals"], f"condition at {identity}.equals")
            demand(
                field in names and any(same_value(condition["equals"], value) for value in domains[field]),
                "conditional is outside the schema",
            )
            visit(node["then"], depth + 1)
            visit(node["else"], depth + 1)
            return

        if kind == "repeat":
            exact_keys(node, {"node", "kind", "count_field", "body"}, set(), f"repeat node {identity}")
            field = node["count_field"]
            demand(isinstance(field, str) and field in names, "repeat count field is absent from the schema")
            demand(
                all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and 0 <= value <= MAX_REPEAT_COUNT
                    for value in domains[field]
                ),
                f"repeat count domain is outside zero through {MAX_REPEAT_COUNT}",
            )
            visit(node["body"], depth + 1)
            return

        exact_keys(
            node,
            {"node", "kind", "event"},
            {"declared_obligations", "origin_override"},
            f"emit node {identity}",
        )
        inspect_event(node["event"])
        declarations = node.get("declared_obligations", [])
        demand(
            isinstance(declarations, list)
            and all(isinstance(item, str) and item for item in declarations)
            and len(set(declarations)) == len(declarations),
            "obligation declaration contains an invalid or duplicate identifier",
        )
        if "origin_override" in node:
            demand(isinstance(node["origin_override"], str) and node["origin_override"], "origin override is invalid")

    visit(root, 1)
    return identities



def _emission_flags(root: Record) -> tuple[dict[str, bool], int]:
    """Independently summarize emitting subtrees with one static-node visit each."""
    flags: dict[str, bool] = {}
    visited = 0

    def visit(node: Record) -> bool:
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
    demand(
        counter[0] <= MAX_TRAVERSAL_STEPS,
        f"generator execution exceeds the {MAX_TRAVERSAL_STEPS}-step traversal bound",
    )

def emitted(root: Record, assignment: Record) -> tuple[list[Record], list[str]]:
    """Independently execute a generator and retain each actual emit node."""
    trace: list[Record] = []
    emitters: list[str] = []
    emission_flags, _ = _emission_flags(root)
    work = [0]

    def walk(node: Record, occurrence: Occurrence = ()) -> None:
        _charge_work(work)
        if not emission_flags[node["node"]]:
            return
        kind = node["kind"]
        if kind == "seq":
            for child in node["children"]:
                walk(child, occurrence)
        elif kind == "if":
            condition = node["condition"]
            branch = (
                node["then"]
                if same_value(assignment[condition["field"]], condition["equals"])
                else node["else"]
            )
            walk(branch, occurrence)
        elif kind == "repeat":
            for index in range(assignment[node["count_field"]]):
                walk(node["body"], occurrence + (index,))
        else:
            demand(len(trace) < MAX_TRACE_EVENTS, f"execution exceeds the {MAX_TRACE_EVENTS}-event trace bound")
            event = copy.deepcopy(node["event"])
            event["origin"] = node.get("origin_override", node["node"])
            event["obligations"] = list(node.get("declared_obligations", []))
            if occurrence:
                event["occurrence"] = list(occurrence)
            trace.append(event)
            emitters.append(node["node"])

    walk(root)
    return trace, emitters


def obligation_map(catalog: Record) -> tuple[list[Record], dict[str, Record]]:
    demand(isinstance(catalog, dict), "catalogue is not an object")
    exact_keys(catalog, {"obligations"}, {"name"}, "catalogue")
    if "name" in catalog:
        demand(isinstance(catalog["name"], str) and catalog["name"], "catalogue name is invalid")
    obligations = catalog["obligations"]
    demand(isinstance(obligations, list) and obligations, "catalogue has no obligations")
    by_id: dict[str, Record] = {}
    for index, obligation in enumerate(obligations):
        demand(isinstance(obligation, dict), "obligation is not an object")
        exact_keys(obligation, {"id", "trigger", "rule"}, {"cwe"}, f"obligation[{index}]")
        identifier = obligation["id"]
        trigger = obligation["trigger"]
        rule = obligation["rule"]
        demand(isinstance(identifier, str) and identifier and identifier not in by_id, "invalid or duplicate obligation id")
        if "cwe" in obligation:
            demand(isinstance(obligation["cwe"], str) and obligation["cwe"], f"obligation {identifier!r} has an invalid CWE label")
        demand(isinstance(trigger, dict), f"obligation {identifier!r} has no trigger object")
        operation = trigger.get("op")
        demand(isinstance(operation, str) and operation in EVENT_FIELDS, f"obligation {identifier!r} has no supported operation trigger")
        trigger_allowed = {"op"} | EVENT_FIELDS[operation][0] | EVENT_FIELDS[operation][1]
        demand(set(trigger).issubset(trigger_allowed), f"obligation {identifier!r} trigger uses an invalid event field")
        demand(
            all(
                isinstance(key, str)
                and bool(key)
                and (key == "op" or (isinstance(value, str) and bool(value)))
                for key, value in trigger.items()
            ),
            f"obligation {identifier!r} has an invalid trigger field or value",
        )
        demand(isinstance(rule, dict), f"obligation {identifier!r} has no rule")
        kind = rule.get("kind")
        if kind == "protection":
            exact_keys(rule, {"kind", "requires"}, {"source_field"}, f"rule for {identifier}")
            requires = rule["requires"]
            demand(
                isinstance(requires, list)
                and bool(requires)
                and all(isinstance(item, str) and item for item in requires)
                and len(set(requires)) == len(requires),
                f"obligation {identifier!r} has invalid protections",
            )
            source_field = rule.get("source_field", "source")
            demand(
                isinstance(source_field, str) and source_field and source_field in trigger_allowed,
                f"obligation {identifier!r} has an invalid source field",
            )
        elif kind == "preceded":
            exact_keys(rule, {"kind"}, {"capability_field"}, f"rule for {identifier}")
            capability_field = rule.get("capability_field", "capability")
            demand(
                isinstance(capability_field, str) and capability_field and capability_field in trigger_allowed,
                f"obligation {identifier!r} has an invalid capability field",
            )
        elif kind == "strong_rng":
            exact_keys(rule, {"kind"}, {"source_field"}, f"rule for {identifier}")
            source_field = rule.get("source_field", "source")
            demand(
                isinstance(source_field, str) and source_field and source_field in trigger_allowed,
                f"obligation {identifier!r} has an invalid source field",
            )
        elif kind == "forbid":
            exact_keys(rule, {"kind"}, {"message"}, f"rule for {identifier}")
            if "message" in rule:
                demand(isinstance(rule["message"], str) and rule["message"], f"obligation {identifier!r} has an invalid message")
        else:
            raise CheckFailure(f"obligation {identifier!r} has an unsupported rule")
        by_id[identifier] = obligation
    return obligations, by_id


def inspect_historical_model(value: Any) -> None:
    demand(isinstance(value, dict), "historical_model is not an object")
    exact_keys(value, {"anchor", "state", "record", "cve", "scope"}, set(), "historical_model")
    demand(all(isinstance(item, str) and item for item in value.values()), "historical_model contains an invalid field")
    demand(value["state"] in {"patched", "vulnerable"}, "historical_model state is invalid")


def inspect_subject(subject: Any) -> None:
    demand(isinstance(subject, dict), "result subject is not an object")
    exact_keys(subject, CASE_REQUIRED_FIELDS, SUBJECT_OPTIONAL_FIELDS, "result subject")
    demand(isinstance(subject["case_id"], str) and subject["case_id"], "subject case_id is invalid")
    demand(isinstance(subject["family"], str) and subject["family"], "subject family is invalid")
    for key in ("subtype", "corpus_source"):
        if key in subject:
            demand(isinstance(subject[key], str) and subject[key], f"subject {key} is invalid")
    if "historical_model" in subject:
        inspect_historical_model(subject["historical_model"])
    identities = inspect_tree(subject["generator"], subject["schema"])
    _, by_id = obligation_map(subject["catalog"])
    known = set(by_id)

    def declarations(node: Record) -> None:
        if node["kind"] == "seq":
            for child in node["children"]:
                declarations(child)
        elif node["kind"] == "if":
            declarations(node["then"])
            declarations(node["else"])
        elif node["kind"] == "repeat":
            declarations(node["body"])
        else:
            unknown = set(node.get("declared_obligations", [])) - known
            demand(not unknown, f"emit node {node['node']} declares unknown obligations {sorted(unknown)!r}")

    declarations(subject["generator"])
    names, domains = schema_domains(subject["schema"])
    domain_cardinality = math.prod(len(domains[name]) for name in names)
    demand(
        domain_cardinality <= MAX_ASSIGNMENTS,
        f"schema exceeds the {MAX_ASSIGNMENTS}-assignment bound",
    )
    full_domain = {name: tuple(copy.deepcopy(domains[name])) for name in names}
    leaves = symbolic_emitted(subject["generator"], full_domain)
    demand(
        len(leaves) <= MAX_ASSIGNMENTS,
        f"symbolic execution exceeds the {MAX_ASSIGNMENTS}-region bound",
    )
    for _, trace, _ in leaves:
        demand(len(trace) <= MAX_TRACE_EVENTS, f"generator exceeds the {MAX_TRACE_EVENTS}-event trace bound")
    _ = identities


def inspect_case(case: Any) -> None:
    demand(isinstance(case, dict), "case is not an object")
    inspect_json_value(case, "case")
    exact_keys(case, CASE_REQUIRED_FIELDS, CASE_OPTIONAL_FIELDS, "case")
    demand(isinstance(case["case_id"], str) and case["case_id"], "case_id is invalid")
    demand(isinstance(case["family"], str) and case["family"], "family is invalid")
    for key in ("subtype", "corpus_source", "fault_kind", "fault_detail"):
        if key in case:
            demand(isinstance(case[key], str) and case[key], f"{key} is invalid")
    if "expected" in case:
        demand(case["expected"] in {"accepted", "rejected"}, "expected label is invalid")
    if "historical_model" in case:
        inspect_historical_model(case["historical_model"])
    subject = {key: case[key] for key in CASE_REQUIRED_FIELDS}
    for key in SUBJECT_OPTIONAL_FIELDS:
        if key in case:
            subject[key] = case[key]
    inspect_subject(subject)


def triggered(event: Record, obligation: Record) -> bool:
    return all(key in event and same_value(event[key], value) for key, value in obligation["trigger"].items())


def state_record(
    protections: dict[str, set[str]],
    checks: set[str],
    strong_sources: set[str],
) -> Record:
    return {
        "protections": {
            name: sorted(values)
            for name, values in sorted(protections.items())
            if values
        },
        "checks": sorted(checks),
        "strong_rng": sorted(strong_sources),
    }


def replay(catalog: Record, emitters: list[str], trace: list[Record]) -> tuple[list[Record], list[Record]]:
    obligations, by_id = obligation_map(catalog)
    demand(len(emitters) == len(trace), "emitter sequence length does not match the trace")
    demand(len(trace) <= MAX_TRACE_EVENTS, f"trace exceeds the {MAX_TRACE_EVENTS}-event bound")
    protections: dict[str, set[str]] = {}
    checks: set[str] = set()
    strong_sources: set[str] = set()
    steps: list[Record] = []
    failures: list[Record] = []

    for position, event in enumerate(trace):
        inspect_public_event(event)
        before = state_record(protections, checks, strong_sources)
        local: list[Record] = []

        claimed_origin = event["origin"]
        actual_emitter = emitters[position]
        if claimed_origin != actual_emitter:
            local.append(
                {
                    "kind": "origin",
                    "obligation": None,
                    "event_index": position,
                    "prefix_length": position + 1,
                    "detail": f"origin {claimed_origin!r} does not match emit node {actual_emitter!r}",
                }
            )

        required = sorted(
            obligation["id"]
            for obligation in obligations
            if triggered(event, obligation)
        )
        declared = sorted(event["obligations"])
        if declared != required:
            local.append(
                {
                    "kind": "coverage",
                    "obligation": required[0] if required else None,
                    "event_index": position,
                    "prefix_length": position + 1,
                    "detail": f"declared obligations {declared!r} do not equal required obligations {required!r}",
                }
            )

        # Evaluate all obligations on the pre-event state.  A check, protection,
        # or RNG declaration cannot satisfy an obligation triggered by itself.
        for identifier in required:
            rule = by_id[identifier]["rule"]
            kind = rule["kind"]
            unsafe = False
            explanation = ""
            if kind == "protection":
                source = event.get(rule.get("source_field", "source"))
                present = protections.get(source, set())
                needed = set(rule["requires"])
                unsafe = not needed.issubset(present)
                explanation = f"value {source!r} has {sorted(present)!r}, needs {sorted(needed)!r}"
            elif kind == "preceded":
                capability = event.get(rule.get("capability_field", "capability"))
                unsafe = capability not in checks
                explanation = f"capability {capability!r} was not checked"
            elif kind == "strong_rng":
                source = event.get(rule.get("source_field", "source"))
                unsafe = source not in strong_sources
                explanation = f"random source {source!r} is not strong"
            else:
                unsafe = True
                explanation = rule.get("message", "forbidden event")
            if unsafe:
                local.append(
                    {
                        "kind": "safety",
                        "obligation": identifier,
                        "event_index": position,
                        "prefix_length": position + 1,
                        "detail": explanation,
                    }
                )

        operation = event["op"]
        if operation == "source":
            target = event["target"]
            protections[target] = set()
            strong_sources.discard(target)
        elif operation == "protect":
            target = event["target"]
            source = event["source"]
            source_is_strong = source in strong_sources
            protections[target] = set(protections.get(source, set()))
            protections[target].add(event["protection"])
            if source_is_strong:
                strong_sources.add(target)
            else:
                strong_sources.discard(target)
        elif operation == "check":
            checks.add(event["capability"])
        elif operation == "rng":
            target = event["target"]
            protections[target] = set()
            if event["strength"] == "strong":
                strong_sources.add(target)
            else:
                strong_sources.discard(target)

        failures.extend(local)
        steps.append(
            {
                "event_index": position,
                "before": before,
                "after": state_record(protections, checks, strong_sources),
                "violations": local,
            }
        )
    return steps, failures


def occurrence_suffix(event: Record) -> str:
    occurrence = event.get("occurrence")
    if occurrence is None:
        return ""
    return "[" + ".".join(str(index) for index in occurrence) + "]"


def pretty_program(trace: list[Record]) -> list[str]:
    rendered: list[str] = []
    for event in trace:
        operation = event["op"]
        occurrence = occurrence_suffix(event)
        if operation == "source":
            text = f"{event['target']}{occurrence} = input({event.get('input', 'request')})"
        elif operation == "protect":
            text = f"{event['target']}{occurrence} = {event['protection']}({event['source']})"
        elif operation == "sink":
            text = f"{event['channel']}_sink({event['source']})"
        elif operation == "check":
            text = f"require({event['capability']})"
        elif operation == "privileged":
            text = f"privileged({event['capability']})"
        elif operation == "rng":
            text = f"{event['target']}{occurrence} = rng({event['strength']})"
        elif operation == "token":
            text = f"token({event['source']})"
        elif operation == "credential_use":
            text = f"credential_use({event['source']})"
        elif operation == "literal_secret":
            text = f"credential_literal({event['name']})"
        elif operation == "reject_input":
            text = f"reject_input({event['reason']})"
        else:
            text = f"{operation}()"
        rendered.append(text)
    return rendered


def subject_from_case(case: Record) -> Record:
    subject = {
        key: case[key]
        for key in ("case_id", "family", "schema", "catalog", "generator")
    }
    for key in ("subtype", "corpus_source", "historical_model"):
        if key in case:
            subject[key] = case[key]
    return subject


def cube_dimensions(
    schema: Record,
    cube: Record,
) -> tuple[list[str], dict[str, list[Any]], dict[str, tuple[Any, ...]]]:
    names, domains = schema_domains(schema)
    demand(isinstance(cube, dict) and set(cube) == set(names), "cube fields do not match schema")
    dimensions: dict[str, tuple[Any, ...]] = {}
    for name in names:
        allowed = cube[name]
        demand(isinstance(allowed, list) and allowed, f"cube dimension {name!r} is empty")
        demand(len({packed(value) for value in allowed}) == len(allowed), f"cube dimension {name!r} has duplicates")
        demand(
            all(any(same_value(value, domain_value) for domain_value in domains[name]) for value in allowed),
            f"cube dimension {name!r} contains an out-of-domain value",
        )
        expected_order = [
            domain_value
            for domain_value in domains[name]
            if any(same_value(domain_value, value) for value in allowed)
        ]
        demand(
            [packed(value) for value in allowed] == [packed(value) for value in expected_order],
            f"cube dimension {name!r} is not in schema order",
        )
        dimensions[name] = tuple(copy.deepcopy(allowed))
    return names, domains, dimensions


def cube_members(schema: Record, cube: Record) -> list[Record]:
    names, _, dimensions = cube_dimensions(schema, cube)
    return [
        dict(zip(names, copy.deepcopy(values), strict=True))
        for values in itertools.product(*(dimensions[name] for name in names))
    ]


def cube_cardinality(dimensions: dict[str, tuple[Any, ...]]) -> int:
    return math.prod(len(values) for values in dimensions.values())


def cubes_overlap(
    names: list[str],
    left: dict[str, tuple[Any, ...]],
    right: dict[str, tuple[Any, ...]],
) -> bool:
    return all(
        bool({packed(value) for value in left[name]} & {packed(value) for value in right[name]})
        for name in names
    )


def symbolic_emitted(
    root: Record,
    dimensions: dict[str, tuple[Any, ...]],
) -> list[tuple[dict[str, tuple[Any, ...]], list[Record], list[str]]]:
    """Execute one rectangular input region without enumerating its assignments.

    Conditions split only the affected coordinate and repeats split only their
    count coordinate. Each returned leaf therefore denotes a subcube whose
    members share one trace and one actual-emitter sequence.
    """

    State = tuple[dict[str, tuple[Any, ...]], list[Record], list[str]]
    emission_flags, _ = _emission_flags(root)
    work = [0]

    def walk(node: Record, states: list[State], occurrence: Occurrence = ()) -> list[State]:
        _charge_work(work, max(1, len(states)))
        if not emission_flags[node["node"]]:
            return states
        kind = node["kind"]
        if kind == "emit":
            output: list[State] = []
            for cube, trace, emitters in states:
                demand(
                    len(trace) < MAX_TRACE_EVENTS,
                    f"symbolic execution exceeds the {MAX_TRACE_EVENTS}-event trace bound",
                )
                event = copy.deepcopy(node["event"])
                event["origin"] = node.get("origin_override", node["node"])
                event["obligations"] = list(node.get("declared_obligations", []))
                if occurrence:
                    event["occurrence"] = list(occurrence)
                output.append((dict(cube), trace + [event], emitters + [node["node"]]))
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
            output: list[State] = []
            for cube, trace, emitters in states:
                selected = tuple(value for value in cube[field] if same_value(value, target))
                rejected = tuple(value for value in cube[field] if not same_value(value, target))
                if selected:
                    next_cube = dict(cube)
                    next_cube[field] = selected
                    output.extend(walk(node["then"], [(next_cube, list(trace), list(emitters))], occurrence))
                if rejected:
                    next_cube = dict(cube)
                    next_cube[field] = rejected
                    output.extend(walk(node["else"], [(next_cube, list(trace), list(emitters))], occurrence))
            return output

        output: list[State] = []
        count_field = node["count_field"]
        for cube, trace, emitters in states:
            for count in cube[count_field]:
                next_cube = dict(cube)
                next_cube[count_field] = (count,)
                branch_states: list[State] = [(next_cube, list(trace), list(emitters))]
                for index in range(count):
                    branch_states = walk(node["body"], branch_states, occurrence + (index,))
                output.extend(branch_states)
        return output

    initial: list[State] = [
        ({name: tuple(copy.deepcopy(values)) for name, values in dimensions.items()}, [], [])
    ]
    return walk(root, initial)


def inspect_state(value: Any, label: str) -> None:
    demand(isinstance(value, dict), f"{label} is not an object")
    exact_keys(value, {"protections", "checks", "strong_rng"}, set(), label)
    protections = value["protections"]
    demand(isinstance(protections, dict), f"{label}.protections is not an object")
    for name, entries in protections.items():
        demand(isinstance(name, str) and name, f"{label}.protections has an invalid name")
        demand(
            isinstance(entries, list)
            and all(isinstance(item, str) and item for item in entries)
            and entries == sorted(set(entries)),
            f"{label}.protections[{name!r}] is malformed",
        )
    for field in ("checks", "strong_rng"):
        entries = value[field]
        demand(
            isinstance(entries, list)
            and all(isinstance(item, str) and item for item in entries)
            and entries == sorted(set(entries)),
            f"{label}.{field} is malformed",
        )


def inspect_violation(value: Any, label: str) -> None:
    demand(isinstance(value, dict), f"{label} is not an object")
    exact_keys(value, {"kind", "obligation", "event_index", "prefix_length", "detail"}, set(), label)
    demand(value["kind"] in {"origin", "coverage", "safety"}, f"{label}.kind is invalid")
    demand(value["obligation"] is None or (isinstance(value["obligation"], str) and value["obligation"]), f"{label}.obligation is invalid")
    demand(isinstance(value["event_index"], int) and not isinstance(value["event_index"], bool) and value["event_index"] >= 0, f"{label}.event_index is invalid")
    demand(isinstance(value["prefix_length"], int) and not isinstance(value["prefix_length"], bool) and value["prefix_length"] == value["event_index"] + 1, f"{label}.prefix_length is invalid")
    demand(isinstance(value["detail"], str) and value["detail"], f"{label}.detail is invalid")


def inspect_monitor_steps(value: Any) -> None:
    demand(isinstance(value, list), "monitor_steps is not a list")
    for index, step in enumerate(value):
        demand(isinstance(step, dict), "monitor step is not an object")
        exact_keys(step, {"event_index", "before", "after", "violations"}, set(), f"monitor_steps[{index}]")
        demand(
            type(step["event_index"]) is int and step["event_index"] == index,
            "monitor step indices are not exact contiguous integers",
        )
        inspect_state(step["before"], f"monitor_steps[{index}].before")
        inspect_state(step["after"], f"monitor_steps[{index}].after")
        demand(isinstance(step["violations"], list), "monitor step violations are not a list")
        for vindex, violation in enumerate(step["violations"]):
            inspect_violation(violation, f"monitor_steps[{index}].violations[{vindex}]")


def inspect_program(value: Any, label: str) -> None:
    demand(isinstance(value, list) and all(isinstance(line, str) for line in value), f"{label} is not a string list")


def inspect_result(result: Any) -> None:
    demand(isinstance(result, dict), "result is not an object")
    inspect_json_value(result, "result")
    kind = result.get("kind")
    if kind == "certificate":
        exact_keys(result, {"kind", "subject", "claim", "cells"}, set(), "certificate")
        inspect_subject(result["subject"])
        claim = result["claim"]
        demand(isinstance(claim, dict), "certificate claim is not an object")
        exact_keys(claim, {"origin_complete", "obligation_complete", "trace_safe", "domain_partitioned"}, set(), "certificate claim")
        demand(all(value is True for value in claim.values()), "certificate claim must contain four true predicates")
        cells = result["cells"]
        demand(isinstance(cells, list) and cells, "certificate has no cells")
        for index, cell in enumerate(cells):
            demand(isinstance(cell, dict), "certificate cell is not an object")
            exact_keys(cell, {"cube", "program", "events", "monitor_steps"}, set(), f"certificate cell {index}")
            demand(isinstance(cell["cube"], dict), "certificate cell cube is not an object")
            inspect_program(cell["program"], f"certificate cell {index} program")
            demand(isinstance(cell["events"], list), "certificate cell events are not a list")
            for event in cell["events"]:
                inspect_public_event(event)
            inspect_monitor_steps(cell["monitor_steps"])
    elif kind == "counterexample":
        exact_keys(result, {"kind", "subject", "witness"}, set(), "counterexample")
        inspect_subject(result["subject"])
        witness = result["witness"]
        demand(isinstance(witness, dict), "counterexample witness is not an object")
        exact_keys(
            witness,
            {"input", "input_size", "program", "events", "monitor_steps", "violation", "violating_prefix"},
            set(),
            "counterexample witness",
        )
        demand(isinstance(witness["input"], dict), "counterexample input is not an object")
        demand(isinstance(witness["input_size"], int) and not isinstance(witness["input_size"], bool) and witness["input_size"] >= 0, "counterexample input_size is invalid")
        inspect_program(witness["program"], "counterexample program")
        for name in ("events", "violating_prefix"):
            demand(isinstance(witness[name], list), f"counterexample {name} is not a list")
            for event in witness[name]:
                inspect_public_event(event)
        inspect_monitor_steps(witness["monitor_steps"])
        inspect_violation(witness["violation"], "counterexample violation")
    else:
        raise CheckFailure("result has an unknown kind")


def classify_case(case: Record) -> str:
    """Classify a supplied generator by checker-side exhaustive replay."""
    inspect_case(case)
    for assignment in assignment_list(case["schema"], structural_order=False):
        trace, emitters = emitted(case["generator"], assignment)
        _, failures = replay(case["catalog"], emitters, trace)
        if failures:
            return "rejected"
    return "accepted"


def verify_certificate(case: Record, result: Record) -> None:
    demand(
        result["claim"]
        == {
            "origin_complete": True,
            "obligation_complete": True,
            "trace_safe": True,
            "domain_partitioned": True,
        },
        "certificate claim is malformed",
    )
    cells = result["cells"]
    names, domains = schema_domains(case["schema"])
    checked_cubes: list[dict[str, tuple[Any, ...]]] = []
    covered_cardinality = 0

    for cell_index, cell in enumerate(cells):
        _, _, dimensions = cube_dimensions(case["schema"], cell["cube"])
        for earlier_index, earlier in enumerate(checked_cubes):
            demand(
                not cubes_overlap(names, earlier, dimensions),
                f"certificate cells {earlier_index} and {cell_index} overlap",
            )
        checked_cubes.append(dimensions)
        covered_cardinality += cube_cardinality(dimensions)

        leaves = symbolic_emitted(case["generator"], dimensions)
        demand(leaves, "certificate cell denotes no symbolic executions")
        demand(
            len(leaves) <= MAX_ASSIGNMENTS,
            f"certificate cell {cell_index} exceeds the symbolic-region bound",
        )
        for _, trace, emitters in leaves:
            steps, failures = replay(case["catalog"], emitters, trace)
            demand(not failures, f"certificate cell {cell_index} contains a rejecting symbolic path")
            demand(cell["events"] == trace, f"event replay differs in certificate cell {cell_index}")
            demand(cell["program"] == pretty_program(trace), f"program replay differs in certificate cell {cell_index}")
            demand(cell["monitor_steps"] == steps, f"monitor replay differs in certificate cell {cell_index}")

    domain_cardinality = math.prod(len(domains[name]) for name in names)
    demand(
        covered_cardinality == domain_cardinality,
        "certificate cells do not exactly partition the schema",
    )


def verify_counterexample(case: Record, result: Record) -> None:
    witness = result["witness"]
    assignment = witness["input"]

    ordered = assignment_list(case["schema"], structural_order=True)
    keys = [packed(item) for item in ordered]
    assignment_key = packed(assignment)
    demand(assignment_key in keys, "counterexample input is outside the schema")

    trace, emitters = emitted(case["generator"], assignment)
    steps, failures = replay(case["catalog"], emitters, trace)
    demand(failures, "counterexample input satisfies the contract")
    first = failures[0]
    demand(witness["events"] == trace, "counterexample trace differs from replay")
    demand(witness["program"] == pretty_program(trace), "counterexample program differs from replay")
    demand(witness["monitor_steps"] == steps, "counterexample monitor trace differs from replay")
    demand(witness["violation"] == first, "reported violation is not the first replayed violation")
    demand(witness["violating_prefix"] == trace[: first["prefix_length"]], "counterexample prefix is incorrect")
    demand(witness["input_size"] == rank(case["schema"], assignment)[0], "counterexample input size is incorrect")

    for earlier in ordered[: keys.index(assignment_key)]:
        earlier_trace, earlier_emitters = emitted(case["generator"], earlier)
        _, earlier_failures = replay(case["catalog"], earlier_emitters, earlier_trace)
        demand(not earlier_failures, f"counterexample is not minimal; earlier input {packed(earlier)} rejects")


def verify(case: Record, result: Record) -> None:
    inspect_case(case)
    inspect_result(result)
    demand(packed(result["subject"]) == packed(subject_from_case(case)), "result is not bound to the supplied generator case")

    if result["kind"] == "certificate":
        verify_certificate(case, result)
    else:
        verify_counterexample(case, result)


def _strict_object(pairs: list[tuple[str, Any]]) -> Record:
    result: Record = {}
    for key, value in pairs:
        if key in result:
            raise CheckFailure(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CheckFailure(f"non-finite JSON number {value!r}")


def load(path: Path) -> Record:
    try:
        demand(path.stat().st_size <= MAX_JSON_BYTES, f"JSON input exceeds the {MAX_JSON_BYTES}-byte bound")
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_strict_object, parse_constant=_reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CheckFailure(f"cannot read strict JSON from {path}: {error}") from error
    demand(isinstance(value, dict), "top-level JSON value is not an object")
    inspect_json_value(value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independently check a bounded-generator certificate or counterexample."
    )
    parser.add_argument("case", type=Path)
    parser.add_argument("result", type=Path)
    arguments = parser.parse_args()
    try:
        verify(load(arguments.case), load(arguments.result))
    except (CheckFailure, KeyError, TypeError, ValueError) as error:
        print(f"REJECT: {error}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
