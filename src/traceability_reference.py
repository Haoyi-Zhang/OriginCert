"""Simple exhaustive same-information reference for the owned operation subset.

Completeness/origin expectations use an iterative stack, not either existing
interpreter, the certificate partition, or the owned source writer. The strict
source parser and subject validator are shared frontends, not independent ones.
"""
from __future__ import annotations

import copy
import itertools
import json

from checker.check import inspect_case, inspect_json_value
from checker.source_extract import extract_call_events


MAX_REFERENCE_NODES = 2_000
MAX_REFERENCE_STEPS = 2_000_000
MAX_REFERENCE_EVENTS = 4_096


class ReferenceResourceError(ValueError):
    """Operational abort, not a semantic counterexample or accepted evidence."""


def emission_summary(root):
    """Independent iterative postorder summary for an already validated tree.

    All static children are visited, including both conditional branches. Only
    an emit-free subtree is skipped dynamically; the summary never validates a
    subject or replaces the shared full-tree admission check.
    """
    pending = [(root, False)]
    flags, static_nodes = {}, 0
    while pending:
        node, expanded = pending.pop()
        kind = node["kind"]
        if not expanded:
            static_nodes += 1
            if static_nodes > MAX_REFERENCE_NODES:
                raise ReferenceResourceError("reference summary exceeds its static-node bound")
            pending.append((node, True))
            if kind == "seq":
                pending.extend((child, False) for child in reversed(node["children"]))
            elif kind == "if":
                pending.extend([(node["else"], False), (node["then"], False)])
            elif kind == "repeat":
                pending.append((node["body"], False))
            elif kind != "emit":
                raise ValueError("outside reference grammar")
        elif kind == "emit":
            flags[node["node"]] = True
        elif kind == "seq":
            flags[node["node"]] = any(flags[child["node"]] for child in node["children"])
        elif kind == "if":
            flags[node["node"]] = flags[node["then"]["node"]] or flags[node["else"]["node"]]
        else:
            flags[node["node"]] = flags[node["body"]["node"]]
    return flags, static_nodes


def key(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def ordered_inputs(case):
    fields = case["schema"]["fields"]
    rows = []
    for positions in itertools.product(*(range(len(f["domain"])) for f in fields)):
        assignment = {f["name"]: copy.deepcopy(f["domain"][p]) for f, p in zip(fields, positions, strict=True)}
        rows.append(((sum(p != 0 for p in positions), sum(positions), positions, key(assignment)), assignment))
    return [assignment for _, assignment in sorted(rows)]


def reference_trace(case, assignment, *, statistics=None):
    """Reconstruct an admitted assignment with bounded work and full occurrences.

    The optional successful-run counters are work observations, not timings.
    Public validators perform full subject admission before calling this helper.
    """
    flags, static_nodes = emission_summary(case["generator"])
    pending = [(case["generator"], ())]
    events, emitters = [], []
    visits = 0
    while pending:
        node, occurrence = pending.pop()
        visits += 1
        if visits > MAX_REFERENCE_STEPS:
            raise ReferenceResourceError("reference execution exceeds its traversal-step bound")
        if not flags[node["node"]]:
            continue
        kind = node["kind"]
        if kind == "seq":
            pending.extend((child, occurrence) for child in reversed(node["children"]))
        elif kind == "if":
            condition = node["condition"]
            side = "then" if key(assignment[condition["field"]]) == key(condition["equals"]) else "else"
            pending.append((node[side], occurrence))
        elif kind == "repeat":
            pending.extend((node["body"], occurrence + (index,))
                           for index in reversed(range(assignment[node["count_field"]])))
        elif kind == "emit":
            if len(events) >= MAX_REFERENCE_EVENTS:
                raise ReferenceResourceError("reference execution exceeds its event bound")
            event = copy.deepcopy(node["event"])
            event.update(origin=node.get("origin_override", node["node"]),
                         obligations=list(node.get("declared_obligations", [])))
            if occurrence:
                event["occurrence"] = list(occurrence)
            events.append(event)
            emitters.append(node["node"])
        else:
            raise ValueError("outside reference grammar")
    if statistics is not None:
        statistics.update(static_nodes=static_nodes, node_visits=visits, emitted_events=len(events))
    return events, emitters


def first_failure(case, events, emitters):
    protections, checks = {}, set()
    for position, (event, emitter) in enumerate(zip(events, emitters, strict=True)):
        if event["origin"] != emitter:
            return {"kind": "origin", "event_index": position, "emitter": emitter}
        applicable = sorted((o for o in case["catalog"]["obligations"]
                             if all(k in event and key(event[k]) == key(v) for k, v in o["trigger"].items())),
                            key=lambda o: o["id"])
        if sorted(event["obligations"]) != [o["id"] for o in applicable]:
            return {"kind": "coverage", "event_index": position, "emitter": emitter}
        for obligation in applicable:
            rule = obligation["rule"]
            if rule["kind"] == "protection":
                safe = set(rule["requires"]) <= protections.get(event[rule.get("source_field", "source")], set())
            elif rule["kind"] == "preceded":
                safe = event[rule.get("capability_field", "capability")] in checks
            else:
                raise ValueError("outside owned reference rule subset")
            if not safe:
                return {"kind": "safety", "event_index": position, "emitter": emitter}
        op = event["op"]
        if op == "source":
            protections[event["target"]] = set()
        elif op == "protect":
            protections[event["target"]] = protections.get(event["source"], set()) | {event["protection"]}
        elif op == "check":
            checks.add(event["capability"])
        elif op not in {"sink", "privileged"}:
            raise ValueError("outside owned reference operation subset")
    return None


def least_failure(case):
    inspect_case(case)
    for assignment in ordered_inputs(case):
        events, emitters = reference_trace(case, assignment)
        failure = first_failure(case, events, emitters)
        if failure:
            return {"input": assignment, **failure}
    return None


def verify_direct(case, rows):
    """Check the same universal source-bound predicate without a certificate."""
    inspect_case(case)
    # Independent completeness reference: enumerate the specified assignment set
    # and compare exact keys, rather than the binding checker's cardinality proof.
    expected_inputs = {key(assignment) for assignment in ordered_inputs(case)}
    if not isinstance(rows, list) or len(rows) > 256:
        raise ValueError("reference bundle is not a bounded row list")
    seen = set()
    total_bytes, event_count = 0, 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"input", "source"} or not isinstance(row["input"], dict):
            raise ValueError(f"reference source row {index} has invalid fields")
        inspect_json_value(row["input"])
        assignment = row["input"]
        input_key = key(assignment)
        if input_key in seen or input_key not in expected_inputs:
            raise ValueError(f"reference source row {index} duplicates or misidentifies an input")
        seen.add(input_key)
        if not isinstance(row["source"], str):
            raise ValueError("reference source is not text")
        size = len(row["source"].encode("utf-8"))
        total_bytes += size
        if size > 4 * 1024 * 1024 or total_bytes > 64 * 1024 * 1024:
            raise ValueError("reference source bundle exceeds its byte bound")
        actual = extract_call_events(row["source"])
        expected, emitters = reference_trace(case, assignment)
        if key(actual) != key(expected):
            raise ValueError(f"source row {index}: full event relation differs")
        failure = first_failure(case, actual, emitters)
        if failure:
            raise ValueError(f"source row {index}: {failure}")
        event_count += len(actual)
    if seen != expected_inputs:
        raise ValueError("reference bundle omits specified inputs")
    return {"inputs": len(seen), "events": event_count}
