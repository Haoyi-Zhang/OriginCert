"""Portable finite regressions for payload-signature reuse; no saved-run inputs."""
from __future__ import annotations

import copy
import itertools
import json
import unittest
from unittest.mock import patch

import src.core as core
from src.certify import make_result
from checker.check import CheckFailure, verify


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def index_rectangle_reference(schema, paths):
    """Greedy first-eligible geometry on domain indices, not producer cube code."""
    fields = schema["fields"]
    rows = []
    for cube, events, emitters in paths:
        coordinates = [tuple(next(i for i, d in enumerate(f["domain"]) if wire(d) == wire(v))
                             for v in cube[f["name"]]) for f in fields]
        rows.append((coordinates, copy.deepcopy(events), list(emitters)))
    while True:
        eligible = []
        for left, right in itertools.combinations(range(len(rows)), 2):
            a, b = rows[left], rows[right]
            if wire([a[1], a[2]]) != wire([b[1], b[2]]):
                continue
            changed = [k for k in range(len(fields)) if a[0][k] != b[0][k]]
            if len(changed) == 1:
                k = changed[0]
                if set(a[0][k]).isdisjoint(b[0][k]):
                    eligible.append((left, right, k))
        if not eligible:
            break
        left, right, k = min(eligible)
        axes, events, emitters = rows[left]
        union = set(axes[k]) | set(rows[right][0][k])
        axes = list(axes)
        axes[k] = tuple(i for i in range(len(fields[k]["domain"])) if i in union)
        rows[left] = (axes, events, emitters)
        rows.pop(right)
    def key(row):
        return tuple((f["name"], tuple(wire(f["domain"][i]) for i in axis))
                     for f, axis in zip(fields, row[0]))
    rows.sort(key=key)
    return [({f["name"]: [copy.deepcopy(f["domain"][i]) for i in axis]
              for f, axis in zip(fields, axes)}, events, emitters)
            for axes, events, emitters in rows]


def merge_fixtures():
    schema = {"fields": [{"name": "z", "domain": [1, True, 1.0]},
                          {"name": "a", "domain": [None, {"b": 2, "a": 1}]}]}
    points = list(itertools.product(*(f["domain"] for f in schema["fields"])))
    for colors in itertools.product(range(2), repeat=len(points)):
        rows = [({"z": (z,), "a": (a,)}, [{"op": "noop", "color": color}], ["n"])
                for (z, a), color in zip(points, colors)]
        for order in (tuple(range(6)), (5, 4, 3, 2, 1, 0), (2, 5, 0, 3, 1, 4)):
            yield schema, [copy.deepcopy(rows[i]) for i in order]
    # A nonrectangular union must not be replaced by its bounding rectangle.
    yield schema, [({"z": (1,), "a": (None,)}, [], []),
                   ({"z": (True,), "a": ({"a": 1, "b": 2},)}, [], [])]
    yield schema, []
    yield schema, [({"z": (1, True, 1.0), "a": (None, {"a": 1, "b": 2})}, [], [])]
    for field in ("origin", "obligations", "occurrence"):
        first = {"op": "noop", field: ["x"]}
        second = {"op": "noop", field: ["y"]}
        yield schema, [({"z": (1,), "a": (None,)}, [first], ["n"]),
                       ({"z": (True,), "a": (None,)}, [second], ["n"])]
    yield schema, [({"z": (1,), "a": (None,)}, [{"op": "noop"}], ["n"]),
                   ({"z": (True,), "a": (None,)}, [{"op": "noop"}], ["other"])]


def expanded_payloads(rows):
    return sorted(wire([dict(zip(cube, values)), events, emitters])
                  for cube, events, emitters in rows
                  for values in itertools.product(*cube.values()))


def literal_execution(node, assignment, occurrence=()):
    kind = node["kind"]
    if kind == "emit":
        event = copy.deepcopy(node["event"])
        event.update(origin=node.get("origin_override", node["node"]),
                     obligations=list(node.get("declared_obligations", [])))
        if occurrence:
            event["occurrence"] = list(occurrence)
        return [event], [node["node"]]
    if kind == "if":
        c = node["condition"]
        branch = "then" if wire(assignment[c["field"]]) == wire(c["equals"]) else "else"
        return literal_execution(node[branch], assignment, occurrence)
    parts = ([literal_execution(n, assignment, occurrence) for n in node["children"]]
             if kind == "seq" else
             [literal_execution(node["body"], assignment, occurrence + (i,))
              for i in range(assignment[node["count_field"]])])
    return ([e for events, _ in parts for e in events],
            [n for _, names in parts for n in names])


def authored_cases():
    def emit(name, op="noop", declarations=(), **fields):
        return {"node": name, "kind": "emit", "event": {"op": op, **fields},
                "declared_obligations": list(declarations)}
    def seq(name, *children):
        return {"node": name, "kind": "seq", "children": list(children)}
    catalog = {"obligations": [
        {"id": "auth", "trigger": {"op": "privileged"}, "rule": {"kind": "preceded"}},
        {"id": "deny", "trigger": {"op": "literal_secret"}, "rule": {"kind": "forbid"}}]}
    for depth, empty, checked, count_order in itertools.product(
            range(3), (False, True), (False, True), ([0, 1, 2], [2, 0, 1])):
        leaf = (seq("empty") if empty else
                seq("body", emit("grant", "check", capability="admin") if checked else seq("no-grant"),
                    emit("use", "privileged", ["auth"], capability="admin")))
        for d in range(depth):
            leaf = {"node": "repeat-" + str(d), "kind": "repeat",
                    "count_field": "count", "body": leaf}
        tree = {"node": "root", "kind": "if", "condition": {"field": "mode", "equals": True},
                "then": leaf, "else": emit("other")}
        yield {"case_id": f"finite-{depth}-{empty}-{checked}-{count_order[0]}",
               "family": "unit", "schema": {"fields": [
                   {"name": "mode", "domain": [1, True, 1.0]},
                   {"name": "count", "domain": count_order}]},
               "catalog": copy.deepcopy(catalog), "generator": tree}
    base = next(authored_case_base())
    for origin, declarations in itertools.product(("use", "absent"), (["auth"], [], ["deny"])):
        case = copy.deepcopy(base)
        node = case["generator"]["children"][1]
        node["origin_override"] = origin
        node["declared_obligations"] = declarations
        case["case_id"] = "evidence-" + origin + "-" + str(len(declarations)) + "-" + str(declarations)
        yield case


def authored_case_base():
    yield {"case_id": "base", "family": "unit",
           "schema": {"fields": [{"name": "unused", "domain": [False, True]}]},
           "catalog": {"obligations": [
               {"id": "auth", "trigger": {"op": "privileged"}, "rule": {"kind": "preceded"}},
               {"id": "deny", "trigger": {"op": "literal_secret"}, "rule": {"kind": "forbid"}}]},
           "generator": {"node": "root", "kind": "seq", "children": [
               {"node": "grant", "kind": "emit", "event": {"op": "check", "capability": "admin"}},
               {"node": "use", "kind": "emit", "event": {"op": "privileged", "capability": "admin"},
                "declared_obligations": ["auth"]}]}}


def first_literal_failure(events, emitters):
    # Independent finite oracle for the authored check/privileged/noop vocabulary.
    checked = set()
    for i, (e, emitter) in enumerate(zip(events, emitters)):
        required = ["auth"] if e["op"] == "privileged" else []
        if e["origin"] != emitter:
            return i, "origin"
        if sorted(e["obligations"]) != required:
            return i, "coverage"
        if required and e["capability"] not in checked:
            return i, "safety"
        if e["op"] == "check":
            checked.add(e["capability"])
    return None


class MergeSignatureTests(unittest.TestCase):
    def test_ordered_merges_match_index_rectangle_reference(self):
        for schema, paths in merge_fixtures():
            original = wire(paths)
            actual = core.merge_equivalent_paths(schema, paths)
            self.assertEqual(wire(index_rectangle_reference(schema, paths)), wire(actual))
            self.assertEqual(expanded_payloads(paths), expanded_payloads(actual))
            self.assertEqual(original, wire(paths))

    def test_signature_is_computed_once_per_encountered_record(self):
        schema, paths = next(merge_fixtures())
        calls = []
        canonical = core.canonical_json
        def observed(value):
            if isinstance(value, dict) and set(value) == {"events", "emitters"}:
                calls.append(wire(value))
            return canonical(value)
        with patch.object(core, "canonical_json", observed):
            actual = core.merge_equivalent_paths(schema, paths)
        self.assertEqual(len(paths), len(calls))
        self.assertEqual(wire(index_rectangle_reference(schema, paths)), wire(actual))

    def test_call_local_mutation_and_typed_payload_identity(self):
        schema = {"fields": [{"name": "x", "domain": [0, 1]}]}
        for a, b in ((1, True), (1, 1.0), ({"a": 1, "b": 2}, {"b": 2, "a": 1})):
            paths = [({"x": (0,)}, [{"value": a}], ["n"]),
                     ({"x": (1,)}, [{"value": b}], ["n"])]
            self.assertEqual(wire(index_rectangle_reference(schema, paths)),
                             wire(core.merge_equivalent_paths(schema, paths)))
            paths[1][1][0]["value"] = copy.deepcopy(a)
            self.assertEqual(1, len(core.merge_equivalent_paths(schema, paths)))

    def test_malformed_input_first_error_and_singleton_validation(self):
        schema = {"fields": [{"name": "x", "domain": [0, 1, 2]}]}
        valid = ({"x": (1,)}, [], [])
        invalid = ({"x": (2,)}, [{"bad": (1,)}], [])
        with self.assertRaisesRegex(KeyError, "x"):
            core.merge_equivalent_paths(schema, [({}, [], []), valid, invalid])
        with self.assertRaisesRegex(core.ModelError, "non-JSON value of type tuple"):
            core.merge_equivalent_paths(schema, [invalid])
        with self.assertRaisesRegex(core.ModelError, "non-JSON value of type tuple"):
            core.merge_equivalent_paths(schema, [({}, [], []), invalid, valid])

    def test_literal_cartesian_certificate_and_least_counterexample(self):
        for case in authored_cases():
            fields = case["schema"]["fields"]
            indexed = list(itertools.product(*(range(len(f["domain"])) for f in fields)))
            indexed.sort(key=lambda p: (sum(i != 0 for i in p), sum(p), p))
            failures = []
            result = make_result(case)
            verify(case, result)
            for indices in indexed:
                assignment = {f["name"]: copy.deepcopy(f["domain"][i])
                              for f, i in zip(fields, indices)}
                events, names = literal_execution(case["generator"], assignment)
                self.assertEqual(wire([events, names]),
                                 wire(core.execute_concrete_evidence(case["generator"], assignment)))
                bad = first_literal_failure(events, names)
                if bad is not None:
                    failures.append((assignment, events, bad))
                if result["kind"] == "certificate":
                    matching = [c for c in result["cells"] if all(
                        any(wire(assignment[name]) == wire(v) for v in values)
                        for name, values in c["cube"].items())]
                    self.assertEqual(1, len(matching))
                    self.assertEqual(wire(events), wire(matching[0]["events"]))
                    checked = set()
                    expected_states = []
                    for event in events:
                        before = {"protections": {}, "checks": sorted(checked), "strong_rng": []}
                        if event["op"] == "check":
                            checked.add(event["capability"])
                        after = {"protections": {}, "checks": sorted(checked), "strong_rng": []}
                        expected_states.append([before, after, []])
                    self.assertEqual(wire(expected_states), wire([
                        [step["before"], step["after"], step["violations"]]
                        for step in matching[0]["monitor_steps"]]))
            self.assertEqual(bool(failures), result["kind"] == "counterexample")
            if failures:
                assignment, events, (i, kind) = failures[0]
                self.assertEqual(wire(assignment), wire(result["witness"]["input"]))
                self.assertEqual(wire(events), wire(result["witness"]["events"]))
                self.assertEqual((i, kind), (result["witness"]["violation"]["event_index"],
                                           result["witness"]["violation"]["kind"]))

    def test_checker_rejects_corruption_and_keeps_budget_boundary(self):
        case = next(authored_case_base())
        result = make_result(case)
        for mutation in ("cube", "origin", "state", "claim"):
            changed = copy.deepcopy(result)
            if mutation == "cube":
                changed["cells"].append(copy.deepcopy(changed["cells"][0]))
            elif mutation == "origin":
                changed["cells"][0]["events"][0]["origin"] = "absent"
            elif mutation == "state":
                changed["cells"][0]["monitor_steps"][0]["after"]["checks"] = []
            else:
                changed["claim"]["trace_safe"] = False
            with self.subTest(mutation=mutation), self.assertRaises(CheckFailure):
                verify(case, changed)
        amounts = []
        charge = core._charge_work
        def observed(counter, amount=1):
            amounts.append(amount)
            return charge(counter, amount)
        with patch.object(core, "_charge_work", observed):
            self.assertEqual(wire(result), wire(make_result(case)))
        self.assertTrue(amounts)
        with patch.object(core, "MAX_TRAVERSAL_STEPS", 0):
            with self.assertRaises(core.ModelError):
                make_result(case)


if __name__ == "__main__":
    unittest.main()
