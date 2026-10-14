"""Small owned controls for bounded same-information reference semantics."""
import copy
import unittest
from unittest.mock import patch

from checker.check import CheckFailure, inspect_case
from checker.source_binding import verify_sources
from src.certify import make_result
from src import traceability_reference as reference


def empty_case(depth=20):
    tree = {"kind": "seq", "node": "empty", "children": []}
    for index in range(depth):
        tree = {"kind": "repeat", "node": f"repeat.{index}", "count_field": "count", "body": tree}
    return {"case_id": "owned-empty-control", "family": "owned-reference-control",
            "schema": {"fields": [{"name": "count", "domain": [4]}]},
            "catalog": {"obligations": [{"id": "sink.protected", "trigger": {"op": "sink"},
                                         "rule": {"kind": "protection", "requires": ["encode"]}}]},
            "generator": tree}


def emitting_case():
    case = empty_case(0)
    case["schema"]["fields"][0]["domain"] = [2]
    emission = {"kind": "emit", "node": "checked", "event": {"op": "check", "capability": "publish"},
                "declared_obligations": []}
    case["generator"] = {"kind": "repeat", "node": "outer", "count_field": "count",
                         "body": {"kind": "repeat", "node": "inner", "count_field": "count",
                                  "body": {"kind": "seq", "node": "body", "children": [
                                      empty_case(20)["generator"], emission]}}}
    return case


def emitting_rows():
    # Authored literal fixture, not output from any interpreter or source writer.
    lines = []
    for occurrence in ([0, 0], [0, 1], [1, 0], [1, 1]):
        event = {"origin": "checked", "obligations": [], "occurrence": occurrence}
        lines.extend(["# cg-evidence " + reference.key(event), "cg_check(capability='publish')"])
    return [{"input": {"count": 2}, "source": "\n".join(lines) + "\n"}]


class ReferenceBoundsTests(unittest.TestCase):
    def test_empty_product_is_identity_with_accounted_static_cost(self):
        for depth in (2, 20):
            with self.subTest(depth=depth):
                case = empty_case(depth)
                inspect_case(case)
                statistics = {}
                self.assertEqual(([], []), reference.reference_trace(case, {"count": 4}, statistics=statistics))
                self.assertEqual({"static_nodes": depth + 1, "node_visits": 1, "emitted_events": 0}, statistics)
                rows = [{"input": {"count": 4}, "source": ""}]
                self.assertEqual({"inputs": 1, "events": 0}, reference.verify_direct(case, rows))
                self.assertEqual(0, verify_sources(case, make_result(case), rows)["events"])

    def test_summary_and_execution_do_not_call_existing_semantics(self):
        case = emitting_case()
        inspect_case(case)
        with patch("checker.check._emission_flags", side_effect=AssertionError("shared summary")), \
             patch("src.core._emission_flags", side_effect=AssertionError("shared producer summary")), \
             patch("checker.check.emitted", side_effect=AssertionError("shared interpreter")), \
             patch("src.core.execute_concrete_evidence", side_effect=AssertionError("shared producer")), \
             patch("src.traceability_workload.generate_source", side_effect=AssertionError("source writer")):
            self.assertEqual(4, len(reference.reference_trace(case, {"count": 2})[0]))

    def test_malformed_empty_tree_cannot_bypass_admission(self):
        case = empty_case()
        case["generator"]["unexpected"] = "invalid even with no output"
        rows = [{"input": {"count": 4}, "source": ""}]
        with self.assertRaises(CheckFailure):
            reference.verify_direct(case, rows)
        certificate = make_result(empty_case())
        with self.assertRaises(CheckFailure):
            verify_sources(case, certificate, rows)

    def test_empty_summary_preserves_order_and_full_nested_occurrences(self):
        case = emitting_case()
        rows = emitting_rows()
        statistics = {}
        inspect_case(case)
        events, emitters = reference.reference_trace(case, {"count": 2}, statistics=statistics)
        self.assertEqual([[0, 0], [0, 1], [1, 0], [1, 1]], [e["occurrence"] for e in events])
        self.assertEqual(["checked"] * 4, emitters)
        self.assertEqual({"static_nodes": 25, "node_visits": 15, "emitted_events": 4}, statistics)
        self.assertEqual({"inputs": 1, "events": 4}, reference.verify_direct(case, rows))
        self.assertEqual(4, verify_sources(case, make_result(case), rows)["events"])
        changed = copy.deepcopy(rows)
        changed[0]["source"] = changed[0]["source"].replace('"occurrence":[0,0]', '"occurrence":[0,1]', 1)
        with self.assertRaises(ValueError):
            reference.verify_direct(case, changed)
        with self.assertRaises(CheckFailure):
            verify_sources(case, make_result(case), changed)

    def test_work_exhaustion_aborts_direct_and_least_failure_without_verdict(self):
        case = emitting_case()
        with patch.object(reference, "MAX_REFERENCE_STEPS", 1):
            with self.assertRaises(reference.ReferenceResourceError):
                reference.verify_direct(case, emitting_rows())
            with self.assertRaises(reference.ReferenceResourceError):
                reference.least_failure(case)

    def test_event_exhaustion_is_an_operational_abort(self):
        case = emitting_case()
        with patch.object(reference, "MAX_REFERENCE_EVENTS", 1):
            with self.assertRaises(reference.ReferenceResourceError):
                reference.verify_direct(case, emitting_rows())

    def test_fault_experiment_does_not_count_resource_abort_as_detection(self):
        from scripts.owned_traceability import rejection
        case = emitting_case()
        with patch.object(reference, "MAX_REFERENCE_STEPS", 1):
            with self.assertRaises(reference.ReferenceResourceError):
                rejection(lambda: reference.verify_direct(case, emitting_rows()))

    def test_declared_limits_match_the_admission_contract(self):
        from checker import check
        from src import core
        for module in (check, core):
            self.assertEqual(module.MAX_GENERATOR_NODES, reference.MAX_REFERENCE_NODES)
            self.assertEqual(module.MAX_TRAVERSAL_STEPS, reference.MAX_REFERENCE_STEPS)
            self.assertEqual(module.MAX_TRACE_EVENTS, reference.MAX_REFERENCE_EVENTS)


if __name__ == "__main__":
    unittest.main()
