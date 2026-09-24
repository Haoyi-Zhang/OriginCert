from __future__ import annotations

import copy
import inspect
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import checker.check as independent_checker
from checker.check import CheckFailure, classify_case, emitted, inspect_tree, verify
from src.certify import load_json as producer_load_json, make_result
from src.core import (
    MAX_GENERATOR_DEPTH,
    ModelError,
    analyze_events,
    canonical_assignments,
    canonical_json,
    cube_assignments,
    execute_concrete_evidence,
    first_violation,
    input_size,
    raw_assignments,
    render_program,
    trigger_matches,
    validate_case,
)


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "data" / "cases"


def load(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = sorted(
            path for path in CASE_DIR.glob("*.json") if path.name != "manifest.json"
        )
        cls.cases = [load(path) for path in cls.paths]

    def by_detail(self, detail: str):
        return next(case for case in self.cases if case["fault_detail"] == detail)

    def test_frozen_corpus_shape_and_fault_subtypes(self) -> None:
        self.assertEqual(360, len(self.cases))
        self.assertEqual(180, sum(case["expected"] == "accepted" for case in self.cases))
        self.assertEqual(108, sum(case["fault_kind"] == "semantic" for case in self.cases))
        self.assertEqual(36, sum(case["fault_kind"] == "coverage" for case in self.cases))
        self.assertEqual(36, sum(case["fault_kind"] == "origin" for case in self.cases))
        self.assertEqual(18, sum(case["fault_detail"] == "missing-obligation" for case in self.cases))
        self.assertEqual(18, sum(case["fault_detail"] == "spurious-obligation" for case in self.cases))
        self.assertEqual(18, sum(case["fault_detail"] == "nonexistent-origin" for case in self.cases))
        self.assertEqual(18, sum(case["fault_detail"] == "wrong-existing-origin" for case in self.cases))

    def test_checker_side_exhaustive_classification_matches_construction(self) -> None:
        for case in self.cases:
            self.assertEqual(case["expected"], classify_case(case), case["case_id"])

    def test_every_producer_record_matches_classification_and_verifies(self) -> None:
        for case in self.cases:
            result = make_result(case)
            verify(case, result)
            observed = "accepted" if result["kind"] == "certificate" else "rejected"
            self.assertEqual(classify_case(case), observed, case["case_id"])

    def test_construction_label_is_not_part_of_checker_trust(self) -> None:
        for expected in ("accepted", "rejected"):
            case = copy.deepcopy(next(item for item in self.cases if item["expected"] == expected))
            result = make_result(case)
            case["expected"] = "rejected" if expected == "accepted" else "accepted"
            verify(case, result)
            self.assertEqual(expected, classify_case(case))

    def test_expected_metadata_is_optional_for_production_and_checking(self) -> None:
        case = copy.deepcopy(next(item for item in self.cases if item["expected"] == "accepted"))
        del case["expected"]
        result = make_result(case)
        verify(case, result)
        self.assertEqual("accepted", classify_case(case))

    def test_checker_imports_no_producer_module(self) -> None:
        source = inspect.getsource(independent_checker)
        self.assertNotIn("from src", source)
        self.assertNotIn("import src", source)

    def test_wrong_existing_origin_is_rejected_even_when_node_membership_holds(self) -> None:
        case = self.by_detail("wrong-existing-origin")
        result = make_result(case)
        self.assertEqual("counterexample", result["kind"])
        verify(case, result)
        witness = result["witness"]
        index = witness["violation"]["event_index"]
        trace, emitters = emitted(case["generator"], witness["input"])
        nodes = inspect_tree(case["generator"], case["schema"])
        self.assertIn(trace[index]["origin"], nodes)
        self.assertNotEqual(trace[index]["origin"], emitters[index])
        self.assertEqual("origin", witness["violation"]["kind"])

    def test_missing_and_spurious_obligation_faults_are_both_checked(self) -> None:
        missing = make_result(self.by_detail("missing-obligation"))["witness"]
        spurious = make_result(self.by_detail("spurious-obligation"))["witness"]
        self.assertEqual("coverage", missing["violation"]["kind"])
        self.assertEqual("coverage", spurious["violation"]["kind"])
        miss_event = missing["events"][missing["violation"]["event_index"]]
        extra_event = spurious["events"][spurious["violation"]["event_index"]]
        self.assertEqual([], miss_event["obligations"])
        self.assertGreaterEqual(len(extra_event["obligations"]), 2)

    def test_certificate_rejects_partition_payload_and_claim_corruption(self) -> None:
        case = next(item for item in self.cases if item["expected"] == "accepted")
        result = make_result(case)
        mutations = []

        bad_claim = copy.deepcopy(result)
        bad_claim["claim"]["origin_complete"] = False
        mutations.append(bad_claim)

        missing_cell = copy.deepcopy(result)
        missing_cell["cells"].pop()
        mutations.append(missing_cell)

        bad_program = copy.deepcopy(result)
        bad_program["cells"][0]["program"].append("forged()")
        mutations.append(bad_program)

        bad_monitor = copy.deepcopy(result)
        bad_monitor["cells"][0]["monitor_steps"].clear()
        mutations.append(bad_monitor)

        bad_event = copy.deepcopy(result)
        if bad_event["cells"][0]["events"]:
            current = bad_event["cells"][0]["events"][0]["origin"]
            existing = next(
                node
                for node in sorted(inspect_tree(case["generator"], case["schema"]))
                if node != current
            )
            bad_event["cells"][0]["events"][0]["origin"] = existing
        else:
            bad_event["cells"][0]["events"].append({"op": "noop"})
        mutations.append(bad_event)

        overlap = copy.deepcopy(result)
        overlap["cells"].append(copy.deepcopy(overlap["cells"][0]))
        mutations.append(overlap)

        for changed in mutations:
            with self.assertRaises((CheckFailure, KeyError, TypeError, ValueError)):
                verify(case, changed)

    def test_certificate_checking_does_not_enumerate_schema_assignments(self) -> None:
        case = next(item for item in self.cases if item["expected"] == "accepted")
        result = make_result(case)
        with mock.patch.object(
            independent_checker,
            "assignment_list",
            side_effect=AssertionError("certificate verification enumerated the concrete domain"),
        ):
            verify(case, result)

    def test_counterexample_rejects_nonminimal_but_otherwise_exact_witness(self) -> None:
        case = next(
            item
            for item in self.cases
            if item["fault_kind"] == "semantic" and input_size(item["schema"], make_result(item)["witness"]["input"]) == 1
        )
        minimal = make_result(case)
        minimal_key = json.dumps(minimal["witness"]["input"], sort_keys=True)
        later = None
        for assignment in reversed(canonical_assignments(case["schema"])):
            events, program, steps, violations = first_violation(case, assignment)
            if violations and json.dumps(assignment, sort_keys=True) != minimal_key:
                later = {
                    "input": assignment,
                    "input_size": input_size(case["schema"], assignment),
                    "program": program,
                    "events": events,
                    "monitor_steps": steps,
                    "violation": violations[0],
                    "violating_prefix": events[: violations[0]["prefix_length"]],
                }
                break
        self.assertIsNotNone(later)
        changed = copy.deepcopy(minimal)
        changed["witness"] = later
        with self.assertRaises(CheckFailure):
            verify(case, changed)

    def test_subject_catalogue_and_schema_tampering_fail_closed(self) -> None:
        case = next(item for item in self.cases if item["expected"] == "accepted")
        result = make_result(case)

        changed_subject = copy.deepcopy(result)
        changed_subject["subject"]["case_id"] = "forged-case"
        with self.assertRaises(CheckFailure):
            verify(case, changed_subject)

        malformed_catalogue = copy.deepcopy(case)
        malformed_catalogue["catalog"]["obligations"][0]["rule"]["requires"] = []
        with self.assertRaises(CheckFailure):
            classify_case(malformed_catalogue)

        oversized = copy.deepcopy(case)
        oversized["schema"]["fields"][0]["domain"] = list(range(100))
        with self.assertRaises(CheckFailure):
            classify_case(oversized)

    def test_json_value_identity_is_unambiguous(self) -> None:
        identity_case = {
            "case_id": "unit-json-identity",
            "family": "unit",
            "schema": {"fields": [{"name": "selector", "domain": [1, True]}]},
            "catalog": {
                "obligations": [
                    {
                        "id": "unit-forbid",
                        "trigger": {"op": "literal_secret"},
                        "rule": {"kind": "forbid"},
                    }
                ]
            },
            "generator": {
                "node": "root",
                "kind": "if",
                "condition": {"field": "selector", "equals": True},
                "then": {
                    "node": "unsafe",
                    "kind": "emit",
                    "event": {"op": "literal_secret", "name": "token"},
                    "declared_obligations": ["unit-forbid"],
                },
                "else": {"node": "safe", "kind": "seq", "children": []},
            },
        }
        validate_case(identity_case)
        assignments = canonical_assignments(identity_case["schema"])
        integer_input = next(item for item in assignments if type(item["selector"]) is int)
        boolean_input = next(item for item in assignments if item["selector"] is True)
        self.assertEqual([], execute_concrete_evidence(identity_case["generator"], integer_input)[0])
        self.assertEqual(
            ["literal_secret"],
            [event["op"] for event in execute_concrete_evidence(identity_case["generator"], boolean_input)[0]],
        )
        self.assertEqual("rejected", classify_case(identity_case))
        verify(identity_case, make_result(identity_case))

        wrong_type_condition = copy.deepcopy(identity_case)
        wrong_type_condition["schema"]["fields"][0]["domain"] = [1, 2]
        with self.assertRaises(ModelError):
            validate_case(wrong_type_condition)
        with self.assertRaises(CheckFailure):
            classify_case(wrong_type_condition)

        boolean_case = {
            "case_id": "unit-json-cube",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [False, True]}]},
            "catalog": {
                "obligations": [
                    {
                        "id": "unit-forbid",
                        "trigger": {"op": "literal_secret"},
                        "rule": {"kind": "forbid"},
                    }
                ]
            },
            "generator": {"node": "root", "kind": "seq", "children": []},
        }
        boolean_result = make_result(boolean_case)
        self.assertEqual("certificate", boolean_result["kind"])
        wrong_cube_type = copy.deepcopy(boolean_result)
        first_cube = wrong_cube_type["cells"][0]["cube"]["enabled"]
        first_cube[0] = int(first_cube[0])
        with self.assertRaises(CheckFailure):
            verify(boolean_case, wrong_cube_type)

    def test_symbolic_cube_merging_respects_json_identity(self) -> None:
        case = {
            "case_id": "unit-symbolic-json-identity",
            "family": "unit",
            "schema": {"fields": [
                {"name": "selector", "domain": [1, True]},
                {"name": "flag", "domain": [False, True]},
            ]},
            "catalog": {"obligations": [{
                "id": "unused",
                "trigger": {"op": "literal_secret"},
                "rule": {"kind": "forbid"},
            }]},
            "generator": {
                "node": "outer",
                "kind": "if",
                "condition": {"field": "selector", "equals": 1},
                "then": {
                    "node": "left",
                    "kind": "if",
                    "condition": {"field": "flag", "equals": True},
                    "then": {"node": "left-true", "kind": "seq", "children": []},
                    "else": {"node": "left-false", "kind": "seq", "children": []},
                },
                "else": {
                    "node": "right",
                    "kind": "if",
                    "condition": {"field": "flag", "equals": True},
                    "then": {"node": "right-true", "kind": "seq", "children": []},
                    "else": {"node": "right-false", "kind": "seq", "children": []},
                },
            },
        }
        result = make_result(case)
        self.assertEqual("certificate", result["kind"])
        verify(case, result)
        represented = {
            canonical_json(assignment)
            for cell in result["cells"]
            for assignment in cube_assignments(case["schema"], cell["cube"])
        }
        expected = {canonical_json(assignment) for assignment in raw_assignments(case["schema"])}
        self.assertEqual(expected, represented)

    def test_subject_binding_uses_json_identity(self) -> None:
        case = {
            "case_id": "unit-subject-json-identity",
            "family": "unit",
            "schema": {"fields": [{"name": "selector", "domain": [1, 2]}]},
            "catalog": {"obligations": [{
                "id": "unused",
                "trigger": {"op": "noop"},
                "rule": {"kind": "forbid"},
            }]},
            "generator": {"node": "root", "kind": "seq", "children": []},
        }
        result = make_result(case)
        changed = copy.deepcopy(result)
        changed["subject"]["schema"]["fields"][0]["domain"][0] = True
        self.assertEqual(result["subject"], changed["subject"])
        with self.assertRaises(CheckFailure):
            verify(case, changed)

    def test_event_and_trigger_well_formedness_fail_closed(self) -> None:
        base = {
            "case_id": "unit-event-shape",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [False, True]}]},
            "catalog": {
                "obligations": [
                    {
                        "id": "unit-protection",
                        "trigger": {"op": "sink", "channel": "sql"},
                        "rule": {"kind": "protection", "requires": ["sql_escape"]},
                    }
                ]
            },
            "generator": {
                "node": "root",
                "kind": "emit",
                "event": {"op": "sink", "channel": "sql", "source": "value"},
                "declared_obligations": ["unit-protection"],
            },
        }

        malformed = []
        missing_argument = copy.deepcopy(base)
        del missing_argument["generator"]["event"]["source"]
        malformed.append(missing_argument)

        reserved_evidence = copy.deepcopy(base)
        reserved_evidence["generator"]["event"]["origin"] = "forged"
        malformed.append(reserved_evidence)

        unknown_operation = copy.deepcopy(base)
        unknown_operation["generator"]["event"] = {"op": "arbitrary"}
        malformed.append(unknown_operation)

        null_trigger = copy.deepcopy(base)
        null_trigger["catalog"]["obligations"][0]["trigger"]["channel"] = None
        malformed.append(null_trigger)

        for case in malformed:
            with self.subTest(case=case):
                with self.assertRaises(ModelError):
                    validate_case(case)
                with self.assertRaises(CheckFailure):
                    classify_case(case)

        self.assertFalse(
            trigger_matches(
                {"op": "reject_input"},
                {"op": "reject_input", "reason": None},
            )
        )
        self.assertFalse(
            independent_checker.triggered(
                {"op": "reject_input"},
                {"trigger": {"op": "reject_input", "reason": None}},
            )
        )

    def test_forbid_rule_is_supported_outside_the_frozen_corpus(self) -> None:
        case = {
            "case_id": "unit-forbid",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [False, True]}]},
            "catalog": {
                "obligations": [
                    {
                        "id": "CWE-798-no-literal",
                        "trigger": {"op": "literal_secret"},
                        "rule": {"kind": "forbid", "message": "literal credential is forbidden"},
                    }
                ]
            },
            "generator": {
                "node": "root",
                "kind": "if",
                "condition": {"field": "enabled", "equals": True},
                "then": {
                    "node": "literal",
                    "kind": "emit",
                    "event": {"op": "literal_secret", "name": "token"},
                    "declared_obligations": ["CWE-798-no-literal"],
                },
                "else": {"node": "empty", "kind": "seq", "children": []},
            },
        }
        self.assertEqual("rejected", classify_case(case))
        result = make_result(case)
        self.assertEqual("counterexample", result["kind"])
        self.assertEqual("safety", result["witness"]["violation"]["kind"])
        verify(case, result)

    def test_pre_event_semantics_prevent_self_satisfaction(self) -> None:
        cases = [
            {
                "case_id": "unit-self-check",
                "family": "unit",
                "schema": {"fields": [{"name": "enabled", "domain": [True]}]},
                "catalog": {"obligations": [{
                    "id": "needs-earlier-check",
                    "trigger": {"op": "check"},
                    "rule": {"kind": "preceded", "capability_field": "capability"},
                }]},
                "generator": {
                    "node": "check",
                    "kind": "emit",
                    "event": {"op": "check", "capability": "admin"},
                    "declared_obligations": ["needs-earlier-check"],
                },
            },
            {
                "case_id": "unit-self-protect",
                "family": "unit",
                "schema": {"fields": [{"name": "enabled", "domain": [True]}]},
                "catalog": {"obligations": [{
                    "id": "needs-earlier-protection",
                    "trigger": {"op": "protect"},
                    "rule": {"kind": "protection", "source_field": "target", "requires": ["sql_escape"]},
                }]},
                "generator": {
                    "node": "protect",
                    "kind": "emit",
                    "event": {"op": "protect", "target": "safe", "source": "raw", "protection": "sql_escape"},
                    "declared_obligations": ["needs-earlier-protection"],
                },
            },
            {
                "case_id": "unit-self-rng",
                "family": "unit",
                "schema": {"fields": [{"name": "enabled", "domain": [True]}]},
                "catalog": {"obligations": [{
                    "id": "needs-earlier-strong-rng",
                    "trigger": {"op": "rng"},
                    "rule": {"kind": "strong_rng", "source_field": "target"},
                }]},
                "generator": {
                    "node": "rng",
                    "kind": "emit",
                    "event": {"op": "rng", "target": "nonce", "strength": "strong"},
                    "declared_obligations": ["needs-earlier-strong-rng"],
                },
            },
        ]
        for case in cases:
            with self.subTest(case=case["case_id"]):
                result = make_result(case)
                self.assertEqual("counterexample", result["kind"])
                self.assertEqual("safety", result["witness"]["violation"]["kind"])
                self.assertEqual(0, result["witness"]["violation"]["event_index"])
                verify(case, result)

    def test_overwrites_invalidate_stale_value_properties(self) -> None:
        token_catalog = {"obligations": [{
            "id": "strong-token",
            "trigger": {"op": "token"},
            "rule": {"kind": "strong_rng", "source_field": "source"},
        }]}

        def emit(node: str, event: dict, obligations: list[str] | None = None) -> dict:
            value = {"node": node, "kind": "emit", "event": event}
            if obligations:
                value["declared_obligations"] = obligations
            return value

        weak_overwrite = {
            "case_id": "unit-weak-overwrite",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [True]}]},
            "catalog": token_catalog,
            "generator": {"node": "root", "kind": "seq", "children": [
                emit("strong", {"op": "rng", "target": "nonce", "strength": "strong"}),
                emit("weak", {"op": "rng", "target": "nonce", "strength": "weak"}),
                emit("token", {"op": "token", "source": "nonce"}, ["strong-token"]),
            ]},
        }
        input_overwrite = copy.deepcopy(weak_overwrite)
        input_overwrite["case_id"] = "unit-input-overwrite"
        input_overwrite["generator"]["children"][1] = emit(
            "input", {"op": "source", "target": "nonce", "input": "request"}
        )
        propagated_copy = copy.deepcopy(weak_overwrite)
        propagated_copy["case_id"] = "unit-strong-copy"
        propagated_copy["catalog"] = {"obligations": [
            token_catalog["obligations"][0],
            {
                "id": "copy-marker",
                "trigger": {"op": "noop"},
                "rule": {"kind": "forbid"},
            },
        ]}
        propagated_copy["generator"]["children"] = [
            emit("strong", {"op": "rng", "target": "nonce", "strength": "strong"}),
            emit("copy", {"op": "protect", "target": "wrapped", "source": "nonce", "protection": "opaque"}),
            emit("token", {"op": "token", "source": "wrapped"}, ["strong-token"]),
        ]

        for case in (weak_overwrite, input_overwrite):
            with self.subTest(case=case["case_id"]):
                result = make_result(case)
                self.assertEqual("counterexample", result["kind"])
                self.assertEqual("safety", result["witness"]["violation"]["kind"])
                verify(case, result)
        accepted = make_result(propagated_copy)
        self.assertEqual("certificate", accepted["kind"])
        verify(propagated_copy, accepted)

        protected_then_overwritten = {
            "case_id": "unit-protection-overwrite",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [True]}]},
            "catalog": {"obligations": [{
                "id": "sql-safe",
                "trigger": {"op": "sink", "channel": "sql"},
                "rule": {"kind": "protection", "requires": ["sql_parameter"]},
            }]},
            "generator": {"node": "root", "kind": "seq", "children": [
                emit("raw", {"op": "source", "target": "raw"}),
                emit("protect", {"op": "protect", "target": "query", "source": "raw", "protection": "sql_parameter"}),
                emit("overwrite", {"op": "rng", "target": "query", "strength": "weak"}),
                emit("sink", {"op": "sink", "channel": "sql", "source": "query"}, ["sql-safe"]),
            ]},
        }
        overwritten = make_result(protected_then_overwritten)
        self.assertEqual("counterexample", overwritten["kind"])
        verify(protected_then_overwritten, overwritten)

    def test_nested_repeat_occurrences_are_complete_paths(self) -> None:
        case = {
            "case_id": "unit-nested-repeat",
            "family": "unit",
            "schema": {"fields": [
                {"name": "outer", "domain": [2]},
                {"name": "inner", "domain": [2]},
            ]},
            "catalog": {"obligations": [{
                "id": "unused-forbid",
                "trigger": {"op": "noop"},
                "rule": {"kind": "forbid"},
            }]},
            "generator": {
                "node": "outer-repeat",
                "kind": "repeat",
                "count_field": "outer",
                "body": {
                    "node": "inner-repeat",
                    "kind": "repeat",
                    "count_field": "inner",
                    "body": {
                        "node": "source",
                        "kind": "emit",
                        "event": {"op": "source", "target": "value"},
                    },
                },
            },
        }
        assignment = {"outer": 2, "inner": 2}
        producer_events, producer_emitters = execute_concrete_evidence(case["generator"], assignment)
        checker_events, checker_emitters = emitted(case["generator"], assignment)
        expected = [[0, 0], [0, 1], [1, 0], [1, 1]]
        self.assertEqual(expected, [event["occurrence"] for event in producer_events])
        self.assertEqual(producer_events, checker_events)
        self.assertEqual(producer_emitters, checker_emitters)
        result = make_result(case)
        self.assertEqual("certificate", result["kind"])
        verify(case, result)

    def test_unknown_fields_and_unknown_declarations_fail_closed(self) -> None:
        case = copy.deepcopy(next(item for item in self.cases if item["expected"] == "accepted"))
        result = make_result(case)

        malformed_cases = []
        extra_case = copy.deepcopy(case)
        extra_case["unexpected"] = True
        malformed_cases.append(extra_case)
        extra_node = copy.deepcopy(case)
        extra_node["generator"]["unexpected"] = True
        malformed_cases.append(extra_node)
        unreachable_unknown = {
            "case_id": "unit-unreachable-unknown",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [False]}]},
            "catalog": {"obligations": [{
                "id": "known",
                "trigger": {"op": "noop"},
                "rule": {"kind": "forbid"},
            }]},
            "generator": {
                "node": "root",
                "kind": "if",
                "condition": {"field": "enabled", "equals": False},
                "then": {"node": "safe", "kind": "seq", "children": []},
                "else": {
                    "node": "unreachable",
                    "kind": "emit",
                    "event": {"op": "noop"},
                    "declared_obligations": ["missing"],
                },
            },
        }
        malformed_cases.append(unreachable_unknown)
        for malformed in malformed_cases:
            with self.subTest(case=malformed["case_id"]):
                with self.assertRaises(ModelError):
                    validate_case(malformed)
                with self.assertRaises(CheckFailure):
                    classify_case(malformed)

        result_mutations = []
        extra_result = copy.deepcopy(result)
        extra_result["unexpected"] = True
        result_mutations.append(extra_result)
        extra_cell = copy.deepcopy(result)
        extra_cell["cells"][0]["unexpected"] = True
        result_mutations.append(extra_cell)
        extra_state = copy.deepcopy(result)
        if extra_state["cells"][0]["monitor_steps"]:
            extra_state["cells"][0]["monitor_steps"][0]["before"]["unexpected"] = []
            result_mutations.append(extra_state)
        for malformed in result_mutations:
            with self.assertRaises(CheckFailure):
                verify(case, malformed)

    def test_strict_json_loaders_reject_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"case_id":"a","case_id":"b"}', encoding="utf-8")
            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"value":NaN}', encoding="utf-8")
            for path in (duplicate, nonfinite):
                with self.subTest(path=path.name):
                    with self.assertRaises((ValueError, CheckFailure)):
                        producer_load_json(path)
                    with self.assertRaises(CheckFailure):
                        independent_checker.load(path)

    def test_deterministic_microgrammar_cross_checks_independent_implementations(self) -> None:
        rng = random.Random(20260905)
        catalog = {"obligations": [
            {
                "id": "sql-safe",
                "trigger": {"op": "sink", "channel": "sql"},
                "rule": {"kind": "protection", "requires": ["sql_parameter"]},
            },
            {
                "id": "auth-checked",
                "trigger": {"op": "privileged"},
                "rule": {"kind": "preceded", "capability_field": "capability"},
            },
            {
                "id": "token-strong",
                "trigger": {"op": "token"},
                "rule": {"kind": "strong_rng", "source_field": "source"},
            },
        ]}
        event_templates = [
            ({"op": "source", "target": "raw"}, []),
            ({"op": "source", "target": "query"}, []),
            ({"op": "protect", "target": "query", "source": "raw", "protection": "sql_parameter"}, []),
            ({"op": "sink", "channel": "sql", "source": "query"}, ["sql-safe"]),
            ({"op": "check", "capability": "admin"}, []),
            ({"op": "privileged", "capability": "admin"}, ["auth-checked"]),
            ({"op": "rng", "target": "nonce", "strength": "strong"}, []),
            ({"op": "rng", "target": "nonce", "strength": "weak"}, []),
            ({"op": "token", "source": "nonce"}, ["token-strong"]),
            ({"op": "noop"}, []),
        ]

        for case_index in range(64):
            counter = 0

            def identity(prefix: str) -> str:
                nonlocal counter
                counter += 1
                return f"{prefix}-{counter}"

            def build(depth: int) -> dict:
                if depth == 0 or rng.random() < 0.42:
                    event, obligations = rng.choice(event_templates)
                    node = {
                        "node": identity("emit"),
                        "kind": "emit",
                        "event": copy.deepcopy(event),
                    }
                    if obligations:
                        node["declared_obligations"] = list(obligations)
                    return node
                choice = rng.choice(("seq", "if", "repeat"))
                if choice == "seq":
                    return {
                        "node": identity("seq"),
                        "kind": "seq",
                        "children": [build(depth - 1) for _ in range(rng.randint(1, 3))],
                    }
                if choice == "if":
                    return {
                        "node": identity("if"),
                        "kind": "if",
                        "condition": {"field": "enabled", "equals": True},
                        "then": build(depth - 1),
                        "else": build(depth - 1),
                    }
                return {
                    "node": identity("repeat"),
                    "kind": "repeat",
                    "count_field": "count",
                    "body": build(depth - 1),
                }

            case = {
                "case_id": f"unit-microgrammar-{case_index}",
                "family": "unit",
                "schema": {"fields": [
                    {"name": "enabled", "domain": [False, True]},
                    {"name": "count", "domain": [0, 1, 2]},
                ]},
                "catalog": copy.deepcopy(catalog),
                "generator": build(3),
            }
            validate_case(case)
            result = make_result(case)
            verify(case, result)
            self.assertEqual(classify_case(case), "accepted" if result["kind"] == "certificate" else "rejected")
            for assignment in canonical_assignments(case["schema"]):
                events, emitters = execute_concrete_evidence(case["generator"], assignment)
                steps, failures = analyze_events(case["catalog"], emitters, events)
                checked_events, checked_emitters = emitted(case["generator"], assignment)
                checked_steps, checked_failures = independent_checker.replay(
                    case["catalog"], checked_emitters, checked_events
                )
                self.assertEqual(events, checked_events)
                self.assertEqual(emitters, checked_emitters)
                self.assertEqual(steps, checked_steps)
                self.assertEqual(failures, checked_failures)

    def test_resource_bounds_fail_before_unbounded_enumeration(self) -> None:
        oversized_schema = {
            "case_id": "unit-too-many-assignments",
            "family": "unit",
            "schema": {"fields": [
                {"name": "left", "domain": list(range(17))},
                {"name": "right", "domain": list(range(17))},
            ]},
            "catalog": {"obligations": [{
                "id": "unused",
                "trigger": {"op": "noop"},
                "rule": {"kind": "forbid"},
            }]},
            "generator": {"node": "root", "kind": "seq", "children": []},
        }

        deep: dict = {"node": "leaf", "kind": "seq", "children": []}
        for index in range(MAX_GENERATOR_DEPTH + 1):
            deep = {"node": f"depth-{index}", "kind": "seq", "children": [deep]}
        excessive_depth = {
            "case_id": "unit-too-deep",
            "family": "unit",
            "schema": {"fields": [{"name": "enabled", "domain": [True]}]},
            "catalog": oversized_schema["catalog"],
            "generator": deep,
        }

        trace: dict = {
            "node": "emit",
            "kind": "emit",
            "event": {"op": "source", "target": "value"},
        }
        for index in range(7):
            trace = {
                "node": f"repeat-{index}",
                "kind": "repeat",
                "count_field": "count",
                "body": trace,
            }
        excessive_trace = {
            "case_id": "unit-too-many-events",
            "family": "unit",
            "schema": {"fields": [{"name": "count", "domain": [4]}]},
            "catalog": oversized_schema["catalog"],
            "generator": trace,
        }

        for malformed in (oversized_schema, excessive_depth, excessive_trace):
            with self.subTest(case=malformed["case_id"]):
                with self.assertRaises(ModelError):
                    validate_case(malformed)
                with self.assertRaises(CheckFailure):
                    classify_case(malformed)

    def test_producer_and_checker_monitor_traces_agree_on_representative_cases(self) -> None:
        details = ["none", "monitor-violation", "missing-obligation", "spurious-obligation", "wrong-existing-origin"]
        for detail in details:
            case = self.by_detail(detail)
            assignment = canonical_assignments(case["schema"])[-1]
            events, _, producer_steps, _ = first_violation(case, assignment)
            checker_events, emitters = emitted(case["generator"], assignment)
            checker_steps, _ = independent_checker.replay(case["catalog"], emitters, checker_events)
            self.assertEqual(events, checker_events)
            self.assertEqual(producer_steps, checker_steps)
            self.assertEqual(render_program(events), independent_checker.pretty_program(checker_events))


if __name__ == "__main__":
    unittest.main()
