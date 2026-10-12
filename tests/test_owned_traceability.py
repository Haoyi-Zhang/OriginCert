import copy
import unittest
from unittest.mock import patch

from checker.check import CheckFailure, verify
from checker.source_binding import verify_sources
from checker.source_extract import extract_call_events
from src.certify import make_result
from src.traceability_reference import least_failure, reference_trace, verify_direct
from src.traceability_workload import (faulty_case, generate_bundle, owned_case,
                                      restrict_edition, source_mutants)


class OwnedTraceabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean = []
        for layout in ("inside", "outside"):
            case = owned_case(layout)
            cls.clean.append((case, make_result(case), generate_bundle(case)))

    def test_pointwise_independent_source_relation(self):
        for case, certificate, bundle in self.clean:
            self.assertEqual(144, len(bundle))
            for row in bundle:
                expected, emitters = reference_trace(case, row["input"])
                actual = extract_call_events(row["source"])
                self.assertEqual(expected, actual)
                self.assertEqual(emitters, [event["origin"] for event in actual])
            self.assertEqual(verify_direct(case, bundle)["events"],
                             verify_sources(case, certificate, bundle)["events"])

    def test_hand_calculated_nested_identity(self):
        case, _, bundle = self.clean[0]
        row = next(row for row in bundle if row["input"] == {
            "channel": "sql", "site": "primary", "admin": True,
            "batches": 2, "items": 2, "edition": "compact"})
        actual = extract_call_events(row["source"])
        self.assertEqual(20, len(actual))
        self.assertEqual(["source", "protect", "sink", "check", "privileged"] * 4,
                         [event["op"] for event in actual])
        self.assertEqual([[0, 0], [0, 1], [1, 0], [1, 1]],
                         [event["occurrence"] for event in actual[2::5]])
        self.assertEqual(["sql.primary"] * 4, [event["origin"] for event in actual[2::5]])
        self.assertEqual([["sql.protected"]] * 4, [event["obligations"] for event in actual[2::5]])

    def test_reference_does_not_call_binding_completeness_or_existing_interpreters(self):
        case, _, bundle = self.clean[0]
        with patch("checker.source_binding.source_rows", side_effect=AssertionError("shared completeness")), \
             patch("checker.check.emitted", side_effect=AssertionError("shared interpreter")), \
             patch("src.core.execute_concrete_evidence", side_effect=AssertionError("shared producer")):
            self.assertEqual(144, verify_direct(case, bundle)["inputs"])

    def test_source_only_faults_are_not_certificate_checks(self):
        for case, certificate, bundle in self.clean:
            mutants = source_mutants(bundle)
            self.assertEqual(9, len(mutants))
            for fault, rows in mutants:
                with self.subTest(layout=case["case_id"], fault=fault):
                    verify(case, certificate)  # unchanged abstract evidence passes
                    with self.assertRaises((CheckFailure, ValueError)):
                        verify_direct(case, rows)
                    with self.assertRaises(CheckFailure):
                        verify_sources(case, certificate, rows)

    def test_subject_fault_diagnostics_have_independent_least_input(self):
        for case, _, _ in self.clean:
            for fault in ("origin", "omission", "extra", "safety"):
                changed = faulty_case(case, fault)
                result = make_result(changed)
                self.assertEqual("counterexample", result["kind"])
                verify(changed, result)
                reference = least_failure(changed)
                witness = result["witness"]
                self.assertEqual(reference["input"], witness["input"])
                self.assertEqual(reference["kind"], witness["violation"]["kind"])
                self.assertEqual(reference["event_index"], witness["violation"]["event_index"])
                with self.assertRaises(ValueError):
                    verify_direct(changed, generate_bundle(changed))

    def test_reuse_intersects_binds_and_rechecks(self):
        for case, certificate, bundle in self.clean:
            changed, reused, rows = restrict_edition(case, certificate, bundle)
            self.assertEqual(72, len(rows))
            with self.assertRaises(CheckFailure):
                verify(changed, certificate)
            # No hidden producer call is allowed during the reuse check.
            with patch("src.certify.make_result", side_effect=AssertionError("fresh production")):
                self.assertEqual(72, verify_sources(changed, reused, rows)["inputs"])
                self.assertEqual(72, verify_direct(changed, rows)["inputs"])
            self.assertEqual([c["events"] for c in certificate["cells"]],
                             [c["events"] for c in reused["cells"]])
            self.assertEqual([c["monitor_steps"] for c in certificate["cells"]],
                             [c["monitor_steps"] for c in reused["cells"]])

    def test_certificate_partition_faults_remain_rejected(self):
        for case, certificate, bundle in self.clean:
            for fault in ("missing", "duplicate"):
                result = copy.deepcopy(certificate)
                if fault == "missing":
                    result["cells"].pop()
                else:
                    result["cells"].append(copy.deepcopy(result["cells"][0]))
                with self.assertRaises(CheckFailure):
                    verify_sources(case, result, bundle)

    def test_unsupported_source_is_never_executed(self):
        case, certificate, bundle = self.clean[0]
        rows = copy.deepcopy(bundle)
        rows[0]["source"] = "import os\n"
        with self.assertRaises(CheckFailure):
            verify_sources(case, certificate, rows)

    def test_diagnostic_names_actual_site_and_source_line(self):
        case, certificate, bundle = self.clean[0]
        rows = dict(source_mutants(bundle))["wrong_existing_origin"]
        with self.assertRaisesRegex(CheckFailure, "event 2 line 6.*origin.*sql.primary"):
            verify_sources(case, certificate, rows)


if __name__ == "__main__":
    unittest.main()
