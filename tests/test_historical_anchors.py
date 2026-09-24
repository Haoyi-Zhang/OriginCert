from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from checker.check import emitted as checker_emitted
from checker.check import pretty_program as checker_pretty_program
from checker.check import replay as checker_replay
from checker.check import CheckFailure, classify_case, verify
from src.certify import make_result
from src.core import analyze_events, canonical_assignments, execute_concrete_evidence, render_program
from src.evaluate import control_shape, node_count, pure_control_shape
from src.historical_models import ANCHORS, classify as classify_historical, render as render_historical

ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "data" / "cases"


class HistoricalAnchorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(CASE_DIR.glob("*.json"))
            if path.name != "manifest.json"
        ]
        cls.historical = [
            case for case in cls.cases
            if case.get("corpus_source") == "public-advisory-abstraction"
        ]

    def test_corpus_split_and_balanced_anchor_states(self) -> None:
        self.assertEqual(360, len(self.cases))
        self.assertEqual(324, sum(case.get("corpus_source") == "constructed" for case in self.cases))
        self.assertEqual(36, len(self.historical))
        self.assertEqual(3, len({case["historical_model"]["anchor"] for case in self.historical}))
        self.assertEqual(18, sum(case["historical_model"]["state"] == "patched" for case in self.historical))
        self.assertEqual(18, sum(case["historical_model"]["state"] == "vulnerable" for case in self.historical))

    def test_historical_oracle_matches_every_anchor_case(self) -> None:
        for case in self.historical:
            model = case["historical_model"]
            patched = model["state"] == "patched"
            observed = classify_historical(model["anchor"], patched, canonical_assignments(case["schema"]))
            self.assertEqual(case["expected"], observed, case["case_id"])
            self.assertEqual(classify_case(case), observed, case["case_id"])

    def test_historical_records_and_payloads_are_bounded(self) -> None:
        facts = json.loads((ROOT / "external_inputs" / "advisory_anchors.json").read_text(encoding="utf-8"))
        self.assertEqual({item["record"] for item in ANCHORS.values()}, {item["record"] for item in facts["records"]})
        forbidden_execution_markers = {
            "child_process", "execsync", "process.start", "os.system", "subprocess", "__import__", "eval(", "exec(",
        }
        for case in self.historical:
            model = case["historical_model"]
            patched = model["state"] == "patched"
            for assignment in canonical_assignments(case["schema"]):
                rendered = render_historical(model["anchor"], patched, assignment)["rendered"].lower()
                self.assertTrue(all(marker not in rendered for marker in forbidden_execution_markers), rendered)

        case = self.historical[0]
        changed = make_result(case)
        changed["subject"]["historical_model"]["record"] = "forged-record"
        with self.assertRaises(CheckFailure):
            verify(case, changed)

    def test_all_assignment_level_semantics_agree(self) -> None:
        compared = 0
        for case in self.cases:
            for assignment in canonical_assignments(case["schema"]):
                producer_events, producer_emitters = execute_concrete_evidence(case["generator"], assignment)
                producer_steps, producer_failures = analyze_events(case["catalog"], producer_emitters, producer_events)
                independent_events, independent_emitters = checker_emitted(case["generator"], assignment)
                independent_steps, independent_failures = checker_replay(
                    case["catalog"], independent_emitters, independent_events
                )
                self.assertEqual(producer_events, independent_events, case["case_id"])
                self.assertEqual(producer_emitters, independent_emitters, case["case_id"])
                self.assertEqual(producer_steps, independent_steps, case["case_id"])
                self.assertEqual(producer_failures, independent_failures, case["case_id"])
                self.assertEqual(render_program(producer_events), checker_pretty_program(independent_events), case["case_id"])
                compared += 1
        self.assertEqual(8640, compared)

    def test_control_skeleton_and_size_floor(self) -> None:
        event_shapes = {repr(control_shape(case["generator"])) for case in self.cases}
        topologies = {repr(pure_control_shape(case["generator"])) for case in self.cases}
        sizes = [node_count(case["generator"]) for case in self.cases]
        self.assertGreaterEqual(len(event_shapes), 100)
        self.assertGreaterEqual(len(topologies), 30)
        self.assertGreaterEqual(min(sizes), 6)
        self.assertLessEqual(max(sizes), 64)


if __name__ == "__main__":
    unittest.main()
