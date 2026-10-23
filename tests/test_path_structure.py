"""Benign controls for owned path growth and checked evidence restriction."""
import copy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import path_structure as study
from checker.check import CheckFailure, verify
from src.certify import make_result


class PathStructureTests(unittest.TestCase):
    def test_observed_paths_cells_and_actual_overlap_calls(self):
        for depth in (0, 1, 3, 5):
            row, record = study.observe(depth)
            self.assertEqual(row['inputs'], 2 ** depth)
            self.assertEqual(row['certificate_cells'], 2 ** depth)
            self.assertEqual(row['cell_pairs_checked'], (2 ** depth) * (2 ** depth - 1) // 2)
            self.assertEqual(row['static_nodes'], 4 * 2 ** depth - 1)
            self.assertEqual(row['trace_events_per_input'], 2)

    def test_restriction_never_reconstructs_certificate(self):
        case = study.branch_case(3)
        old = make_result(case)
        with patch.object(study, 'make_result', side_effect=AssertionError('fresh producer called')):
            changed, restricted = study.restrict_first(case, old)
            verify(changed, restricted)
        self.assertEqual(study.check_pointwise(changed, restricted), 4)
        name = changed['schema']['fields'][0]['name']
        originals = [cell for cell in old['cells'] if 0 in cell['cube'][name]]
        for original, retained in zip(originals, restricted['cells'], strict=True):
            for key in ('events', 'program', 'monitor_steps'):
                self.assertEqual(original[key], retained[key])
        self.assertEqual(len(old['cells']), 8)

    def test_old_binding_and_corrupt_reuse_are_rejected(self):
        case = study.branch_case(3)
        old = make_result(case)
        changed, restricted = study.restrict_first(case, old)
        with self.assertRaises(CheckFailure):
            verify(changed, old)
        for field in ('origin', 'obligations'):
            broken = copy.deepcopy(restricted)
            broken['cells'][0]['events'][1][field] = 'wrong-site' if field == 'origin' else []
            with self.assertRaises(CheckFailure):
                verify(changed, broken)
        broken = copy.deepcopy(restricted)
        broken['cells'].append(copy.deepcopy(broken['cells'][0]))
        with self.assertRaises(CheckFailure):
            verify(changed, broken)

    def test_pointwise_oracle_cannot_ignore_changed_payload(self):
        case = study.branch_case(1)
        record = make_result(case)
        record['cells'][0]['monitor_steps'][0]['after']['checks'] = []
        with self.assertRaisesRegex(RuntimeError, 'pointwise replay'):
            study.check_pointwise(case, record)

    def test_depth_and_existing_destination_controls(self):
        for depth in (-1, 9, True, 1.5):
            with self.assertRaises(ValueError):
                study.branch_case(depth)
        with TemporaryDirectory() as directory:
            with patch.object(sys, 'argv', ['path_structure.py', '--out', directory]), \
                 patch.object(study, 'collect', side_effect=AssertionError('unexpected evaluation')):
                with self.assertRaisesRegex(SystemExit, 'must be new'):
                    study.main()


if __name__ == '__main__':
    unittest.main()
