from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import reproduce

ROOT = Path(__file__).resolve().parents[1]


class ReproductionScriptTests(unittest.TestCase):
    def test_stage_zero_exit_requires_successful_fresh_output(self) -> None:
        for body in (None, '{"status":"FAIL"}', '{"status":"PASS"}'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "report.json"
                output.write_text('{"status":"PASS"}', encoding="utf-8")
                stages = []
                command = ["-c", "print('benign stage')"]
                if body is not None:
                    command = ["-c", "from pathlib import Path; Path('report.json').write_text(" + repr(body) + ", encoding='utf-8')"]
                with patch.object(reproduce, "ROOT", root), patch.object(reproduce, "RESULTS", root):
                    if body == '{"status":"PASS"}':
                        reproduce.run_stage("output", command, [output], dict(os.environ), stages)
                    else:
                        with self.assertRaises(RuntimeError):
                            reproduce.run_stage("output", command, [output], dict(os.environ), stages)
                self.assertEqual(0, stages[0]["exit_code"])
                self.assertEqual("PASS" if body == '{"status":"PASS"}' else "FAIL", stages[0]["status"])
                self.assertTrue((root / stages[0]["log"]).is_file())

    def test_stage_timeout_retains_partial_log_and_execution_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stages = []
            command = ["-c", "import time; print('benign timeout', flush=True); time.sleep(2)"]
            with patch.object(reproduce, "ROOT", root), patch.object(reproduce, "RESULTS", root), \
                    patch.object(reproduce, "STAGE_TIMEOUT_SECONDS", 0.5):
                with self.assertRaises(RuntimeError):
                    reproduce.run_stage("timeout", command, [], dict(os.environ), stages)
            row = stages[0]
            self.assertEqual("TIMEOUT", row["status"])
            self.assertEqual(command, row["command"])
            self.assertIsNone(row["exit_code"])
            self.assertGreater(row["elapsed_seconds"], 0)
            self.assertIn("benign timeout", (root / row["log"]).read_text(encoding="utf-8"))

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(ROOT)
        return subprocess.run(
            [sys.executable, *arguments],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_differential_stress_writes_the_requested_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "stress.json"
            completed = self.run_script(
                "scripts/differential_stress.py",
                "--cases-per-seed",
                "2",
                "--seeds",
                "0x1,0x2",
                "--output",
                str(output),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(output.is_file())
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["seed_count"], 2)
            self.assertEqual(report["cases"], 4)
            self.assertEqual(report["assignments"], 48)

    def test_backend_roundtrip_uses_data_cases_and_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "backend.json"
            completed = self.run_script(
                "scripts/backend_roundtrip.py",
                "--cases",
                "data/cases",
                "--limit-cases",
                "1",
                "--output",
                str(output),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["cases"], 1)
            self.assertEqual(report["assignments"], 24)
            self.assertEqual(report["roundtrips"], 48)


if __name__ == "__main__":
    unittest.main()
