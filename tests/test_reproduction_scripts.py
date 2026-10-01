from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReproductionScriptTests(unittest.TestCase):
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
