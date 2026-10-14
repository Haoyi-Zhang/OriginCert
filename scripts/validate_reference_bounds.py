"""Fresh offline receipt for bounded direct/source-bound owned controls only.

No Linux corpus regeneration, source execution, historical-result replacement,
paper export, network access, or dependency installation is performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from scripts.owned_traceability import experiment
from src.traceability_reference import reference_trace
from test_reference_bounds import empty_case, emitting_case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    # This focused entry point may write only a new local artifact result directory.
    output.relative_to((ROOT / "results").resolve())
    if output.exists():
        raise SystemExit("output directory already exists; choose a fresh result directory")
    output.mkdir(parents=True)
    started = time.perf_counter()
    receipt = {"status": "FAIL", "utc_time": datetime.now(timezone.utc).isoformat(),
               "command": [sys.executable, "-B", "scripts/validate_reference_bounds.py", *sys.argv[1:]],
               "environment": {"python": sys.version, "platform": platform.platform(), "workers": 1},
               "scope": "focused owned tests and the existing two-layout source experiment; not a full Linux reproduction",
               "source_executed": False, "historical_results_overwritten": False}
    try:
        suites = [unittest.defaultTestLoader.loadTestsFromName(name)
                  for name in ("test_owned_traceability", "test_reference_bounds")]
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite(suites))
        (output / "tests.txt").write_text(stream.getvalue(), encoding="utf-8")
        receipt["tests"] = {"run": result.testsRun, "failures": len(result.failures),
                            "errors": len(result.errors), "skipped": len(result.skipped)}
        if not result.wasSuccessful() or result.skipped:
            raise RuntimeError("focused regressions did not all execute successfully")
        controls = []
        for label, case, assignment in [
                ("empty-depth-two", empty_case(2), {"count": 4}),
                ("empty-depth-twenty", empty_case(20), {"count": 4}),
                ("mixed-emitting-and-empty", emitting_case(), {"count": 2})]:
            statistics = {}
            events, emitters = reference_trace(case, assignment, statistics=statistics)
            controls.append({"control": label, "assignment": assignment, **statistics,
                             "events": events, "actual_emitters": emitters})
        receipt["controls"] = controls
        owned = experiment()
        (output / "owned_traceability.json").write_text(
            json.dumps(owned, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        receipt["owned_experiment"] = {"status": owned["status"], "clean_bundles": len(owned["clean"]),
                                       "source_faults_rejected_by_both": len(owned["source_faults"]),
                                       "subject_diagnostics": len(owned["subject_faults"]),
                                       "restricted_bundles": len(owned["restriction_reuse"])}
        tracked = ["scripts/validate_reference_bounds.py", "scripts/owned_traceability.py",
                   "src/traceability_reference.py", "src/traceability_workload.py",
                   "src/core.py", "src/certify.py", "checker/check.py", "checker/source_binding.py",
                   "checker/source_extract.py", "tests/test_reference_bounds.py", "tests/test_owned_traceability.py"]
        receipt["source_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in tracked}
        receipt["status"] = "PASS"
    except Exception as error:
        receipt["error"] = repr(error)
        raise
    finally:
        receipt["elapsed_seconds"] = time.perf_counter() - started
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "tests": receipt["tests"],
                      "owned_experiment": receipt["owned_experiment"], "output": str(output)}))


if __name__ == "__main__":
    main()
