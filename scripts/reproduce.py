#!/usr/bin/env python3
"""Run the complete public reproduction and all independent validation layers."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def run(arguments: list[str]) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT) + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    completed = subprocess.run(arguments, cwd=ROOT, env=environment, check=False)
    if completed.returncode:
        raise SystemExit(f"command failed with exit {completed.returncode}: {' '.join(arguments)}")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"expected a JSON object in {path}")
    return value


def main() -> None:
    started = time.perf_counter()
    python = sys.executable
    run([python, str(ROOT / "scripts" / "reproduce_core.py")])
    run([python, str(ROOT / "scripts" / "backend_roundtrip.py")])
    run([python, str(ROOT / "scripts" / "differential_stress.py")])
    run([python, str(ROOT / "scripts" / "scaling_study.py")])
    run([python, str(ROOT / "scripts" / "audit_code.py")])
    run([python, str(ROOT / "scripts" / "audit_references.py")])
    run([python, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-q"])

    results = ROOT / "results"
    backend = load(results / "backend_roundtrip.json")
    stress = load(results / "differential_stress.json")
    scaling = load(results / "scaling_study.json")
    for name, report in (("backend", backend), ("stress", stress), ("scaling", scaling)):
        if report.get("status") != "PASS":
            raise SystemExit(f"{name} validation did not report PASS")

    summary_path = results / "summary.json"
    if summary_path.exists():
        summary = load(summary_path)
        summary["independent_validation"] = {
            "reference_backend_roundtrips": backend.get("roundtrips"),
            "reference_backend_assignments": backend.get("assignments"),
            "reference_backend_count": len(backend.get("backends", [])),
            "stress_seed_count": stress.get("seed_count"),
            "stress_cases": stress.get("cases"),
            "stress_assignments": stress.get("assignments"),
            "scaling_rows": len(scaling.get("rows", [])),
            "certificate_checker_enumerates_assignments": False,
        }
        summary["complete_reproduction_elapsed_seconds"] = round(time.perf_counter() - started, 6)
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Complete reproduction PASS in {time.perf_counter() - started:.3f} seconds")


if __name__ == "__main__":
    main()
