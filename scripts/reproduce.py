#!/usr/bin/env python3
"""Run the complete public scientific reproduction and validation layers."""
from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def run(arguments: list[str]) -> None:
    print("[reproduce] " + " ".join(arguments), flush=True)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
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
    case_directory = ROOT / "data" / "cases"
    backend_path = RESULTS / "backend_roundtrip.json"
    stress_path = RESULTS / "differential_stress.json"
    scaling_json = RESULTS / "scaling_study.json"
    scaling_csv = RESULTS / "scaling_study.csv"

    run([python, str(ROOT / "scripts" / "reproduce_core.py")])
    for path in (backend_path, stress_path, scaling_json, scaling_csv):
        path.unlink(missing_ok=True)

    run(
        [
            python,
            str(ROOT / "scripts" / "backend_roundtrip.py"),
            "--cases",
            str(case_directory),
            "--output",
            str(backend_path),
        ]
    )
    run(
        [
            python,
            str(ROOT / "scripts" / "differential_stress.py"),
            "--output",
            str(stress_path),
        ]
    )
    run(
        [
            python,
            str(ROOT / "scripts" / "scaling_study.py"),
            "--cases",
            str(case_directory),
            "--output-json",
            str(scaling_json),
            "--output-csv",
            str(scaling_csv),
        ]
    )
    run([python, str(ROOT / "scripts" / "audit_code.py")])
    run([python, str(ROOT / "scripts" / "audit_formal_alignment.py")])
    run([python, str(ROOT / "scripts" / "audit_experimental_design.py")])

    backend = load(backend_path)
    stress = load(stress_path)
    scaling = load(scaling_json)
    for name, report in (("backend", backend), ("stress", stress), ("scaling", scaling)):
        if report.get("status") != "PASS":
            raise SystemExit(f"{name} validation did not report PASS")

    summary_path = RESULTS / "summary.json"
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
    complete_elapsed = time.perf_counter() - started
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    performance = summary.setdefault("performance", {})
    performance["complete_reproduction_wall_seconds"] = round(complete_elapsed, 6)
    performance["complete_reproduction_peak_rss_kib"] = int(usage.ru_maxrss)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(f"Complete reproduction PASS in {complete_elapsed:.3f} seconds")


if __name__ == "__main__":
    main()
