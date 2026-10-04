from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE_TIMEOUT_SECONDS = 180
sys.dont_write_bytecode = True


def run(*args: str) -> None:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            [sys.executable, *args],
            cwd=ROOT,
            check=False,
            env=environment,
            timeout=STAGE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"stage exceeded {STAGE_TIMEOUT_SECONDS} seconds: {args!r}") from error
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    started = time.perf_counter()
    case_dir = ROOT / "data" / "cases"
    result_dir = ROOT / "results"
    if case_dir.exists():
        shutil.rmtree(case_dir)
    if result_dir.exists():
        shutil.rmtree(result_dir)
    case_dir.mkdir(parents=True)
    result_dir.mkdir(parents=True)
    run("-m", "src.corpus", str(case_dir))
    run("-m", "src.evaluate", str(case_dir), str(result_dir))
    examples = ROOT / "examples"
    examples.mkdir(parents=True, exist_ok=True)
    for source, target in (
        (case_dir / "python-model-001.json", examples / "accepted-generator.json"),
        (case_dir / "python-model-007.json", examples / "rejected-generator.json"),
        (result_dir / "cases" / "python-model-001.json", examples / "accepted-certificate.json"),
        (result_dir / "cases" / "python-model-007.json", examples / "minimal-counterexample.json"),
    ):
        shutil.copyfile(source, target)
    sys.path.insert(0, str(ROOT))
    run("scripts/run_tests.py", "--output", str(result_dir / "test_results.json"),
        "--log", str(result_dir / "tests.txt"))
    test_report = json.loads((result_dir / "test_results.json").read_text(encoding="utf-8"))
    if test_report["status"] != "PASS":
        raise SystemExit("test runner reported failure")
    test_count = test_report["tests_run"]
    summary_path = result_dir / "summary.json"
    with summary_path.open("r", encoding="utf-8") as handle:
        summary = json.load(handle)
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    correctness = summary["correctness"]
    correctness["contract_tests_passed"] = test_count
    correctness["contract_tests_run"] = test_count
    performance = summary["performance"]
    performance["reproduction_wall_seconds"] = time.perf_counter() - started
    performance["reproduction_peak_rss_kib"] = max(
        int(performance["evaluation_peak_rss_kib"]), int(child_usage.ru_maxrss)
    )
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
