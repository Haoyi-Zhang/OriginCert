#!/usr/bin/env python3
"""Round-trip every frozen trace through two concrete reference lowerings."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checker.check import assignment_list  # noqa: E402
from checker.source_extract import extract_events  # noqa: E402
from src.core import execute_concrete_evidence  # noqa: E402
from src.reference_backends import lower_ast, lower_template  # noqa: E402

Record = dict[str, Any]


def packed(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def iter_cases(case_directory: Path) -> Iterator[tuple[Path, Record]]:
    for path in sorted(case_directory.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            continue
        if not {"case_id", "schema", "generator"}.issubset(value):
            continue
        yield path, value


def atomic_write_json(path: Path, report: Record) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "data" / "cases")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "backend_roundtrip.json")
    parser.add_argument("--limit-cases", type=int)
    arguments = parser.parse_args()
    if arguments.limit_cases is not None and arguments.limit_cases <= 0:
        parser.error("--limit-cases must be positive")

    selected = list(iter_cases(arguments.cases))
    if arguments.limit_cases is not None:
        selected = selected[: arguments.limit_cases]
    if not selected:
        raise SystemExit(f"no case records found in {arguments.cases}")

    started = time.perf_counter()
    assignments = 0
    statements = 0
    source_bytes = {"template": 0, "ast": 0}
    backends = {"template": lower_template, "ast": lower_ast}

    for _, case in selected:
        for assignment in assignment_list(case["schema"], structural_order=False):
            events, _ = execute_concrete_evidence(case["generator"], assignment)
            assignments += 1
            statements += len(events)
            expected = packed(events)
            for name, lower in backends.items():
                source = lower(events)
                source_bytes[name] += len(source.encode("utf-8"))
                recovered = extract_events(source)
                if packed(recovered) != expected:
                    raise AssertionError(
                        f"{name} backend round-trip mismatch in {case['case_id']} at {packed(assignment)}"
                    )

    report: Record = {
        "status": "PASS",
        "cases": len(selected),
        "assignments": assignments,
        "backends": sorted(backends),
        "roundtrips": assignments * len(backends),
        "emitted_statements_per_backend": statements,
        "source_bytes": source_bytes,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }
    atomic_write_json(arguments.output, report)
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
