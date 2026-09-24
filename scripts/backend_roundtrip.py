#!/usr/bin/env python3
"""Round-trip every frozen trace through two concrete reference lowerings."""
from __future__ import annotations

import argparse
import copy
import importlib
import inspect
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checker.check import assignment_list  # noqa: E402
from checker.source_extract import extract_events  # noqa: E402
from src.reference_backends import lower_ast, lower_template  # noqa: E402

Record = dict[str, Any]


def packed(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def producer_executor() -> Callable[[Record, Record], tuple[list[Record], list[str]]]:
    core = importlib.import_module("src.core")
    candidates = ("execute_generator", "execute", "interpret_generator", "emitted")
    for name in candidates:
        function = getattr(core, name, None)
        if not callable(function):
            continue
        try:
            parameters = inspect.signature(function).parameters
        except (TypeError, ValueError):
            continue
        if len(parameters) < 2:
            continue

        def run(root: Record, assignment: Record, function: Callable[..., Any] = function) -> tuple[list[Record], list[str]]:
            output = function(root, assignment)
            if not isinstance(output, tuple) or len(output) != 2:
                raise TypeError(f"{function.__name__} did not return (events, emitters)")
            events, emitters = output
            if not isinstance(events, list) or not isinstance(emitters, list):
                raise TypeError(f"{function.__name__} returned an invalid trace")
            return copy.deepcopy(events), list(emitters)

        # Probe with the first frozen case instead of selecting by name alone.
        first = json.loads(next(sorted((ROOT / "cases").glob("*.json"))).read_text(encoding="utf-8"))
        assignment = assignment_list(first["schema"], structural_order=False)[0]
        try:
            run(first["generator"], assignment)
        except Exception:
            continue
        return run
    raise RuntimeError("no compatible production generator interpreter was found")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "cases")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "backend_roundtrip.json")
    args = parser.parse_args()

    execute = producer_executor()
    started = time.perf_counter()
    assignments = 0
    statements = 0
    source_bytes = {"template": 0, "ast": 0}
    backends = {"template": lower_template, "ast": lower_ast}

    for path in sorted(args.cases.glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        for assignment in assignment_list(case["schema"], structural_order=False):
            events, _ = execute(case["generator"], assignment)
            assignments += 1
            statements += len(events)
            expected = packed(events)
            for name, lower in backends.items():
                source = lower(events)
                source_bytes[name] += len(source.encode("utf-8"))
                recovered = extract_events(source)
                if packed(recovered) != expected:
                    raise AssertionError(
                        f"{name} backend round-trip mismatch in {case['id']} at {packed(assignment)}"
                    )

    report = {
        "status": "PASS",
        "cases": len(list(args.cases.glob("*.json"))),
        "assignments": assignments,
        "backends": sorted(backends),
        "roundtrips": assignments * len(backends),
        "emitted_statements_per_backend": statements,
        "source_bytes": source_bytes,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
