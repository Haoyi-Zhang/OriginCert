#!/usr/bin/env python3
"""Round-trip every frozen trace through two distinct reference codecs."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checker.check import assignment_list  # noqa: E402
from checker.source_extract import extract_call_events, extract_record_events  # noqa: E402
from src.core import execute_concrete_evidence  # noqa: E402
from src.reference_backends import lower_ast, lower_template  # noqa: E402

Record = dict[str, Any]
Lower = Callable[[list[Record]], str]
Extract = Callable[[str], list[Record]]


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
    distinct_source_forms = 0
    source_bytes = {"template_calls": 0, "ast_record_table": 0}
    codecs: dict[str, tuple[Lower, Extract]] = {
        "template_calls": (lower_template, extract_call_events),
        "ast_record_table": (lower_ast, extract_record_events),
    }

    for _, case in selected:
        for assignment in assignment_list(case["schema"], structural_order=False):
            events, _ = execute_concrete_evidence(case["generator"], assignment)
            assignments += 1
            statements += len(events)
            expected = packed(events)
            sources: dict[str, str] = {}
            for name, (lower, extract) in codecs.items():
                source = lower(events)
                sources[name] = source
                source_bytes[name] += len(source.encode("utf-8"))
                recovered = extract(source)
                if packed(recovered) != expected:
                    raise AssertionError(
                        f"{name} round-trip mismatch in {case['case_id']} at {packed(assignment)}"
                    )
            if len(set(sources.values())) != len(sources):
                raise AssertionError(
                    f"reference codecs emitted identical source in {case['case_id']} at {packed(assignment)}"
                )
            distinct_source_forms += 1

    report: Record = {
        "status": "PASS",
        "cases": len(selected),
        "assignments": assignments,
        "backends": sorted(codecs),
        "decoders": sorted(codecs),
        "roundtrips": assignments * len(codecs),
        "distinct_source_forms": distinct_source_forms,
        "emitted_statements_per_backend": statements,
        "source_bytes": source_bytes,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "interpretation": (
            "The two codecs use different restricted Python surface grammars and paired syntax-only decoders; "
            "they remain reference transports for the same event relation, not independent product integrations."
        ),
    }
    atomic_write_json(arguments.output, report)
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
