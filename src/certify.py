from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from .core import (
    analyze_events,
    canonical_assignments,
    canonical_json,
    first_violation,
    input_size,
    render_program,
    symbolic_paths,
    validate_case,
)

Json = dict[str, Any]
MAX_JSON_BYTES = 64 * 1024 * 1024


def make_result(case: Json) -> Json:
    validate_case(case)
    certificate_cells: list[Json] = []
    all_safe = True
    for cube, events, emitters in symbolic_paths(case):
        steps, violations = analyze_events(case["catalog"], emitters, events)
        certificate_cells.append({
            "cube": cube,
            "program": render_program(events),
            "events": events,
            "monitor_steps": steps,
        })
        if violations:
            all_safe = False

    subject = {
        "case_id": case["case_id"],
        "family": case["family"],
        "schema": copy.deepcopy(case["schema"]),
        "catalog": copy.deepcopy(case["catalog"]),
        "generator": copy.deepcopy(case["generator"]),
    }
    for key in ("subtype", "corpus_source", "historical_model"):
        if key in case:
            subject[key] = copy.deepcopy(case[key])
    if all_safe:
        return {
            "kind": "certificate",
            "subject": subject,
            "claim": {
                "origin_complete": True,
                "obligation_complete": True,
                "trace_safe": True,
                "domain_partitioned": True,
            },
            "cells": certificate_cells,
        }

    for assignment in canonical_assignments(case["schema"]):
        events, program, steps, violations = first_violation(case, assignment)
        if violations:
            first = violations[0]
            return {
                "kind": "counterexample",
                "subject": subject,
                "witness": {
                    "input": assignment,
                    "input_size": input_size(case["schema"], assignment),
                    "program": program,
                    "events": events,
                    "monitor_steps": steps,
                    "violation": first,
                    "violating_prefix": events[: first["prefix_length"]],
                },
            }
    raise AssertionError("symbolic analysis found a violation but concrete enumeration did not")


def _strict_object(pairs: list[tuple[str, Any]]) -> Json:
    result: Json = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def load_json(path: Path) -> Json:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON input exceeds the {MAX_JSON_BYTES}-byte bound")
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(
            handle,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def save_json(path: Path, value: Json) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            value,
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Produce a certificate or minimal counterexample for one bounded generator case.")
    parser.add_argument("case", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    case = load_json(args.case)
    result = make_result(case)
    save_json(args.output, result)
    print(f"{case['case_id']}: {result['kind']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
