#!/usr/bin/env python3
"""Measure certificate checking as irrelevant schema dimensions grow."""
from __future__ import annotations

import copy
import csv
import json
import math
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checker.check import (  # noqa: E402
    MAX_ASSIGNMENTS,
    assignment_list,
    cube_dimensions,
    emitted,
    replay,
    schema_domains,
    symbolic_emitted,
    verify,
)
from src.certify import make_result  # noqa: E402

Record = dict[str, Any]


def accepted_case() -> Record:
    for path in sorted((ROOT / "cases").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        if case.get("expected") == "accepted":
            return case
    raise RuntimeError("no accepted frozen case")


def field_container(schema: Any) -> tuple[list[Record] | None, dict[str, Any] | None]:
    if isinstance(schema, list) and all(isinstance(item, dict) for item in schema):
        return schema, None
    if isinstance(schema, dict):
        for key in ("fields", "properties", "inputs"):
            value = schema.get(key)
            if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                return value, None
        if all(isinstance(value, list) for value in schema.values()):
            return None, schema
    raise TypeError("unsupported schema representation")


def add_boolean_field(schema: Any, name: str) -> None:
    fields, mapping = field_container(schema)
    if mapping is not None:
        mapping[name] = [False, True]
        return
    assert fields is not None and fields
    _, domains = schema_domains(schema)
    template = None
    original_name = None
    for item in fields:
        candidate = item.get("name") or item.get("id") or item.get("field")
        if isinstance(candidate, str) and candidate in domains:
            template = copy.deepcopy(item)
            original_name = candidate
            break
    if template is None or original_name is None:
        raise TypeError("could not identify a schema field template")
    for key in ("name", "id", "field"):
        if template.get(key) == original_name:
            template[key] = name
            break
    old_domain = domains[original_name]
    changed = False
    for key, value in list(template.items()):
        if isinstance(value, list) and value == old_domain:
            template[key] = [False, True]
            changed = True
            break
    if not changed:
        for key in ("values", "domain", "enum"):
            if key in template:
                template[key] = [False, True]
                changed = True
                break
    if not changed:
        raise TypeError("could not identify the schema domain field")
    fields.append(template)


def median_ms(action: Callable[[], None], repetitions: int = 7) -> float:
    samples: list[float] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        action()
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return round(statistics.median(samples), 6)


def main() -> None:
    base = accepted_case()
    rows: list[Record] = []
    for irrelevant in range(0, 16):
        case = copy.deepcopy(base)
        for index in range(irrelevant):
            add_boolean_field(case["schema"], f"unused_{index}")
        names, domains = schema_domains(case["schema"])
        assignments = math.prod(len(domains[name]) for name in names)
        if assignments > MAX_ASSIGNMENTS:
            break

        result = make_result(case)
        if result.get("kind") != "certificate":
            raise AssertionError("scaling base unexpectedly stopped certifying")
        verify(case, result)

        symbolic_leaves = 0
        for cell in result["cells"]:
            _, _, dimensions = cube_dimensions(case["schema"], cell["cube"])
            symbolic_leaves += len(symbolic_emitted(case["generator"], dimensions))

        def symbolic_check() -> None:
            verify(case, result)

        concrete_inputs = assignment_list(case["schema"], structural_order=False)

        def exhaustive_check() -> None:
            for assignment in concrete_inputs:
                trace, emitters = emitted(case["generator"], assignment)
                _, failures = replay(case["catalog"], emitters, trace)
                if failures:
                    raise AssertionError("accepted scaling case rejected")

        rows.append(
            {
                "irrelevant_boolean_fields": irrelevant,
                "assignments": assignments,
                "certificate_cells": len(result["cells"]),
                "symbolic_leaf_replays": symbolic_leaves,
                "certificate_bytes": len(
                    json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ),
                "symbolic_verify_median_ms": median_ms(symbolic_check),
                "exhaustive_replay_median_ms": median_ms(exhaustive_check),
            }
        )

    if len(rows) < 3:
        raise AssertionError("assignment bound is too small for a scaling study")
    report = {
        "status": "PASS",
        "max_assignments": MAX_ASSIGNMENTS,
        "rows": rows,
        "interpretation": (
            "Irrelevant dimensions enlarge the concrete domain while certificate cells and symbolic leaf "
            "replays are determined by control-relevant dimensions. Timings are feasibility measurements, "
            "not cross-machine performance claims."
        ),
    }
    result_dir = ROOT / "results"
    result_dir.mkdir(exist_ok=True)
    (result_dir / "scaling_study.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (result_dir / "scaling_study.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
