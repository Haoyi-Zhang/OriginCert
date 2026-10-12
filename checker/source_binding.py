"""Bind a positive generator certificate to a complete restricted-source bundle.

Source is parsed, never executed. Certificate checking alone does not inspect a
generated file; this boundary check is an additional, explicit operation.
"""
from __future__ import annotations

import ast
import math
from typing import Any

from .check import CheckFailure, demand, packed, rank, same_value, verify
from .source_extract import SourceExtractionError, extract_call_events

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def source_rows(case: dict[str, Any], rows: Any) -> list[tuple[dict, list, list[int]]]:
    """Check assignment completeness/uniqueness and decode every submitted file."""
    fields = case["schema"]["fields"]
    count = math.prod(len(field["domain"]) for field in fields)
    demand(isinstance(rows, list) and len(rows) == count,
           "source bundle does not cover the schema cardinality")
    seen: set[str] = set()
    decoded = []
    total_bytes = 0
    for index, row in enumerate(rows):
        demand(isinstance(row, dict) and set(row) == {"input", "source"},
               f"source row {index} has invalid fields")
        rank(case["schema"], row["input"])
        key = packed(row["input"])
        demand(key not in seen, f"source row {index} duplicates an input")
        seen.add(key)
        source = row["source"]
        demand(isinstance(source, str), f"source row {index} is not text")
        size = len(source.encode("utf-8"))
        total_bytes += size
        demand(size <= MAX_SOURCE_BYTES and total_bytes <= MAX_BUNDLE_BYTES,
               "source bundle exceeds its byte bound")
        try:
            events = extract_call_events(source)
            lines = [statement.lineno for statement in ast.parse(source).body]
        except (SourceExtractionError, SyntaxError, RecursionError) as error:
            raise CheckFailure(f"source row {index}: {error}") from error
        decoded.append((row["input"], events, lines))
    return decoded


def verify_sources(case: dict, certificate: dict, rows: list[dict]) -> dict:
    """Verify universal positive evidence AND source-to-generation equality."""
    demand(certificate.get("kind") == "certificate",
           "source binding requires positive evidence, not a counterexample")
    verify(case, certificate)
    decoded = source_rows(case, rows)
    event_count = 0
    for index, (assignment, actual, lines) in enumerate(decoded):
        matches = [cell for cell in certificate["cells"] if all(
            any(same_value(assignment[name], value) for value in values)
            for name, values in cell["cube"].items())]
        demand(len(matches) == 1, f"source row {index} has no unique certificate cell")
        expected = matches[0]["events"]
        demand(len(actual) == len(expected),
               f"source row {index}: event completeness differs "
               f"({len(actual)} statements, expected {len(expected)})")
        for position, (event, reference) in enumerate(zip(actual, expected, strict=True)):
            if not same_value(event, reference):
                differing = sorted(key for key in set(event) | set(reference)
                                   if key not in event or key not in reference
                                   or not same_value(event[key], reference[key]))
                raise CheckFailure(
                    f"source row {index} input {packed(assignment)} event {position} "
                    f"line {lines[position]}: fields {differing!r} differ from "
                    f"emitter {reference['origin']!r} "
                    f"occurrence {reference.get('occurrence', [])!r}")
        event_count += len(actual)
    return {"inputs": len(decoded), "events": event_count,
            "certificate_cells": len(certificate["cells"])}
