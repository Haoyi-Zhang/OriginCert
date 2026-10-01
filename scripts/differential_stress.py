#!/usr/bin/env python3
"""Run deterministic multi-seed differential stress checks and retain a JSON report."""
from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checker.check import classify_case, emitted, replay, verify  # noqa: E402
from src.certify import make_result  # noqa: E402
from src.core import (  # noqa: E402
    analyze_events,
    canonical_assignments,
    canonical_json,
    cube_assignments,
    execute_concrete_evidence,
    symbolic_paths,
    validate_case,
)

Record = dict[str, Any]
DEFAULT_SEEDS = (
    0x5EED2027,
    0x13579BDF,
    0x2468ACE0,
    0x0BADF00D,
    0x31415926,
    0x27182818,
    0xC0FFEE11,
    0xA5A5A5A5,
)

CATALOGUE: Record = {
    "obligations": [
        {
            "id": "sql-safe",
            "trigger": {"op": "sink", "channel": "sql"},
            "rule": {"kind": "protection", "requires": ["sql_parameter"]},
        },
        {
            "id": "html-safe",
            "trigger": {"op": "sink", "channel": "html"},
            "rule": {"kind": "protection", "requires": ["html_escape"]},
        },
        {
            "id": "auth-checked",
            "trigger": {"op": "privileged"},
            "rule": {"kind": "preceded", "capability_field": "capability"},
        },
        {
            "id": "token-strong",
            "trigger": {"op": "token"},
            "rule": {"kind": "strong_rng", "source_field": "source"},
        },
        {
            "id": "no-shell",
            "trigger": {"op": "sink", "channel": "shell"},
            "rule": {"kind": "forbid", "message": "shell sink forbidden"},
        },
    ]
}

EVENTS: tuple[tuple[Record, list[str]], ...] = (
    ({"op": "source", "target": "raw"}, []),
    ({"op": "source", "target": "query"}, []),
    ({"op": "protect", "target": "query", "source": "raw", "protection": "sql_parameter"}, []),
    ({"op": "protect", "target": "query", "source": "raw", "protection": "html_escape"}, []),
    ({"op": "protect", "target": "alias", "source": "nonce", "protection": "tag"}, []),
    ({"op": "sink", "channel": "sql", "source": "query"}, ["sql-safe"]),
    ({"op": "sink", "channel": "html", "source": "query"}, ["html-safe"]),
    ({"op": "sink", "channel": "shell", "source": "raw"}, ["no-shell"]),
    ({"op": "check", "capability": "admin"}, []),
    ({"op": "privileged", "capability": "admin"}, ["auth-checked"]),
    ({"op": "rng", "target": "nonce", "strength": "strong"}, []),
    ({"op": "rng", "target": "nonce", "strength": "weak"}, []),
    ({"op": "token", "source": "nonce"}, ["token-strong"]),
    ({"op": "token", "source": "alias"}, ["token-strong"]),
    ({"op": "noop"}, []),
)


def same(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def required_obligations(event: Record) -> list[str]:
    return sorted(
        obligation["id"]
        for obligation in CATALOGUE["obligations"]
        if all(key in event and same(event[key], value) for key, value in obligation["trigger"].items())
    )


def oracle(events: list[Record], emitters: list[str]) -> list[tuple[str, str | None, int]]:
    protections: dict[str, set[str]] = {}
    capabilities: set[str] = set()
    strong_sources: set[str] = set()
    failures: list[tuple[str, str | None, int]] = []
    obligations = {item["id"]: item for item in CATALOGUE["obligations"]}

    for index, event in enumerate(events):
        if event["origin"] != emitters[index]:
            failures.append(("origin", None, index))
        required = required_obligations(event)
        if sorted(event["obligations"]) != required:
            failures.append(("coverage", required[0] if required else None, index))
        for obligation_id in required:
            rule = obligations[obligation_id]["rule"]
            kind = rule["kind"]
            bad = False
            if kind == "protection":
                source = event.get(rule.get("source_field", "source"))
                bad = not set(rule["requires"]).issubset(protections.get(source, set()))
            elif kind == "preceded":
                bad = event.get(rule.get("capability_field", "capability")) not in capabilities
            elif kind == "strong_rng":
                bad = event.get(rule.get("source_field", "source")) not in strong_sources
            elif kind == "forbid":
                bad = True
            if bad:
                failures.append(("safety", obligation_id, index))

        operation = event["op"]
        if operation == "source":
            protections[event["target"]] = set()
            strong_sources.discard(event["target"])
        elif operation == "protect":
            source_is_strong = event["source"] in strong_sources
            protections[event["target"]] = set(protections.get(event["source"], set())) | {
                event["protection"]
            }
            if source_is_strong:
                strong_sources.add(event["target"])
            else:
                strong_sources.discard(event["target"])
        elif operation == "check":
            capabilities.add(event["capability"])
        elif operation == "rng":
            protections[event["target"]] = set()
            if event["strength"] == "strong":
                strong_sources.add(event["target"])
            else:
                strong_sources.discard(event["target"])
    return failures


def normalized_failures(failures: list[Record]) -> list[tuple[str, str | None, int]]:
    return [(item["kind"], item["obligation"], item["event_index"]) for item in failures]


def make_case(index: int, seed: int, rng: random.Random) -> Record:
    counter = 0

    def node_id(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter}"

    def emit() -> Record:
        event, obligations = rng.choice(EVENTS)
        node: Record = {"node": node_id("emit"), "kind": "emit", "event": copy.deepcopy(event)}
        if obligations:
            node["declared_obligations"] = list(obligations)
        return node

    def tree(depth: int) -> Record:
        if depth <= 0 or rng.random() < 0.38:
            return emit()
        kind = rng.choice(("seq", "ifflag", "ifmode", "repeat"))
        if kind == "seq":
            return {
                "node": node_id("seq"),
                "kind": "seq",
                "children": [tree(depth - 1) for _ in range(rng.randint(1, 3))],
            }
        if kind == "ifflag":
            return {
                "node": node_id("if"),
                "kind": "if",
                "condition": {"field": "flag", "equals": rng.choice((False, True))},
                "then": tree(depth - 1),
                "else": tree(depth - 1),
            }
        if kind == "ifmode":
            return {
                "node": node_id("if"),
                "kind": "if",
                "condition": {"field": "mode", "equals": rng.choice((1, True))},
                "then": tree(depth - 1),
                "else": tree(depth - 1),
            }
        return {
            "node": node_id("repeat"),
            "kind": "repeat",
            "count_field": "count",
            "body": tree(depth - 1),
        }

    generator = tree(rng.randint(1, 4))
    emit_nodes: list[Record] = []

    def collect(node: Record) -> None:
        if node["kind"] == "emit":
            emit_nodes.append(node)
        elif node["kind"] == "seq":
            for child in node["children"]:
                collect(child)
        elif node["kind"] == "if":
            collect(node["then"])
            collect(node["else"])
        else:
            collect(node["body"])

    collect(generator)
    if emit_nodes and rng.random() < 0.35:
        node = rng.choice(emit_nodes)
        if rng.random() < 0.5:
            node["origin_override"] = "nonexistent-node"
        else:
            declarations = list(node.get("declared_obligations", []))
            node["declared_obligations"] = [] if declarations else ["sql-safe"]

    return {
        "case_id": f"stress-{seed:08x}-{index:04d}",
        "family": "stress",
        "schema": {
            "fields": [
                {"name": "flag", "domain": [False, True]},
                {"name": "mode", "domain": [1, True]},
                {"name": "count", "domain": [0, 1, 2]},
            ]
        },
        "catalog": copy.deepcopy(CATALOGUE),
        "generator": generator,
    }


def run_seed(seed: int, case_count: int) -> Record:
    rng = random.Random(seed)
    assignments = 0
    certificates = 0
    for index in range(case_count):
        case = make_case(index, seed, rng)
        validate_case(case)
        result = make_result(case)
        verify(case, result)
        certificates += int(result["kind"] == "certificate")
        expected = "accepted" if result["kind"] == "certificate" else "rejected"
        if classify_case(case) != expected:
            raise AssertionError(("classification", seed, index))

        expanded: list[Record] = []
        for cube, _, _ in symbolic_paths(case):
            expanded.extend(cube_assignments(case["schema"], cube))
        observed = [canonical_json(item) for item in expanded]
        target = [canonical_json(item) for item in canonical_assignments(case["schema"])]
        if sorted(observed) != sorted(target) or len(observed) != len(set(observed)):
            raise AssertionError(("partition", seed, index))

        for assignment in canonical_assignments(case["schema"]):
            assignments += 1
            producer_events, producer_emitters = execute_concrete_evidence(case["generator"], assignment)
            producer_states, producer_failures = analyze_events(
                case["catalog"], producer_emitters, producer_events
            )
            checker_events, checker_emitters = emitted(case["generator"], assignment)
            checker_states, checker_failures = replay(
                case["catalog"], checker_emitters, checker_events
            )
            if (
                producer_events,
                producer_emitters,
                producer_states,
                producer_failures,
            ) != (
                checker_events,
                checker_emitters,
                checker_states,
                checker_failures,
            ):
                raise AssertionError(("dual", seed, index, assignment))
            expected_failures = oracle(producer_events, producer_emitters)
            if normalized_failures(producer_failures) != expected_failures:
                raise AssertionError(
                    (
                        "oracle",
                        seed,
                        index,
                        assignment,
                        normalized_failures(producer_failures),
                        expected_failures,
                    )
                )
    return {
        "seed": seed,
        "cases": case_count,
        "assignments": assignments,
        "certificates": certificates,
        "counterexamples": case_count - certificates,
        "status": "PASS",
    }


def atomic_write_json(path: Path, report: Record) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def parse_seeds(value: str) -> tuple[int, ...]:
    seeds = tuple(int(item.strip(), 0) for item in value.split(",") if item.strip())
    if not seeds:
        raise argparse.ArgumentTypeError("at least one seed is required")
    return seeds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases-per-seed", type=int, default=75)
    parser.add_argument(
        "--seeds",
        type=parse_seeds,
        default=DEFAULT_SEEDS,
        help="comma-separated integers; decimal and 0x-prefixed forms are accepted",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "differential_stress.json",
    )
    arguments = parser.parse_args()
    if arguments.cases_per_seed <= 0:
        parser.error("--cases-per-seed must be positive")

    per_seed = [run_seed(seed, arguments.cases_per_seed) for seed in arguments.seeds]
    report: Record = {
        "status": "PASS",
        "seed_count": len(per_seed),
        "seeds": [item["seed"] for item in per_seed],
        "cases_per_seed": arguments.cases_per_seed,
        "cases": sum(item["cases"] for item in per_seed),
        "assignments": sum(item["assignments"] for item in per_seed),
        "certificates": sum(item["certificates"] for item in per_seed),
        "counterexamples": sum(item["counterexamples"] for item in per_seed),
        "per_seed": per_seed,
    }
    atomic_write_json(arguments.output, report)
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
