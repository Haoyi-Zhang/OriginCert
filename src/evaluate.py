from __future__ import annotations

import argparse
import copy
import csv
import json
import resource
import statistics
import time
from pathlib import Path
from typing import Any, Callable

from checker.check import (
    CheckFailure,
    classify_case,
    emitted as checker_emitted,
    pretty_program as checker_pretty_program,
    replay as checker_replay,
    verify,
)
from .certify import load_json as strict_load_json, make_result
from .core import (
    analyze_events,
    canonical_assignments,
    canonical_json,
    execute_concrete_evidence,
    input_size,
    raw_assignments,
    render_program,
    required_obligations,
)
from .historical_models import ANCHORS, classify as classify_historical, render as render_historical

Json = dict[str, Any]


def control_shape(node: Json) -> Any:
    """Return a node-id-free control skeleton for diversity accounting."""
    kind = node["kind"]
    if kind == "emit":
        event = node["event"]
        return ("emit", event.get("op"), event.get("channel"))
    if kind == "seq":
        return ("seq", tuple(control_shape(child) for child in node["children"]))
    if kind == "if":
        return (
            "if",
            node["condition"]["field"],
            control_shape(node["then"]),
            control_shape(node["else"]),
        )
    return ("repeat", node["count_field"], control_shape(node["body"]))


def pure_control_shape(node: Json) -> Any:
    """Return only the seq/if/repeat/emit topology, without event labels."""
    kind = node["kind"]
    if kind == "emit":
        return ("emit",)
    if kind == "seq":
        return ("seq", tuple(pure_control_shape(child) for child in node["children"]))
    if kind == "if":
        return ("if", pure_control_shape(node["then"]), pure_control_shape(node["else"]))
    return ("repeat", pure_control_shape(node["body"]))


def node_count(node: Json) -> int:
    if node["kind"] == "emit":
        return 1
    if node["kind"] == "seq":
        return 1 + sum(node_count(child) for child in node["children"])
    if node["kind"] == "if":
        return 1 + node_count(node["then"]) + node_count(node["else"])
    return 1 + node_count(node["body"])


def load(path: Path) -> Json:
    return strict_load_json(path)


def save(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        handle.write("\n")


def trace_rejects(case: Json, assignments: list[Json], enabled_kinds: set[str]) -> bool:
    """Return whether any selected contract dimension rejects the sampled traces.

    The implementation deliberately reuses the producer-side trace monitor because these
    are ablations and output-only controls, not independent validators. The independent
    result checker remains checker/check.py.
    """
    for assignment in assignments:
        trace, emitters = execute_concrete_evidence(case["generator"], assignment)
        _, violations = analyze_events(case["catalog"], emitters, trace)
        if any(item["kind"] in enabled_kinds for item in violations):
            return True
    return False


def semantic_rejects(case: Json, assignments: list[Json]) -> bool:
    return trace_rejects(case, assignments, {"safety"})


def flatten_events(node: Json) -> list[Json]:
    kind = node["kind"]
    if kind == "emit":
        event = copy.deepcopy(node["event"])
        event["obligations"] = list(node.get("declared_obligations", []))
        return [event]
    if kind == "seq":
        return [event for child in node["children"] for event in flatten_events(child)]
    if kind == "if":
        return flatten_events(node["then"]) + flatten_events(node["else"])
    return flatten_events(node["body"])


def global_lint_rejects(case: Json) -> bool:
    events = flatten_events(case["generator"])
    protections = {event.get("protection") for event in events if event.get("op") == "protect"}
    checks = {event.get("capability") for event in events if event.get("op") == "check"}
    has_strong_rng = any(event.get("op") == "rng" and event.get("strength") == "strong" for event in events)
    for event in events:
        for oid in required_obligations(case["catalog"], event):
            obligation = next(item for item in case["catalog"]["obligations"] if item["id"] == oid)
            rule = obligation["rule"]
            if rule["kind"] == "protection" and not set(rule["requires"]).issubset(protections):
                return True
            if rule["kind"] == "preceded" and event.get("capability") not in checks:
                return True
            if rule["kind"] == "strong_rng" and not has_strong_rng:
                return True
            if rule["kind"] == "forbid":
                return True
    return False


def timed(call: Callable[[], Any], repetitions: int = 3) -> tuple[Any, float]:
    values: list[float] = []
    result: Any = None
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        result = call()
        values.append((time.perf_counter_ns() - start) / 1_000_000.0)
    return result, statistics.median(values)


def classification_metrics(rows: list[Json], method: str) -> Json:
    tp = sum(row["truth_rejected"] and row[method] for row in rows)
    tn = sum((not row["truth_rejected"]) and (not row[method]) for row in rows)
    fp = sum((not row["truth_rejected"]) and row[method] for row in rows)
    fn = sum(row["truth_rejected"] and (not row[method]) for row in rows)
    total = len(rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "method": method,
        "accuracy": (tp + tn) / total,
        "precision": precision,
        "recall": recall,
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
    }


def mutations(result: Json) -> list[Json]:
    items: list[Json] = []
    if result["kind"] == "certificate":
        a = copy.deepcopy(result)
        first_field = next(iter(a["cells"][0]["cube"]))
        del a["cells"][0]["cube"][first_field]
        items.append(a)

        b = copy.deepcopy(result)
        if b["cells"][0]["events"]:
            b["cells"][0]["events"][0]["origin"] = "tampered-origin"
        else:
            b["claim"]["origin_complete"] = False
        items.append(b)

        c = copy.deepcopy(result)
        if c["cells"][0]["monitor_steps"]:
            c["cells"][0]["monitor_steps"].pop()
        else:
            c["claim"]["trace_safe"] = False
        items.append(c)

        d = copy.deepcopy(result)
        if len(d["cells"]) > 1:
            d["cells"].pop()
        else:
            d["claim"]["domain_partitioned"] = False
        items.append(d)
    else:
        a = copy.deepcopy(result)
        a["witness"]["violation"]["detail"] = "tampered detail"
        items.append(a)

        b = copy.deepcopy(result)
        if b["witness"]["events"]:
            b["witness"]["events"].pop()
        items.append(b)

        c = copy.deepcopy(result)
        c["witness"]["input_size"] += 1
        items.append(c)

        d = copy.deepcopy(result)
        d["subject"]["case_id"] = "tampered-case"
        items.append(d)
    return items


def evaluate(case_dir: Path, result_dir: Path) -> Json:
    full_start = time.perf_counter()
    case_paths = sorted(path for path in case_dir.glob("*.json") if path.name != "manifest.json")
    result_case_dir = result_dir / "cases"
    result_case_dir.mkdir(parents=True, exist_ok=True)
    classification_rows: list[Json] = []
    case_rows: list[Json] = []
    tamper_total = 0
    tamper_rejected = 0
    checker_passed = 0
    total_assignments = 0
    producer_times: list[float] = []
    checker_times: list[float] = []
    certificate_sizes: list[int] = []
    counterexample_sizes: list[int] = []
    compression_ratios: list[float] = []
    minimal_sizes: list[int] = []
    branch_first_sizes: list[int] = []
    semantic_comparisons = 0
    historical_rows: list[Json] = []
    control_event_skeletons: set[str] = set()
    pure_control_topologies: set[str] = set()
    generator_node_counts: list[int] = []

    for case_path in case_paths:
        case = load(case_path)
        control_event_skeletons.add(repr(control_shape(case["generator"])))
        pure_control_topologies.add(repr(pure_control_shape(case["generator"])))
        generator_node_counts.append(node_count(case["generator"]))
        result, producer_ms = timed(lambda: make_result(case))
        producer_times.append(producer_ms)
        _, checker_ms = timed(lambda: verify(case, result))
        checker_times.append(checker_ms)
        checker_passed += 1
        output_path = result_case_dir / f"{case['case_id']}.json"
        save(output_path, result)
        result_bytes = output_path.stat().st_size
        assignments = raw_assignments(case["schema"])
        total_assignments += len(assignments)
        if result["kind"] == "certificate":
            certificate_sizes.append(result_bytes)
            compression_ratios.append(len(assignments) / len(result["cells"]))
        else:
            counterexample_sizes.append(result_bytes)
            minimal_sizes.append(result["witness"]["input_size"])
            for assignment in reversed(assignments):
                trace, emitters = execute_concrete_evidence(case["generator"], assignment)
                _, violations = analyze_events(case["catalog"], emitters, trace)
                if violations:
                    branch_first_sizes.append(input_size(case["schema"], assignment))
                    break

        for mutation in mutations(result):
            tamper_total += 1
            try:
                verify(case, mutation)
            except (CheckFailure, KeyError, TypeError, ValueError):
                tamper_rejected += 1

        raw = raw_assignments(case["schema"])
        sample_indices = sorted({0, len(raw) // 2, len(raw) - 1})
        exhaustive = canonical_assignments(case["schema"])
        checker_class = classify_case(case)

        # Compare the two independently implemented concrete interpreters and
        # monitors on every assignment, not merely on final accept/reject labels.
        for assignment in exhaustive:
            producer_events, producer_emitters = execute_concrete_evidence(case["generator"], assignment)
            producer_steps, producer_failures = analyze_events(case["catalog"], producer_emitters, producer_events)
            independent_events, independent_emitters = checker_emitted(case["generator"], assignment)
            independent_steps, independent_failures = checker_replay(
                case["catalog"], independent_emitters, independent_events
            )
            if (
                producer_events != independent_events
                or producer_emitters != independent_emitters
                or producer_steps != independent_steps
                or producer_failures != independent_failures
                or render_program(producer_events) != checker_pretty_program(independent_events)
            ):
                raise AssertionError(f"producer/checker semantic mismatch in {case['case_id']} for {assignment!r}")
            semantic_comparisons += 1

        if case.get("corpus_source") == "public-advisory-abstraction":
            model = case["historical_model"]
            patched = model["state"] == "patched"
            historical_class = classify_historical(model["anchor"], patched, exhaustive)
            historical_rows.append({
                "case_id": case["case_id"],
                "anchor": model["anchor"],
                "record": model["record"],
                "state": model["state"],
                "assignments": len(exhaustive),
                "unsafe_assignments": sum(
                    not render_historical(model["anchor"], patched, assignment)["safe"]
                    for assignment in exhaustive
                ),
                "historical_oracle_class": historical_class,
                "checker_class": checker_class,
                "agreement": historical_class == checker_class,
            })

        row = {
            "case_id": case["case_id"],
            "fault_kind": case["fault_kind"],
            "truth_rejected": checker_class == "rejected",
            "certificate_method": result["kind"] == "counterexample",
            "global_template_lint": global_lint_rejects(case),
            "default_trace_safety": trace_rejects(case, [raw[0]], {"safety"}),
            "three_trace_tests": trace_rejects(case, [raw[index] for index in sample_indices], {"safety"}),
            "exhaustive_trace_safety": trace_rejects(case, exhaustive, {"safety"}),
            "coverage_plus_safety": trace_rejects(case, exhaustive, {"coverage", "safety"}),
            "origin_plus_safety": trace_rejects(case, exhaustive, {"origin", "safety"}),
            "origin_plus_coverage": trace_rejects(case, exhaustive, {"origin", "coverage"}),
        }
        classification_rows.append(row)
        case_rows.append({
            "case_id": case["case_id"],
            "family": case["family"],
            "subtype": case["subtype"],
            "corpus_source": case.get("corpus_source", "constructed"),
            "fault_kind": case["fault_kind"],
            "fault_detail": case["fault_detail"],
            "expected": case["expected"],
            "checker_class": checker_class,
            "result_kind": result["kind"],
            "assignments": len(assignments),
            "certificate_cells": len(result.get("cells", [])),
            "result_bytes": result_bytes,
            "producer_ms": producer_ms,
            "checker_ms": checker_ms,
            "witness_input_size": result.get("witness", {}).get("input_size", ""),
            "witness_prefix_length": result.get("witness", {}).get("violation", {}).get("prefix_length", ""),
        })

    methods = [
        "certificate_method",
        "global_template_lint",
        "default_trace_safety",
        "three_trace_tests",
        "exhaustive_trace_safety",
        "coverage_plus_safety",
        "origin_plus_safety",
        "origin_plus_coverage",
    ]
    baseline_summary = [classification_metrics(classification_rows, method) for method in methods]

    ablation_rows: list[Json] = []
    for method in methods:
        row: Json = {"method": method}
        for fault_kind in ("semantic", "coverage", "origin"):
            subset = [item for item in classification_rows if item["fault_kind"] == fault_kind]
            row[f"{fault_kind}_detected"] = sum(bool(item[method]) for item in subset)
            row[f"{fault_kind}_total"] = len(subset)
        ablation_rows.append(row)

    result_dir.mkdir(parents=True, exist_ok=True)
    with (result_dir / "case_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(case_rows[0]))
        writer.writeheader()
        writer.writerows(case_rows)
    with (result_dir / "baseline_predictions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(classification_rows[0]))
        writer.writeheader()
        writer.writerows(classification_rows)
    with (result_dir / "baseline_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(baseline_summary[0]))
        writer.writeheader()
        writer.writerows(baseline_summary)
    with (result_dir / "ablation_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(ablation_rows[0]))
        writer.writeheader()
        writer.writerows(ablation_rows)

    with (result_dir / "historical_anchor_cases.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(historical_rows[0]))
        writer.writeheader()
        writer.writerows(historical_rows)

    historical_summary: list[Json] = []
    for anchor in ANCHORS:
        subset = [row for row in historical_rows if row["anchor"] == anchor]
        historical_summary.append({
            "anchor": anchor,
            "record": ANCHORS[anchor]["record"],
            "cases": len(subset),
            "patched_cases": sum(row["state"] == "patched" for row in subset),
            "vulnerable_cases": sum(row["state"] == "vulnerable" for row in subset),
            "assignments": sum(row["assignments"] for row in subset),
            "unsafe_assignments": sum(row["unsafe_assignments"] for row in subset),
            "oracle_checker_agreements": sum(bool(row["agreement"]) for row in subset),
        })
    with (result_dir / "historical_anchor_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(historical_summary[0]))
        writer.writeheader()
        writer.writerows(historical_summary)

    family_rows: list[Json] = []
    for family in sorted({row["family"] for row in case_rows}):
        subset = [row for row in case_rows if row["family"] == family]
        accepted_subset = [row for row in subset if row["result_kind"] == "certificate"]
        rejected_subset = [row for row in subset if row["result_kind"] == "counterexample"]
        family_rows.append({
            "family": family,
            "cases": len(subset),
            "accepted": len(accepted_subset),
            "rejected": len(rejected_subset),
            "median_certificate_cells": statistics.median([row["certificate_cells"] for row in accepted_subset]),
            "median_certificate_bytes": statistics.median([row["result_bytes"] for row in accepted_subset]),
            "median_counterexample_bytes": statistics.median([row["result_bytes"] for row in rejected_subset]),
            "median_producer_ms": statistics.median([row["producer_ms"] for row in subset]),
            "median_checker_ms": statistics.median([row["checker_ms"] for row in subset]),
        })
    with (result_dir / "family_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(family_rows[0]))
        writer.writeheader()
        writer.writerows(family_rows)

    def percentile(values: list[float], fraction: float) -> float:
        ordered = sorted(values)
        if not ordered:
            return 0.0
        position = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
        return ordered[position]

    summary: Json = {
        "corpus": {
            "cases": len(case_rows),
            "families": len({row["family"] for row in case_rows}),
            "constructed_families": len({row["family"] for row in case_rows if row["corpus_source"] == "constructed"}),
            "historical_anchor_families": len({row["family"] for row in case_rows if row["corpus_source"] == "public-advisory-abstraction"}),
            "constructed_cases": sum(row["corpus_source"] == "constructed" for row in case_rows),
            "historical_anchor_cases": sum(row["corpus_source"] == "public-advisory-abstraction" for row in case_rows),
            "historical_patched_cases": sum(row["fault_detail"] == "advisory-patched" for row in case_rows),
            "historical_vulnerable_cases": sum(row["fault_detail"] == "advisory-vulnerable" for row in case_rows),
            "pure_control_topologies": len(pure_control_topologies),
            "control_event_skeletons": len(control_event_skeletons),
            "generator_nodes_min": min(generator_node_counts),
            "generator_nodes_median": statistics.median(generator_node_counts),
            "generator_nodes_max": max(generator_node_counts),
            "accepted": sum(row["checker_class"] == "accepted" for row in case_rows),
            "rejected": sum(row["checker_class"] == "rejected" for row in case_rows),
            "semantic_faults": sum(row["fault_kind"] == "semantic" for row in case_rows),
            "coverage_faults": sum(row["fault_kind"] == "coverage" for row in case_rows),
            "origin_faults": sum(row["fault_kind"] == "origin" for row in case_rows),
            "missing_obligation_faults": sum(row["fault_detail"] == "missing-obligation" for row in case_rows),
            "spurious_obligation_faults": sum(row["fault_detail"] == "spurious-obligation" for row in case_rows),
            "nonexistent_origin_faults": sum(row["fault_detail"] == "nonexistent-origin" for row in case_rows),
            "wrong_existing_origin_faults": sum(row["fault_detail"] == "wrong-existing-origin" for row in case_rows),
            "exhaustive_assignments": total_assignments,
        },
        "correctness": {
            "construction_labels_match_checker_classification": sum(
                row["expected"] == row["checker_class"] for row in case_rows
            ),
            "producer_matches_checker_classification": sum(
                row["checker_class"] == ("rejected" if row["result_kind"] == "counterexample" else "accepted")
                for row in case_rows
            ),
            "independent_checker_passes": checker_passed,
            "tampered_records_tested": tamper_total,
            "tampered_records_rejected": tamper_rejected,
            "producer_checker_assignment_semantics_compared": semantic_comparisons,
            "historical_oracle_cases": len(historical_rows),
            "historical_oracle_matches_checker_classification": sum(
                bool(row["agreement"]) for row in historical_rows
            ),
        },
        "certificate": {
            "accepted_certificate_count": len(certificate_sizes),
            "median_bytes": statistics.median(certificate_sizes),
            "p95_bytes": percentile([float(v) for v in certificate_sizes], 0.95),
            "median_assignment_to_cell_ratio": statistics.median(compression_ratios),
            "p95_assignment_to_cell_ratio": percentile(compression_ratios, 0.95),
        },
        "counterexample": {
            "count": len(counterexample_sizes),
            "median_bytes": statistics.median(counterexample_sizes),
            "median_minimal_input_size": statistics.median(minimal_sizes),
            "median_reverse_branch_first_size": statistics.median(branch_first_sizes),
            "mean_size_reduction": statistics.mean(branch_first_sizes) - statistics.mean(minimal_sizes),
        },
        "historical_anchors": historical_summary,
        "performance": {
            "producer_median_ms": statistics.median(producer_times),
            "producer_p95_ms": percentile(producer_times, 0.95),
            "checker_median_ms": statistics.median(checker_times),
            "checker_p95_ms": percentile(checker_times, 0.95),
            "evaluation_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "evaluation_wall_seconds": time.perf_counter() - full_start,
        },
        "baselines": baseline_summary,
        "ablations": ablation_rows,
    }
    save(result_dir / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproduce the corpus, certificates, checker tests, and evaluation tables.")
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    summary = evaluate(args.case_dir, args.result_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
