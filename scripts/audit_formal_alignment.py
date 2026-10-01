#!/usr/bin/env python3
"""Cross-check the written contract, producer, checker, and regression evidence."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "checker" / "check.py"
CORE = ROOT / "src" / "core.py"
PROOFS = ROOT / "proofs.md"
TESTS = ROOT / "tests"
OUT = ROOT / "audit" / "formal-alignment-audit.json"


def imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            result.append(node.module or "")
    return result


def function_source(path: Path, name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(source, node) or ""
    raise ValueError(f"function not found: {path}:{name}")


def ordered(source: str, *markers: str) -> bool:
    positions = [source.find(marker) for marker in markers]
    return all(position >= 0 for position in positions) and positions == sorted(positions)


def main() -> int:
    issues: list[dict[str, str]] = []
    checker_text = CHECKER.read_text(encoding="utf-8")
    proof_text = PROOFS.read_text(encoding="utf-8").lower()
    checker_imports = imports(CHECKER)
    forbidden_imports = [name for name in checker_imports if name == "src" or name.startswith("src.")]
    if forbidden_imports:
        issues.append({"code": "checker-imports-producer", "detail": repr(forbidden_imports)})

    verify_source = function_source(CHECKER, "verify_certificate")
    if "assignment_list" in verify_source or "cube_members" in verify_source:
        issues.append(
            {
                "code": "certificate-expands-assignments",
                "detail": "verify_certificate references assignment expansion",
            }
        )
    for required in (
        "cube_dimensions",
        "cubes_overlap",
        "cube_cardinality",
        "symbolic_emitted",
        "covered_cardinality",
    ):
        if required not in verify_source:
            issues.append({"code": "missing-symbolic-check", "detail": required})

    decision_functions = "\n".join(
        function_source(CHECKER, name)
        for name in ("verify_certificate", "verify_counterexample", "verify")
    )
    for label in ("expected", "fault_kind"):
        if re.search(rf"\b{label}\b", decision_functions):
            issues.append({"code": "checker-uses-construction-label", "detail": label})

    core_monitor = function_source(CORE, "analyze_events")
    checker_monitor = function_source(CHECKER, "replay")
    core_order = ordered(core_monitor, "for oid in required", 'op = event["op"]', "violations.extend(local)")
    checker_order = ordered(
        checker_monitor,
        "for identifier in required",
        'operation = event["op"]',
        "failures.extend(local)",
    )
    if not core_order:
        issues.append({"code": "producer-monitor-order", "detail": "rules -> transition -> record"})
    if not checker_order:
        issues.append({"code": "checker-monitor-order", "detail": "rules -> transition -> record"})
    if "if not local" in core_monitor or "if not local" in checker_monitor:
        issues.append({"code": "conditional-post-violation-transition", "detail": "local gate found"})

    proof_requirements = {
        "symbolic_cardinality": ("pairwise disjointness", "cardinality"),
        "region_homogeneity": ("homogeneity", "symbolic leaf"),
        "concrete_equivalence": ("concrete execution", "structural induction"),
        "unconditional_transition": ("regardless of whether", "sticky"),
        "operation_projection_limit": ("sound and complete", "operation-only"),
    }
    for code, phrases in proof_requirements.items():
        if not all(phrase in proof_text for phrase in phrases):
            issues.append({"code": f"proof-omits-{code}", "detail": repr(phrases)})

    tests_text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(TESTS.glob("test_*.py")))
    required_test_markers = {
        "symbolic_non_enumeration": "test_certificate_checking_does_not_enumerate_schema_assignments",
        "source_roundtrip": "test_both_reference_backends_round_trip_without_execution",
        "json_type_identity": "test_json_value_identity_is_unambiguous",
        "occurrence_path": "test_nested_repeat_occurrences_are_complete_paths",
        "stress_output_contract": "test_differential_stress_writes_the_requested_report",
        "backend_input_contract": "test_backend_roundtrip_uses_data_cases_and_writes_output",
    }
    for code, marker in required_test_markers.items():
        if marker not in tests_text:
            issues.append({"code": "missing-regression-marker", "detail": code})

    report = {
        "status": "PASS" if not issues else "FAIL",
        "checker_imports_producer": bool(forbidden_imports),
        "certificate_assignment_expansion": "assignment_list" in verify_source or "cube_members" in verify_source,
        "construction_labels_used_for_decision": any(
            re.search(rf"\b{label}\b", decision_functions) for label in ("expected", "fault_kind")
        ),
        "symbolic_partition_checks": all(
            item in verify_source
            for item in ("cube_dimensions", "cubes_overlap", "cube_cardinality", "symbolic_emitted")
        ),
        "producer_monitor_order": core_order,
        "checker_monitor_order": checker_order,
        "proof_contract_covers_region_soundness_and_complete_replay": not any(
            issue["code"].startswith("proof-") for issue in issues
        ),
        "issues": issues,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
