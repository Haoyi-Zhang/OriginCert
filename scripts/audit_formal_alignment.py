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


def main() -> int:
    issues: list[dict[str, str]] = []
    checker_text = CHECKER.read_text(encoding="utf-8")
    core_text = CORE.read_text(encoding="utf-8")
    proof_text = PROOFS.read_text(encoding="utf-8").lower()
    checker_imports = imports(CHECKER)
    forbidden_imports = [x for x in checker_imports if x == "src" or x.startswith("src.")]
    if forbidden_imports:
        issues.append({"code": "checker-imports-producer", "detail": repr(forbidden_imports)})

    verify_src = function_source(CHECKER, "verify_certificate")
    if "assignment_list" in verify_src:
        issues.append({"code": "certificate-expands-assignments", "detail": "verify_certificate references assignment_list"})
    for required in ("cube_cardinality", "cubes_overlap", "symbolic_emitted"):
        if required not in checker_text:
            issues.append({"code": "missing-symbolic-check", "detail": required})

    decision_functions = "\n".join(
        function_source(CHECKER, name)
        for name in ("verify_certificate", "verify_counterexample", "check_record")
        if re.search(rf"^def {name}\b", checker_text, flags=re.M)
    )
    for label in ("expected", "fault_kind"):
        if re.search(rf"\b{label}\b", decision_functions):
            issues.append({"code": "checker-uses-construction-label", "detail": label})

    # Both implementations must check obligations before applying an event's
    # transition and must retain deterministic post-violation replay.
    semantic_markers = {
        "core": ["violations", "apply"],
        "checker": ["violations", "apply"],
    }
    for label, text in (("core", core_text), ("checker", checker_text)):
        for marker in semantic_markers[label]:
            if marker not in text.lower():
                issues.append({"code": "semantic-marker-missing", "detail": f"{label}:{marker}"})
    if not any(phrase in proof_text for phrase in ("pre-state", "prestate", "state before")):
        issues.append({"code": "proof-omits-pre-state", "detail": "monitor obligation timing"})
    if not any(phrase in proof_text for phrase in ("continue", "still applied", "regardless", "complete replay")):
        issues.append({"code": "proof-omits-post-violation-transition", "detail": "complete replay semantics"})

    tests_text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(TESTS.glob("test_*.py")))
    required_test_markers = {
        "symbolic_non_enumeration": "assignment_list",
        "source_roundtrip": "reference_backends",
        "json_type_identity": "True",
        "occurrence_path": "occurrence",
    }
    for code, marker in required_test_markers.items():
        if marker not in tests_text:
            issues.append({"code": "missing-regression-marker", "detail": code})

    report = {
        "status": "PASS" if not issues else "FAIL",
        "checker_imports_producer": False if not forbidden_imports else True,
        "certificate_assignment_expansion": "assignment_list" in verify_src,
        "construction_labels_used_for_decision": any(x in decision_functions for x in ("expected", "fault_kind")),
        "symbolic_partition_checks": all(x in checker_text for x in ("cube_cardinality", "cubes_overlap", "symbolic_emitted")),
        "proof_contract_covers_pre_state_and_complete_replay": not any(i["code"].startswith("proof-") for i in issues),
        "issues": issues,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
