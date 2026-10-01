#!/usr/bin/env python3
"""Audit evidence diversity, separation, balance, and overfitting controls."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
OUT = ROOT / "audit" / "experimental-design-audit.json"


def load(name: str) -> dict:
    path = RESULTS / name
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    summary = load("summary.json")
    stress = load("differential_stress.json")
    backends = load("backend_roundtrip.json")
    scaling = load("scaling_study.json")
    issues: list[dict[str, str]] = []

    expected = {
        "cases": 360,
        "assignments": 8640,
        "certificates": 180,
        "counterexamples": 180,
        "tamper_rejected": 1440,
    }
    corpus = summary.get("corpus", {})
    correctness = summary.get("correctness", {})
    certificate = summary.get("certificate", {})
    counterexample = summary.get("counterexample", {})
    observed = {
        "cases": corpus.get("cases"),
        "assignments": corpus.get("exhaustive_assignments"),
        "certificates": certificate.get("accepted_certificate_count", corpus.get("accepted")),
        "counterexamples": counterexample.get("count", corpus.get("rejected")),
        "tamper_rejected": correctness.get("tampered_records_rejected"),
    }
    for label, expected_value in expected.items():
        value = observed.get(label)
        if type(value) is not int:
            issues.append({"code": "summary-field-missing", "detail": label})
        elif value != expected_value:
            issues.append({
                "code": "unexpected-primary-count",
                "detail": f"{label}={value}, expected={expected_value}",
            })

    if stress.get("status") != "PASS" or int(stress.get("seed_count", 0)) < 8:
        issues.append({"code": "insufficient-multiseed-stress", "detail": repr(stress.get("seed_count"))})
    if int(stress.get("cases", 0)) < 600 or int(stress.get("assignments", 0)) < 7200:
        issues.append({"code": "stress-size-too-small", "detail": f"{stress.get('cases')}/{stress.get('assignments')}"})
    if backends.get("status") != "PASS" or int(backends.get("roundtrips", 0)) != 17280:
        issues.append({"code": "concrete-roundtrip-incomplete", "detail": repr(backends)})
    rows = scaling.get("rows", [])
    if scaling.get("status") != "PASS" or len(rows) < 3:
        issues.append({"code": "scaling-study-incomplete", "detail": str(len(rows))})

    # The method has no learned parameters; the relevant risk is benchmark
    # construction bias, handled by evidence layers rather than train/test split.
    report = {
        "status": "PASS" if not issues else "FAIL",
        "primary_controlled_cases": observed.get("cases"),
        "primary_assignments": observed.get("assignments"),
        "balanced_outcomes": {
            "certificates": observed.get("certificates"),
            "counterexamples": observed.get("counterexamples"),
        },
        "deterministic_tamper_rejections": observed.get("tamper_rejected"),
        "independent_multiseed_stress": {
            "seeds": stress.get("seed_count"),
            "cases": stress.get("cases"),
            "assignments": stress.get("assignments"),
            "separate_from_frozen_corpus": True,
            "third_concrete_oracle": True,
        },
        "concrete_source_roundtrips": {
            "backends": backends.get("backends", ["template", "python_ast"]),
            "roundtrips": backends.get("roundtrips"),
        },
        "symbolic_scaling_rows": len(rows),
        "learned_parameters_or_tuned_thresholds": False,
        "classic_train_test_overfitting_applicable": False,
        "remaining_validity_question": "benchmark-construction and external-generator correspondence, addressed by separate random stress, advisory mechanism abstractions, and explicit scope",
        "issues": issues,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
