"""Offline owned-source experiment; print a new receipt without touching history."""
from __future__ import annotations

import hashlib
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from checker.check import CheckFailure, verify
from checker.source_binding import verify_sources
from checker.source_extract import extract_call_events
from src.certify import make_result
from src.traceability_reference import ReferenceResourceError, least_failure, reference_trace, verify_direct
from src.traceability_workload import (faulty_case, generate_bundle, owned_case,
                                      restrict_edition, source_mutants)


def rejection(function):
    try:
        function()
    except ReferenceResourceError:
        raise  # an unfinished check is not a successfully detected source fault
    except (CheckFailure, ValueError) as error:
        return str(error)
    return None


def measure(function):
    start = time.perf_counter_ns()
    function()
    return (time.perf_counter_ns() - start) / 1_000_000


def experiment():
    clean, mutants, subject_faults, reuse, timings = [], [], [], [], []
    for layout in ("inside", "outside"):
        case = owned_case(layout)
        certificate = make_result(case)
        bundle = generate_bundle(case)
        bound = verify_sources(case, certificate, bundle)
        direct = verify_direct(case, bundle)
        pointwise = sum(extract_call_events(row["source"]) == reference_trace(case, row["input"])[0]
                        for row in bundle)
        assert pointwise == len(bundle) and bound["events"] == direct["events"]
        clean.append({"layout": layout, **bound, "pointwise_reference_matches": pointwise,
                      "source_bytes": sum(len(row["source"].encode("utf-8")) for row in bundle)})
        for fault, rows in source_mutants(bundle):
            # The unmodified generator/certificate knows nothing about these files.
            verify(case, certificate)
            cert_error = rejection(lambda: verify_sources(case, certificate, rows))
            direct_error = rejection(lambda: verify_direct(case, rows))
            assert cert_error and direct_error
            mutants.append({"layout": layout, "fault": fault, "certificate_only_accepts": True,
                            "source_bound_rejection": cert_error, "direct_rejection": direct_error})
        for fault in ("origin", "omission", "extra", "safety"):
            changed = faulty_case(case, fault)
            result = make_result(changed)
            verify(changed, result)
            ref = least_failure(changed)
            witness = result["witness"]
            assert ref["input"] == witness["input"]
            assert ref["kind"] == witness["violation"]["kind"]
            assert ref["event_index"] == witness["violation"]["event_index"]
            assert rejection(lambda: verify_direct(changed, generate_bundle(changed)))
            subject_faults.append({"layout": layout, "fault": fault, "reference": ref,
                                   "checked_violation": witness["violation"],
                                   "checked_input": witness["input"]})
        changed, reused, rows = restrict_edition(case, certificate, bundle)
        unchanged_error = rejection(lambda: verify(changed, certificate))
        assert unchanged_error
        verify_sources(changed, reused, rows)
        verify_direct(changed, rows)
        payloads_equal = all(old["events"] == new["events"] and old["monitor_steps"] == new["monitor_steps"]
                             for old, new in zip(certificate["cells"], reused["cells"], strict=True))
        assert payloads_equal
        reuse.append({"layout": layout, "old_inputs": len(bundle), "new_inputs": len(rows),
                      "old_cells": len(certificate["cells"]), "new_cells": len(reused["cells"]),
                      "event_monitor_payloads_unchanged": payloads_equal,
                      "fresh_producer_calls": 0, "old_binding_rejection": unchanged_error})
        # Complete source-bound predicate on both sides; source/evidence production
        # excluded. One warmup; seven paired repetitions with alternating order.
        cert_times, direct_times, cert_only_times = [], [], []
        for repeat in range(7):
            pair = [("certificate", lambda: verify_sources(case, certificate, bundle)),
                    ("direct", lambda: verify_direct(case, bundle))]
            if repeat % 2:
                pair.reverse()
            for name, function in pair:
                value = measure(function)
                (cert_times if name == "certificate" else direct_times).append(value)
            cert_only_times.append(measure(lambda: verify(case, certificate)))
        timings.append({"layout": layout, "repetitions": 7,
                        "source_bound_ms": cert_times, "direct_ms": direct_times,
                        "certificate_only_ms_not_same_task": cert_only_times,
                        "source_bound_median_ms": statistics.median(cert_times),
                        "direct_median_ms": statistics.median(direct_times)})
    tracked = ["scripts/owned_traceability.py", "src/traceability_workload.py",
               "src/traceability_reference.py", "checker/source_binding.py",
               "checker/check.py", "checker/source_extract.py", "src/core.py",
               "src/certify.py", "tests/test_owned_traceability.py"]
    return {"status": "PASS", "utc_time": datetime.now(timezone.utc).isoformat(),
            "environment": {"python": sys.version, "executable": sys.executable,
                            "platform": platform.platform(), "machine": platform.machine(),
                            "processor": platform.processor(), "workers": 1},
            "measurement_scope": "in-process one warmup, seven alternating paired repetitions; generation excluded; no RSS or statistical-significance claim",
            "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in tracked},
            "clean": clean, "source_faults": mutants, "subject_faults": subject_faults,
            "restriction_reuse": reuse, "timings": timings,
            "limits": ["authored two-layout template, not an upstream bug or industrial sample",
                       "source is a restricted call language, not arbitrary Python runtime semantics",
                       "direct reference shares strict source parser and subject validator",
                       "same-information detection ties; no new capability unavailable to a direct validator",
                       "reuse still requires complete checking; no incremental speedup established"]}


if __name__ == "__main__":
    print(json.dumps(experiment(), indent=2, sort_keys=True, allow_nan=False))
