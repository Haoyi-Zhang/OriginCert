#!/usr/bin/env python3
"""Bind the manuscript to one retained successful scientific run.

Explicit paper destination keeps the standalone scientific command independent
of LaTeX files. Running this after a new run intentionally updates measurements.
"""
import argparse, json, shutil
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper-dir", type=Path, required=True)
    args=parser.parse_args()
    s=json.loads((ROOT/"results/summary.json").read_text(encoding="utf-8"))
    r=json.loads((ROOT/"results/reproduction.json").read_text(encoding="utf-8"))
    t=json.loads((ROOT/"results/test_results.json").read_text(encoding="utf-8"))
    if r.get("status") != "PASS" or t.get("status") != "PASS":
        raise SystemExit("A successful retained reproduction and test run are required")
    p=s["performance"]
    values={
      "TestCount": str(r["tests_run"]),
      "CertBytes": f'{s["certificate"]["median_bytes"]:,.0f}',
      "CertPBytes": f'{s["certificate"]["p95_bytes"]:,.0f}',
      "CexBytes": f'{s["counterexample"]["median_bytes"]:,.0f}',
      "ProdMedian": f'{p["producer_median_ms"]:.3f}',
      "ProdPfive": f'{p["producer_p95_ms"]:.3f}',
      "CheckMedian": f'{p["checker_median_ms"]:.3f}',
      "CheckPfive": f'{p["checker_p95_ms"]:.3f}',
      "EvalTime": f'{p["evaluation_wall_seconds"]:.3f}',
      "EvalRSS": f'{p["evaluation_peak_rss_kib"]:,}',
      "FullTime": f'{r["elapsed_seconds"]:.3f}',
      "FullRSS": f'{r["peak_rss_kib"]:,}',
    }
    args.paper_dir.mkdir(parents=True, exist_ok=True)
    text="% Numerical values exported from one successful retained scientific run.\n"
    for k,v in values.items():
        text += "\\newcommand{\\"+k+"}{"+v+"}\n"
    (args.paper_dir/"results.tex").write_text(text,encoding="utf-8")
    shutil.copyfile(ROOT/"results/scaling_study.csv",args.paper_dir/"scaling.csv")
    print(json.dumps({"status":"PASS","values":values},indent=2))
if __name__ == "__main__":
    main()
