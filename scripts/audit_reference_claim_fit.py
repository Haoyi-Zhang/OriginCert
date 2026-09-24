#!/usr/bin/env python3
"""Check that each citation is used in a context compatible with its audited role."""
from __future__ import annotations
import csv, json, re
from collections import defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
IN=ROOT/'audit/reference-claim-context-audit.csv'
OUT=ROOT/'audit/reference-claim-fit-audit.json'
KEYWORDS={
 'secure-code-generation evidence': {'code','generation','generated','llm','assistant','security','secure','weakness','vulnerability'},
 'certification and translation-validation foundations': {'certificate','certification','validation','compiler','monitor','proof','checking','checked','translation'},
 'generated-code assurance and verification witnesses': {'generated','generator','verification','verifier','certifying','witness','assurance','code'},
 'testing and differential-analysis foundations': {'test','testing','fuzz','differential','bounded','symbolic','random','counterexample','compiler'},
 'traceability, provenance, and vulnerability taxonomy': {'traceability','provenance','origin','cwe','weakness','supply','taxonomy','source'},
 'supporting literature': {'code','software','security','verification','testing','generator'},
}

def main()->int:
    rows=list(csv.DictReader(IN.open(encoding='utf-8')))
    by_key=defaultdict(list)
    issues=[]
    for row in rows:
        role=row['paper_role']
        context=row['context'].lower()
        words=set(re.findall(r"[a-z]+",context))
        fit=bool(words & KEYWORDS.get(role,KEYWORDS['supporting literature']))
        row['keyword_fit']=fit
        by_key[row['key']].append(fit)
    for key,values in sorted(by_key.items()):
        if not any(values):
            issues.append({'code':'role-context-mismatch','key':key})
    report={
      'status':'PASS' if not issues else 'FAIL',
      'entries':len(by_key),
      'citation_occurrences':len(rows),
      'entries_with_at_least_one_role-compatible_context':sum(any(v) for v in by_key.values()),
      'audit_scope':'semantic role/context fit; identity verification is reported separately',
      'issues':issues,
    }
    OUT.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(report,sort_keys=True))
    return 0 if not issues else 1
if __name__=='__main__': raise SystemExit(main())
