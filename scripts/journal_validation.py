#!/usr/bin/env python3
"""Executable checks of refinement, restriction, and catalogue sensitivity."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any
ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from checker.check import (CheckFailure, assignment_list, cube_dimensions, emitted,
                          inspect_case, packed, replay, same_value, subject_from_case,
                          symbolic_emitted, triggered, verify)
from src.certify import load_json, make_result, save_json


def refine_certificate(result: dict[str,Any]) -> dict[str,Any]:
    refined=copy.deepcopy(result)
    cells=[]
    for cell in result['cells']:
        coordinate=next((name for name, values in cell['cube'].items() if len(values)>1),None)
        if coordinate is None:
            cells.append(copy.deepcopy(cell))
            continue
        values=cell['cube'][coordinate]
        for subset in [values[:1], values[1:]]:
            piece=copy.deepcopy(cell)
            piece['cube'][coordinate]=copy.deepcopy(subset)
            cells.append(piece)
    refined['cells']=cells
    return refined


def restricted_pair(case:dict[str,Any],result:dict[str,Any]):
    for index,field in enumerate(case['schema']['fields']):
        if len(field['domain'])<2:continue
        changed=copy.deepcopy(case)
        changed['schema']['fields'][index]['domain']=copy.deepcopy(field['domain'][:-1])
        try:inspect_case(changed)
        except CheckFailure:continue
        record=copy.deepcopy(result)
        record['subject']=subject_from_case(changed)
        cells=[]
        allowed=changed['schema']['fields'][index]['domain']
        for cell in record['cells']:
            remaining=[v for v in cell['cube'][field['name']] if any(same_value(v,a) for a in allowed)]
            if remaining:
                cell['cube'][field['name']]=remaining
                cells.append(cell)
        record['cells']=cells
        return changed,record
    return None


def active_catalogue_extension(case:dict[str,Any],result:dict[str,Any]):
    obligations=case['catalog']['obligations']
    by_id={o['id']:o for o in obligations}
    used=next((oid for cell in result['cells'] for event in cell['events'] for oid in event['obligations']),None)
    if used is None:return None
    changed=copy.deepcopy(case)
    extra=copy.deepcopy(by_id[used])
    new_id='journal-added-obligation'
    while new_id in by_id:new_id+='-x'
    extra['id']=new_id
    changed['catalog']['obligations'].append(extra)
    record=make_result(changed)
    verify(changed,record)
    if record['kind']!='counterexample' or record['witness']['violation']['kind']!='coverage':
        raise AssertionError(('catalogue-change-not-coverage',case['case_id']))
    return record


def validate(cases:Path,results:Path) -> dict[str,Any]:
    rows=[]
    pointwise=0
    for path in sorted(cases.glob('*.json')):
        if path.name=='manifest.json':continue
        case=load_json(path)
        result=load_json(results/path.name)
        if result['kind']!='certificate':continue
        verify(case,result)
        refined=refine_certificate(result)
        verify(case,refined)
        reversed_cells=copy.deepcopy(result)
        reversed_cells['cells'].reverse()
        verify(case,reversed_cells)
        restriction=restricted_pair(case,result)
        restricted_assignments=None
        if restriction:
            restricted_case,restricted_result=restriction
            verify(restricted_case,restricted_result)
            restricted_assignments=len(assignment_list(restricted_case['schema'],structural_order=False))
        extended=active_catalogue_extension(case,result)
        # Exhaustive equivalence is evaluation evidence, never used by verify_certificate.
        count=0
        for assignment in assignment_list(case['schema'],structural_order=False):
            matches=[cell for cell in result['cells'] if all(any(same_value(assignment[k],v) for v in vs) for k,vs in cell['cube'].items())]
            if len(matches)!=1:raise AssertionError('not a partition')
            trace,origins=emitted(case['generator'],assignment)
            steps,failures=replay(case['catalog'],origins,trace)
            if failures or not same_value(matches[0]['events'],trace) or not same_value(matches[0]['monitor_steps'],steps):
                raise AssertionError(('pointwise mismatch',case['case_id']))
            count+=1
        pointwise+=count
        rows.append({'case_id':case['case_id'],'original_cells':len(result['cells']),
                     'refined_cells':len(refined['cells']), 'concrete_inputs':count,
                     'restriction_checked':restriction is not None,'restricted_inputs':restricted_assignments,
                     'catalogue_coverage_counterexample':extended is not None})
    if not rows:raise ValueError('no certificates examined')
    return {'status':'PASS','certificates':len(rows),'concrete_inputs_compared':pointwise,
            'refinement_checks':len(rows),'cell_permutation_checks':len(rows),
            'admissible_restriction_checks':sum(r['restriction_checked'] for r in rows),
            'restriction_unavailable':sum(not r['restriction_checked'] for r in rows),
            'catalogue_sensitivity_checks':sum(r['catalogue_coverage_counterexample'] for r in rows),
            'records':rows,'interpretation':'Tests of stated algebraic consequences, not an independent proof or new industrial sample.'}


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases',type=Path,default=ROOT/'data/cases')
    parser.add_argument('--records',type=Path,default=ROOT/'results/cases')
    parser.add_argument('--output',type=Path,default=ROOT/'results/journal_validation.json')
    args=parser.parse_args()
    report=validate(args.cases,args.records)
    save_json(args.output,report)
    print(json.dumps({k:v for k,v in report.items() if k!='records'},sort_keys=True))
    return 0
if __name__=='__main__':raise SystemExit(main())
