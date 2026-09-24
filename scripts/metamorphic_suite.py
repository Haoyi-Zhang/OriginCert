#!/usr/bin/env python3
"""Whole-corpus metamorphic checks against incidental ordering and node names."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
from typing import Any

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.certify import produce_record  # type: ignore
from checker.check import check_record  # type: ignore

OUT=ROOT/'results/metamorphic_suite.json'


def case_paths()->list[Path]:
    candidates=[ROOT/'data'/'cases',ROOT/'cases']
    for d in candidates:
        paths=sorted(d.glob('*.json'))
        if paths: return paths
    raise FileNotFoundError('frozen case directory')


def checker_accepts(result: Any)->bool:
    if isinstance(result,bool): return result
    if isinstance(result,dict):
        for key in ('ok','valid','accepted'):
            if key in result: return bool(result[key])
        if result.get('status') in ('PASS','pass','ok','valid'): return True
    raise TypeError(f'unrecognized checker result: {result!r}')


def record_class(record:dict[str,Any])->str:
    for key in ('kind','record_type','type'):
        value=record.get(key)
        if isinstance(value,str) and value.lower() in {'certificate','counterexample','witness','refutation'}:
            return value.lower()
    if 'certificate' in record: return 'certificate'
    if 'counterexample' in record: return 'counterexample'
    # Frozen schema uses a single top-level discriminator; fail rather than infer
    # from construction metadata.
    for value in record.values():
        if isinstance(value,str) and value.lower() in {'certificate','counterexample'}:
            return value.lower()
    raise ValueError(f'no record discriminator: {sorted(record)}')


def rename_nodes(node:Any,counter:list[int])->Any:
    if isinstance(node,dict):
        out={}
        for key,value in node.items():
            if key in {'id','node_id'} and isinstance(value,str):
                out[key]=f'alpha_{counter[0]:04d}'; counter[0]+=1
            else:
                out[key]=rename_nodes(value,counter)
        return out
    if isinstance(node,list): return [rename_nodes(x,counter) for x in node]
    return copy.deepcopy(node)


def alpha_case(case:dict[str,Any])->dict[str,Any]:
    out=copy.deepcopy(case)
    if 'generator' not in out: raise ValueError('case lacks generator')
    out['generator']=rename_nodes(out['generator'],[0])
    return out


def reverse_schema_case(case:dict[str,Any])->dict[str,Any]:
    out=copy.deepcopy(case)
    schema=out.get('schema')
    if not isinstance(schema,dict): raise ValueError('case lacks object schema')
    out['schema']={k:schema[k] for k in reversed(list(schema))}
    return out


def main()->int:
    paths=case_paths()
    if len(paths)!=360: raise RuntimeError(f'expected 360 cases, found {len(paths)}')
    checks=0
    class_matches=0
    for path in paths:
        case=json.loads(path.read_text(encoding='utf-8'))
        baseline=produce_record(copy.deepcopy(case))
        if not checker_accepts(check_record(copy.deepcopy(baseline))):
            raise RuntimeError(f'baseline checker rejection: {path.name}')
        baseline_class=record_class(baseline)
        for label,transform in (('alpha-renaming',alpha_case),('schema-order',reverse_schema_case)):
            changed=transform(case)
            record=produce_record(changed)
            if not checker_accepts(check_record(copy.deepcopy(record))):
                raise RuntimeError(f'{label} checker rejection: {path.name}')
            checks+=1
            if record_class(record)!=baseline_class:
                raise RuntimeError(f'{label} changed record class: {path.name}')
            class_matches+=1
    result={
      'status':'PASS','frozen_cases':len(paths),'metamorphic_transformations':['alpha-renaming','schema-key-order reversal'],
      'transformed_records_checked':checks,'classification_invariants':class_matches,
      'purpose':'detect dependence on incidental node spelling or JSON object order',
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(result,sort_keys=True))
    return 0
if __name__=='__main__': raise SystemExit(main())
