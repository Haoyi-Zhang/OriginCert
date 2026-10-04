#!/usr/bin/env python3
"""Check consistent alpha-renaming and object-key permutation, not field reordering."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any
ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from src.certify import make_result, load_json, save_json
from checker.check import verify


def nodes(tree: dict[str, Any]):
    yield tree
    if tree['kind'] == 'seq':
        for child in tree['children']:
            yield from nodes(child)
    elif tree['kind'] == 'if':
        yield from nodes(tree['then'])
        yield from nodes(tree['else'])
    elif tree['kind'] == 'repeat':
        yield from nodes(tree['body'])


def alpha_case(case: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(case)
    all_nodes = list(nodes(result['generator']))
    mapping = {node['node']: f'alpha_{i:04d}' for i, node in enumerate(all_nodes)}
    unknown = sorted({n['origin_override'] for n in all_nodes if 'origin_override' in n} - set(mapping))
    mapping.update({value: f'absent_{i:04d}' for i, value in enumerate(unknown)})
    for node in all_nodes:
        node['node'] = mapping[node['node']]
        if 'origin_override' in node:
            node['origin_override'] = mapping[node['origin_override']]
    return result


def reverse_object_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: reverse_object_keys(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        # Lists, especially schema fields and domains, have semantic order.
        return [reverse_object_keys(item) for item in value]
    return copy.deepcopy(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=ROOT/'data/cases')
    parser.add_argument('--output', type=Path, default=ROOT/'results/metamorphic_suite.json')
    args = parser.parse_args()
    paths = [p for p in sorted(args.cases.glob('*.json')) if p.name != 'manifest.json']
    if not paths:
        raise ValueError('no cases')
    rows = []
    for path in paths:
        case = load_json(path)
        record = make_result(case)
        verify(case, record)
        for name, transform in [('consistent-node-renaming', alpha_case), ('object-key-permutation', reverse_object_keys)]:
            changed = transform(case)
            observed = make_result(changed)
            verify(changed, observed)
            if observed['kind'] != record['kind']:
                raise RuntimeError(f'{case["case_id"]}: {name} changed verdict')
            rows.append({'case_id':case['case_id'], 'transformation':name, 'kind':observed['kind']})
    save_json(args.output, {'status':'PASS','cases':len(paths),'transformed_records':len(rows),
        'scope':'Consistent node/origin renaming and JSON object-key permutation; ordered field/domain lists preserved.', 'records':rows})
    print(json.dumps({'status':'PASS','cases':len(paths),'transformed_records':len(rows)}))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
