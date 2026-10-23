"""Owned, bounded path-growth and certificate-restriction observations.

Every added Boolean coordinate changes the executed branch. These are finite
generator-tree checks, not a third-party frontend, speedup or industrial study.
"""
import argparse
import copy
import gzip
import io
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.certify import make_result
import checker.check as checker_code
from checker.check import (CheckFailure, assignment_list, emitted, replay,
                           subject_from_case, verify)


def branch_case(depth):
    if type(depth) is not int or not 0 <= depth <= 8:
        raise ValueError('branch depth must be an integer from zero to eight')
    def tree(level, path):
        if level == depth:
            return {'kind': 'seq', 'node': 'leaf-' + path, 'children': [
                {'kind': 'emit', 'node': 'check-' + path,
                 'event': {'op': 'check', 'capability': 'publish'},
                 'declared_obligations': []},
                {'kind': 'emit', 'node': 'publish-' + path,
                 'event': {'op': 'privileged', 'capability': 'publish'},
                 'declared_obligations': ['checked-publication']}]}
        return {'kind': 'if', 'node': 'branch-' + (path or 'root'),
                'condition': {'field': 'choice_' + str(level), 'equals': 0},
                'then': tree(level + 1, path + '0'),
                'else': tree(level + 1, path + '1')}
    fields = [{'name': 'choice_' + str(i), 'domain': [0, 1]} for i in range(depth)]
    return {'case_id': 'path-structure-' + str(depth), 'family': 'owned-path-structure',
            'schema': {'fields': fields or [{'name': 'unit', 'domain': [0]}]},
            'generator': tree(0, ''),
            'catalog': {'obligations': [{'id': 'checked-publication',
                         'trigger': {'op': 'privileged'}, 'rule': {'kind': 'preceded'}}]}}


def restrict_first(case, certificate):
    """Intersect/rebind payloads; never invoke the certificate producer."""
    if len(case['schema']['fields'][0]['domain']) != 2:
        raise ValueError('restriction needs a binary first coordinate')
    subject = copy.deepcopy(case)
    name = subject['schema']['fields'][0]['name']
    subject['schema']['fields'][0]['domain'] = [0]
    result = copy.deepcopy(certificate)
    result['subject'] = subject_from_case(subject)
    result['cells'] = [cell for cell in result['cells'] if 0 in cell['cube'][name]]
    for cell in result['cells']:
        cell['cube'][name] = [0]
    return subject, result


def check_pointwise(case, certificate):
    assignments = assignment_list(case['schema'], structural_order=False)
    for assignment in assignments:
        cells = [cell for cell in certificate['cells']
                 if all(assignment[k] in values for k, values in cell['cube'].items())]
        if len(cells) != 1:
            raise RuntimeError('not an exact input partition')
        trace, actual = emitted(case['generator'], assignment)
        steps, failures = replay(case['catalog'], actual, trace)
        if failures or cells[0]['events'] != trace or cells[0]['monitor_steps'] != steps:
            raise RuntimeError('pointwise replay disagrees with recorded payload')
    return len(assignments)


def observe(depth):
    case = branch_case(depth)
    certificate = make_result(case)
    if certificate['kind'] != 'certificate':
        raise RuntimeError('owned well-checked branch unexpectedly rejected')
    comparisons = [0]
    original_overlap = checker_code.cubes_overlap
    def count_overlap(*args):
        comparisons[0] += 1
        return original_overlap(*args)
    with patch.object(checker_code, 'cubes_overlap', side_effect=count_overlap):
        verify(case, certificate)
    count = check_pointwise(case, certificate)
    if count != 2 ** depth or len(certificate['cells']) != count:
        raise RuntimeError('path/cell growth differs from complete-tree construction')
    pending, nodes, branches = [case['generator']], 0, 0
    while pending:
        node = pending.pop()
        nodes += 1
        if node['kind'] == 'seq':
            pending.extend(node['children'])
        elif node['kind'] == 'if':
            branches += 1
            pending.extend((node['then'], node['else']))
    if nodes != 4 * count - 1 or branches != count - 1 or comparisons[0] != count * (count - 1) // 2:
        raise RuntimeError('observed tree or verifier work differs from construction')
    row = {'depth': depth, 'inputs': count, 'branch_nodes': branches,
           'static_nodes': nodes, 'certificate_cells': len(certificate['cells']),
           'trace_events_per_input': 2,
           'cell_pairs_checked': comparisons[0],
           'restricted_inputs': 0, 'reused_payloads': 0,
           'fresh_certificate_constructions_for_restriction': 0,
           'rechecking_required': True}
    record = {'case': case, 'certificate': certificate}
    if depth:
        changed, restricted = restrict_first(case, certificate)
        verify(changed, restricted)
        retained = check_pointwise(changed, restricted)
        name = changed['schema']['fields'][0]['name']
        originals = [cell for cell in certificate['cells'] if 0 in cell['cube'][name]]
        for old, new in zip(originals, restricted['cells'], strict=True):
            if any(old[k] != new[k] for k in ('events', 'program', 'monitor_steps')):
                raise RuntimeError('restriction changed a reused payload')
        try:
            verify(changed, certificate)
        except CheckFailure:
            pass
        else:
            raise RuntimeError('unrebound old certificate accepted changed subject')
        row.update(restricted_inputs=retained, reused_payloads=len(restricted['cells']))
        record.update(restricted_case=changed, restricted_certificate=restricted)
    return row, record


def collect():
    rows, records = [], []
    for depth in range(9):
        row, record = observe(depth)
        rows.append(row)
        records.append(record)
    return {'status': 'PASS', 'rows': rows, 'original_inputs_checked': sum(r['inputs'] for r in rows),
            'restricted_inputs_checked': sum(r['restricted_inputs'] for r in rows),
            'scope': 'Nine owned binary generator trees; no timing or external frontend claim'}, records


def latex_table(rows):
    text = ['\\begin{tabular}{rrrrrr}', '\\toprule',
            'Depth & Inputs & Branches & Cells & Cell pairs & Reused \\\\', '\\midrule']
    for row in rows:
        text.append(' & '.join(str(row[k]) for k in
                    ('depth', 'inputs', 'branch_nodes', 'certificate_cells', 'cell_pairs_checked', 'reused_payloads')) + ' \\\\')
    return '\n'.join(text + ['\\bottomrule', '\\end{tabular}', ''])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('output directory must be new')
    report, records = collect()
    raw = json.dumps(records, sort_keys=True, separators=(',', ':')).encode('utf-8')
    args.out.mkdir(parents=True)
    (args.out / 'summary.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0) as stream:
        stream.write(raw)
    (args.out / 'cases.json.gz').write_bytes(buffer.getvalue())
    (args.out / 'table.tex').write_text(latex_table(report['rows']), encoding='utf-8', newline='\n')
    if args.compare is not None:
        for name in ('summary.json', 'table.tex'):
            if (args.out / name).read_bytes() != (args.compare / name).read_bytes():
                raise SystemExit('Scientific output differs: ' + name)
        if raw != gzip.decompress((args.compare / 'cases.json.gz').read_bytes()):
            raise SystemExit('Scientific case/certificate records differ')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
