from __future__ import annotations
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from checker.check import CheckFailure, verify, schema_domains
from src.certify import make_result
from scripts.journal_validation import refine_certificate, restricted_pair, active_catalogue_extension
from scripts.metamorphic_suite import alpha_case, reverse_object_keys
ROOT=Path(__file__).resolve().parents[1]

class JournalPrincipleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case=json.loads((ROOT/'data/cases/python-model-001.json').read_text())
        cls.cert=make_result(cls.case)

    def test_cartesian_refinement_preserves_acceptance(self):
        refined=refine_certificate(self.cert)
        self.assertGreater(len(refined['cells']),len(self.cert['cells']))
        verify(self.case,refined)

    def test_positive_certificate_does_not_call_assignment_enumeration(self):
        with patch('checker.check.assignment_list',side_effect=AssertionError('unexpected enumeration')):
            verify(self.case,self.cert)

    def test_restriction_under_well_formedness_preserves_acceptance(self):
        pair=restricted_pair(self.case,self.cert)
        self.assertIsNotNone(pair)
        changed,result=pair
        verify(changed,result)
        self.assertNotEqual(changed['schema'],self.case['schema'])

    def test_catalogue_extension_requires_new_declarations(self):
        record=active_catalogue_extension(self.case,self.cert)
        self.assertIsNotNone(record)
        self.assertEqual('coverage',record['witness']['violation']['kind'])

    def test_alpha_renaming_updates_wrong_existing_origins_consistently(self):
        cases=[json.loads(p.read_text()) for p in sorted((ROOT/'data/cases').glob('*.json')) if p.name!='manifest.json']
        case=next(c for c in cases if c['fault_detail']=='wrong-existing-origin')
        changed=alpha_case(case)
        record=make_result(changed)
        verify(changed,record)
        self.assertEqual('origin',record['witness']['violation']['kind'])

    def test_object_order_permutation_preserves_ordered_schema(self):
        changed=reverse_object_keys(self.case)
        self.assertEqual(changed['schema']['fields'],self.case['schema']['fields'])
        verify(changed,make_result(changed))

    def test_monitor_index_uses_exact_json_integer_type(self):
        for alias in (False,0.0):
            record=copy.deepcopy(self.cert)
            record['cells'][0]['monitor_steps'][0]['event_index']=alias
            with self.subTest(alias=repr(alias)),self.assertRaises(CheckFailure):
                verify(self.case,record)

    def test_overlapping_refinement_is_rejected(self):
        result=refine_certificate(self.cert)
        result['cells'].append(copy.deepcopy(result['cells'][0]))
        with self.assertRaises(CheckFailure):verify(self.case,result)

    def test_domain_order_changes_least_failure_not_safety(self):
        def emit(node):return {'node':node,'kind':'emit','event':{'op':'literal_secret','name':'secret'},'declared_obligations':['forbidden']}
        case={'case_id':'order-unit','family':'unit','schema':{'fields':[{'name':'x','domain':[0,1,2]}]},
              'catalog':{'obligations':[{'id':'forbidden','trigger':{'op':'literal_secret'},'rule':{'kind':'forbid'}}]},
              'generator':{'node':'root','kind':'if','condition':{'field':'x','equals':0},
                           'then':{'node':'empty','kind':'seq','children':[]},'else':emit('bad')}}
        first=make_result(case)
        verify(case,first)
        self.assertEqual(1,first['witness']['input']['x'])
        changed=copy.deepcopy(case);changed['schema']['fields'][0]['domain']=[0,2,1]
        second=make_result(changed)
        verify(changed,second)
        self.assertEqual(2,second['witness']['input']['x'])


class SourceBoundaryTests(unittest.TestCase):
    def test_source_occurrence_rejects_numeric_aliases(self):
        from checker.source_extract import extract_events, SourceExtractionError
        for token in ("true", "false", "0.0", "1.0", "4"):
            source = '# cg-evidence {"origin":"n","obligations":[],"occurrence":[' + token + ']}\ncg_noop()\n'
            with self.subTest(token=token), self.assertRaises(SourceExtractionError):
                extract_events(source)

    def test_source_payload_rejects_python_only_literals(self):
        from checker.source_extract import extract_events, SourceExtractionError
        for literal in ("(1, 2)", "{1, 2}", "b'x'", "1j", "{1: 'x'}", "1e999"):
            source = '# cg-evidence {"origin":"n","obligations":[]}\ncg_noop(value=' + literal + ')\n'
            with self.subTest(literal=literal), self.assertRaises(SourceExtractionError):
                extract_events(source)
