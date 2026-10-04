from __future__ import annotations

import unittest

from checker.source_extract import (
    SourceExtractionError,
    extract_call_events,
    extract_record_events,
)
from src.reference_backends import lower_ast, lower_template


class ReferenceBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [
            {
                "op": "source",
                "target": "x",
                "kind": "untrusted",
                "origin": "n1",
                "obligations": ["o-source"],
            },
            {
                "op": "sink",
                "value": "x",
                "sink": "shell",
                "origin": "n2",
                "obligations": ["o-sink"],
                "occurrence": [1, 0],
            },
        ]

    def test_two_distinct_reference_codecs_round_trip_without_execution(self) -> None:
        pairs = (
            (lower_template, extract_call_events),
            (lower_ast, extract_record_events),
        )
        sources = []
        for lower, extract in pairs:
            with self.subTest(lower=lower.__name__, extract=extract.__name__):
                source = lower(self.events)
                sources.append(source)
                self.assertEqual(extract(source), self.events)
        self.assertNotEqual(sources[0], sources[1])
        self.assertIn("cg_source", sources[0])
        self.assertIn("TRACE_EVENTS", sources[1])

    def test_decoders_reject_the_other_surface_grammar(self) -> None:
        with self.assertRaises(SourceExtractionError):
            extract_call_events(lower_ast(self.events))
        with self.assertRaises(SourceExtractionError):
            extract_record_events(lower_template(self.events))

    def test_call_decoder_rejects_executable_or_unbound_source(self) -> None:
        bad_sources = [
            "import os\n",
            "# cg-evidence {\"origin\":\"n\",\"obligations\":[]}\nprint(value())\n",
            "cg_source(target='x', kind='untrusted')\n",
            "# unrelated\ncg_source(target='x')\n",
            "# cg-evidence {\"origin\":\"n\",\"obligations\":[]}\ncg_noop(value={'x': 1, 'x': 2})\n",
        ]
        for source in bad_sources:
            with self.subTest(source=source):
                with self.assertRaises(SourceExtractionError):
                    extract_call_events(source)

    def test_record_decoder_rejects_executable_or_ambiguous_source(self) -> None:
        bad_sources = [
            "import os\nTRACE_EVENTS = []\n",
            "TRACE_EVENTS = []\nprint('x')\n",
            "OTHER = []\n",
            "TRACE_EVENTS = tuple()\n",
            "TRACE_EVENTS = [{'op':'noop','origin':'n','obligations':[], 'x': {'a': 1, 'a': 2}}]\n",
            "# comment\nTRACE_EVENTS = []\n",
            "TRACE_EVENTS = [{'op':'noop','origin':'n'}]\n",
        ]
        for source in bad_sources:
            with self.subTest(source=source):
                with self.assertRaises(SourceExtractionError):
                    extract_record_events(source)

    def test_evidence_tampering_changes_the_recovered_trace(self) -> None:
        source = lower_template(self.events).replace('"origin":"n1"', '"origin":"other"', 1)
        recovered = extract_call_events(source)
        self.assertNotEqual(recovered, self.events)
        self.assertEqual(recovered[0]["origin"], "other")

    def test_empty_trace_has_distinct_valid_encodings(self) -> None:
        call_source = lower_template([])
        record_source = lower_ast([])
        self.assertNotEqual(call_source, record_source)
        self.assertEqual([], extract_call_events(call_source))
        self.assertEqual([], extract_record_events(record_source))


if __name__ == "__main__":
    unittest.main()
