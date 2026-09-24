from __future__ import annotations

import unittest

from checker.source_extract import SourceExtractionError, extract_events
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

    def test_both_reference_backends_round_trip_without_execution(self) -> None:
        for lower in (lower_template, lower_ast):
            with self.subTest(lower=lower.__name__):
                self.assertEqual(extract_events(lower(self.events)), self.events)

    def test_extractor_rejects_executable_or_unbound_source(self) -> None:
        bad_sources = [
            "import os\n",
            "# cg-evidence {\"origin\":\"n\",\"obligations\":[]}\nprint(value())\n",
            "cg_source(target='x', kind='untrusted')\n",
            "# unrelated\ncg_source(target='x')\n",
        ]
        for source in bad_sources:
            with self.subTest(source=source):
                with self.assertRaises(SourceExtractionError):
                    extract_events(source)

    def test_evidence_tampering_changes_the_recovered_trace(self) -> None:
        source = lower_template(self.events).replace('"origin":"n1"', '"origin":"other"', 1)
        recovered = extract_events(source)
        self.assertNotEqual(recovered, self.events)
        self.assertEqual(recovered[0]["origin"], "other")


if __name__ == "__main__":
    unittest.main()
