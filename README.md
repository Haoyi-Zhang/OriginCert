# Origin-Complete Traceability Certificates for Bounded Code Generators

TraceCert checks a finite generator-to-event relation. Output safety, exact immediate emit-node origin, and exact catalogue-obligation coverage are separate conjuncts. The journal manuscript supplies the mathematical definitions and proofs; `proofs.md` states the same arguments here.

## Scope and evidence

The generator language has literal events, sequences, equality branches and repeats bounded by four. Ordered finite schemas have at most 256 inputs. Event arguments are literals; schema values select control flow and counts. The monitor checks obligations in the event pre-state and always performs the specified diagnostic update afterward. A failure remains recorded even if later states acquire the missing fact.

The 360-subject corpus contains 324 controlled subjects from one construction framework and 36 bounded abstractions of three public advisories. It contains 180 safe subjects, 108 operation-safety faults, 36 exact-declaration faults and 36 origin faults, with 24 inputs per subject. The advisories motivate local source-to-sink models: they are not full vendor executions or general CWE compliance tests.

A positive checker validates Cartesian membership, disjointness, cardinality coverage and every symbolic leaf; it does not enumerate assignments. A negative checker concretely replays the recorded input and all lower-ranked inputs to establish validity and leastness. Both accept valid *evidence*, including a counterexample showing that a subject rejects.

## Supported reproduction environment

The complete scientific command requires **CPython 3.10 or later on Linux**, including the standard-library `resource` module. WSL with Linux Python is an equivalent environment. It is sequential (one worker), CPU-only, offline and uses no third-party Python package. The retained measurements used CPython 3.13.5 on Linux; RSS is reported in KiB. Other operating systems are not claimed as tested by the complete runner. Individual pure-Python checkers may work elsewhere.

## One complete command

From this artifact root:

```bash
python scripts/reproduce.py
```

This rebuilds `data/cases/` and `results/cases/`, runs the evaluation, then explicitly runs source round trips, stress, scaling, metamorphic transformations, theorem-directed transformations and syntactic audits. It deletes each auxiliary report before invoking its producer and checks that a new successful JSON is written at the exact requested path. Every subprocess has a 240-second stage timeout. The retained complete run reports 51 actual unittest executions; source definition counts are not used as a substitute.

The full outputs include 8,640 frozen inputs; 1,440 record mutants; 17,280 source round trips; **600 total** stress trees and 7,200 inputs across eight seeds; 720 metamorphic records; four scaling points; and transformations of all 180 positive certificates. Stress is not 600 cases per seed. The call-statement and AST-built record-table codecs use different surface grammars and paired syntax-only decoders. Their output is parsed, never imported or executed; the codecs remain reference transports for one event contract, not independent product integrations.

## Focused commands

```bash
python scripts/run_tests.py
python scripts/differential_stress.py --output results/differential_stress.json
python scripts/backend_roundtrip.py --cases data/cases --output results/backend_roundtrip.json
python scripts/metamorphic_suite.py --output results/metamorphic_suite.json
python scripts/journal_validation.py --output results/journal_validation.json
```

The case loader skips `manifest.json`; subject identity is `case_id`. Stress and other experiments write the report requested by their caller instead of only printing JSON. Running any command updates its own outputs. Re-run the complete command before interpreting summary values across stages.

## Results and measurement scope

`results/summary.json` aggregates the scientific counts, bytes and evaluation measurements. `results/case_results.csv` has one row per subject. `results/reproduction.json` records actual stage completion, test count, environment and complete elapsed time. `results/tests.txt` and `test_results.json` come from the unittest runner. The `results/logs/` directory contains subprocess logs, not invented validation declarations.

`evaluation_wall_seconds` measures the 360-subject evaluation; `reproduction_wall_seconds` inside the performance block is the core stage (including construction/tests); `complete_reproduction_wall_seconds` includes all scientific stages. Fresh runs legitimately change elapsed time and RSS. Scientific comparisons must not discard classification, case count, size, violation or oracle fields when normalizing those performance fields.

The accepted-certificate cell distribution is 3 cells: 3 records; 4 cells: 98; 6 cells: 74; 8 cells: 5. Its median is 4, and the median 24-input/cell ratio is 6.0. Region compression is not claimed to be a globally minimal cover or a uniform speedup.

## Paper-only operations

The standalone scientific command does not read a sibling paper directory. In the complete project, these separate commands bind a selected run to manuscript numbers and audit citation structure:

```bash
python scripts/export_paper_results.py --paper-dir ../paper
python scripts/audit_references.py --paper-dir ../paper
python scripts/audit_writing.py --paper-dir ../paper
```

The first command intentionally overwrites `paper/results.tex` and `paper/scaling.csv` with the current run. The delivered PDF retains the included run's numbers; an independent clean-run check should compare scientific values but need not replace the retained timings. Compile the manuscript using the commands in `paper/README.md`.

## Interpretation of audits

`audit_code.py` checks a specified set of syntax and API patterns; it is not a security proof. `audit_formal_alignment.py` checks specified source/proof markers; it is not theorem proving. `audit_experimental_design.py` checks the retained construction statistics. Reference structure means defined/used keys and locators, not that every cited full paper was read. `reference-reading-notes.csv` records more detailed evidence levels and limits. No test suite establishes absence of unknown implementation errors or deployment completeness.

The mathematical trusted boundary includes the supplied schema, tree, event abstraction and catalogue. The implementation trusted boundary includes the independently written Python checker, parser, runtime and their conformance to the stated mathematics. The project neither checks a vendor executable against that tree nor proves that a catalogue represents every relevant weakness.

The inherited BSD 3-Clause license notice is retained unchanged. The manuscript byline does not add an assertion about copyright ownership or author approval.
