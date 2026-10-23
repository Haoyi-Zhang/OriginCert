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

This rebuilds `data/cases/` and `results/cases/`, runs the evaluation, then explicitly runs source round trips, stress, scaling, metamorphic transformations, theorem-directed transformations and syntactic audits. It deletes each auxiliary report before invoking its producer and checks that a new successful JSON is written at the exact requested path. The outer scientific runner uses a 240-second timeout per stage; subprocesses inside the core stage use a 180-second timeout. The retained complete run reports 51 actual unittest executions; source definition counts are not used as a substitute.

Run that rebuilding command only in a fresh copy if prior results must be preserved. The supplied `Bounded scientific reproduction` workflow does so on a `main` push or manual dispatch, with a 30-minute job bound and raw result/log upload even on failure. It runs only the offline Python models; it does not run a vendor product or generated source. Stage status becomes `PASS` only after both process success and fresh-output validation; timeouts and failed output checks retain a non-PASS execution record and a log. The current Linux CPython 3.12.14 output in `results/current` contains nine completed stages, 54 passing methods without skips, all 360 subjects and 1,440 rejected record mutations. It took 46.066 wall seconds with 53,280 KiB peak RSS. Earlier timing exports remain separate.

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

For a portable pure-computation regression without rewriting saved results:

```bash
python -B -m unittest discover -s tests -p test_merge_signatures.py -v
```

The test uses authored finite inputs, an independent domain-index rectangle reference and a literal Cartesian interpreter/oracle; it also exercises the independent checker. Full test discovery in the scientific workflow includes it. The producer retains a lazily computed exact payload signature per working record within one greedy merge call; merges change only the cube, not the payload. Encounter order, type-sensitive JSON identity and the final cube order are unchanged. The retained 51- and 54-test receipts and runtime measurements predate this regression and signature reuse; neither is evidence of a measured improvement for this implementation. No minimum-cover claim is added.

## Owned source-to-generation workload

The supplemental `src/traceability_workload.py` template writes restricted
batch-handler source directly, without calling either existing interpreter or
event-to-source codec. Two layouts exercise channel selection inside/outside
nested batch/item repetitions, real primary/fallback sites with identical sink
calls, optional checked publication, and compact/spaced formatting. Each has
144 configurations. Source is parsed, never executed; protection names are
explicit model labels, not validated sanitizer implementations.

`checker/source_binding.py:verify_sources` adds a source-bound positive check:
verify the certificate, require one unique in-domain file per assignment, then
compare every parsed statement with its unique cell's complete event payload.
Certificate-only `verify` does not receive source files and cannot detect edits
to those files. The added check retains strict parsing and introduces explicit
per-file/bundle byte bounds; it does not weaken existing checker checks.

`src/traceability_reference.py` is the same-information direct control. It checks
completeness against an independently enumerated assignment set, reconstructs
actual emitters with a separate iterative stack, and interprets the workload's
protection/preceding-check rules. It does not use certificate cells or either
existing concrete interpreter. Both paths share the restricted source parser,
strict JSON validation and subject validator; parser/specification independence
is not claimed.

From the artifact root, these commands do not rewrite historical outputs:

```bash
python -B -m unittest discover -s tests -p test_owned_traceability.py -v
python -B scripts/owned_traceability.py
```

The experiment prints its JSON receipt to stdout. The saved
`results/owned_traceability.json` records CPython 3.12.14/Windows, exact measured
source identities, all raw repetitions and diagnostics. There are 288 pointwise
matches, 1,152 emitted statements, nine passing tests (plus 18 source-fault
subtests), and 34 cells per clean layout. Both source-bound paths accept two
clean bundles and reject all 18 source faults. Eight subject faults yield checked
counterexamples with independently matching least inputs, first failing event
indices and fault classes. These are authored faults, not upstream discoveries.

Detection ties. The retained seven alternating paired repetitions after a warmup, excluding
source/certificate production, give certificate-plus-source versus direct
medians of 89.149 versus 26.220 ms (inside) and 90.168 versus 25.815 ms (outside).
The certificate path is slower; no statistical-significance or throughput claim
is made. The initial measurement receipt is retained separately as
`results/owned_traceability_initial.json`; its reference still shared the
source-bundle completeness frontend before that check was independently
implemented. It is not the final independence evidence or manuscript timing
source.

### Bounded direct reference: current focused receipt

The direct reference now uses an independently written iterative postorder
emit-free summary, after full shared subject admission. It caps static nodes at
2,000, per-input dynamic visits at 2,000,000 and events at 4,096. It does not call
either existing summary/interpreter or use certificate cells. A
`ReferenceResourceError` is an operational abort, not a semantic counterexample;
the owned experiment propagates it rather than counting it as detected fault.

Run this portable standard-library-only command from the artifact root, choosing
a **new** result-directory name on each run:

```bash
python -B scripts/validate_reference_bounds.py --output-dir results/reference-bounds-fresh
```

It refuses an existing output directory or a destination outside this artifact's
`results/` tree. `results/reference-bounds-20261014/receipt.json`, `tests.txt` and
`owned_traceability.json` retain the current CPython 3.12.14/Windows execution:
17 methods, zero failures/errors/skips; both clean bundles accepted; the same
18 source edits rejected by both paths; eight subject diagnostics and two
restricted bundles checked. Empty depth-2/depth-20 controls respectively use
3/21 static nodes and one dynamic visit, with zero events. The mixed fixture
uses 25 static nodes, 15 dynamic visits and preserves four full nested
occurrences. Small lowered-budget controls test aborts without a large dynamic
expansion. No generated source is executed.

The new raw paired timings include the direct summary on every reconstructed
input, along with full subject admission, assignment enumeration/order, all
source parsing, complete comparison and rule checks. Certificate/source
production is excluded on both sides. Static/dynamic node counters are not
timings. Both paths still detect the same faults; the certificate-plus-source
path still takes longer on these two layouts. The older
`results/owned_traceability.json` and manuscript timing table identify the
pre-bounded-reference implementation and are preserved as historical evidence,
not current-code timing claims. The Linux nine-stage runner was not executed by
this focused portable command.

Intersecting/rebinding the existing certificates to compact formatting keeps
their 34 event/monitor payloads unchanged and validates 72 retained inputs per
layout without fresh certificate construction. Rechecking remains necessary;
the old unrebound certificate rejects. Mismatch diagnostics identify input,
source line, differing fields, expected site and occurrence. A direct validator
could offer the same reuse/diagnostic facilities. No end-to-end build-system
integration or certificate-specific speed/detection gain is established.

## Results and measurement scope

The separate owned path-structure study varies relevant branches rather than
unused coordinates. Nine binary trees cover 511 original inputs; eight checked
restrictions cover 255 retained inputs. At depth eight, the generator has 1,023
nodes, 255 branches and 256 distinct origin-bearing certificate cells. The
unchanged verifier performs 32,640 overlap comparisons. Restriction reuses
payloads without calling the producer but still requires full checking; no
timing gain or external-generator integration is claimed. The paper directly
consumes `results/path-structure/table.tex` from this study.

```sh
python -B -m unittest discover -s tests -p test_path_structure.py -v
python -O -B -m unittest discover -s tests -p test_path_structure.py -v
python -B scripts/path_structure.py --out /new/path-study --compare results/path-structure
```

The last command refuses an existing output directory and compares all summary
fields, the table, and decompressed case/certificate records. Compression
container bytes do not determine scientific agreement. Its counts are separate
from the retained 360-subject run and its measurements below.

`results/summary.json` aggregates the scientific counts, bytes and evaluation measurements. `results/case_results.csv` has one row per subject. `results/reproduction.json` records actual stage completion, test count, environment and complete elapsed time. `results/tests.txt` and `test_results.json` come from the unittest runner. The `results/logs/` directory contains subprocess logs, not invented validation declarations.

`evaluation_wall_seconds` measures the 360-subject evaluation; `reproduction_wall_seconds` inside the performance block is the core stage (including construction/tests); `complete_reproduction_wall_seconds` includes all scientific stages. Fresh runs legitimately change elapsed time and RSS. Scientific comparisons must not discard classification, case count, size, violation or oracle fields when normalizing those performance fields.

The accepted-certificate cell distribution is 3 cells: 3 records; 4 cells: 98; 6 cells: 74; 8 cells: 5. Its median is 4, and the median 24-input/cell ratio is 6.0. Region compression is not claimed to be a globally minimal cover or a uniform speedup.

`results/local_validation_20261006.json` records a separate finite check on CPython 3.12.14/Windows: 54 tests passed, the 360 regenerated subjects and records matched the retained corpus, all 8,640 input-level comparisons and 1,440 record mutations agreed, and the full codec, stress, metamorphic, scaling and theorem-directed checks passed. A supplemental check compared both implementations' symbolic leaf payloads at all 7,200 fixed stress inputs. This is not a new Linux RSS measurement or an execution of the complete Linux runner. The 51-test Linux run and its cost exports remain unchanged.

## Paper-only operations

The standalone scientific command does not read a sibling paper directory. In the complete project, these separate commands bind a selected run to manuscript numbers and audit citation structure:

```bash
python -B scripts/export_paper_results.py --paper-dir ../paper --mode retained
python scripts/audit_references.py --paper-dir ../paper
```

The first command validates the successful retained receipts and CSV snapshot,
then freshly renders the two Python vector plots before publishing numerical
exports (`results.tex`, `scaling.csv`, `figures/recall.csv`) and their PDFs. It
requires the paper renderer's ReportLab and TeX font lookup; failure is nonzero
and invalidates cached statistical/manuscript PDFs. These dependencies do not
apply to the standalone scientific command.

To intentionally export a different completed run of the same experiment,
choose it explicitly with `--mode selected-run --results-dir /path/to/results`.
This mode retains schema, finite-number, millisecond-unit, row/cardinality and
recall-count/denominator validation; it is not a validation bypass. Default
`retained` mode continues to reject changes to its snapshots. No experiment is
run by the exporter. The delivered measurements remain retained history; an
independent clean-run check need not replace them. From `paper/`, `python -B
build.py` performs export, actual plotting, bibliography rendering and TeX in
that order, stopping on failure. See `paper/README.md` for explicit run selection
and paper-only regressions.

## Interpretation of audits

`audit_code.py` checks a specified set of syntax and API patterns; it is not a security proof. `audit_formal_alignment.py` checks specified source/proof markers; it is not theorem proving. `audit_experimental_design.py` checks the retained construction statistics. Reference structure means defined/used keys and locators, not that every cited full paper was read. `reference-reading-notes.csv` records more detailed evidence levels and limits. No test suite establishes absence of unknown implementation errors or deployment completeness.

The mathematical trusted boundary includes the supplied schema, tree, event abstraction and catalogue. The implementation trusted boundary includes the independently written Python checker, parser, runtime and their conformance to the stated mathematics. The project neither checks a vendor executable against that tree nor proves that a catalogue represents every relevant weakness.

The inherited BSD 3-Clause license notice is retained unchanged. The manuscript byline does not add an assertion about copyright ownership or author approval.

## Manuscript diagrams

The model and protocol schematics are drawn directly in Python as vector PDFs
with embedded STIX fonts. They encode the stated relationships, not measured
performance. To regenerate them with Python 3.9+ and Matplotlib:

```sh
python -B figures/draw_schematics.py --output figures
```

## Portable path notation

Published execution records use `<PYTHON_ROOT>`, `<NODE_ROOT>` and `<RUNTIME_ROOT>` for local tool installations, `<DEPENDENCIES_ROOT>` for local dependencies, and `<PROJECTS_ROOT>`, `<ARTIFACT_ROOT>`, `<SOURCE_ROOT>` and `<WORK_ROOT>` for the workspace, artifact checkout, source checkout and temporary work directory of the recorded run. These are path aliases, not literal directories or claims that historical temporary files are included in this bundle. Substitute the corresponding local roots when replaying a command. Recorded tool versions, source/input identities, measurements, outcomes and failures are unchanged. Current file inventories bind the portable published bytes; any `recorded_` identity denotes pre-normalization bytes.
