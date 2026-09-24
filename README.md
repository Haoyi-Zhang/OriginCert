# Traceability certificates for bounded code generators

This artifact implements the finite generator language, certificate producer,
separately implemented checker, corpus, mechanism controls, component ablations,
and every quantitative result in the accompanying paper.

## What is checked

The subject is a deterministic template or AST generator with an explicitly
finite input schema, a security-event intermediate representation, and an
obligation catalogue. For each input, the contract asks three separate questions:

1. **Origin integrity:** does each event name the exact `emit` node reached by
   generator execution, including its full occurrence path through nested repeats?
2. **Exact obligation coverage:** does the event declare exactly the catalogue
   obligations triggered by its ordinary fields?
3. **Trace safety:** do those obligations hold in the monitor state immediately
   before the event?

Monitor updates do not retroactively satisfy obligations on the same event. A
new source or random assignment clears stale facts for its target; a protection
operation copies facts from its source and adds the declared protection; a strong
random fact propagates only from a source that already has it.

A successful result is a certificate whose disjoint cubes cover the complete
schema. Each cube records one common trace, the rendered pseudo-program, actual
emitter evidence, exact obligation declarations, and monitor transitions. A failed
result is the least rejecting input under the documented structural order and the
prefix ending at its first violation.

## Evidence corpus

The 360 cases have two roles:

- **324 controlled cases** across web, automation, and service themes isolate
  semantic-safety, coverage, and origin faults under balanced control structures.
- **36 advisory abstractions** model one source-to-sink mechanism from each of
  three public code-generator advisories: a Python factory expression, a PHP
  double-quoted literal, and a TypeScript mock `const` expression. These models
  neither contain nor execute vendor code.

Every case has 24 assignments, giving 8,640 complete executions. The corpus is
split evenly between 180 accepted and 180 rejected cases. The rejected cases
contain 108 semantic faults, 36 exact-coverage faults, and 36 exact-origin faults.

The generic DSL models control-dependent emission: schema values choose branches
and bounded repeat counts, while ordinary event arguments are literal identifiers
in the tree. The advisory models add three narrowly defined, context-specific
renderings. Results therefore concern the frozen language, schemas, event IR,
catalogue, and fixtures—not arbitrary host languages or production generators.

## Reproduce the results

Run from this directory:

```bash
python scripts/reproduce.py
```

The command regenerates all 360 cases and results, then performs:

- checker-side classification without construction labels;
- 8,640 assignment-level producer/checker semantic comparisons;
- independent verification of every certificate and counterexample;
- 1,440 deterministic record-mutation checks;
- mechanism-specific oracle checks for all 36 advisory cases; and
- 29 contract and regression tests.

Only the Python standard library is required.

A separate deterministic differential stress run exercises 600 additional mixed
generator trees and 7,200 assignments against the producer, checker, a third
concrete oracle, and expanded symbolic cells:

```bash
python scripts/differential_stress.py
```

Its retained output is `results/differential_stress.json`. It is a robustness check,
not part of the 360-case evaluation counts.

Principal outputs:

- `results/summary.json`: corpus, correctness, size, control, ablation, anchor,
  and bounded-feasibility results;
- `results/case_results.csv`: one row per case;
- `results/baseline_summary.csv`: aggregate control outcomes;
- `results/ablation_summary.csv`: detections by semantic, coverage, and origin
  class;
- `results/historical_anchor_summary.csv`: advisory-model outcomes by record;
- `results/family_summary.csv`: per-family evidence-size and runtime summaries;
- `results/cases/`: the checked result for each case.

## Check one result

```bash
python -m src.certify data/cases/python-model-001.json /tmp/result.json
python checker/check.py data/cases/python-model-001.json /tmp/result.json
```

The checker prints `PASS` only after it binds the result to the supplied subject,
replays the generator, recomputes emitter paths, obligations, monitor states, and
violations, and verifies exact partition coverage or counterexample minimality.
It imports no producer module.

## What the controls show

Exhaustive operation-safety replay finds all 108 semantic faults and none of the
72 origin or coverage faults. Coverage plus safety misses the 36 origin faults;
origin plus safety misses the 36 coverage faults; origin plus coverage misses the
108 semantic faults. These are mechanism-separation results for the frozen corpus,
not population estimates.

The advisory-specific oracles agree with the generic checker on all 36 anchor
cases and inspect all 864 anchor assignments without executing generated text.
This checks fidelity to the three selected transformations, not a complete vendor
implementation.

## Defensive input boundary

Both producer and checker fail closed on malformed or ambiguous serialized
subjects. The validators enforce exact object keys, finite JSON values, canonical
JSON identity (so integer `1` and Boolean `true` remain distinct), unique node and
obligation identifiers, operation-specific event shapes, valid trigger fields,
bounded domains, bounded generator depth and size, and bounded trace length. The
checker also limits input size and rejects duplicate JSON keys and non-finite
numeric literals.

## Directory map

- `src/`: producer semantics, corpus construction, advisory models, and evaluation;
- `checker/`: separately implemented concrete checker;
- `tests/`: contract, boundary, tamper, cross-implementation, and anchor tests;
- `data/cases/`: frozen corpus and selection manifest;
- `external_inputs/`: factual public-record selections used by the anchor models;
- `results/`: checked records and claim-linked aggregate results;
- `proofs.md`: formal definitions and proof arguments;
- `claim_evidence_ledger.csv`: claim-to-evidence mapping;
- `external_resources.csv`: scholarly and public-record provenance.

## Interpretation

Producer/checker agreement is strong implementation evidence, not an external
semantic oracle: both implementations instantiate the same written contract. The
certificate establishes the serialized generator-to-event relation; it does not
bind that subject to a deployed binary or prove that the event abstraction and
catalogue capture every concrete effect. Runtime measurements establish that the
frozen finite experiment closes on one host, not a comparative performance claim.
