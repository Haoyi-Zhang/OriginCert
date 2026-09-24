# Formal contract and proof arguments

## 1. Finite subject

A schema is an ordered tuple
`S = <x_1:D_1, ..., x_n:D_n>`. Each `D_i` is finite, nonempty, and ordered. Domain
members are compared by canonical JSON identity, so JSON integer `1` and Boolean
`true` remain distinct even on a host language that equates them. The concrete
domain is the Cartesian product `Dom(S) = D_1 x ... x D_n`. The implementation
accepts at most 256 assignments.

The first member of each `D_i` is the default. For an assignment `d`, let `p_i(d)`
be its value index. The structural rank is

`rank_S(d) = (# non-default coordinates, sum of indices, index vector, canonical JSON)`.

Lexicographic comparison gives a total order on the finite domain.

A generator is a finite tree with unique node identifiers:

- `emit(e)` appends one well-formed event;
- `seq(g_1,...,g_k)` concatenates child executions;
- `if x=v then g_t else g_f` selects one child; and
- `repeat x do g` executes `g` the bounded nonnegative integer stored in `x`.

The frozen implementation admits repeat counts zero through four, at most 2,000
nodes, depth at most 256, and at most 4,096 emitted events per execution. Event
templates have operation-specific exact shapes and cannot prepopulate the reserved
fields `origin`, `obligations`, or `occurrence`.

Concrete execution returns both public events and an actual-emitter sequence. Each
actual emitter consists of the reached `emit` node identifier and the complete
occurrence path through nested repeats. The path prevents two dynamic instances of
the same nested body from collapsing into one location.

A cube maps every schema field to a nonempty subset of its domain and denotes their
Cartesian product. A symbolic cell pairs a cube with one trace. The producer splits
cubes at conditions and repeat counts, then merges equal-trace cells only when they
differ in one coordinate and the two value subsets are disjoint. Trace comparison
uses canonical JSON identity throughout.

## 2. Obligation and monitor semantics

The catalogue is finite and explicit. Every obligation contains a unique identifier,
a type-correct partial event trigger, and one rule. A trigger matches only when each
named field is present and canonically JSON-equal to the trigger value. The rules are:

1. `protection`: a referenced value must already carry every named protection;
2. `preceded`: a referenced capability must already have been checked;
3. `strong_rng`: a referenced source must already be known as strong; and
4. `forbid`: the triggering event is disallowed.

The monitor state `sigma = <P,A,R>` contains value protections, checked
capabilities, and strong-random sources. At event position `i`, validation proceeds
in this order:

1. compare claimed and actual emitter identities;
2. require the declared obligation set to equal the triggered set;
3. evaluate every triggered rule against `sigma_i`; and
4. if no rule rejects, apply the event transition to obtain `sigma_{i+1}`.

The pre-event order is essential: a check, protection, or RNG declaration cannot
satisfy an obligation on itself. Assignment-like events also obey overwrite
semantics. A fresh source or RNG assignment clears stale facts for its target.
Protection copies source facts to the target and adds its named protection. A
strong-random fact propagates only from a source already in `R`.

## 3. Symbolic partition

**Lemma 1 (partition).** The unmerged symbolic interpreter returns pairwise-disjoint
cubes whose union is `Dom(S)`, and every assignment in a cube produces the cell's
trace.

**Proof.** By structural induction. `emit` appends the same event to each incoming
cell. `seq` composes children and preserves the invariant. A conditional replaces
an incoming cube by its intersections with `x=v` and `x!=v`; the pieces are
disjoint and cover the original cube, and the induction hypothesis applies to the
selected children. A repeat splits the count coordinate into singleton values and
applies the body a fixed finite number of times, preserving coverage, disjointness,
and trace agreement. Therefore the invariant holds at the root. QED.

**Lemma 2 (merge preservation).** Replacing two equal-trace cells that are equal on
all but one coordinate and have disjoint subsets on that coordinate by their union
preserves coverage, disjointness, and trace agreement.

**Proof.** The merged Cartesian product is exactly the union of the two prior
products. Both have the same trace, and neither overlapped any third cell. QED.

## 4. Accepted-certificate soundness

**Theorem 1.** If the checker accepts a certificate for `(S, O, G)`, then for every
`d` in `Dom(S)`:

1. `d` belongs to exactly one certificate cube;
2. checker-side execution of `G` yields that cell's events and rendered program;
3. each claimed emitter, including its occurrence path, equals the actual emitter;
4. each declaration set equals the obligations triggered by the ordinary event
   fields; and
5. the deterministic monitor accepts the complete trace.

**Proof.** The checker enumerates `Dom(S)`, expands every cube, rejects overlap, and
compares the covered set with the domain, giving (1). It executes `G` for every
covered input and compares structured events and rendering, giving (2). Its own
traversal records emitter node and occurrence path and requires exact equality,
giving (3). It recomputes the trigger relation and requires set equality, giving
(4). It then recomputes each pre-state, rule result, and post-state and rejects any
violation, giving (5). These predicates all precede acceptance. QED.

The theorem is relative to the supplied schema, generator semantics, event
abstraction, and catalogue. It does not assert that these inputs capture every
behavior of a separate concrete implementation.

## 5. Counterexample validity and minimality

**Theorem 2 (validity).** If the checker accepts a counterexample, its input is in
the schema, replay yields the recorded events and program, the reported violation
is the first violation, and the stored prefix ends at that event.

**Proof.** The checker tests domain membership, exact replay, monitor-state equality,
first-violation equality, and equality with the corresponding trace slice. QED.

**Theorem 3 (structural minimality).** If the checker accepts witness input `d`, no
rejecting input has smaller `rank_S`.

**Proof.** The checker enumerates every lower-ranked assignment and replays all
origin, coverage, and monitor checks. Acceptance requires every such assignment to
be non-rejecting. QED.

## 6. Relative completeness and termination

**Theorem 4.** For every well-formed subject in the frozen fragment, the producer
terminates and returns either a checker-acceptable certificate when every input
satisfies the contract, or a checker-acceptable counterexample at the least
rejecting input.

**Proof.** The schema, generator, operation vocabulary, and repeat counts are
finite, so symbolic and concrete execution terminate. Lemmas 1 and 2 yield a finite
partition. If every cell is accepted, its serialization satisfies Theorem 1's
predicates. Otherwise at least one concrete input rejects; enumeration in the total
structural order reaches its least member, whose replay and minimality satisfy
Theorems 2 and 3. QED.

## 7. Traceability is not operation-only safety

Let `pi_op(t)` erase event origins, declarations, and certificate-only monitor
records while retaining the ordered operations and their ordinary arguments.

**Theorem 5 (traceability separation).** Let an accepted trace contain an event
with a nonempty triggered-obligation set, and let `n'` differ from its actual
emitter. There are two traces with the same `pi_op` projection and the same
operation-safety verdict such that exact coverage rejects one and origin integrity
rejects the other.

**Proof.** In the first trace, delete one required declaration. In the second,
replace the event's emitter claim by `n'`. Neither edit changes an ordinary event
field, so the projection, monitor transitions, and operation-safety verdict are
unchanged. Exact-set equality fails in the first trace and emitter equality fails
in the second. QED.

**Corollary.** A validator whose verdict is only a function of `pi_op(t)` cannot be
complete for the full certificate contract.

## 8. Serialization and implementation boundary

The checker imports no producer module and separately implements schema enumeration,
concrete traversal, rendering, trigger matching, monitor execution, replay, and
minimality checking. This removes shared executable semantics from the acceptance
path, but both programs still implement the same written contract; agreement is
not an external oracle.

Both sides validate exact serialized shapes and finite JSON before interpretation.
Duplicate object keys, non-finite numbers, unknown fields, malformed operation
arguments, invalid catalogue references, oversized domains or traces, and ambiguous
condition/repeat values are rejected. Result validation likewise checks exact
certificate, cell, step, state, violation, and witness shapes before use.

The test suite targets errors that simple producer/checker agreement could miss:
pre-event self-satisfaction, stale state after overwrite, strong-random propagation,
nested occurrence paths, JSON Boolean/integer identity, symbolic merge identity,
subject aliasing, unknown declarations, malformed triggers, resource limits, and
record tampering. A fixed-seed mixed-grammar stress audit additionally compared the
producer, checker, a third concrete semantic oracle, and the symbolic partition on
600 cases and 7,200 assignments; all four views agreed. This stress audit is a
review check rather than part of the reported 360-case evaluation.

## 9. Advisory abstractions

Each advisory family retains only a public source field, generated-code sink
context, and mitigation pattern. The artifact encodes that mechanism twice: as a
bounded event generator consumed by the generic certificate machinery and as a
separately written context-specific string oracle. Agreement checks the selected
transformation. It does not establish behavior of a full vendor frontend, release,
build, or runtime, and no generated payload is executed.
