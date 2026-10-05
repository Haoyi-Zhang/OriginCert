# Proofs for the bounded traceability contract

This document records mathematical proof arguments, synchronized with the journal manuscript. It is not a machine-checked proof of the Python implementation. The syntactic formal-alignment audit is a regression check, not a proof checker.

## Definitions used below

A subject is Q = (S, G, O): an ordered finite schema, a deterministic generator tree, and an explicit obligation catalogue. JSON identity is canonical, finite and type-sensitive: Boolean, integer and floating-point values are distinct. An assignment chooses one value from each domain. The structural rank is (number of nondefault coordinates, sum of domain indices, index vector, canonical assignment serialization); the ordered domain lists are part of the subject.

The tree has literal event emission, sequence, equality-conditioned branches, and bounded repetition. Schema values control branches and repetition counts; ordinary event fields are literal. Concrete execution returns public events and separately reconstructed actual emitter identifiers. Each event also has its full nested iteration vector. The operational projection erases origin, occurrence and declaration evidence but retains ordinary operation fields and their order.

The monitor has protection sets P, authorization capabilities A, and strong-random facts R. At each event it checks origin, exact declaration equality and applicable safety rules in the pre-state. It then updates state **regardless of whether** a rule failed. Source/random overwrites clear stale target facts; protection copies valid source facts; a check adds its capability. Violations accumulate, so rejection is **sticky**, although post-states continue changing for diagnostic replay. This defines an observational monitor, not a blocking enforcement mechanism.

All algorithmic completeness statements require well-formed subjects and completion within the declared work/output limits. Finite input alone is not a time bound. A validated subtree containing no emit node has the identity output summary and need not be expanded through a nested repetition product.

A positive record is a disjoint Cartesian cover with common event and monitor payloads. A negative record binds an input, its complete replay, the first violation under the declared priority, and the prefix ending at that event. Acceptance of a negative record means valid evidence of a rejecting subject, not a safe subject.

Bibliographic keys below resolve in the accompanying paper. The standalone code and tests do not need paper files.

## What the Evidence Must Preserve

### A safe operation trace with two wrong explanations
Figure (see the corresponding manuscript section) separates three versions of a small generated trace. The first has correct origins and declarations. The second omits the database operation's applicable obligation. The third attributes that operation to a different emit node. Both modified traces retain the sanitization operation and the database operation with the same ordinary arguments. Therefore a monitor whose inputs are only those operations returns the same safety verdict for all three.

\input{figures/motivating.tex}

Using a nonexistent node makes the origin failure visually obvious, but existence is not the contract. Replacing the correct identifier with that of a different, real emit node is also a failure. An origin-membership check cannot distinguish this case. Exact traversal-derived equality can. Similarly, declaration coverage is not a count: replacing one required obligation with a different obligation can preserve the number of declared items while breaking the relation.

The safety monitor must not use declarations as an instruction to decide which rules to run. It derives triggers from ordinary event fields. This means the omitted-declaration trace can be operationally safe and simultaneously fail coverage, rather than becoming artificially safe because the missing rule was never checked. The distinction also provides a useful fault classification: a coverage rejection need not imply an unsafe operation, and an unsafe operation need not imply a broken origin map.

### Observation sufficiency
The general reasoning is elementary but useful for selecting a baseline. Let $X$ be a set of full evidence objects, $P:X\to\{0,1\}$ the desired predicate, and $h:X\to Y$ the observation available to a validator. An $h$-only validator has the form $f\circ h$ for some $f:Y\to\{0,1\}$.

**Proposition 1 (observation criterion).**
There is an $h$-only validator deciding $P$ exactly if and only if $P$ is constant on every nonempty fiber $h^{-1}(y)$.

*Proof.* If $P=f\circ h$ and $h(x)=h(x')$, then $P(x)=f(h(x))=f(h(x'))=P(x')$. Conversely, suppose $P$ is constant on each fiber. For each $y$ in the image of $h$, define $f(y)$ to be that common value. This is well defined. Values outside the image may be chosen arbitrarily. Then $f(h(x))=P(x)$ for every $x$. This is an existence criterion for exact decisions, not a claim that computing $f$ is efficient. ∎

Apply the proposition to a fixed generator execution augmented with origin and declaration claims. Take $h=\pi_{\mathrm{op}}$ and $P$ to be the complete event-trace contract relative to the supplied actual emitters and catalogue. If a valid trace contains a triggered obligation, deleting its declaration preserves $h$ while changing $P$. If an event's emitter claim can be replaced by a different identifier, that edit provides another such pair. These are same-observation objects with different correct verdicts.

**Corollary 1 (operation-only insufficiency).**
On this family of full-contract objects, a validator that observes only $\pi_{\mathrm{op}}$ cannot be both sound and complete for the complete traceability contract.

*Proof.* The two objects in either pair have the same observation, so the validator must return the same answer. Returning acceptance is unsound for the invalid object; returning rejection is incomplete for the valid object. ∎

This statement does not rule out a sound validator that always rejects. It also does not apply to a tool that receives and interprets the entire generator, schema, catalogue, and evidence in addition to the operation trace. Such a tool has a richer observation than $h$ and could reconstruct the missing relations. The evaluation's operation-only controls intentionally lack those relations; they establish an observation boundary, not a defect in all existing static analyzers.

The universal subject property compares a family of executions, while the example above already establishes an ambiguity in a single evidence-rich trace. Hyperproperties provide a general vocabulary for sets of traces [clarkson2010hyperproperties], but the argument here does not require that machinery. It requires only that evidence erased by the observation can affect the desired predicate. Calling the origin field ``metadata'' does not make it irrelevant to a predicate explicitly defined over it.

### Three conjuncts and the role of the catalogue
The complete contract is neither an alternative definition of output safety nor a claim that every provenance relation is security-sensitive. Its origin conjunct checks a chosen immediate source relation. Its coverage conjunct checks the agreement between two representations of requirements: the catalogue's trigger semantics and the event's explicit declarations. Its safety conjunct evaluates the catalogue's rules over the ordinary trace. This decomposition makes the trust in the catalogue visible.

A catalogue with no relevant trigger may certify a trace that a stronger policy would reject. Such an outcome is not a false theorem: the subject asked a weaker question. It would be misleading, however, to describe it as assurance against every weakness represented by a CWE name. The catalogue is an input to the claim, not a learned inventory or a complete formalization of the taxonomy. Changing its trigger or rule changes the contract even if its human-readable CWE label is unchanged.

These choices also distinguish our origins from broader provenance models. Why- and where-provenance recover different aspects of data derivation [buneman2001why]; provenance semirings retain algebraic information about contributions to query results [green2007semirings]. Our immediate emitter relation answers a narrower question: which static emission node, in which repetition occurrence, produced this event? It does not recover all input dependencies or establish the authenticity of the build environment. Keeping that granularity explicit allows exact checking without implying a complete causal history.

## Independent Checking and Correctness Arguments

The checker implements its own JSON validation, schema handling, tree traversal, symbolic interpreter, catalogue matching, monitor, rendering, and witness order. It does not call the producer's executable semantics. This arrangement reduces direct code sharing on the acceptance path, but implementation diversity is not a correctness theorem. The proofs in this section concern the mathematical algorithms given here. Their correspondence to the Python implementation is tested and inspected, not established by a proof assistant.

### Checker-side symbolic traversal
For a cube $C$ and current occurrence vector $\omega$, write
$$
 \mathrm{Sym}(G,C,\omega)=\{(C_1,t_1,a_1),\ldots,(C_k,t_k,a_k)\}.
$$
The braces denote a finite collection of leaf records; iteration order is not its semantic content. Its intended invariant has two parts: the leaf cubes partition $C$, and each assignment in a leaf concretely produces that leaf's trace and actual-emitter sequence. The implementation carries trace prefixes through a sequence; below, concatenation of prefixes with suffixes is made explicit.

The checker uses the following rules. Emit yields $(C,[e],[n])$, attaching the current occurrence and the subject's origin/declaration claims to $e$. For a condition $x=v$, form $C^=$ and $C^\ne$ by intersecting its $x$ coordinate with $\{v\}$ and its complement; recurse on each nonempty side. For a sequence, start with $(C,\varepsilon,\varepsilon)$ and, for each child, replace every current record $(D,t,a)$ by all $(E,t\cdot u,a\cdot b)$ obtained from that child's traversal on $D$. For a repeat, first split the count coordinate into its singleton values and apply the body that many times, appending each iteration index to $\omega$.

The output-empty summary is an additional identity rule. It returns $(C,\varepsilon,\varepsilon)$ without recursive expansion when the validated subtree contains no emit node. Structural induction on that subtree proves its concrete execution emits nothing: an empty sequence contributes nothing; sequences concatenate empty results; either branch of a condition remains empty; and a finite repeat concatenates only empty results. The optimization thus preserves the same invariant as the ordinary rules.

**Lemma 1 (checker-region equivalence).**
For every well-formed $G$, nonempty cube $C\subseteq\mathcal{D}(S)$, and occurrence prefix $\omega$, an in-budget checker symbolic traversal returns nonempty leaf cubes satisfying: (i) pairwise disjointness, (ii) union $C$, and (iii) for every leaf $(D,t,a)$ and $d\in D$, $\mathrm{Exec}(G,d,\omega)=(t,a)$.

*Proof.* We use structural induction on $G$, with an inner induction over sequence children or repeat iterations. The induction statement includes arbitrary incoming occurrence prefixes; otherwise the repeat case would not establish the full dynamic path.

For emit, the event template and declarations are fixed by the node. For a fixed $\omega$, so is the occurrence vector. The actual emitter is its static node identifier. The single leaf $C$ therefore covers the incoming cube, is trivially disjoint, and agrees with concrete execution for every member.

For a condition, canonical equality splits the tested coordinate into a selected subset and its complement. The two products are disjoint and their union is $C$. Empty products are discarded. On each nonempty product, concrete execution selects precisely the corresponding branch. By the induction hypothesis, the recursive leaves partition that product and have concrete agreement. Leaves from different branches cannot overlap because they disagree on membership in the selected coordinate subset. Combining the branch leaves proves all three properties.

For a sequence, the base collection $(C,\varepsilon,\varepsilon)$ has the desired prefix invariant. Suppose the collection after $i$ children partitions $C$ and each record contains the exact execution prefix of those children for all its members. Apply the induction hypothesis to child $i+1$ separately within each record's cube. Its subcubes partition that cube and have exact suffix traces. Concatenation produces the correct execution prefix through child $i+1$. Different parent cubes were disjoint; refining each cannot introduce overlap between them. Their union remains $C$. Induction over the finite child list proves the sequence case.

For a repeat over $x$, products restricted to each value $r\in C_x$ partition $C$. Every member of such a product has exactly $r$ iterations. For $r=0$, the one empty trace is exact. For $r>0$, apply the body induction hypothesis successively with occurrence prefixes $\omega\cdot\langle0\rangle,\ldots,\omega\cdot\langle r-1\rangle$. The same prefix-composition argument as for sequence proves exactness after each iteration and preserves a disjoint partition. Combining all singleton-count products proves the result. Finally, the output-empty identity rule is correct by the structural argument above. All recursion and iteration are finite, and the in-budget premise ensures the algorithm returns instead of reporting resource exhaustion. ∎

### Coverage and monitor lemmas
**Lemma 2 (finite Cartesian coverage).**
Let $C_1,\ldots,C_m$ be nonempty in-domain Cartesian cubes. If they are pairwise disjoint and $\sum_i |C_i|=|\mathcal{D}(S)|$, then they partition $\mathcal{D}(S)$ exactly.

*Proof.* In-domain membership gives $\bigcup_i C_i\subseteq\mathcal{D}(S)$. Pairwise disjointness gives $|\bigcup_i C_i|=\sum_i|C_i|$. A proper subset of a finite set has strictly smaller cardinality. The equality therefore implies full coverage. Two cubes overlap exactly when their coordinate subsets intersect in every dimension, so the check can be performed without enumerating their assignments. ∎

Cardinality without disjointness would be insufficient. For example, repeating the same half-domain cell twice reaches the full numerical cardinality while leaving the other half uncovered. Disjointness without the cardinality equality would accept incomplete evidence. In-domain membership is the third necessary premise: otherwise outside points could compensate numerically for missing inside points.

**Lemma 3 (monitor connection).**
If two concrete executions have the same complete public event sequence and actual-emitter sequence, monitoring them from the same initial state under the same catalogue gives identical pre-states, ordered violations, and post-states. When a checker leaf agrees with a submitted cell's trace and its replay has no violations, every assignment in that leaf satisfies the complete contract.

*Proof.* Induct on event position. The initial states agree. At position $j$, the event and actual emitter agree, so origin comparison agrees. The trigger function sees equal ordinary fields and the same catalogue; the required identifier list and declaration comparison therefore agree. Every safety rule is evaluated in equal pre-states, so its outcome and diagnostic agree. Stable ordering yields the same local violation list. The deterministic transition is then applied unconditionally and produces equal post-states, including after a violation. This establishes the induction invariant. Combine the resulting replay equality with Lemma 1 for the second claim. ∎

The unconditional transition is part of this lemma. A proof that updated only after a successful rule check would describe a different diagnostic trace. Sticky rejection follows because the accumulated list is extended but never cleared; it does not require post-states to stop changing.

### Positive certificate acceptance
A positive checker first validates the result and its subject binding. For every submitted cell, it validates its cube, compares it with earlier cubes for overlap, and adds its cardinality to a total. It symbolically traverses the entire generator over that cube. Every returned leaf must reproduce the recorded event list and pseudo-program, and its freshly computed monitor steps must equal those recorded in the cell. Every leaf must have an empty violation list. Finally, the sum of cube cardinalities must equal the schema cardinality.

This procedure checks every symbolic leaf, not one representative assignment. A submitted cell may cross multiple syntactic branches that happen to have the same evidence. Such a cell is acceptable only when all resulting leaves agree with its record. A cell crossing branches with different emitter claims, occurrence paths, or monitor states is rejected even when both branches are operationally safe.

**Theorem 1 (positive-certificate soundness).**
If this checker accepts a positive certificate for $Q=\langle S,G,\mathcal{O}\rangle$, then every $d\in\mathcal{D}(S)$ belongs to exactly one submitted cell and its concrete execution agrees with that cell's event trace, pseudo-program, and monitor steps. Every event's origin and occurrence are correct, every declaration set equals the triggered set, and the complete trace is safe under $\mathcal{O}$.

*Proof.* The cube checks and final cardinality test satisfy Lemma 2, establishing unique membership. Fix any assignment $d$ and its unique cell $C$. Lemma 1 supplies a symbolic leaf of the checker traversal containing $d$, whose trace and actual emitters are its concrete execution. The checker compares that leaf's trace and rendered view with the submitted cell. Replay is required to have no origin mismatch, no declaration mismatch, and no safety failure. Event equality includes the reconstructed occurrence vector. Lemma 3 connects the same replay and recorded monitor steps to $d$. The assignment was arbitrary, so the conclusions hold over the whole domain. ∎

This proof places no trust in the producer's cell order, merge choices, branch exploration order, or saved classification label. It also does not use producer/checker agreement on a test corpus as a premise. Its remaining implementation assumption is that the checker carries out the stated parsing, traversal, comparison, and monitoring rules correctly.

### Negative evidence and diagnostic order
**Theorem 2 (negative-evidence validity).**
If the checker accepts a counterexample record, its input $d$ belongs to $\mathcal{D}(S)$, its event and monitor records equal independent concrete replay, and its reported violation is the first violation in that replay. The recorded prefix is precisely the trace through that event.

*Proof.* Schema membership is checked by canonical identity. The checker derives the trace and actual emitters from $G$ at $d$, computes monitoring, and requires a nonempty violation list. It compares the complete event list, rendered view, monitor steps, and first violation to the record. It then compares the prefix with the trace slice whose length is the first violation's index plus one. These predicates establish each conclusion directly. The result-shape checks require exact integer indices, preventing Boolean or floating-point aliases from passing numeric equality. ∎

**Theorem 3 (least counterexample).**
An accepted counterexample input is the least rejecting member of $\mathcal{D}(S)$ under $\rank_S$.

*Proof.* The checker constructs the ordered finite assignment list and locates $d$ using canonical identity. For every preceding assignment, it independently executes all origin, coverage, and safety checks and requires an empty violation list. By Theorem 2, $d$ itself rejects. Since the rank is total, there is no other smaller rejecting assignment. ∎

Theorem 3 does not assert that the chosen prefix is a minimal generator fragment. Replacing or deleting statements can change occurrence positions and triggers, so a separate reduction relation would be needed for that claim. Our record reports an exact least input and a deterministic first failure, which are sufficient for reproducing the subject's contract violation.

### Producer completeness within the bounded contract
The producer uses its own symbolic traversal. Its corresponding partition invariant is proved by the same four language cases as Lemma 1, but with the producer's state representation. This is a separate algorithmic argument, not an inference from matching outputs. The permitted merge preserves its invariant: the two merged products differ in exactly one coordinate, so replacing that coordinate with the union yields exactly their union. Equal payloads preserve homogeneity, and a third cell cannot overlap the union unless it overlapped an original cell.

**Theorem 4 (relative completeness and termination).**
For a well-formed subject on which the stated concrete and symbolic algorithms remain within the work and output bounds, the producer terminates. If $\mathrm{Contract}(Q)$ holds, it returns a checker-acceptable positive certificate. Otherwise it returns a checker-acceptable counterexample at the least rejecting input.

*Proof.* The tree and all input domains are finite; repetitions use finite counts. The symbolic partition rules terminate with finitely many nonempty cubes. Repeated permitted merging terminates because each successful merge strictly decreases the number of cells. If every input satisfies the contract, every producer cell has an accepting common trace. Its partition is in-domain, disjoint, and complete. Applying Lemma 1 to the checker's traversal over such a cell yields concrete-equal leaf payloads. Those equal the cell's common payload, and Lemma 3 gives the same accepting monitor record. Therefore all positive checker predicates hold.

Otherwise, some assignment fails. The finite total ordering has a least such assignment. Concrete evaluation in that order reaches it, and the producer records its exact trace and first diagnostic. The checker reconstructs those values by the concrete semantics and verifies all earlier assignments, satisfying Theorems 2 and 3. The in-budget premise excludes operational aborts on either path. It cannot be dropped merely because the mathematical input is finite. ∎

### What has, and has not, been proved
Theorem 1 certifies the complete supplied generator-to-event relation through checker-side regions. Theorem 4 relates the mathematical producer and checker definitions. Neither is a machine-checked proof of the Python source. This difference is substantive: Alkassar et al. combine verified checker implementations with higher-level mathematical proofs [alkassar2014framework]; Noschinski et al. connect certifying computations with verification infrastructures for C [noschinski2014autocorres]. Our work retains the Python checker and its runtime in the trusted implementation base.

The practical benefit of separate code is that a producer fault cannot automatically be accepted by calling the same faulty routine in the consumer. Shared requirements mistakes remain possible. Foundational proof-carrying code explicitly addresses the size of the trusted foundations [appel2001foundational]; our domain-specific checker is not a foundational proof kernel. The bounded exhaustive, differential, transformation, and mutation evidence in Section (see the corresponding manuscript section) complements the mathematical argument at this implementation boundary.

## Consequences for Partitioning, Evolution, and Diagnostics

The contract has consequences that are useful when changing the producer or maintaining a generator specification. We state them separately from the soundness theorem because they specify which edits preserve evidence and which require new evidence. They are algebraic consequences of the model, not a claim that certificate reuse has already been integrated with a build system.

### Refinement and order of positive cells
**Proposition 2 (refinement closure).**
Suppose a positive certificate is accepted and one of its cells $C$ is replaced by a finite disjoint Cartesian partition $D_1,\ldots,D_k$ of $C$. Copy the original cell's trace, program, and monitor payload to every replacement. If the replacement traversals remain within the bounds, the resulting certificate is accepted.

*Proof.* Every $D_i$ remains in-domain. Replacement cells are disjoint from one another by hypothesis and from all unchanged cells because they are subsets of $C$. Their cardinalities sum to $|C|$, so the global total remains the schema cardinality. By Theorem 1, every assignment of $C$ has the recorded payload and satisfies the contract. Lemma 1 partitions each $D_i$ into checker leaves with exactly those concrete executions, and Lemma 3 reproduces the copied monitor record. All acceptance predicates are therefore preserved. ∎

Cell permutation also preserves acceptance: it changes neither overlap, total cardinality, nor the checks local to a cell. These statements explain why a positive certificate is not tied to one producer traversal order. They also give a direct negative test. Duplicating a cell without removing its original violates disjointness; deleting one without replacing its assignments violates coverage. Both can leave every surviving local trace perfectly safe.

The converse---that any grouping of cells with a common safety verdict is valid---is false. Two cells can both be safe while emitting different operations or different occurrences. Even equal complete traces do not imply their union is Cartesian. The admissible merge in Section (see the corresponding manuscript section) is a sufficient geometric condition, not a license to draw a bounding rectangle around an arbitrary group. Figure (see the corresponding manuscript section) makes this distinction visible.

### Schema restriction
**Proposition 3 (admissible restriction).**
Let $S'$ retain the same field names and replace each $D_i$ by a nonempty ordered subdomain $D'_i\subseteq D_i$. Suppose $G$ and $\mathcal{O}$ remain well formed under $S'$ and all relevant checks remain in budget. Intersect every accepted certificate cube with $\mathcal{D}(S')$, discard empty intersections, and bind the resulting record to $\langle S',G,\mathcal{O}\rangle$. The restricted positive certificate is accepted.

*Proof.* The intersection of two Cartesian products is the product of coordinate intersections. Thus each nonempty intersection is an admissible cube. Intersections preserve pairwise disjointness. For any assignment in $\mathcal{D}(S')$, the original certificate has exactly one containing cube; the corresponding intersection contains it. Hence the intersections partition the restricted domain. Restriction does not change the concrete execution for any retained assignment, because the generator reads the same field values and the catalogue is unchanged. Lemmas 1 and 3 establish its old payload and monitor record over each intersection. ∎

The well-formedness condition is essential in the implementation. For example, it requires a conditional's compared value to occur in the declared domain. Removing that value can make a syntactically unchanged generator invalid even though the condition would simply be false on the remaining mathematical assignments. The proposition applies only when the new subject passes its own validation; it does not bypass that validation. The experiment chooses a legal nonempty restriction for each positive subject. Its rows record that checking occurred and the remaining assignment count; the exact field/domain choice is reconstructible from the deterministic `restricted_pair` driver.

Extension behaves differently. Enlarging a domain can introduce an input whose branch was absent from the old domain. Reusing an old certificate without accounting for the new assignments then fails cardinality coverage. Copying an old trace over them is justified only if the checker proves the larger region homogeneous. Thus narrowing and widening a subject have different obligations even when they seem like symmetric changes in a configuration editor.

### Catalogue changes and exact coverage
Suppose an event triggers obligation $o$, and extend the catalogue with a new identifier $o'$ having exactly the same trigger and rule. If the old trace satisfied $o$, it also satisfies the safety predicate of $o'$. Yet its old declaration set omits $o'$. Exact coverage must now reject that trace.

**Proposition 4 (coverage sensitivity).**
There are accepted subjects for which adding a semantically redundant obligation changes an unchanged generated trace from full-contract acceptance to coverage rejection without changing operation-safety acceptance.

*Proof.* Use any accepted subject with a nonempty triggered set and add the fresh-identifier duplicate just described. On an input reaching the trigger, the safety conditions are duplicated, so their truth values remain true. The required identifier set strictly grows while the declaration set does not. Their equality fails. The event operations and origins are unchanged. ∎

This is a feature of explicit obligations, not an anomaly to be normalized away. A maintainer who adds a requirement may want every affected emission to acknowledge it. Treating requirements only as anonymous logical formulas would lose that traceability obligation. Conversely, adding a trigger that matches no reachable event leaves existing per-event coverage unchanged. An implementation can distinguish these cases only by considering both the catalogue and the generator-to-event relation.

A changed catalogue invalidates the old subject binding even when its final truth value happens to be the same. Rebinding is not itself a proof of correctness: the new record must still pass the checker. The construction in Proposition 4 deliberately rebinds the record and generates a negative witness to demonstrate the coverage change, rather than accepting any serialized header edit as sufficient evidence.

### Renaming and order-sensitive diagnostics
A bijection on node identifiers preserves the complete contract when it is applied consistently to node definitions, correct origin claims, and wrong-but-existing origin claims. A wrong identifier must remain wrong after renaming. If an absent identifier is mapped to a real node accidentally, the transformation is not a semantics-preserving renaming of the full subject. The metamorphic test therefore constructs one consistent mapping and keeps absent identifiers outside its image.

Object-key permutation is another representational change: canonical JSON identity ignores dictionary insertion order. Schema field lists and domain lists, however, are ordered data. Reversing a JSON object's keys is not the same operation as reversing the list of domain values. A subject's universal verdict is unchanged by a domain-value permutation that preserves all values and well-formedness, but the least counterexample can change because the rank uses domain indices.

Consider a field with domain $[0,1,2]$ and a generator that is safe only at $0$. Under this order, $1$ precedes $2$. Under domain order $[0,2,1]$, the least failure becomes $2$, while the failing set remains $\{1,2\}$. This example prevents the term ``minimum'' from being mistaken for an order-independent semantic optimum. The positive contract quantifies over a set of assignments; the negative diagnostic additionally uses an order on that set.

### Observation, preservation, and invalidation together
Table (see the corresponding manuscript section) summarizes these consequences. The distinction between preservation and invalidation is more informative than asking whether an edit leaves the operation trace unchanged. Origin edits can invalidate traceability without changing operations. Catalogue additions can invalidate declarations without changing the safety truth value. Input restrictions can preserve a positive result but alter which negative input would be least. Partition refinements can preserve all semantics while increasing certificate size.



These principles do not eliminate the need to recheck a changed subject. They explain what a proposed evidence transformation must preserve. In particular, proving that an edit preserves the operation projection establishes only one part of the contract; it does not supply a missing declaration or source relation. This is the same observation boundary that motivated the original problem, now expressed as conditions on maintenance operations.
