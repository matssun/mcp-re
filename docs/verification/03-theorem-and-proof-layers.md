# Theorem and Proof Layers

Status: **Working model / pre-ADR**

## 1. Purpose

The theorem package should not be a catalogue of independent claims.

It should form a deliberate proof graph in which:

- lower-level properties establish mechanism correctness;
- subsystem invariants compose those properties;
- cross-subsystem theorems establish interaction correctness;
- configuration theorems quantify over supported semantic configurations;
- a small set of top-level security theorems state the security properties MCP-RE actually intends to provide.

The structure should support both **downward closure** and **upward closure**.

## 2. Proposed theorem layers

### Layer 0 — External assumptions

Facts genuinely outside MCP-RE's proof boundary.

Examples might include properties of:

- OS entropy;
- hardware security modules;
- external clocks, where explicitly required;
- external trust anchors;
- cryptographic primitives below the verified interface.

Internal implementation behavior should not remain here merely because proving it is inconvenient.

### Layer 1 — Mechanism theorems

Claims close to one operation or type.

Examples:

- a `SigningWindow` is non-empty when constructed;
- an epoch advance is monotonic;
- a continuation consume operation is one-shot;
- a trusted identity value can only be constructed from verified material.

### Layer 2 — Subsystem invariants

Claims spanning a bounded semantic machine.

Examples:

- delegated signing cannot emit outside an active signing window;
- retired signer authority cannot become active without a legal transition;
- replay admission cannot be created without verified request material;
- trust state never moves below its monotonic floor.

### Layer 3 — Composition theorems

Claims about interaction between semantic machines.

Examples:

$$
Admission.Accepted(actor)
\Rightarrow
Identity.Verified(actor)
$$

$$
Continuation.Created(actor)
\Rightarrow
Admission.Accepted(actor)
$$

$$
Signing.Allowed(epoch)
\Rightarrow
TrustEpoch.Authorizes(epoch)
$$

These are critical because individually correct subsystems can still compose incorrectly.

### Layer 4 — Configuration theorems

Claims quantified over accepted semantic configuration classes (02 §5.1), not over syntactic inputs.

Example:

$$
\forall [c] \in AcceptedClasses:\;
RequiredSubsystemInvariants([c])
$$

The goal is not representative configuration testing but coverage of every accepted semantic configuration class. Where the class space is large or unbounded, the theorem quantifies over a symbolic constraint describing a set of classes rather than enumerating them; brute-force enumeration of input combinations is neither required nor sufficient.

### Layer 5 — Top-level security theorems

A small set of system properties that express why MCP-RE is secure.

Candidate families may include:

- identity authenticity and binding;
- authority confinement;
- integrity of protected operations;
- replay resistance;
- continuation binding;
- revocation monotonicity;
- signing authority lifecycle safety;
- bounded degradation/fail-closed behavior;
- trust-state rollback resistance;
- audit/transparency evidence integrity;
- confidentiality/noninterference where required.

These should be few enough to understand as the system's security contract.

## 3. Two graphs: logical dependency and traceability

The theorem package carries two different kinds of relationship, and they are kept in two graphs because they answer different questions and obey different rules.

### 3.1 Logical dependency DAG

Edges that participate in **establishing** a theorem, and therefore in **invalidating** it:

- `requires`: the parent's proof uses the child as a premise;
- `derived_from`: the parent is obtained from its children by a stated implication;
- any other edge whose removal would leave the parent unproved.

This graph **must be acyclic**. A cycle is a circular argument.

It is also the graph that **propagates the verification verdict**. A theorem is currently verified only if it is review-current, its own evidence is established, and every logical dependency is itself currently verified (§10). When a child stops being currently verified, every theorem reachable upward along logical edges stops being currently verified with it, without its own review or evidence axis being reported as stale.

### 3.2 Traceability / semantic relationship graph

Edges that **locate** a theorem in the system without being part of its proof:

- `implemented_by`: the code that realizes the property;
- `refines`: the implementation operation claimed to refine a semantic transition (the claim itself is a theorem with its own logical edges; the edge is the pointer);
- `preserves`: the transition whose preservation obligation this theorem discharges;
- `projects_to`: the higher-level property this one is a projection of;
- `covers_configuration`: the configuration classes the theorem is stated for;
- `associated_with_transition`: the semantic transition the theorem talks about;
- `supported_by`: the verification units whose evidence is cited;
- `discharges_assumption`, where it records which premise a proof made unnecessary rather than being itself a step of the argument.

This graph does **not** have to be acyclic: code implements several theorems, theorems cover several transitions, and those relationships form cycles harmlessly.

The logical DAG alone controls **logical dependency propagation**: a theorem becomes non-current because something it logically depends on did. A traceability edge never becomes a logical dependency by being present.

That does not make traceability irrelevant to currency. Semantically relevant traceability and correspondence information is part of what a theorem's review or evidence covers, and a change to it can invalidate that review or evidence **through the theorem's own fingerprint**. Changing which implementation path refines a semantic transition, for example, requires the correspondence to be re-reviewed, without creating any theorem dependency edge. Once the theorem is non-current for that reason, its logical ancestors follow along the logical DAG in the ordinary way.

### 3.3 When an edge changes graphs

Whether an edge is logical or traceability is a property of how it is used, not of its name. `discharges_assumption` is traceability when it records history; it is logical when the parent's proof actually depends on the discharging theorem instead of on the premise. The edge's role is stated where it is declared, and an edge that becomes load-bearing for a proof is moved into the logical graph.

### 3.4 Example of a logical derivation

$$
T_1:\ VerifiedIdentity\ cannot\ be\ forged
$$

$$
T_2:\ Authorization\ requires\ VerifiedIdentity
$$

$$
T_3:\ ProtectedMutation\ requires\ Authorization
$$

compose into:

$$
T_1 \land T_2 \land T_3
\Rightarrow
T_4:\ UnauthenticatedInput\ cannot\ cause\ ProtectedMutation
$$

The implication from children to parent is itself part of the proof architecture.

## 4. Downward closure

For every top-level theorem $T$, recursively expand dependencies along the logical dependency DAG (§3.1).

Every leaf must terminate in an acceptable category:

- machine-checked theorem;
- structural/compiler-enforced property;
- executable evidence where proof is inappropriate;
- explicit current external assumption.

There should be no unexplained leaves. A leaf in the external-assumption category is **assumed**, not established: the theorems above it are verified relative to that premise.

Being in an acceptable category is necessary but not sufficient. Each leaf must also be **admissible** for the obligation it discharges (01 §3.1): its evidence class must be one that the obligation's `Requirement` admits. A `Hybrid` obligation expands into one leaf per named part, each checked against its own part. A leaf that is valid evidence of the wrong class (a test standing in for a universal claim, a premise standing in for MCP-RE's own behavior) is an unexplained leaf.

Formally:

$$
Leaves(T)
\subseteq
MachineProved
\cup
StructuralGuarantee
\cup
ExecutableEvidence
\cup
ExternalAssumption
$$

## 5. Upward closure

Every low-level theorem should contribute to a meaningful higher-order property.

For each low-level theorem $t$:

$$
\exists T_{system}:
t \leadsto T_{system}
$$

where $\leadsto$ is reachability in the logical dependency DAG. A traceability edge such as `projects_to` can suggest where the missing logical path belongs, but does not by itself count as contribution.

If no such path exists, investigate whether:

- the theorem is unnecessary;
- it is merely implementation trivia;
- or its security consequence has not yet been captured by a higher theorem.

This helps detect both decorative formalism and missing composition claims.

## 6. Theorem generation from semantic machines

A semantic machine should generate standard theorem obligations rather than relying on humans to remember them.

For each machine:

1. initialization preserves invariants;
2. every registered transition preserves invariants;
3. every security effect requires explicit authority;
4. boundary-derived trusted values have valid provenance;
5. failures do not increase authority;
6. restart/recovery preserves required invariants;
7. rollback cannot restore forbidden authority;
8. concurrent security transitions have defined ordering semantics;
9. supported configuration classes are non-vacuously reachable;
10. refusal behavior is explicit for disallowed transitions;
11. every cross-machine invariant $I_{ij}$ the machine participates in is preserved by each of its transitions (02 §12).

Additional obligations arise from subsystem-specific assets and observations.

Each generated obligation is recorded with its **property class** (01 §8a) and its **assurance requirement** (01 §3.1) at the time it is generated. The class constrains the requirement: a liveness bound, a noninterference property and a state invariant do not have the same admissible evidence. The requirement is not chosen later to fit whatever evidence exists.

## 7. Refinement relationship

Where practical, establish a three-part chain:

1. **Abstract model theorem** — e.g. Lean proves a property of the semantic transition system.
2. **Implementation refinement theorem** — e.g. Verus proves a Rust operation implements/refines the abstract transition.
3. **Structural closure gate** — repository analysis proves there is no production mutation path outside the registered operation.

Conceptually:

$$
ModelCorrectness
+
ImplementationRefinement
+
MutationClosure
\Rightarrow
ProductionProperty
$$

No single layer is sufficient by itself.

The roles are intended as follows, without making any tool mandatory where a different method is better:

- **model correctness**: properties of the semantic machine itself, typically Lean;
- **implementation refinement**: that a production operation refines its semantic transition under the abstraction $\alpha$ (02 §13.1), typically Verus or an equivalent method for the code at hand;
- **mutation closure**: that no production path reaches the state or effect except through the refined operation, typically a structural gate.

A mapping that names a Rust method as a transition is not the second part. The second part is a refinement statement with evidence. The precise forms are in `05-refinement-and-closure-model.md`.

## 8. Completeness of the theorem package

The theorem list should not define its own completeness.

Security obligations should be generated independently from the generators listed in 01 §8: security goals; semantic machines; accepted configuration classes; trust boundaries; the authority/capability graph; the implementation/security-surface census; failure/recovery; persistence/restart/rollback; concurrency; threat derivation; and mutation/proof-coverage analysis.

Let the combined obligation set be $\mathcal{O}$ (written so to keep it distinct from the outcome type $O$ of 02).

Then require:

$$
\forall o \in \mathcal{O},\quad
Discharged(o)
$$

where $Discharged(o)$ means established by admissible evidence, or assumed externally by a current explicit premise where the obligation is genuinely external (01 §3.1), or $o$ has another terminal disposition (`05-refinement-and-closure-model.md` §5.2). An obligation that remains applicable and is not discharged is open; it is never closed as accepted risk.

Unknown obligations are not allowed at closure. As 01 §3.2 states, that condition has meaning only when each generator has been run over its domain: closure requires generator coverage **and** disposition, not disposition alone.

## 9. Theorem mutation

The proof graph should eventually support mutation in both directions.

### Implementation/model mutation

Perturb a security-relevant transition or model element.

At least one relevant security theorem should fail unless that element is explicitly irrelevant.

### Theorem mutation

Weaken a child theorem:

- remove a conjunct;
- weaken a bound;
- omit a state;
- remove a configuration case;
- weaken a universal quantifier.

A meaningful weakening should cause an appropriate parent/top-level theorem to fail.

If it does not, either:

- the child clause is unnecessary; or
- the parent theorem architecture is incomplete.

## 10. Review state versus evidence state

Human semantic review and current machine evidence should remain separate.

A theorem may have:

- `REVIEW_CURRENT`
- `EVIDENCE_ESTABLISHED`

and should be presented as currently verified only if:

$$
CURRENTLY\_VERIFIED(v)
=
REVIEW\_CURRENT(v)
\land
EVIDENCE\_ESTABLISHED(v)
\land
\forall u \in LogicalDeps(v):\ CURRENTLY\_VERIFIED(u)
$$

The two axes are local to $v$. `REVIEW_CURRENT(v)` says the exact proposition and semantic material reviewed for $v$ are current. `EVIDENCE_ESTABLISHED(v)` says the evidence for $v$'s own supporting units, refinement and proof surface is established. Dependencies compose only at the final verdict.

Semantic review should depend on:

- exact claim;
- exact premises;
- semantic source/specification inputs;
- relied-upon test/probe selection;
- proved-symbol surface.

Evidence establishment should additionally depend on:

- proof/test execution policy;
- current verifier/toolchain where relevant;
- generated/extracted artifact identity;
- successful current execution.

Toolchain churn should generally force evidence re-establishment, not automatic semantic re-review.

Neither axis propagates. A child whose evidence is stale makes its logical ancestors not currently verified, but does not make the ancestors' own evidence stale, and they are not reported that way. A dependency change can move a parent's `REVIEW_CURRENT` directly only through the parent's own review digest, where the dependency's claim or other semantically relevant information about it is part of what was reviewed. Admissibility (01 §3.1) is part of review, not of evidence: whether a class of evidence is acceptable for a claim is a semantic judgment, and a change to an obligation's requirement is a change to what was reviewed.

## 11. End state

The desired theorem architecture should allow MCP-RE to answer:

- Which top-level security property does this theorem support?
- Which lower-level properties establish this theorem (logical graph), and which artifacts locate it (traceability graph)?
- What is its property class and assurance requirement, and is its evidence admissible for that requirement?
- Which semantic states/transitions does it describe?
- Which implementation paths refine it?
- Which configuration classes does it cover?
- Which external assumptions remain?
- What change would invalidate its review?
- What current execution evidence establishes it?

A theorem without these relationships is not yet fully integrated into the security theory.
