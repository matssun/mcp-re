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

Claims quantified over accepted semantic configuration classes.

Example:

$$
AcceptedConfig(c)
\Rightarrow
RequiredSubsystemInvariants(c)
$$

The goal is not representative configuration testing but coverage of every accepted semantic configuration class.

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

## 3. Proof DAG

The theorem structure is a directed acyclic graph, not merely a list.

Possible edge types:

- `requires`
- `refines`
- `preserves`
- `strengthens`
- `projects_to`
- `excludes`
- `discharges_assumption`
- `covers_configuration`
- `implemented_by`

Example:

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

For every top-level theorem $T$, recursively expand dependencies.

Every leaf must terminate in exactly one acceptable category:

- machine-checked theorem;
- structural/compiler-enforced property;
- executable evidence where proof is inappropriate;
- explicit current external assumption.

There should be no unexplained leaves.

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
10. refusal behavior is explicit for disallowed transitions.

Additional obligations arise from subsystem-specific assets and observations.

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

## 8. Completeness of the theorem package

The theorem list should not define its own completeness.

Security obligations should be generated independently from several sources:

- top-level security goals;
- semantic machines;
- accepted configuration space;
- implementation/security-surface census;
- trust-boundary and authority graph;
- threat derivation;
- failure/recovery analysis;
- persistence and concurrency;
- mutation/property coverage.

Let the combined obligation set be $O$.

Then require:

$$
\forall o \in O,\quad
\exists e:\ Discharges(e,o)
$$

or an explicit classification that the obligation is not security relevant.

Unknown obligations are not allowed at closure.

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
CURRENTLY\_VERIFIED
=
REVIEW\_CURRENT
\land
EVIDENCE\_ESTABLISHED
$$

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

## 11. End state

The desired theorem architecture should allow MCP-RE to answer:

- Which top-level security property does this theorem support?
- Which lower-level properties establish this theorem?
- Which semantic states/transitions does it describe?
- Which implementation paths refine it?
- Which configuration classes does it cover?
- Which external assumptions remain?
- What change would invalidate its review?
- What current execution evidence establishes it?

A theorem without these relationships is not yet fully integrated into the security theory.
