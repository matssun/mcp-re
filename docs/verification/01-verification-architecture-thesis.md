# Verification Architecture Thesis

Status: **Working model / pre-ADR**

## 1. Problem statement

MCP-RE already contains tests, verification units, theorem records, assumptions, Verus proofs, Lean proofs, mutation probes, structural gates, and security-audit machinery.

That does not by itself establish that the verification package is complete.

There are at least three different questions:

1. **Correctness:** Are the theorems we wrote true?
2. **Correspondence:** Do those theorems accurately describe the current implementation?
3. **Completeness:** Have we identified every security property that needs to be established?

The current remediation campaign has demonstrated that these questions are separable. A theorem may remain syntactically reviewed while a premise or implementation surface moves. Conversely, a proof can be completely valid while the system contains an unmodelled security path.

The long-term architecture therefore needs to make omission itself increasingly difficult.

## 2. Core objective

The target is not "prove every function".

The target is:

> Every security-relevant behavior of every accepted MCP-RE configuration is owned by an explicit semantic model and is connected to a security obligation whose leaves terminate in machine-checked proof, structural enforcement, executable evidence, or an explicit external assumption.

No security-relevant behavior should remain unclassified.

## 3. Closed-world relative verification completeness

Absolute security cannot be proved without defining the system, environment, threat model, and external assumptions.

The intended claim is therefore **relative and closed-world**:

> Given the declared MCP-RE architecture, accepted configuration space, threat model, trust model, environmental assumptions, and semantic machines, every security-relevant reachable behavior has an explicit verification disposition.

A possible formal target is:

$$
\forall c \in AcceptedConfigurations,\;
\forall r \in ReachableExecutions(c),\;
\forall o \in SecurityObligations(c,r),\;
Satisfied(o)
$$

where:

$$
Satisfied(o)
=
Proved(o)
\lor StructurallyEnforced(o)
\lor ExecutablyEstablished(o)
\lor ExplicitExternalAssumption(o)
$$

with the additional requirement:

$$
Unknown = 0
$$

## 4. Why state machines are central

Security-sensitive behavior is fundamentally about changes in authority, trust, identity, custody, freshness, replay state, continuation state, revocation, and persistence.

These are state-transition questions.

An explicit semantic state machine provides a finite structure over which we can ask:

- what states can exist;
- how they are reached;
- which transitions are legal;
- which authority each transition requires;
- what happens on failure;
- what survives restart;
- which transitions may race;
- what observations are permitted;
- which configurations enable each transition.

This makes theorem discovery less dependent on human imagination.

## 5. Architectural correspondence

A formal model is useful only if the implementation is structurally constrained to correspond to it.

The eventual architectural invariant should approach:

$$
SecurityEffect_{production}
\Rightarrow
RegisteredSemanticTransition
$$

Likewise:

$$
SecurityStateMutation
\Rightarrow
RegisteredTransitionAPI
$$

$$
TrustedValue
\Rightarrow
RegisteredBoundaryConstructor
$$

$$
SecurityEffect
\Rightarrow
RequiredAuthority
$$

$$
AcceptedConfiguration
\Rightarrow
ValidatedSecurityConfiguration
$$

The implementation should not contain alternate paths that bypass the model.

## 6. The verification universe

A first useful decomposition is:

$$
V =
C \dot\cup
S \dot\cup
B \dot\cup
A \dot\cup
D \dot\cup
T \dot\cup
F \dot\cup
R \dot\cup
Q
$$

where:

- $C$: accepted semantic configurations;
- $S$: externally reachable security-sensitive surfaces;
- $B$: trust boundaries;
- $A$: authorities/capabilities;
- $D$: security-sensitive data/assets;
- $T$: state transitions;
- $F$: failures/degradation/recovery behavior;
- $R$: persistence/restart/rollback properties;
- $Q$: concurrency/ordering properties.

This must not remain a flat inventory. The security model is the typed relationship graph between these objects.

Examples:

- configuration **enables** surface;
- surface **crosses** boundary;
- boundary **produces** evidence;
- evidence **creates** authority;
- authority **permits** transition;
- transition **mutates** asset/state;
- failure **interrupts** transition;
- restart **reconstructs** state;
- concurrency **orders** transitions.

The relationships generate proof obligations.

## 7. Two directions of completeness

### Top-down

Start from security goals and decompose them into sufficient lower-level claims.

For a parent claim $G$:

$$
G_1 \land G_2 \land \dots \land G_n \Rightarrow G
$$

The sufficiency of the decomposition is itself an obligation.

### Bottom-up

Start independently from implementation and semantic state.

For each security-relevant implementation element or transition, determine which theorem or invariant observes it.

A security-relevant element that can be changed without falsifying any property is a candidate verification gap.

The two directions should converge.

## 8. Independent obligation generation

No single source should define the theorem universe.

Obligations should eventually be generated independently from:

- security goals;
- semantic state machines;
- configuration-space enumeration;
- trust-boundary census;
- authority/capability graph;
- implementation-surface census;
- failure/recovery enumeration;
- persistence/restart/rollback analysis;
- concurrency analysis;
- threat derivation;
- mutation and proof-coverage analysis.

The union forms the candidate obligation set.

The system is not closed while any obligation lacks a disposition.

## 9. Formal methods from project inception

For new security-sensitive projects, the preferred direction is:

$$
\text{Security purpose}
\rightarrow
\text{semantic machines}
\rightarrow
\text{proof obligations}
\rightarrow
\text{types and APIs}
\rightarrow
\text{implementation}
\rightarrow
\text{refinement evidence}
$$

Formal methods should influence software architecture before implementation, rather than being attached afterwards.

MCP-RE must migrate toward this incrementally.

## 10. Migration principle

Do not perform one global refactor.

For each bounded subsystem:

1. define its security purpose;
2. define its semantic machine;
3. enumerate generated obligations;
4. map current implementation to model elements;
5. identify only the mismatches;
6. refactor those mismatches;
7. prove/refute the relevant obligations;
8. add structural gates that prevent regression;
9. compose the subsystem with its neighbors.

Repeat subsystem by subsystem.

## 11. Success criterion

The eventual claim should not be "MCP-RE is mathematically proven secure."

A more defensible target is:

> For the declared MCP-RE security model, every accepted security configuration, registered security transition, trust boundary, authority surface, failure/recovery path, and relevant composition is assigned to an explicit invariant; every invariant has current evidence or a declared external assumption; and repository gates reject production security behavior that escapes the registered model.

That is the architectural destination this document set is intended to develop.
