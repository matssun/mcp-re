# MCP-RE Verification Architecture

Status: **Working model / pre-ADR**
Date: 2026-10-07

This directory captures the emerging model for moving MCP-RE from a codebase with formal verification attached to it toward a system whose **security architecture, implementation structure, and theorem structure correspond by construction**.

The working thesis is:

> Security-sensitive software should be constructed as a composition of closed semantic state machines whose inputs are validated configuration, current security state, external evidence/events, and explicit authority; whose outcomes are closed; whose transitions generate proof obligations; and whose implementation is structurally constrained to refine those machines.

The immediate purpose of these documents is not to prescribe a complete refactor. It is to establish a stable conceptual model that can be decomposed into investigations, ADRs, issues, and bounded implementation slices.

## Document hierarchy

1. **01-verification-architecture-thesis.md**  
   The overall problem, goals, principles, and the distinction between theorem correctness and verification completeness; admissibility-checked discharge, generator coverage as a condition of closure, and property classes.

2. **02-semantic-machine-model.md**  
   The core semantic form

   $$
   step : C \times S \times E \times A \rightarrow O
   $$

   with all nondeterministic observations carried as events, so that `step` is deterministic; how it recursively applies at system, subsystem, and transition levels; semantic configuration classes; cross-machine invariants; and the difference between mapping and refinement.

3. **03-theorem-and-proof-layers.md**  
   A proposed theorem hierarchy; the split between the logical dependency DAG, which controls currency, and the traceability graph, which does not; and the relationship between local mechanism proofs, subsystem invariants, composition theorems, configuration theorems, and top-level security claims.

4. **04-work-program-and-governance.md**  
   How the model should drive investigation, ADRs, issues, sprint planning, implementation mapping, refactoring, sealing, and verification closure; the phased pilot (P0–P6); and the relationship to the current remediation PR.

5. **05-refinement-and-closure-model.md**  
   The formal relationships between 02 and 03 in one place: transition semantics, implementation abstraction and refinement, obligation requirements and admissible evidence, the two graphs, the closure condition, composition invariants, configuration classes, the definition of a migrated machine, and the open questions the pilot should answer.

These are **working architecture documents**, not ratified ADRs.

## What belongs where

### Working architecture documents

Use these documents for:

- models still being refined;
- definitions and terminology;
- theorem architecture;
- proposed decomposition;
- verification-completeness methodology;
- pilot designs;
- questions that remain open.

They may change substantially while the architecture is being developed.

### ADRs

Create an ADR only when a specific architectural decision has been made and should constrain future work.

Examples:

- security state has private representation and mutates only through registered transition APIs;
- security code consumes only `ValidatedSecurityConfig`;
- trusted identity types have no public constructors outside registered validation boundaries;
- theorem `REVIEWED` state depends on current premises and semantic evidence;
- production security effects must map to a registered semantic-machine transition.

An ADR should say **what is now binding and why**, not attempt to contain the entire theory.

### Issues

Use issues for bounded questions or implementation obligations.

Examples:

- enumerate all production mutations of trust-epoch state;
- map delegated-signing code paths to the semantic machine;
- replace direct Redis epoch writes with the registered transition;
- prove restart monotonicity for trust epoch;
- add a structural gate for unregistered signing effects.

### Sprints / work packages

Group issues by **logical/proof layer**, not by conventional software layer.

A work package should ideally complete one coherent chain:

> security obligation → semantic state/transition → theorem obligation → implementation mapping → refactor gap → proof/evidence → structural sealing

This is intentionally different from organizing work as "API sprint", "database sprint", or "frontend/backend".

## Working principle

The model remains the semantic authority.

Implementation work may reveal that the model is incomplete or wrong, in which case the model must be amended explicitly. Ordinary implementation convenience must not silently redefine the security semantics.

The target direction is:

$$
\text{Security goals}
\rightarrow
\text{semantic machines}
\rightarrow
\text{proof obligations}
\rightarrow
\text{types/APIs/authorities}
\rightarrow
\text{implementation}
\rightarrow
\text{refinement evidence}
$$

rather than:

$$
\text{implementation}
\rightarrow
\text{retrofit specification}
$$

## Near-term recommendation

Before large-scale migration, use one difficult subsystem as a pilot. The pilot is an experiment on this model, not a demonstration of it: it may falsify or change any part of these documents (04 §5.1). Delegated signing and trust epoch are good candidates because they exercise configuration, authority, mutable state, persistence, rollback, concurrency, entropy, failure handling, and multi-replica composition.

The pilot should answer:

1. Can every production behavior be represented as a path through the semantic machine?
2. Does every semantic transition generate the necessary proof obligations?
3. Can the implementation be refactored incrementally until it structurally refines the model?
4. Can structural gates prevent new bypass paths?
5. Do the local proofs compose into meaningful top-level security claims?

The fuller list of open questions, including the points where the model needs a decision before it can be made precise, is in `05-refinement-and-closure-model.md` §9.

Only after that pilot should the pattern be generalized across MCP-RE.
