# Work Program and Governance

Status: **Working model / pre-ADR**

## 1. Purpose

This document turns the verification architecture into an incremental work model suitable for issues, agents, reviews, and bounded implementation sprints.

The work should be organized primarily by **logical/proof layer and semantic machine**, not by traditional software layers.

## 2. Core migration loop

For each bounded security subsystem:

### Step 1 — Security purpose

State what security property the subsystem exists to provide.

Do not begin from its files or modules.

### Step 2 — Semantic machine

Define:

$$
C,\;S,\;E,\;A,\;O
$$

and the transition relation.

Include:

- allowed states;
- legal transitions;
- explicit refusals;
- failure/degradation states;
- persistence/recovery;
- rollback;
- concurrency;
- observations if confidentiality is relevant.

### Step 3 — Generated obligations

Generate the standard theorem obligations from the semantic machine.

Do not write implementation code merely to satisfy existing theorem names.

### Step 4 — Current implementation mapping

Map current production code to the model:

```text
code type/API/site -> semantic element
```

Classify every relevant site as:

- exact correspondence;
- model missing behavior;
- implementation contains unmodelled behavior;
- implementation duplicates an authority/transition;
- implementation representation prevents proof;
- non-security-relevant.

### Step 5 — Gap decision

For every mismatch decide:

- amend model;
- narrow/refactor implementation;
- introduce explicit authority type;
- introduce state type;
- introduce boundary conversion;
- introduce transition API;
- remove bypass/dead path.

This is where ADRs may become appropriate if the decision establishes a general architectural rule.

### Step 6 — Bounded refactor

Refactor only what is necessary to establish sound correspondence.

Avoid broad aesthetic or style changes.

### Step 7 — Proof/evidence

Establish, with evidence admissible for each obligation's requirement (01 §3.1):

- mechanism proof;
- implementation refinement of each mapped transition (02 §13.1), not only the mapping;
- subsystem invariant;
- relevant composition theorem;
- structural closure;
- mutation/falsification evidence.

### Step 8 — Seal

Add repository gates preventing reintroduction of bypass paths.

Examples:

- no mutation outside registered transition APIs;
- no trusted-type constructor outside registered boundaries;
- no raw epoch write outside epoch authority;
- no security-sensitive raw config consumption;
- no unregistered authority constructor.

### Step 9 — Compose

Prove the interface contracts between this machine and adjacent machines.

Only then declare the subsystem migrated, against the criterion in `05-refinement-and-closure-model.md` §8.

## 3. Issue taxonomy

Use consistent issue classes.

### `MODEL`

Define or correct semantic states, events, authorities, outcomes, or transitions.

### `MAP`

Map existing implementation to semantic elements and identify mismatches.

### `PROOF`

Implement or repair Lean/Verus/compositional theorem evidence.

### `STRUCTURE`

Make illegal paths unrepresentable: visibility, constructors, capability types, transition ownership.

### `GATE`

Add mechanical census/closure checks.

### `COMPOSE`

Prove interactions between semantic machines.

### `ASSUMPTION`

Review, discharge, or isolate an external premise.

### `COVERAGE`

Investigate an obligation or implementation surface not owned by the current proof graph.

Issues should be small enough to complete independently but trace to a semantic-machine work package.

## 4. Work packages / sprints

A sprint should normally target one coherent vertical proof chain rather than one conventional code layer.

Example:

### Trust epoch work package

- MODEL: define trust-epoch states and transitions.
- MAP: enumerate all production epoch reads/mutations.
- STRUCTURE: private epoch state representation.
- STRUCTURE: one registered monotonic advance operation.
- PROOF: advance monotonicity.
- PROOF: rollback cannot restore prior authority.
- PROOF: restart preserves accepted floor.
- COMPOSE: delegated signing requires authorized epoch.
- GATE: no raw Redis epoch writes.
- GATE: every epoch mutation maps to registered transition.

This is preferable to separate "Redis sprint", "CLI sprint", "Rust API sprint", and "tests sprint".

## 5. Pilot recommendation

Use delegated signing + trust epoch as the first full pilot.

It contains:

- semantic configuration differences;
- explicit authority;
- lifecycle state;
- multi-replica operation;
- Redis coordination;
- persistence;
- rollback;
- concurrency;
- OS entropy;
- degraded/failure behavior;
- restart behavior;
- composition with signer lifecycle and credential validity.

The pilot should produce reusable templates for later subsystems.

### 5.1 Pilot phases

The phases below are a recommendation, not a binding plan. Each phase ends with a short written result; a later phase does not start on the assumption that an earlier one went as expected.

**P0 — Model only.** Define $C$, $S$, $E$, $A$, $O$ and the transition relation for delegated signing and trust epoch, including failure, recovery, rollback and concurrency. Name every nondeterministic observation as an event (02 §1.1). No production refactor.

**P1 — Implementation census.** Map every relevant production site to a semantic element, or mark it unmappable with the reason. Classify each site as in §2 Step 4. No refactor.

**P2 — Generated obligations.** Derive the obligations from the model (03 §6), each with its property class and assurance requirement. Compare them against the existing THM/ASM registry: which existing theorems correspond, which generated obligations have no theorem, which theorems correspond to no generated obligation, and which premises are actually MCP-RE-owned behavior.

**P3 — Architecture decisions.** Ratify only rules that survived contact with the real implementation in P1 and P2. This is where ADR candidates may emerge (§7), and where the working model is amended where the pilot showed it wrong.

**P4 — Bounded implementation migration.** Refactor model/implementation mismatches one at a time, each with its refinement evidence.

**P5 — Structural sealing.** Make the bypass paths found in P1 mechanically impossible or gate-detectable.

**P6 — Composition.** Establish the cross-machine invariants and ordering contracts with neighbouring machines (signer lifecycle, credential validity, admission).

**The pilot is allowed to falsify the working model.** It is an experiment on the model, not a demonstration of it. If P0–P2 show that the semantic form, the determinism choice, the evidence classes, or the two-graph split do not fit real code, the result is an amended model, and that result is as valuable as a confirmation. The documents in this directory should be read with that in mind.

## 6. Pilot exit criteria

The pilot's machines are complete when they meet the **migrated** criterion in `05-refinement-and-closure-model.md` §8. In this document's terms, do not call the pilot complete until:

1. every production behavior maps to the semantic machine;
2. every registered transition has generated obligations;
3. every generated obligation has a disposition;
4. implementation mismatch has been refactored or model amended;
5. relevant Lean/Verus/structural evidence passes;
6. no production state mutation bypasses the registered transition surface;
7. configuration classes are explicit;
8. failure/recovery/rollback/concurrency are represented;
9. cross-machine dependencies are expressed as composition theorems;
10. mutation/falsification demonstrates that important clauses are actually observed by the proof package;
11. every obligation's evidence is admissible for its requirement (01 §3.1), not merely present;
12. the pilot has produced a written account of where the working model held and where it was amended.

## 7. ADR policy

Create ADRs only for ratified rules with durable architectural consequences.

Potential future ADRs might include:

- **Security semantic machines are authoritative for security-relevant state changes.**
- **Security state has private representation and mutates only through registered transition APIs.**
- **Security code consumes normalized validated configuration rather than raw CLI/Helm/environment state.**
- **Trusted evidence types are constructible only at registered trust boundaries.**
- **Security effects require nominal authority/capability values.**
- **Current theorem verification requires both current semantic review and current established evidence.**
- **Production security effects must be registered in the verification graph.**

Do not create these ADRs merely because they sound good. Pilot them first where practical, then ratify.

## 8. Agent workflow

Agents should not be asked vague questions such as:

> Review this subsystem and make it formally verified.

Instead give bounded tasks.

Example investigation prompt shape:

1. Identify all production sites relevant to the specified semantic machine.
2. Map each to `C/S/E/A/O` or declare it unmappable.
3. Do not change code.
4. Report only mismatches and uncertainty.
5. Include exact file/symbol evidence.
6. Separate model gaps from implementation bypasses.

Implementation agents should then receive already-ratified semantic decisions.

This avoids allowing an implementation agent to silently redesign the security model while fixing code.

## 9. Dependency order

A reasonable program order is:

1. normalize theorem/assumption review machinery;
2. pilot semantic-machine approach;
3. ratify architectural rules learned from pilot;
4. migrate neighboring machines;
5. establish composition contracts;
6. build automated implementation-surface census;
7. build verification-completeness census;
8. establish top-level system theorems;
9. run whole-system closure.

The exact subsystem sequence should be chosen by security coupling, not directory layout.

## 10. Tracking progress

Track progress in terms of semantic closure, not lines changed.

For each machine report:

- model status;
- implementation-mapping completeness;
- number of unclassified production sites;
- obligation generators run over this machine's domain;
- generated obligations, by property class;
- obligations discharged with admissible evidence;
- obligations with evidence of an inadmissible class;
- external assumptions;
- structural bypasses remaining;
- composition edges unresolved;
- mutation coverage;
- current evidence state.

The strongest progress signal is:

$$
UnclassifiedSecuritySurface = 0
$$

for the subsystem.

## 11. Relationship to current remediation PR

The current security-remediation campaign (#1083) **must not** become this migration programme.

Its job is to leave the current branch secure, internally consistent, and truthfully verified. Nothing in these documents is a reason to widen its scope, delay its closure, or restructure its theorems ahead of the pilot.

The semantic-machine program begins after #1083 as a follow-on architecture effort, initially with read-only modelling and one bounded pilot.

That separation avoids turning the remediation PR into an uncontrolled architectural rewrite while preserving the lessons discovered by the campaign.

### 11.1 Remediation machinery as proto-infrastructure

Some machinery the remediation built for its own needs may already be early forms of what this model needs:

- separate review and evidence axes (`REVIEW_CURRENT` / `EVIDENCE_ESTABLISHED`);
- semantic review digests over claim, premises, sources, selected tests and proved symbols;
- explicit premise closure, with unit-scoped and boundary-scoped premises attached by rule;
- the distinction between a model registration and a logical premise;
- the structural and mutation census;
- non-vacuity probes for proof targets;
- validated security configuration types;
- typed authenticated/verified values with constrained construction.

After #1083, the first question for each of these is **whether it already corresponds to the semantic model**, and if so what it is in the model's terms (a review axis, a premise of class `External`, a structural closure, a reachability obligation). Only where it does not correspond is a rewrite considered, and then as a P3 decision with a reason, not as a default.
