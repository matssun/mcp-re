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

Establish:

- mechanism proof;
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

Only then declare the subsystem migrated.

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

## 6. Pilot exit criteria

Do not call the pilot complete until:

1. every production behavior maps to the semantic machine;
2. every registered transition has generated obligations;
3. every generated obligation has a disposition;
4. implementation mismatch has been refactored or model amended;
5. relevant Lean/Verus/structural evidence passes;
6. no production state mutation bypasses the registered transition surface;
7. configuration classes are explicit;
8. failure/recovery/rollback/concurrency are represented;
9. cross-machine dependencies are expressed as composition theorems;
10. mutation/falsification demonstrates that important clauses are actually observed by the proof package.

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
- generated obligations;
- obligations proved;
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

The current security-remediation campaign should not be expanded into the entire migration described here.

Its job is to leave the current branch secure, internally consistent, and truthfully verified.

The semantic-machine program should begin as a follow-on architecture effort, initially with read-only modelling and one bounded pilot.

That separation avoids turning the remediation PR into an uncontrolled architectural rewrite while preserving the lessons discovered by the campaign.
