<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-068 — Evidence classes: what kind of thing supports a security claim

**Status:** 📄 **PROPOSED** 2026-09-17. Not ratified, not implemented. Phase 0 is a registry
and tooling change; no product claim moves under this record.
**Discussion:** to be opened.
**Predecessor:** ADR-MCPRE-059 (discussion #527, rev. 2 = the theorem registry). This record
does **not** supersede it. It adds one missing sort to a model 059 got right in every other
respect, and §7 below *declines* one of the changes that motivated it because 059's existing
rule is better.
**Assurance TCB, not a product claim.** Everything here sits where issue #739 sits: outside
the product theorem roots, inside the layer that decides whether the word `ESTABLISHED` may
be believed. No entry in this record becomes a `THM-`.

---

## 1. The ruling this record starts from

Owner ruling, 2026-09-17, taken on the falsifier measurement reported below:

> **Do not run a standalone falsifier campaign.** The finding that most verification units
> carry no mutation probe is a useful alarm, but it is not yet evidence that those units
> need one. Finish the R11 remediation, establish the clean baseline, then start ADR-068 —
> and make the falsifier gap its first measured workstream. Put the affected **roots**
> first, not the units. Start at the consequence, decompose downward, and let that analysis
> say whether each leaf needs a theorem, a structural redesign, or a falsifier.

And the reason, which is the premise of this whole record rather than a conclusion it argues
toward:

> The present assurance model cannot distinguish the evidence classes we have been
> discussing. The registry can say *theorem → supported_by → verification unit*. It cannot
> say *proved by Verus*, *structurally established by the representation*, *tested and
> falsified by a mutation probe*, *assumed*, *external boundary*, or *review obligation*.

Two designs are eliminated by that ruling before any work starts.

- **Do not manufacture a mutation probe for every unit that lacks one.** Mutation is the
  falsifier for a *tested* proposition. Attaching one to a proposition whose honest class is
  PROVED or STRUCTURAL buys a green cell and teaches the registry to lie about what kind of
  thing establishes the claim.
- **Do not solve the count before solving the architecture.** How many units genuinely need
  a falsifier is not knowable until the classification exists. §3 measures it under one
  stated assumption and the number is 42, not 80 — but that number is an *estimate produced
  by this record's own proposal*, and it is offered as a cost, not as a worklist.

---

## 2. What was measured, and two corrections to the alarm

Measured on `main` at `3cdfc5ff`, directly from `verification/policy/*.toml`.

| quantity | value |
|---|---|
| review units | 127 |
| theorems | 130 |
| declared system roots | 12 |
| assumption records | 47 |
| `supported_by` edges | 164, **all** of sort `unit://` |
| evidence URIs by scheme | `test://` 131, `mutation://` 48, `verus://` 6, `lean://` 1 |
| unit classes | V0 120, V1 6, V2 1 |
| units with no evidence at all | 0 |

**Correction 1 — the unit count is 79, not 80.** Units carrying no `mutation://` evidence:
**79** of 127. The alarm was raised at 80; one has landed since.

**Correction 2 — "7 of 12 roots" and "3 of 12 roots" are both true, of different
propositions, and the difference matters more than either number.**

- Roots none of whose **directly supporting** units carries a falsifier: **7** — THM-0075,
  THM-0076, THM-0094, THM-0095, THM-0077, THM-0091, THM-0071.
- Roots whose **entire transitive closure** reaches no falsifier at all: **3** — THM-0094,
  THM-0095, THM-0091.

The first is the sharper alarm: it says a root's own top-level support is unfalsified even
where its premises are well exercised. The second says the root is unfalsified *end to end*.
Recording only one of them would be exactly the defect this record exists to fix — a graph
that reads more precisely than the measurement behind it. Both go in the registry views.

The three end-to-end cases are the ones to look at first, and they share a shape: each is a
root with **one** supporting unit and **no** premises.

| root | sole supporting unit | class | files | controls | falsifier |
|---|---|---|---|---|---|
| THM-0094 — the shipped Python SDK accepts only an answer to its own request | `sdk_python.exchange_path` | V0 | 5 | 39 | none |
| THM-0095 — the shipped TypeScript SDK, same claim | `sdk_typescript.exchange_path` | V0 | 6 | 33 | none |
| THM-0091 — the sidecar signs only for a request its ingress policy admitted | `client.local_ingress_authority` | V0 | 7 | 16 | none |

"Undecomposed" is structural, not small: each is **one** V0 unit spanning five to seven
source files with dozens of controls, carrying a **root** promise, with no theorem premises
beneath it and nothing that demonstrates any of its controls can fail. That is the shallow-
authority shape ADR-MCPRE-061 question 2 exists to catch, sitting directly under a system
promise — and for the two SDK members it is the shape the parity finding (#746) already
warned about from the other direction: byte-level fixtures green while the implementations
diverge behaviourally.

THM-0091 is the sharpest illustration of this record's thesis, because **its own statement
names a structural fact**: *possession of the scope IS that permission — there is no other
constructor.* That is a seal, stated in the theorem, and the registry records the whole
claim as `test://`. Under §4 the seal's falsifier is a construction that must not compile,
and no such control exists.

**One further measurement nobody asked for, and it is the largest number in this record.**
**42 of 127 units are not reachable from any declared root** — they support no system
promise. Thirty-three of those also carry no falsifier. That is not necessarily wrong: the
root set is deliberately partial, and an honest local claim nobody has composed yet is a
legitimate thing to hold. But it means *a third of the verification estate is not currently
load-bearing for anything MCP-RE promises*, and no view says so. Phase 1 must report it.

---

## 3. The defect, stated once

> **A security proposition's evidence has a *kind*, and the assurance model has no term for
> it. Every support edge in the registry says the same thing — `unit://` — whether the
> claim underneath is proved by a prover, made unconstructible by a representation,
> exercised by a battery, trusted outright, delegated to an outside owner, or owed a human
> review. Because the kind is unstated, no rule can require the kind to be *adequate* to
> what the claim is used to promise.**

Everything in §5–§8 is an instance of that one defect, and the falsifier gap is its
first symptom rather than a separate problem: *mutation probe absent* is only alarming once you
know the proposition was relying on being TESTED.

### 3.1 The cost of repairing it

Under the rule this record proposes (§9, N1), the obligated set is **every unit reachable
from a Medium-or-higher root, classified TESTED, with no falsifier** — assuming for the
estimate that all 12 declared roots are Medium or above, which §10 does not get to assume in
the implementation.

| | units |
|---|---|
| reachable from some declared root | 85 |
| …with a falsifier | 39 |
| …without a falsifier | 46 |
| …of those, carrying formal (`verus://`/`lean://`) evidence already | 4 |
| **obligated under N1 unless reclassified** | **42** |
| not reachable from any root (no N1 obligation; reported as non-load-bearing) | 42 |

So the true worklist is at most 42, against an alarm of 80, and every one of the 42 has three
legitimate exits: add the falsifier, reclassify to a stronger class and satisfy *that* class's
obligation, or record an owner-approved review obligation that stays visible as debt. That
spread is the whole argument for doing the architecture first.

---

## 4. The six evidence classes, and the falsifier each one takes

This is the substance of the record. Each class is defined by **what establishes it** and by
**what would demonstrate it could fail** — and those differ per class, which is precisely
why one universal "add a mutation probe" rule is wrong.

| class | what establishes the proposition | its falsifier | mechanical obligation |
|---|---|---|---|
| `proved` | a prover discharges a specification over named symbols | **proof-obligation probe**: delete the production property and the prover must report an error | a `verus://`/`lean://` evidence URI, `proved_symbols`, a pinned toolchain identity, and a production carrier — the proved symbol must be on the path the product runs |
| `structural` | the representation admits no illegal inhabitant; possession is the proof | **compile-refusal probe**: the illegal construction must fail to *compile* | a `structural://` evidence URI naming a negative-compilation probe, plus the owning module's privacy boundary |
| `tested` | a named battery exercises the property | **mutation probe**: remove the production property and a named control must fail | a `test://` URI, `tested_symbols`, and — under N1 — a `mutation://` probe naming the production property it attacks |
| `assumed` | nothing. It is trusted | none exists, by construction | an `ASM-NNNN` record whose `justification` names *what would stop making it acceptable* |
| `external` | an owner outside MCP-RE guarantees it | none MCP-RE can run | an `ASM-NNNN` typed `external-boundary` naming the **owner** and the **interface** across which the guarantee is claimed |
| `review-obligation` | a human read it at a stated fingerprint | none | an `ASM-NNNN` typed `review-obligation` with an owner and a discharging **event** (never a date), reported as unresolved assurance debt |

Four notes on the table, each of which is why it is the table and not a different one.

**The `proved` falsifier is not hypothetical here — it has already been run once.** The
THM-0006 presenter-binding note in `theorems.toml` records exactly this measurement: with the
production check removed, *the prover reported 14 verified / 1 error while the unit tests
reported 9 passed / 0 failed*. That single sentence is the strongest evidence in the
repository that falsification is class-specific, because it shows the same deletion being
caught by one class and missed by another. The record makes that measurement a requirement
instead of an anecdote.

**`structural` is the class the repository has been producing for months and cannot say,
and the gap is measurable.** `docs/dev/sealed-owners.md` lists **23** sealed owners — values
where, in the document's own words, *possession is the proof*. Of those, **14** have a
registry unit and **9** have none at all. And every one of the 14 units is **class V0 with
`test://` and `mutation://` evidence and nothing else**: the strongest propositions in the
repository are recorded identically to a behavioural check.

Worse than indistinguishable — **mis-falsified**. The honest falsifier for a seal is not a
mutation probe. Deleting a runtime check from a sealed owner changes nothing, because the
seal is the representation, so a probe that deletes one and watches a control go red is
measuring something other than the seal. What falsifies a seal is a construction that must
not compile, and the repository already knows how to write that control:
`clippy_ratchet_gate.py --activation-probe` compiles a deliberately violating file and fails
the build if the lints stop firing. `structural://` resolves to that lane.

**A `structural://` scheme must ship with its lane, and the existing machinery says why.**
`_evidence.required_lanes` deliberately returns **every** declared scheme rather than the
recognised subset, so an unimplemented `structural://` does not read as a false green — it
resolves to a lane nothing measured, and the unit **refuses issuance**. That is the correct
behaviour and it is also the constraint: declaring the scheme before the lane exists takes
every unit that declares it out of the graph. Phase 0B therefore builds the lane — the
compiler, driven by a negative-compilation probe corpus — before any unit may name it.

**`assumed`, `external` and `review-obligation` are three classes, not one, because they
answer three different questions.** *Will this ever be discharged?* Assumed: no, and that is
accepted. External: not by us. Review obligation: yes, by a named event. Collapsing them —
which is today's state, 47 records with one shape — makes the only question anybody actually
asks unanswerable: **which Critical or High root ultimately rests on something we merely
assume?** An external-boundary premise on a Critical root is a supply-chain statement. An
unresolved review obligation on the same root is a *debt*. They must not read alike.

---

## 5. Gap A — the class is not machine-readable

**Decision A1.** `evidence_class` becomes a **required** field on `[[unit]]`, taking one of
the six values in §4. Unknown value is a validation FAILURE, as every unknown key already is.

**Decision A2 — one unit, one class.** A unit that needs two classes is **two units**. This
is not a new rule; it is the rule `verification.toml` already follows and explains, in the
one place it was forced to: `http_profile.keyid` and `http_profile.keyid_selector` are the
same file split into two units precisely because there are two propositions with two
different trusted bases, and merging them would make the digest assumption a premise of a
derivation claim that does not need it. Evidence class is exactly that situation
generalized.

**The alternative, and why it is refused.** Putting the class on the *support edge*
(`theorem → unit`) would let one unit tell two theorems two different stories about what
supports them. That is flat authority relocated rather than removed — the same move ADR-061
refuses when a composition root grows one wide struct carrying everything. The edge is not
where a unit's evidence lives; the unit is.

**Decision A3 — the class is a declaration checked against the evidence, not derived from
it.** The loader must refuse a unit whose declared class and evidence list disagree:
`proved` without a formal URI, `tested` without `tested_symbols`, `structural` without a
negative-compilation probe. Deriving the class from the URIs instead would mean a unit could
silently *lose* a class by losing an evidence entry, and a silent downgrade is the failure
mode the whole registry exists to prevent.

---

## 6. Gap B — a theorem cannot express what kind of thing supports it

**Measurement correction first.** It is not true that formal proof sits entirely outside the
assurance graph: six units carry `verus://` evidence and one carries `lean://`, and
`[[edge]]` already distinguishes `PROOF_DEPENDENCY` from `COMPILE_DEPENDENCY` and
`CONTRACT_CONSUMES` at the unit layer. The graph knows more than the alarm suggested.

**What is actually missing, precisely.** At the *theorem* layer the sort is lost. A theorem
resting on a proved unit and a theorem resting on a tested-but-unfalsified unit are written
identically — `supported_by = ["unit://x"]` — and **no rule requires the class of the support
to be adequate to the severity of the claim**. Adequacy, not presence, is the defect.

**Decision B1.** `supported_by` entries keep the `unit://` sort. The class is read from the
unit (A1) and surfaced on the edge in every generated view, so a root's decomposition prints
as a *typed* tree:

```
THM-0076  client accepts only an answer to its own request        [HIGH]
  ├── unit://client.proxy_request_correspondence     tested      ⚠ no falsifier
  ├── unit://client.response_acceptance              tested      ⚠ no falsifier
  ├── THM-00xx  request identity injectivity         proved      verus://…
  ├── THM-00xx  response/request binding             structural  structural://…
  └── ASM-00xx  Ed25519 verification                 external    owner: ring
```

**Decision B2 — `supported_by` does not gain an `asm://` sort.** ADR-MCPRE-059 §8 gives the
assumption→unit direction as the single authoritative one, for a measured reason: nine
pairs had diverged when both directions existed, and three units carried theorems whose
premises could be rewritten without the claim deriving DIRTY. The edges this view needs are
**already derivable** through that single direction, and the views derive them today.
Restoring the second direction to make a diagram easier would re-buy a defect that was paid
for once. The premise line in the tree above is derived, not declared.

**Decision B3 — adequacy becomes a conjunct of `ESTABLISHED`, not a parallel concept.**
`theorems.toml` already defines ESTABLISHED as a conjunction: structural support AND fresh
unit evidence AND established dependencies AND fresh specification review AND fresh
assumption review. This record adds one term — **AND class-adequate evidence under N1/N4** —
rather than inventing a second verdict vocabulary beside it.

---

## 7. Gap C — assumptions are untyped

**Measurement correction, in two halves.** The connectivity is not missing.
`[[assumption]].scope` names `unit://` and `boundary://` targets, and
`_catalogue_views.assumption_consumers` already derives, at render time, *scope → unit →
theorem* for all 47 records — storing that direction being exactly what ADR-059 §8.2
forbids.

But it stops at the **directly supported** theorem. Answering *which **root** rests on this
assumption* needs that derivation composed with the `depends_on` closure, and that closure
is already walked, separately, by `_review.root_completeness`. So the honest statement is:
**both halves exist and nothing composes them.** No new edge is required — one derived view
is.

What is genuinely **not** answerable at all is *what kind of assumption*, and that is the
question that actually gates a release.

**Decision C1.** `[[assumption]]` gains a required `class` field: `assumed`,
`external-boundary`, or `review-obligation` — the last three rows of §4.

**Decision C2.** `external-boundary` additionally requires `boundary_owner` (who guarantees
it) and an interface the guarantee is claimed across. "Redis", alone, is not an owner
statement; *what Redis guarantees, across which API, under which configuration* is.

**Decision C3.** `review-obligation` additionally requires a **discharging event**, never a
date, and every such record is reported as open assurance debt in the release view. A review
obligation that nothing can discharge is an assumption wearing a promise, and the release
view is where that has to be visible.

**Decision C4 — no new direction.** C1–C3 add fields to existing records. They do not add
edges, and B2's reasoning governs here too.

---

## 8. Gap D — evidence that runs but nothing claims

Not in the original alarm. Found while working R11 findings against this record's own
thesis, and it is the **mirror image** of the falsifier gap: the falsifier gap is evidence
*claimed but not demonstrated*; this is evidence *demonstrated but not claimed*.

**Measured on `main` at `3cdfc5ff`**, over every `#[test]` / `#[tokio::test]` function
defined in a file some unit lists in `paths`, counting a function as unregistered only when
it appears in **no** unit's `tested_symbols`:

| | count |
|---|---|
| test functions inside declared unit paths | 2146 |
| of those, in no unit's declared battery | **620** |
| units with at least one such function in their own paths | 54 of 127 |

The lane selects `tested_symbols` with `--exact`. A control that is not in that list runs,
passes, and is **not part of any claim's evidence** — delete it and no unit's declared
evidence changes, no fingerprint moves, and nothing goes red.

**Not all 620 are defects, and the number must not be read as a worklist.** A file can sit
in several units' paths, and a test of a local helper is legitimately not a security claim's
evidence. Curation here is careful and reasoned — `proxy.continuation_correlation_store`
annotates each registered symbol with the conjunct it establishes, and that is the standard,
not the exception.

**But the class is real, and here is the worked instance.** `continuation_store/mod.rs`
holds seven test functions. Two are registered under `proxy.continuation_correlation_store`.
The other five were written for R11-348 — `the_first_open_leg_stores`,
`a_second_open_on_a_live_key_is_refused_and_changes_nothing`,
`concurrent_creators_yield_exactly_one_stored`, `an_expired_key_may_be_established_again`,
`a_backing_failure_is_unavailable_and_never_a_collision`. Every one passes in CI.
**None of the five is in any unit's `tested_symbols`.** They establish single-writer establishment
semantics, which is a real security proposition, and it is a proposition *no unit claims and
no theorem names*. The honest reading is not that the list drifted: it is that these controls
answer a question the graph has never been told to ask.

**Decision D1.** Phase 0D reports, per unit, the test functions in its own paths that no
unit registers, and each is dispositioned as **register** (it is this unit's evidence),
**reattribute** (it is another unit's), **new proposition** (it establishes something no unit
claims — the continuation case), or **not evidence** (a local helper's control). The count
is not the deliverable; the dispositions are.

**Decision D2 — no auto-registration, ever.** Bulk-adding 620 symbols to the batteries
nearest them would inflate every unit's apparent evidence without a single new proposition
being stated, and would destroy exactly the per-symbol reasoning that makes the existing
lists worth reading. This is the same refusal as §1's: do not solve the count.

---

## 9. The normative rules

Proposed as binding text. The owner's wording is kept where it was given; N4 and N5 are this
record's additions, and N1's second clause is narrowed from the ruling to match what §4
establishes about class-specific falsification.

> **N1 — Falsifier obligation.** Any proposition classified `tested` whose effective
> consequence severity is Medium, High, or Critical MUST name at least one registered
> falsifier that attacks the proposition's production property and causes one or more of its
> declared controls to fail. Absence of such a falsifier makes the proposition **incomplete**,
> and an incomplete proposition MUST NOT satisfy a root assurance dependency.

> **N2 — No discretionary waiver.** An automated agent or LLM may not waive the falsifier
> requirement. A proposition may avoid it only by being reclassified into another evidence
> class and satisfying that class's mechanically enforced requirements, or by an explicit
> owner-approved `review-obligation` that remains visible as unresolved assurance debt.

> **N3 — Inherited severity.** Falsifier and proof obligations SHALL be computed from the
> highest severity of every root that transitively depends on the proposition, not solely
> from the proposition's local label.

**N3 and §10 are not yet consistent, deliberately.** N3's "not solely from the
proposition's local label" presumes a local label exists and is one input to a maximum.
§10 (S2) proposes there be **no** local label at all, so the inherited value is the only
one. Both readings are defensible and they produce different schemas, so the tension is
left visible for the grill rather than resolved by whoever edits last. If S2 is accepted,
N3's final clause is struck; if it is rejected, S2 is.

> **N4 — Class adequacy.** Every evidence class carries its own falsifier form (§4), and the
> obligation is discharged only in that form. A `mutation://` probe does not discharge a
> `proved` or `structural` obligation, and a `structural://` probe does not discharge a
> `tested` one. A unit whose declared class and declared evidence disagree is a validation
> failure, not a weaker claim.

> **N5 — Typed premises.** Every assumption record carries a class of `assumed`,
> `external-boundary`, or `review-obligation`, and every root's view resolves the typed
> premises its closure depends on. A Critical or High root whose closure reaches an
> `external-boundary` or an open `review-obligation` states that in its own row.

**Implementation note — N1 needs no new walker.** `_review.root_completeness` already
walks each unestablished root's whole `depends_on` closure and reports the nodes that block
it, with a cause. Class-inadequacy becomes **one more blocking cause** in that existing
walk, which is why B3 puts adequacy inside `ESTABLISHED` rather than beside it: the report
that must name the seven roots already knows how to name them.

**The gate fails closed on all five.** A proposition whose class cannot be determined, whose
falsifier cannot be resolved, or whose severity cannot be computed is INCOMPLETE — never
assumed adequate. This is `unknown_is_dirty = true` applied to a sort the registry did not
previously have.

### 9.1 What N1 does to the seven roots

Under N1 the roots in §2 stop reading green. They read:

```
ROOT assurance status: INCOMPLETE
reason: depends on Medium-or-higher TESTED evidence with no registered falsifier
```

That is the intended outcome and the reason the rule is worth the work: it is strictly safer
than the present state, in which the same tree reads as established.

### 9.2 The gate may not satisfy itself

Every control this record adds ships with a mutation probe of its own — remove the
production property the gate claims to check and the gate must go red. The repository has
recorded this failure class three times now (`too-many-lines-threshold` parameterising a
lint nobody enabled; a documented SLO rehearsal with no caller; `--require-root-complete`
with zero invokers), and a classification gate is an unusually easy place to repeat it,
because a gate that reads a declared class can be green about a field nobody filled in
honestly. Each new control also gets a **named required check on the merge path**: presence
in `local_gate.sh` is not enforcement.

---

## 10. Severity: declared on roots, inherited everywhere else

N3 needs a severity to inherit, and the registry has none — no `severity` key exists in any
of the three policy files.

**Decision S1 — severity is declared only on roots.** `root_theorems` becomes a table array
carrying `theorem`, `consequence_severity`, and the rationale for the level. Twelve
declarations, each a security-sensitive change under ADR-059 §21.1.

**Decision S2 — every other proposition's severity is inherited, and there is no local
label to disagree with it.** This is stronger than N3 as given: rather than taking the max of
an inherited and a local severity, there *is* no local severity. A claim's consequence is
whatever the worst promise resting on it would lose, which is a fact about the graph, not an
opinion recordable per row. A local label would be a second representation of one fact and
the two would drift — the same defect §7's `scope` direction was built to avoid.

**Decision S3 — a proposition reachable from no root has no inherited severity and therefore
no N1 obligation, and is reported as supporting no declared promise.** This is the honest
reading and it is also the right incentive: the way to place a claim under obligation is to
declare the root it serves. The 42 currently-unreachable units (§2) surface here rather than
being silently exempt.

---

## 11. Phase plan

Phase 0 is registry and tooling only: **no product claim changes class in Phase 0**, and no
theorem statement is touched. Reclassification (0D) records what is *already* true about
each unit; it does not decide anything about the product.

| phase | what it does | done when |
|---|---|---|
| **0A** | `evidence_class` on `[[unit]]`, the six values, loader validation, class↔evidence agreement (A1–A3) | the loader refuses a disagreeing unit; self-test probe red on removal |
| **0B** | the `structural://` lane: negative-compilation probe corpus + runner, wired as a named required check | a probe that *compiles* fails the lane |
| **0C** | `class` on `[[assumption]]`, plus `boundary_owner` and discharging-event requirements (C1–C3); all 47 typed | zero untyped records; release view lists open review obligations |
| **0D** | reclassify all 127 units honestly against the six classes | every unit classified; the count of `tested`-without-falsifier is measured, not estimated |
| **0E** | severity on the 12 roots (S1), inheritance computed (S2), non-load-bearing units reported (S3) | `review` prints a typed, severity-annotated root tree |
| **1** | examine the 12 roots **consequence-first**, decomposing downward — THM-0094, THM-0095, THM-0091 first, since each is one undecomposed unit with no falsifier | each root has a typed decomposition; each leaf has a named class and a stated obligation |
| **2** | discharge: formalize, structurally redesign, or falsify, per leaf, as Phase 1 assigns | no Medium-or-higher root reads INCOMPLETE without a recorded, owner-approved obligation |

Phase 0E is new to this plan and is not optional: N1 and N3 cannot be evaluated at all until
severity exists, so it blocks Phase 1's ordering.

**The worked example the owner gave, kept as the Phase 1 template.** One root, decomposed
consequence-first, each leaf landing in whatever class is honest for it:

```
ROOT  client accepts only an answer to its own request
  request identity injectivity              proved
  response/request binding type             structural
  wire parser rejects a different request   tested + mutation
  cryptographic library behavior            external
  production composition calls the binding  tested + mutation
```

Five participating leaves; **two** falsifiers. Manufacturing five would be actively wrong.

---

## 12. What Phase 0D will probably find — a heuristic, not a classification

Produced mechanically so Phase 0D starts from something falsifiable rather than from a blank
registry. The rule is crude on purpose: a unit carrying formal evidence is a `proved`
candidate, a unit one of whose paths is a sealed owner is a `structural` candidate,
everything else defaults to `tested`. **It classifies nothing.** A heuristic that reads a
path list cannot know what proposition a unit states, and Phase 0D's job is exactly the
judgement it skips.

| proposed | units | of which load-bearing and unfalsified |
|---|---|---|
| `tested` | 109 | 40 |
| `structural` (candidate) | 11 | 2 |
| `proved` | 7 | 4 |

Two things in that table are worth looking at before anything is decided.

**The `proved` row.** Four of seven units carrying formal evidence are load-bearing and have
no falsifier — and for them a mutation probe was never the right instrument. What N1 asks of
a `proved` unit is the proof-obligation probe of §4, which the repository has run exactly
once, by hand, for THM-0006.

**Eight `structural` candidates carry a `mutation://` probe:**
`proxy.peer_identity_value`, `proxy.certificate_identity`, `proxy.ed25519_public_key`,
`proxy.credential_key_correspondence`, `proxy.delegated_resolver_materialization`,
`proxy.trust_configuration_state`, `proxy.client_credential_window`, `proxy.trust_plan`.
If the seal is what makes the proposition true, then deleting a runtime check cannot falsify
it, and a probe that goes red is measuring a different property from the one the unit
claims. That is not "extra evidence": it is a falsifier pointed at the wrong proposition, and
it is the most likely place for this record's thesis to be WRONG — if those probes turn out
to attack exactly the right thing, `structural` is not the distinct class §14 question 1
suspects it is.

---

## 13. What this record does NOT decide

- **It does not decide any product claim.** No theorem statement, no root set membership, no
  product behaviour. Assurance TCB only.
- **It does not decide which units are reclassified where.** 0D measures; this record
  supplies the vocabulary and the rules for adjudicating disagreement.
- **It does not decide the 12 roots' severities.** S1 says they must be declared and that
  declaring one is security-sensitive. It does not pre-fill them, and the §3.1 estimate
  assumed all twelve are Medium-or-above solely to bound the cost.
- **It does not authorize a falsifier sweep.** N1 creates obligations that Phase 1 assigns
  per leaf. The 42 in §3.1 is a ceiling, not a backlog.
- **It does not reopen ADR-059 §8's single assumption direction** (B2), or §6.3's rule that a
  theorem names no path, symbol, feature, or assumption. Both survive this record intact.

---

## 14. Open questions for the grill

1. **Is `structural` genuinely a distinct class, or is it `proved` with the compiler as the
   prover?** The argument for distinctness is that its falsifier is a compile failure and its
   obligation is a privacy boundary, neither of which resembles a prover run. The argument
   against is that both are "a machine refuses the illegal state" and two classes invite
   boundary arguments about which applies. This record takes distinctness; it is the most
   attackable decision in it.
2. **Does `external` belong in the class table at all, given it is recorded as a typed
   assumption (C1) rather than as unit evidence?** It appears in both because a *unit* can be
   the MCP-RE-side wrapper over an external guarantee. That may be one class too many.
3. **S2 removes local severity entirely.** Is there a real proposition whose consequence
   genuinely exceeds every root that depends on it? If yes, S2 is wrong and N3's max-rule is
   right.
4. **What discharges a `review-obligation` mechanically?** C3 requires an event, not a date,
   but an event is only enforceable if a gate can observe it. Which ones can?
5. **42 units support no declared root.** Is the correct response to declare more roots, to
   retire units, or to accept a large non-load-bearing estate — and does a fourth verdict
   (`NOT-LOAD-BEARING`, distinct from `INCOMPLETE`) need to exist?

---

## Appendix — how §2 and §3.1 were measured

Stated so the numbers can be recomputed and disagreed with, because a record that demands
falsifiability of everything else may not assert its own figures. Measured on `main` at
`3cdfc5ff`, reading `verification/policy/{verification,theorems,assumptions}.toml` only.

**Definitions, exactly as applied.**

- A root's **direct** support is the unit set named by that root theorem's own
  `supported_by`. Nothing below it.
- A root's **closure** is the transitive `depends_on` closure of the root theorem, and the
  union of every `supported_by` unit of every theorem in it.
- A unit **has a falsifier** iff some entry of its `evidence` list begins `mutation://`.
  Nothing else in the registry currently denotes one; `structural://` does not yet exist
  and is proposed by §4.
- A unit is **reachable** iff it appears in the closure of at least one declared root.
- The **obligated set** is: reachable, no falsifier, and carrying no `verus://` or `lean://`
  evidence — the last exclusion because a unit already bearing formal evidence is a
  reclassification candidate under N4 rather than a falsifier candidate.

**The one assumption, and what it costs.** The §3.1 figure of 42 assumes every declared root
is Medium-or-higher. If any root is Low, its exclusively-owned units leave the set. The
figure is therefore a **ceiling**, and it cannot be replaced by a real number until Phase 0E
declares the twelve severities. No work should be scheduled against it.

**What is NOT measured here, and must not be inferred from it.**

- Whether any existing `mutation://` probe actually attacks the production property its
  unit's claim depends on. Presence of a probe is a declaration, and N1 requires a
  *demonstrated* falsifier. Phase 0D re-measures.
- Whether a unit's honest class is `tested` at all. Every count above treats the 127 units
  as tested-by-default because that is the only class the registry can express today. Some
  of the 42 will turn out to be `structural` — the sealed owners especially — and will
  discharge their obligation by reclassification rather than by a probe.
- Whether the 12 declared roots are the right 12. The 42 non-load-bearing units are
  evidence about the root set as much as about the units.

The census is a throwaway script for this record. **Phase 0A lands it in
`tools/verification/` as a first-class tool with its own self-test**, because a number in a
document is a claim and a number a gate recomputes is a measurement — which is the same
distinction this whole record is about.
