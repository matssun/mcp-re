<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-068 — Evidence classes: what kind of thing supports a security claim

**Status:** ✅ **ACCEPTED**, revision 3, ratified 2026-09-17. Phase 0 is a registry and
tooling change; no product claim moves under this record.
**Revision 3** applies the owner's ratification, which granted every §14 item with an exact
resolution and broadened three of them. §1.2 holds the grant; §14 is now the ratification
record rather than a list of open calls.
**Revision 2** applied the owner's four grill rulings and the findings of the Codex/Judge
grill run against revision 1.
**Discussion:** [#967](https://github.com/matssun/mcp-re/discussions/967). The record exceeds
GitHub's 65,536-character body limit, so §13, §14 and the appendix are its first comment
there rather than silently dropped; this file is the whole of it.
**Predecessor:** ADR-MCPRE-059 (discussion #527, rev. 2 = the theorem registry). This record
does **not** supersede it. It adds one missing sort to a model 059 got right in every other
respect, and §6 below *declines* one of the changes that motivated it because 059's existing
rule is better.
**Subordinate:** ADR-MCPRE-069 — *Evidence that runs but nothing claims*
([discussion #968](https://github.com/matssun/mcp-re/discussions/968)). §8 of revision 1
became its own record; see §8 here for why.
**Assurance TCB, not a product claim.** Everything here sits where issue #739 sits: outside
the product theorem roots, inside the layer that decides whether the word `ESTABLISHED` may
be believed. No entry in this record becomes a `THM-`.

---

## 1. The rulings this record starts from

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
  a falsifier is not knowable until the classification exists. §3.1 measures it under one
  stated assumption and the number is 42, not 80 — but that number is an *estimate produced
  by this record's own proposal*, and it is offered as a cost, not as a worklist.

### 1.1 The four grill rulings (revision 2)

Given on revision 1, before the grill ran, and binding on this record:

> **Ruling 1 — severity is not root-only; S2 is rejected.** Two distinct facts exist:
> `direct_consequence_severity(P)`, the worst credible security consequence if P itself is
> false; and `inherited_severity(P)`, the highest severity of every declared root that
> transitively depends on P. `effective_severity(P) = max(direct, inherited)`. For a root,
> its direct consequence severity is the root severity. Make `direct_consequence_severity`
> explicit for every assurance proposition, from the closed vocabulary `none | info | low |
> medium | high | critical`. **Missing may not mean `none`.** `effective_severity` is derived
> only and must never be independently editable.

> **Ruling 2 — separate establishing evidence from non-establishing dependencies.**
> `[[unit]].evidence_class` is `proved | structural | tested | measured`, answering *how does
> MCP-RE establish this proposition?* The other three — `assumed | external-boundary |
> review-obligation` — remain typed dependency records answering *why does this assurance
> chain terminate without MCP-RE establishing the proposition?* Do not create a unit
> classified `external` merely because it wraps an external guarantee: our Redis wrapper
> semantics are TESTED or PROVED, Redis command atomicity is an EXTERNAL BOUNDARY. Keep
> ADR-MCPRE-059's existing assumption→unit authority; add no second theorem→assumption
> authority. Generated root views must surface the typed assumptions transitively.

> **Ruling 3 — STRUCTURAL survives.** The sealed-owner units with existing `mutation://`
> evidence are the first challenge set. For each, determine what the existing probe actually
> falsifies. The structural proposition is discharged only if the hostile construction is
> refused by the representation/API, normally at compile time. A probe that changes
> visibility or construction and then proves hostile construction compiles may already be a
> structural falsifier. A probe that merely deletes a runtime check and turns a behavioural
> test red attacks an adjacent TESTED proposition and does not establish the seal. Do not
> collapse STRUCTURAL into TESTED merely because the mechanism is called a mutation probe.

> **Ruling 4 — restore MEASURED.** A measured proposition must identify its measurement
> protocol, its scope/environment/corpus, its measurement artifact/result, and a
> reproducibility or sensitivity control. It must not be promoted into a universal TESTED or
> PROVED claim, and it does not inherit the TESTED mutation-falsifier rule.

> **Deterministic adequacy.** The gate, not an LLM, decides obligation existence. No
> automated agent may waive the per-class requirements. Reclassification is allowed only by
> satisfying the destination class mechanically. An owner-approved `review-obligation`
> remains visible unresolved assurance debt; it is not equivalent to completed assurance.

Rulings 1–4 settle revision 1's §14 questions 1 (structural is distinct), 2 (external leaves
the unit class table) and 3 (S2 is rejected). What they left open is what the grill resolved.

### 1.2 The ratification (revision 3)

Owner ratification, 2026-09-17, granted on revision 2 *"subject to the following exact
resolutions"*. Every revision-2 §14 item is settled by it, and three are settled by being
made **stricter** than this record proposed rather than by being waved through. The grant, in
the terms it was given:

> **N3 — ACCEPTED, broadened.** Every assurance proposition has
> `direct_consequence_severity`, `inherited_severity` and
> `effective_severity = max(direct, inherited)`. `direct_consequence_severity` is declared;
> the other two are derived and never independently editable. **Root-only severity is
> rejected.**

> **ADR-059 §28.8 jurisdiction.** ADR-MCPRE-059 remains authoritative for ROOT COMPLETENESS
> and for its existing report-only ordinary-development mode versus binding closure/release
> mode. ADR-068 owns EVIDENCE ADEQUACY. A malformed class/schema/evidence declaration is an
> ordinary gate FAIL. An honest unmet assurance obligation is INCOMPLETE, never ESTABLISHED,
> and is tracked/ratcheted where grandfathering is required. An incomplete declared root is
> visible in ordinary review and a binding failure in §28.8 closure/release mode. **Do not
> rewrite §28.8 into an everyday global completeness gate.**

> **Phase 0B carries both schemes.** `structural://` and `measured://` are distinct classes
> with distinct obligations. `structural://`: a closed construction/privacy boundary, a
> hostile illegal construction, and compilation must refuse it. `measured://`: a measurement
> protocol, scope/environment/corpus identity, a result artifact, and a reproducibility or
> sensitivity control. **Neither scheme may satisfy the other's obligation.** No unit may
> declare either scheme before its required lane exists **and fail-closes on zero
> execution**.

> **Non-root-reachable units.** Do NOT manufacture roots to absorb the measured 42. Record
> root reachability as a **graph fact**. A unit not reachable from a declared root may still
> acquire Medium/High/Critical obligations from its direct consequence severity.
> `NOT-ROOT-REACHABLE` therefore means only: *no currently declared system root transitively
> depends on this proposition.* It does not mean low importance, complete assurance, or
> permission to omit evidence. Phase 1 may discover that some reveal missing roots; change
> the root set only for semantic reasons.

> **The assurance debt registry** is accepted only as a **migration ratchet** for
> pre-existing unmet ADR-068 assurance obligations. It is NOT an evidence class, an
> exception, a waiver, or a substitute for a falsifier / proof / structural witness /
> measurement. An entry remains INCOMPLETE. New or materially changed propositions may not
> create new debt entries merely to pass a gate. The register must have a one-way closure
> lifecycle and an exact owning proposition and effective obligation. Do not duplicate
> `assumptions.toml`: `assumed`, `external-boundary` and `review-obligation` remain typed
> premise records there.

> **Sealed-owner witness.** The §12.1 correction is accepted. A sealed owner is structurally
> established **only for the exact invariant for which its construction boundary is closed**.
> Private fields alone are insufficient. The structural witness must account for **every
> producer path relevant to the claimed invariant**, including module-tree visibility,
> alternate constructors, generated/deserialization routes where applicable, and test-only
> construction. The compile-refusal probe attacks that exact boundary.

> **ADR-MCPRE-069** is accepted as subordinate to 068 for the separate Gap-D authority,
> rather than folding that concern back into the evidence-class ADR. Maintain two-way
> cross-reference and no duplicated normative authority.

Each tightening is carried into this record's normative text rather than left in the
quotation: the debt registry's scope (§9.4), the two lanes' zero-execution behaviour (§4.3,
§11), and what a structural witness must account for (§12.1). The jurisdiction resolution is
§9.3.

---

## 2. What was measured, and two corrections to the alarm

Re-measured on the current tree by `tools/verification/evidence-class-census`, directly from
`verification/policy/*.toml`.

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
| registered mutation probes | 180 |

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
| THM-0091 — the sidecar signs only for a request its ingress policy admitted | `client.local_ingress_authority` | V0 | 7 | 16 | none declared |

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

**THM-0091's "none" is a declaration error, not an absence** — see the next correction.

**Correction 3 — the falsifier gap is wrong in BOTH directions, and one direction is free.**
180 probes are registered. They attack **56** units. Only **48** units *declare* a
`mutation://` URI. So eight units are attacked by a probe their own `evidence` list does not
name:

`client.local_ingress_authority`, `proxy.admission_state_source`,
`proxy.audit_record_coordinates`, `proxy.continuation_leg_binding`,
`proxy.continuation_materialization`, `proxy.dispatch_commitment`,
`proxy.outbound_destination`, `proxy.remote_signer_egress_bound`.

Nothing is claimed-but-not-attacked; the error is one-directional. These are **declaration
errors, not obligations** — the evidence exists and the registry omits it — and one of them
is `client.local_ingress_authority`, the sole support of root THM-0091, whose "no closure
falsifier" status in the table above is therefore an artefact of a missing line rather than
a missing control. §11 fixes all eight in 0A, before any backlog is baselined.

**One further measurement nobody asked for, and it is the largest number in this record.**
**42 of 127 units are not reachable from any declared root** — they support no system
promise. Thirty-three of those also carry no falsifier. Under revision 1 that was a reason to
exempt them; under Ruling 1 it is the opposite (§10, S3 struck). It means *a third of the
verification estate is not currently load-bearing for anything MCP-RE promises*, and no view
says so.

---

## 3. The defect, stated once

> **A security proposition's evidence has a *kind*, and the assurance model has no term for
> it. Every support edge in the registry says the same thing — `unit://` — whether the
> claim underneath is proved by a prover, made unconstructible by a representation,
> exercised by a battery, measured over a corpus, trusted outright, delegated to an outside
> owner, or owed a human review. Because the kind is unstated, no rule can require the kind
> to be *adequate* to what the claim is used to promise.**

Everything in §5–§7 is an instance of that one defect, and the falsifier gap is its first
symptom rather than a separate problem: *mutation probe absent* is only alarming once you
know the proposition was relying on being TESTED.

**The defect is not hypothetical and the tree already exhibits it twice, in opposite
classes.** §12 shows `http_profile.verifier_result_separation` producing STRUCTURAL evidence
— hostile constructions refused by the compiler, on the merge path, fingerprint-bound — and
recording it as `test://`. §12.2 shows `conformance.verdict_vocabulary_scope` producing a
MEASURED claim with all four of Ruling 4's required elements already present, and recording
that as `test://` too. Neither is a plan. Both are running today. The vocabulary is what is
missing.

### 3.1 The cost of repairing it

Under the rule this record proposes (§9, N1), the obligated set is **every unit whose
effective severity is Medium or higher, classified TESTED, with no falsifier** — assuming
for the estimate that all 12 declared roots are Medium or above, which §11 does not get to
assume in the implementation.

| | units |
|---|---|
| reachable from some declared root | 85 |
| …with a falsifier | 39 |
| …without a falsifier | 46 |
| …of those, carrying formal (`verus://`/`lean://`) evidence already | 4 |
| **obligated under N1 unless reclassified** | **42** |
| not reachable from any root (no *inherited* term; **not** exempt — §10 S3) | 42 |

So the root-reachable worklist is at most 42, against an alarm of 80, and every one of the 42
has three legitimate exits: add the falsifier, reclassify to another class and satisfy *that*
class's obligation, or record an owner-approved review obligation that stays visible as debt.
That spread is the whole argument for doing the architecture first.

> **MEASURED AT 0E: 63, not 42 — and the difference is the ratification working, not an
> error in the estimate.** The table above counts the ROOT-REACHABLE estate, because that is
> what Ruling 1's literal text obligates. N3 as ratified rejects root-only severity (§14 item
> 1), so a proposition's own `direct` label obligates it whether or not a declared root
> reaches it — which adds the 28 non-root-reachable units the estimate deliberately set
> aside on the line below. The last row already said they are **not** exempt; 0E is where
> that stopped being a note and became a count.
>
> The measured population, from `tools/verification/_assurance_graph.py` over the live
> registries: **63 open obligations — 34 critical, 19 high, 10 medium; 35 of them
> root-reachable, 28 not.** Also measured, and worth its own line because it is what N3 buys:
> **36 propositions owe more than their own label says**, because something that depends on
> them declares more.

**Under Ruling 1 the 42 unreachable units are not a second exempt population.** Their
`effective_severity` is their `direct_consequence_severity`, and whichever of them is
declared Medium or above joins the obligated set. §11's transition (0A's debt baseline)
exists because those two numbers land on the same day.

---

## 4. The classes, and the falsifier each one takes

This is the substance of the record. Ruling 2 splits what revision 1 ran together into one
six-row table, because the two halves answer two different questions and only one of them is
about evidence at all.

### 4.1 Establishing classes — *how does MCP-RE establish this proposition?*

`[[unit]].evidence_class`, one of exactly four. Each is defined by **what establishes it**
and by **what would demonstrate it could fail** — and those differ per class, which is
precisely why one universal "add a mutation probe" rule is wrong.

| class | what establishes the proposition | its falsifier | mechanical obligation |
|---|---|---|---|
| `proved` | a prover discharges a specification over named symbols | **proof-obligation probe**: delete the production property and the prover must report an error | a `verus://`/`lean://` evidence URI, `proved_symbols`, a pinned toolchain identity, and a production carrier — the proved symbol must be on the path the product runs |
| `structural` | the representation admits no illegal inhabitant; possession is the proof | **compile-refusal probe**: the illegal construction must fail to *compile* | a `structural://` URI naming a negative-compilation probe; a **closed** construction/privacy boundary; a **hostile illegal construction** that compilation REFUSES; and an accounting of every producer path relevant to the claimed invariant (§12.1) |
| `tested` | a named battery exercises the property | **mutation probe**: remove the production property and a named control must fail | a `test://` URI, `tested_symbols`, and — under N1 — a `mutation://` probe naming the production property it attacks |
| `measured` | a stated protocol observes a stated corpus or environment | **none of the above.** A measurement's own failure mode is a dead apparatus, not a false proposition | a `measured://` URI plus the four fields the ratification names: `measurement_protocol`, `measurement_scope` (scope/environment/corpus identity), `measurement_artifact` (the result), `measurement_control` (reproducibility **or** sensitivity) |

**Neither scheme may satisfy the other's obligation** (ratification). N4 is where that is
mechanical: a `structural://` probe discharges no `tested` obligation and a `mutation://`
probe discharges no `structural` one, in either direction, whatever lane implementation the
two happen to share underneath.

### 4.2 Premise classes — *why does this chain terminate without MCP-RE establishing it?*

`[[assumption]].premise_class`, one of exactly three. These are **not** evidence and never
appear on a unit.

| class | what it means | will it ever be discharged? | mechanical obligation |
|---|---|---|---|
| `assumed` | nothing establishes it. It is trusted | No, and that is accepted | a `justification` naming *what would stop making it acceptable* |
| `external-boundary` | an owner outside MCP-RE guarantees it | Not by us | `boundary_owner` and the interface the guarantee is claimed across |
| `review-obligation` | a human must read it | Yes, at a named event | a `discharging_event` (§7) and a standing line in the release view as unresolved debt |

**Ruling 2's wrapper rule.** A unit is never classified by the fact that it sits in front of
something external. *Our Redis wrapper semantics* is `tested` or `proved`; *Redis command
atomicity* is an `external-boundary` premise. The unit establishes what it establishes; the
premise records where our establishment stops.

### 4.3 Five notes on the tables, each of which is why they are these tables

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
repository are recorded identically to a behavioural check. §12 measures what those probes
actually attack, and the answer is unanimous.

**`measured` is not a weaker `tested`, and conflating them is the specific error Ruling 4
prevents.** A tested proposition is universal — *no input of this shape is accepted* — and a
mutation probe falsifies it by making the production property absent. A measured proposition
is existential and scoped — *over THIS corpus, on THIS hardware class, the observed value was
X* — and deleting a production property does not make it false, it makes it a measurement of
a different tree. So `measured` takes no mutation falsifier. What it owes instead is an
apparatus control: the demonstration that the measurement can still MOVE. The repository
already ships the worked example — `tools/verification/evidence-class-census`'s own self-test
perturbs a synthetic registry and requires each number to change, and "a figure that cannot
move is not a measurement" is this record's own commit message.

**A new scheme must ship with its lane, and the existing machinery says why.**
`_evidence.required_lanes` deliberately returns **every** declared scheme rather than the
recognised subset, so an unimplemented `structural://` or `measured://` does not read as a
false green — it resolves to a lane nothing measured, and the unit **refuses issuance**. That
is the correct behaviour and it is also the constraint: declaring a scheme before the lane
exists takes every unit that declares it out of the graph. Phase 0B therefore builds **both**
lanes before either scheme may be named (§11).

**The ratification made that binding and added its second half: the lane must also FAIL-CLOSE
ON ZERO EXECUTION.** A runner that selected no probe, found no fixture, or skipped its corpus
may not report PASS, and a unit declaring the scheme with nothing registered against it is a
lane failure rather than a vacuous success. That is this repository's oldest failure class —
`-- --ignored` selecting zero tests and exiting 0 — and a brand-new lane is the easiest place
to reintroduce it, because nobody has a prior expectation of how many probes it should run.
A `structural://` URI whose lane can be green having attempted no hostile construction is a
word that costs nothing.

**`assumed`, `external-boundary` and `review-obligation` are three classes, not one, because
they answer three different questions.** *Will this ever be discharged?* Assumed: no, and
that is accepted. External boundary: not by us. Review obligation: yes, by a named event.
Collapsing them — which is today's state, 47 records with one shape — makes the only question
anybody actually asks unanswerable: **which Critical or High root ultimately rests on
something we merely assume?** An external-boundary premise on a Critical root is a
supply-chain statement. An unresolved review obligation on the same root is a *debt*. They
must not read alike.

---

## 5. Gap A — the class is not machine-readable

**Decision A1.** `evidence_class` becomes a **required** field on `[[unit]]`, taking one of
the four values in §4.1. Unknown value is a validation FAILURE, as every unknown key already
is. The field cannot be called `class`: `[[unit]].class` already means the V0/V1/V2
verification tier.

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
`structural://` probe, `measured` without its four measurement fields. Deriving the class
from the URIs instead would mean a unit could silently *lose* a class by losing an evidence
entry, and a silent downgrade is the failure mode the whole registry exists to prevent.

**Decision A4 — the measured fields.** A unit whose `evidence_class` is `measured` declares
all four, and a unit whose class is anything else declares none of them:

| field | what it names | why the gate needs it |
|---|---|---|
| `measurement_protocol` | the executable protocol — a script or target, never prose | a protocol nobody can run is not a protocol |
| `measurement_scope` | the corpus/environment identity that bounds the claim: hardware class, feature lane, corpus digest | the thing that makes the number mean something, and the thing a reader must not have to infer |
| `measurement_artifact` | where the result record is written | the lane reads this; a measurement with no artifact was not recorded |
| `measurement_control` | the reproducibility or sensitivity control: what perturbation must MOVE the number | `measured`'s analogue of a falsifier, and the only thing a measurement can be independently wrong about |

`measurement_control` is deliberately not called `measurement_sensitivity`: Ruling 4 allows a
reproducibility control *or* a sensitivity control, and the narrower name would exclude half
of what the ruling permits. It is **not** the mutation rule smuggled back in — a mutation
probe falsifies the PROPOSITION, and this falsifies the APPARATUS.

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
as a *typed, severity-annotated* tree:

```
THM-0076  client accepts only an answer to its own request        [HIGH]
  ├── unit://client.proxy_request_correspondence     tested      ⚠ no falsifier
  ├── unit://client.response_acceptance              tested      ⚠ no falsifier
  ├── THM-00xx  request identity injectivity         proved      verus://…
  ├── THM-00xx  response/request binding             structural  structural://…
  └── ASM-00xx  Ed25519 verification                 external-boundary  owner: ring
```

**Decision B2 — `supported_by` does not gain an `asm://` sort.** ADR-MCPRE-059 §8 gives the
assumption→unit direction as the single authoritative one, for a measured reason: nine
pairs had diverged when both directions existed, and three units carried theorems whose
premises could be rewritten without the claim deriving DIRTY. The edges this view needs are
**already derivable** through that single direction, and the views derive them today.
Restoring the second direction to make a diagram easier would re-buy a defect that was paid
for once. The premise line in the tree above is derived, not declared.

**Decision B3 — adequacy becomes a conjunct of `ESTABLISHED`, not a parallel concept — but
only its DYNAMIC half.** `theorems.toml` already defines ESTABLISHED as a conjunction:
structural support AND fresh unit evidence AND established dependencies AND fresh
specification review AND fresh assumption review. This record adds one term — **AND
class-adequate attestation** — rather than inventing a second verdict vocabulary beside it.

Revision 1 stopped there, and §9.3 explains why that was incomplete.

---

## 7. Gap C — premises are untyped

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

What is genuinely **not** answerable at all is *what kind of premise*, and that is the
question that actually gates a release.

**Phase 0C built the composition, and building it measured the estate.** `review` now prints,
per declared root, which typed premises its closure ultimately rests on. The join is derived
at read time from the two existing halves and stored nowhere, because §8.2 forbids storing
the `consumed_by` direction and a second stored authority over reachability would be free to
disagree with the live ones. The first numbers it produced:

| root | assumed | external-boundary | review-obligation |
|---|---:|---:|---:|
| THM-0074 | 11 | 15 | 8 |
| THM-0075 | 10 | 6 | 1 |
| THM-0076 | 10 | 3 | 1 |
| THM-0077 | 6 | 4 | 3 |
| the other eight roots | 0 | 0 | 0 |

**The first version of that join returned zero for all twelve**, because `supported_by` and
`scope` both carry `unit://` URIs and one side was compared bare. An empty composition reads
exactly like a clean tree — *no root rests on any premise* — so its control asserts the count
is non-zero rather than only that the function runs.

**Decision C1.** `[[assumption]]` gains a required **`premise_class`** field: `assumed`,
`external-boundary`, or `review-obligation` — §4.2. The field is *not* named `class`: that
key already carries the V0/V1/V2 vocabulary on `[[unit]]`, and one key name holding two
unrelated closed vocabularies in two registries loaded by one loader is precisely the
collision A1 avoided on the other side. `premise_class` takes its name from N5, "Typed
premises".

**Decision C2.** `external-boundary` additionally requires `boundary_owner` (who guarantees
it) and an interface the guarantee is claimed across. "Redis", alone, is not an owner
statement; *what Redis guarantees, across which API, under which configuration* is.

**Decision C3 — the discharging event is a tagged, closed predicate, never prose.**
`review-obligation` additionally requires `discharging_event`, and its value is a tagged
record from a closed set of kinds with typed operands — not an English sentence. The 47
existing `review_requirement` strings already contain three genuinely different kinds of
trigger, and all three are expressible:

| kind | observable by the gate over | worked instance from today's registry |
|---|---|---|
| `registry-fact` | the three policy TOMLs | "discharge if vstd gains a specification for it" → `{ kind = "registry-fact", predicate = "unit-has-evidence-scheme", unit = "…", scheme = "verus" }` |
| `tree-fact` | the source tree at the current fingerprint | "any change to `parse_fixed_digits` or its callers" → `{ kind = "tree-fact", predicate = "site-absent", site = "…#parse_fixed_digits" }` |
| `owner-event` | **nothing.** This is the honest residue | "replace with a proof if a theorem ever concerns Display output" |

**Decision C4 — an observable event that has come TRUE while the record still exists is a
gate FAIL**, cause `STALE_REVIEW_OBLIGATION`. Not a pass, and not a silent discharge. The
registry would be asserting debt the tree says is paid, which is the identical stale-record
defect `_evidence.write_bundle` records for the evidence bundle: *"the bundle describes the
last run, not the last successful one"* — a record that outlives the state it describes makes
the tree look measured when it is not. Discharge is a registry EDIT, owner-reviewed like
every other security-sensitive change; the gate's job is not to notice discharge, it is to
make the debt impossible to stop seeing.

For `owner-event`, the gate never tries to decide whether the event happened. It reports the
obligation as open, against every root whose closure reaches it, with that root's effective
severity beside it (N5).

**Decision C5 — `discharging_event` sits beside `review_requirement`, not in place of it.**
`review_requirement` remains the human review rule — *who must review a change to it* — which
is a different fact from *what would discharge it*. The discharge condition migrates out of
the prose into the typed field, and **the gate ignores prose for discharge**.

**Decision C6 — no new direction.** C1–C5 add fields to existing records. They do not add
edges, and B2's reasoning governs here too.

---

## 8. Gap D — evidence that runs but nothing claims (moved to ADR-MCPRE-069, #968)

Revision 1 carried this as a section. It is now its own record, and the reason is that it is
not the same defect.

**The measurement stays here, because it was taken here.** Over every `#[test]` /
`#[tokio::test]` function defined in a file some unit lists in `paths`, counting a function
as unregistered only when it appears in **no** unit's `tested_symbols`:

| | count |
|---|---|
| test functions inside declared unit paths | 2168 |
| of those, in no unit's declared battery | **626** |
| units with at least one such function in their own paths | 54 of 127 |

The lane selects `tested_symbols` with `--exact`. A control that is not in that list runs,
passes, and is **not part of any claim's evidence** — delete it and no unit's declared
evidence changes, no fingerprint moves, and nothing goes red.

**Why it is a separate record.** It is the *mirror image* of this one. The falsifier gap is
evidence **claimed but not demonstrated**; Gap D is evidence **demonstrated but not
claimed**. Concretely:

- It is not about evidence *kind*. Every one of the 626 is `tested`; no amount of
  classification addresses them.
- Its deliverable is a different type of thing. This record's deliverables are a schema, a
  loader, two lanes and a gate. Gap D's deliverable is 626 **per-symbol dispositions**.
- One of those dispositions — *new proposition* — **creates theorems**, and §13 of this
  record says in terms that it decides no product claim. The worked instance proves it: five
  R11-348 controls in `continuation_store/mod.rs` establish single-writer establishment
  semantics, "a proposition no unit claims and no theorem names". Acting on that means
  writing a theorem.
- It has no dependency on this record landing. The 626 are discoverable and dispositionable
  against the registry as it stands today.

**And ADR-069 must widen the census this record took.** The figure above counts only
`#[test]` and `#[tokio::test]`, which makes it structurally blind to `compile_fail` doctests
— and there are unregistered ones, at `mcp-re-client-core/src/delegated_trust/mod.rs:52` and
`:63`, each a hostile construction that must not compile and that no unit claims. They are
exactly Gap D's subject and this record's census would never have found them. See §12.1 for
why that blind spot matters twice over.

---

## 9. The normative rules

Proposed as binding text. The owner's wording is kept where it was given; N4 and N5 are this
record's additions.

> **N1 — Falsifier obligation.** Any proposition classified `tested` whose effective
> consequence severity is Medium, High, or Critical MUST name at least one registered
> falsifier that attacks the proposition's production property and causes one or more of its
> declared controls to fail. Absence of such a falsifier makes the proposition **incomplete**,
> and an incomplete proposition MUST NOT satisfy a root assurance dependency.

> **N2 — No discretionary waiver.** An automated agent or LLM may not waive the falsifier
> requirement. A proposition may avoid it only by being reclassified into another evidence
> class and satisfying that class's mechanically enforced requirements, or by an explicit
> owner-approved `review-obligation` that remains visible as unresolved assurance debt.

> **N3 — Inherited severity.** Falsifier and proof obligations SHALL be computed from
> `effective_severity(P) = max(direct_consequence_severity(P), inherited_severity(P))`, where
> `inherited_severity(P) = max(effective_severity(Q))` over every assurance proposition Q
> that directly depends on P — theorem→theorem through `depends_on`, theorem→unit through
> `supported_by`. `effective_severity` and `inherited_severity` are DERIVED and are never
> stored or independently editable.

**N3 generalizes Ruling 1's text, and the ratification ACCEPTED the broadening (§14 item 1,
in the owner's words "ACCEPTED, broadened", with root-only severity explicitly rejected).**
The ruling says
"every declared root that transitively depends on P". Read literally, only roots contribute,
so a unit supporting an intermediate theorem declared `critical` inherits nothing from it
unless a root above is also critical. That silently drops the intermediate theorem's own
declared consequence — the same hole Ruling 1 was written to close, one layer down. Under the
general form a root's severity still reaches every unit beneath it, because
`effective(root) >= direct(root)` and the maximum propagates through the whole closure, so
Ruling 1's stated behaviour is a *consequence* of N3 rather than a special case excluded by
it. The cycle hazard the general form would introduce does not exist: `depends_on` cycles are
already refused by `_theorems._check_acyclic`, and severity derivation reuses that same
acyclic graph. Any future proposition-edge kind must be cycle-checked *before* severity is
computed.

> **N4 — Class adequacy.** Every evidence class carries its own falsifier form (§4.1), and
> the obligation is discharged only in that form. A `mutation://` probe does not discharge a
> `proved` or `structural` obligation, a `structural://` probe does not discharge a `tested`
> one, and `measured` takes no mutation obligation at all. A unit whose declared class and
> declared evidence disagree is a validation failure, not a weaker claim.

> **N5 — Typed premises.** Every assumption record carries a `premise_class` of `assumed`,
> `external-boundary`, or `review-obligation`, and every root's view resolves the typed
> premises its closure depends on. A Critical or High root whose closure reaches an
> `external-boundary` or an open `review-obligation` states that in its own row.

### 9.1 What N1 does to the seven roots

Under N1 the roots in §2 stop reading green. They read:

```
ROOT assurance status: INCOMPLETE
reason: depends on Medium-or-higher TESTED evidence with no registered falsifier
```

That is the intended outcome and the reason the rule is worth the work: it is strictly safer
than the present state, in which the same tree reads as established.

### 9.2 The gate may not satisfy itself

Every control this record adds ships with a probe of its own — remove the production property
the gate claims to check and the gate must go red. The repository has recorded this failure
class three times now (`too-many-lines-threshold` parameterising a lint nobody enabled; a
documented SLO rehearsal with no caller; `--require-root-complete` with zero invokers), and a
classification gate is an unusually easy place to repeat it, because a gate that reads a
declared class can be green about a field nobody filled in honestly. Each new control also
gets a **named required check on the merge path**: presence in `local_gate.sh` is not
enforcement.

**§12.1 is a fourth instance of the same class, found by this grill**, and it is the reason
that rule is restated here rather than assumed: `docs/dev/sealed-owners.md` argues that
`cargo check --all-targets` passing *is* the witness for an in-crate seal. It is not. It
cannot go red when the seal is deleted, because nothing in the tree attempts the
construction.

### 9.3 Registry adequacy fails the merge; attestation adequacy subtracts ESTABLISHED

Revision 1 said adequacy "becomes one more blocking cause" in `_review.root_completeness`.
That is true of half of it and false of the other half, and the halves have opposite
dispositions:

- `_review.theorem_assurance` is *"the one place the word established is earned"*, and
  B3's conjunct belongs there.
- `_review.root_completeness` carries an explicit standing ruling in its own docstring:
  *"an honest unresolved GAP must not fail ordinary CI (§28.8): a gate that punishes
  recording an obligation teaches people not to record it."*
- `_evidence.decide_issuance` is fail-closed and REFUSES outright.

So "the gate decides obligation existence" needs a line, and it is this one:

> **Declaring a class you do not satisfy is a lie, and is fatal. Failing to have run the
> evidence yet is debt, and is visible.**

**REGISTRY ADEQUACY — merge-fatal, in the loader, always.** Computable from the three TOMLs
alone: a missing or unknown `evidence_class`; a missing `direct_consequence_severity`;
`proved` without a formal URI, a pinned toolchain or a production carrier; `structural`
without a `structural://` probe or without a named owning privacy boundary; `tested` without
`tested_symbols`; `measured` without its four fields; any unit whose `effective_severity` is
Medium or higher and whose class is `tested` with no registered `mutation://` falsifier. A
unit that cannot state its own class adequately is MALFORMED, and malformed has always been
fatal here — `unknown_is_dirty = true` is not optional and cannot be edited away.

**The last of those clauses activates later than the rest**, because it is the only one that
needs a derived value. `effective_severity` does not exist until 0E builds N3's derivation,
so 0A enforces the severity-independent checks and 0E switches on the falsifier clause
against a debt baseline generated in the same commit (§11.1). Splitting the rule across two
phases is not a weakening of it: every clause is merge-fatal from the moment its inputs
exist, and none is ever advisory.

**ATTESTATION ADEQUACY — not merge-fatal.** The declared falsifier exists but its lane
FAILED, or was measured at the wrong fingerprint, or has not run. This subtracts
`ESTABLISHED` in `theorem_assurance` and prints as a blocking cause in `root_completeness`.
§28.8 governs here and is right: this is the campaign-in-progress state.

N1's "an incomplete proposition MUST NOT satisfy a root assurance dependency" is implemented
by the second. The owner's "the gate decides obligation existence" is implemented by the
first — because the obligation's **existence** is a static fact about class and severity,
even though its **discharge** is dynamic.

**The jurisdiction is RATIFIED, and it is a split of authority rather than a relaxation of
§28.8 (§14 item 2).** ADR-MCPRE-059 remains authoritative for **root completeness** and for
its existing report-only ordinary-development mode versus binding closure/release mode.
ADR-068 owns **evidence adequacy**. The owner's mapping, which is the operative text:

```text
malformed class/schema/evidence declaration
    -> ordinary gate FAIL

honest unmet assurance obligation
    -> INCOMPLETE
    -> never ESTABLISHED
    -> tracked/ratcheted where grandfathering is required

incomplete declared root
    -> visible in ordinary review
    -> binding failure in §28.8 closure/release mode
```

**Do not rewrite §28.8 into an everyday global completeness gate.** The temptation is real
and it is the failure mode §28.8 was written against: once `root_completeness` can see an
adequacy verdict, making it merge-fatal everywhere looks like rigour and is actually the
gate that punishes recording an obligation. What became merge-fatal is exactly one thing —
a declaration that is malformed — and a declaration is malformed when it cannot be
reconciled with the record it sits in, never because the work behind it is unfinished.

**Where the severity walk lives.** Not in `_manifest.py`. Registry adequacy needs
`effective_severity`, which needs a graph closure, and burying a graph walk in the loader
would make the loader own a fact it should be handed. A shared pure derivation layer —
`tools/verification/_assurance_graph.py` — is used by both loader validation and `_review`,
so the two can never compute different severities for one proposition.

### 9.4 Two ratchets, because there are two invariants

**The class-transition ratchet.** A downgrade from `proved` to `tested` passes registry
adequacy trivially — delete the formal URI, delete the class, and nothing notices the claim
got weaker. That is the silent downgrade A3 names. The ratchet compares `evidence_class`
against `origin/main` and refuses any change not accompanied by an explicit reclassification
record naming `unit`, `from_evidence_class` and `to_evidence_class`, with the destination
class's mechanics satisfied by the loader. It is **not** a waiver: if destination adequacy
fails, the merge still fails.

It is deliberately **not a total order**. `proved > structural > tested > measured` is the
wrong shape — the four are incomparable establishment modes, not strength tiers, and a
`structural` proposition is not a weaker `proved` one. The ratchet constrains *unrecorded
change*, not *direction*.

**The obligation-backlog ratchet, `config/assurance-obligation-debt.toml`.** §11 explains
why it must exist. It takes the shape the repository already uses for
`config/module-size-debt.toml` and `config/clippy-debt.toml`: a baseline at a named SHA, the
three states `unreviewed` / `reviewed-action-required` / `reviewed-exception`, a `review_ref`
on both reviewed states, no return to `unreviewed`, and a registry that may only shrink. A
new over-bar obligation fails immediately. A stale row whose obligation is now discharged
fails until removed.

**The ratification narrowed what that registry may hold, and the narrowing is the point.**
`config/assurance-obligation-debt.toml` is accepted **only as a migration ratchet for
pre-existing unmet ADR-068 assurance obligations** — the residue 0E measures against a tree
that predates the rule. It is explicitly **not** an evidence class, not an exception, not a
waiver, and not a substitute for a falsifier, a proof, a structural witness or a
measurement. Four consequences, each mechanical:

- **An entry remains INCOMPLETE.** A row never subtracts from the obligation and never adds
  to the assurance; it records that a known obligation is open and bounds the population.
- **A new or materially changed proposition may not create a new debt entry.** The registry
  is closed to anything whose obligation did not exist at the baseline. A unit that gains an
  obligation by being added, reclassified, or raised in severity discharges it or fails; the
  migration ratchet is not a route new work may take.
- **The lifecycle is one-way.** A row closes and never reopens, in the same sense
  `module-size-debt.toml` never returns to `unreviewed`.
- **Each row names its exact owning proposition and effective obligation.** Not a file, not a
  campaign — the proposition the obligation belongs to and the obligation itself, or the
  registry cannot say what closing the row would mean.

**SUCCESSION — the one way the registry's row count may rise, added in Phase 1 because
Phase 1 could not otherwise start.** Phase 1 decomposes a root's one wide proposition into
the narrow propositions it was always the conjunction of. A wide `tested` unit that OWED a
falsifier becomes several narrow `tested` units that owe one each, and under the rules above
that is indistinguishable from new work: the predecessor's row goes dead, and every
successor is an unregistered owing unit. The ratchet built to stop obligations *appearing*
would have been stopping them from being *stated more precisely* — and a registry that makes
a decomposition impossible has stopped bounding a population and started protecting a
granularity.

So a row may carry `succeeds` and `decomposition_ref`, and `scripts/assurance_obligation_gate.py`
requires five things together: the predecessor is a row in the BASE registry; it is gone from
both the registry and the measured population; every successor's effective severity is at
most the predecessor's; every successor unit's `paths` are a SUBSET of the predecessor's at
the base; and `decomposition_ref` names a file the tree holds. A malformed succession does
not also buy growth — the row is excused from the shrink-only rule only if it survives every
clause.

**One authorization buys one transition**, by the mechanism `config/module-size-debt.toml`'s
`growth_ref` uses: after merge the predecessor is no longer in the base registry, so a later
row naming it matches nothing. And succession **discharges nothing** — successor rows are
ordinary open obligations, INCOMPLETE like every other row, bounding the same production code
measured more finely. What may not ride one is new production code: that is what the path
subset clause is for.

**And it does not duplicate `assumptions.toml`.** `assumed`, `external-boundary` and
`review-obligation` remain typed premise records there (§7). A premise says *why this chain
terminates without MCP-RE establishing the proposition*; a debt row says *MCP-RE owes this
establishment and has not yet produced it*. Recording one as the other is how a permanent
premise and a temporary backlog become indistinguishable — which is the exact defect §4.2
exists to fix, reintroduced one layer over.

**No row in either registry is ever evidence.** Neither counts as an attestation, as FRESH,
or as ESTABLISHED. Both are visible unresolved assurance debt, which is the only thing N2
permits them to be.

---

## 10. Severity: declared locally, inherited everywhere, derived nowhere twice

N3 needs a severity to compute with, and the registry has none — no `severity` key exists in
any of the three policy files.

**Decision S1 — `direct_consequence_severity` is required on `[[theorem]]` and `[[unit]]`.**
Both are propositions: a theorem states one, and A2's "one unit, one class" means a unit does
too. Vocabulary: `none | info | low | medium | high | critical`. Missing is a validation
failure and never means `none`.

*Revision 1's S1 — turning `root_theorems` into a table array carrying
`consequence_severity` — is **STRUCK**.* Ruling 1 says a root's direct consequence severity
IS the root severity, so the root theorem's own field already holds it, and a second copy on
the root entry is the exact duplicated authority `_theorems.py` rejects by name for `root`,
`is_root` and `root_claim`. `root_theorems` stays a flat list of ids. The rationale the old
S1 wanted to carry belongs in the theorem's existing prose `security_consequence`, beside the
label it justifies.

**Decision S2 — `[[assumption]]` carries NO direct severity.** A premise is by construction
not established by MCP-RE, so *what is lost if it is false* is entirely a fact about what
rests on it. A direct label there would own no independent fact; it would restate downstream
graph impact, and the two would drift. An assumption's severity in every view is inherited.

*Revision 1's S2 — no local severity anywhere — is **REJECTED by Ruling 1**.*

**Decision S3 — a theorem's and its unit's direct severities are not two copies of one
fact.** `direct(t)` is what is lost if that proposition is false; `direct(u)` is what is lost
if that unit's claim is false. A unit may be worth *less* than a theorem it partly supports
(it is one of several supports) or *more* (it is load-bearing beyond that theorem). They
never need to agree, so there is no single fact for them to disagree about. What **would** be
duplicated authority is a stored `effective_severity` or `inherited_severity` — which N3
forbids.

**Decision S4 — a proposition reachable from no root has `effective_severity = direct`, and
is under the full obligation of its class at that severity.** Root-reachability changes only
the *inherited* term. It grants no exemption.

*Revision 1's S3 — "no inherited severity and therefore no N1 obligation" — is **STRUCK**.*
It exempted the 42 unreachable units, and Ruling 1 exists precisely to stop that: *"this
preserves severity for propositions not yet reachable from a declared root, which the Phase-0
census has shown is currently a material set."*

**Decision S5 — no fourth root verdict; root reachability is a derived GRAPH FACT.**
`COMPLETE` / `INCOMPLETE` / `UNDECLARED` are verdicts about the **declared root set**; a unit
no root reaches is not a fact about that set, and adding a fourth member to that enum would
make the root verdict answer a question it is not about. Instead reachability is **derived**
per unit in the generated views — never stored — and reported beside each unit's
`direct_consequence_severity`, so the honest and alarming reading is printable:

> *N units of direct consequence severity HIGH or CRITICAL support no declared system
> promise.*

**The ratification named the fact and bounded what it may be read to mean**, and the name it
gave is the one this record now uses. Revision 2 called the derived boolean `load_bearing`;
that word carries an importance claim the ratification explicitly forbids, so the derived
fact is `root_reachable` and the reported token is:

> **`NOT-ROOT-REACHABLE`** — *no currently declared system root transitively depends on this
> proposition.* **Nothing else.** Not low importance, not complete assurance, and not
> permission to omit evidence.

Three things follow, and S4 is the first of them stated in the ratification's own terms:

- **A non-reachable unit still carries the full obligation of its class** at
  `effective_severity = direct_consequence_severity`. Medium, High and Critical obligations
  arise from the direct label alone; reachability changes only the *inherited* term.
- **Do NOT manufacture roots to absorb the measured 42.** A root declared in order to make a
  reachability report look better is a product claim invented for a tooling reason, and it
  would put the assurance TCB in the business of writing promises.
- **Phase 1 may discover that some of the 42 reveal a genuinely missing root**, and then the
  root set changes — for that semantic reason and no other.

---

## 11. Phase plan

Phase 0 is registry and tooling only: **no product claim changes class in Phase 0**, and no
theorem statement is touched. Reclassification (0D) records what the evidence already
supports; it does not decide anything about the product. §11.1.1 is precise about what
"already" means, because it is not "what the unit really is" — it is what the unit's declared
evidence establishes at the moment it is read.

| phase | what it does | done when |
|---|---|---|
| **0A** | **schema event 1 and its activation.** `evidence_class` and `direct_consequence_severity` required on `[[unit]]`, `direct_consequence_severity` required on `[[theorem]]`, both populated; the loader enforces presence, vocabulary and class↔evidence agreement; the eight declaration repairs; the census moved to `tools/verification/` | the loader refuses a disagreeing unit; every self-test probe red on removal; the estate is re-attested at the new fingerprints |
| **0B** | the two new lanes: `structural://` (both probe kinds, §12.1) and `measured://`, each wired as a named required check and each **fail-closed on zero execution**. **No registry change** | a structural probe that *compiles* fails the lane; a measurement whose apparatus cannot move fails the lane; a lane that selected nothing reports neither PASS nor a silent skip |
| **0C** | **schema event 2 and its activation.** `premise_class` on `[[assumption]]`, plus `boundary_owner` and `discharging_event` (C1–C5); all 47 typed | zero untyped records; release view lists open review obligations; a satisfied observable event fails until its record is removed |
| | *landed:* 21 external-boundary, 12 assumed, 10 review-obligation, 4 withdrawn and deliberately untyped; the loader refuses an untyped live record and a typed withdrawn one; `check-assumptions` fails on `STALE_REVIEW_OBLIGATION`; `review` prints the root→premise composition and the open obligations | |
| **0D** | reclassify to `structural` and `measured` where that is now declarable, sealed-owner challenge set first (§12); the composite splits; every transition through the class-transition ratchet. Carries the THIRD re-attestation: the probe entries and lane identities become fingerprint components, which is an encoding bump | every unit's class matches the evidence it declares; the count of `tested`-without-falsifier is measured, not estimated |
| | *0D-1 landed:* encoding 8 → 9 with four new components; `scripts/evidence_class_ratchet.py` + `config/evidence-class-transitions.toml`; §12's two worked units reclassified — `http_profile.verifier_result_separation` to `structural` and `conformance.verdict_vocabulary_scope` to `measured`, each dropping the battery its class no longer names. Classes now: 118 tested, 7 proved, 1 structural, 1 measured | |
| | *0D-3 landed:* the FIRST composite split. `proxy.client_credential_window` narrowed to its predicate proposition (`new` refuses an illegal pair — M113–M115 keep attacking it, untouched), and `proxy.client_credential_window_sole_producer` added as a `structural` unit carrying S04. THM-0102 is `supported_by` BOTH, because "cannot be represented" needs the refusal and the absence of another producer. Not a transition — no unit's class moved; a proposition that had no unit acquired one. Classes now: 118 tested, 7 proved, 2 structural, 1 measured, of 128 units | |
| | *0D-4 landed:* the second split, `proxy.delegated_resolver_materialization` — the clearer case, because the sole-producer claim was already written in a registry comment and in THM-0027's scope, discharged there by NAMING the routes. `proxy.delegated_resolver_materialization_sole_producer` added (`structural`, critical) with probe **S06**, `E0451` from a sibling module inside `delegated_tls`; THM-0027 `supported_by` both. Measured: with all three fields opened, 6/6 behavioural tests green and S06 FAIL. Classes now: 118 tested, 7 proved, 3 structural, 1 measured, of 129 units | |
| | *0D-5 landed:* the third split, `proxy.ed25519_public_key` — and the one where the seal is NOT a refusal. Every `[u8; 32]` is a legal point, so the second constructor `for_point` is TOTAL; the invariant is the canonical RFC 8410 ENCODING rather than a predicate over the bytes, and a probe asserting one-way-in would state something false. `proxy.ed25519_public_key_sole_producer` added (`structural`, critical) with probe **S07**, which attacks where the bytes may be PLACED — its hostile value is a legal key. THM-0025 `supported_by` both. Measured: field opened, 7/7 tests green, S07 FAIL. Classes now: 118 tested, 7 proved, 4 structural, 1 measured, of 130 units | |
| | *0D-6 landed:* the fourth split, `proxy.peer_identity_value` — where the quantifier was written down THREE times (the struct doc, the unit description, and THM-0023's own STATEMENT: "no sequence of operations available to a caller produces an inhabitant that violates it") and attacked by nothing. `proxy.peer_identity_value_sole_producer` added (`structural`, medium) with probe **S08**. THM-0023 `supported_by` both. Measured: field opened, 5/5 tests green, S08 FAIL. Classes now: 118 tested, 7 proved, 5 structural, 1 measured, of 131 units | |
| | *0D-7 landed:* the fifth split, `proxy.credential_key_correspondence` — the first whose proposition spans THREE boundaries, so the claim is worded as that conjunction and three probes attack it: **S10** a credential key nobody read out of a credential, **S11** a signer key no signer exported, **S09** the fact value itself, which is also `DelegatedCertResolver`'s `_correspondence` witness. `proxy.credential_key_correspondence_sole_producer` added (`structural`, critical); THM-0026 `supported_by` both. Measured: all three fields opened, 22/22 tests green (including the eleven cross-machine ones in `tls.rs`), all three probes FAIL. Classes now: 118 tested, 7 proved, 6 structural, 1 measured, of 132 units | |
| | *0D-8 landed:* the sixth split, `proxy.certificate_identity` — and the FIRST whose structural unit is not a sole-producer one. `new` is `pub(super)` by the owner's deliberate argument, so the claim is worded to the set that visibility admits (`communication_assurance` and its descendants) and the probes are injected at the CRATE ROOT: **S12** the constructor (`E0624`), **S13** the struct literal (`E0451`, refused even inside the authority). `proxy.certificate_identity_authority_boundary` added (`structural`, critical); THM-0024 `supported_by` both. Measured: `new` and both fields opened, 26/26 tests green, both probes FAIL. The lane also refused my own first draft of S13 as a MEASUREMENT FAILURE (`expected E0451 … saw ['E0599']`) rather than reading a typo as a seal. Classes now: 118 tested, 7 proved, 7 structural, 1 measured, of 133 units | |
| | *0D-9 landed:* the seventh split, `proxy.trust_plan` — a THIRD shape of structural claim. `from_validated` is TOTAL and refuses nothing; the whole security content of its signature is the single `&ValidatedDeployment` parameter, so the seal is CO-PROVENANCE: separately legal parts cannot be combined by a caller. `proxy.trust_plan_co_provenance` added (`structural`, medium) with probe **S14**; THM-0036 `supported_by` both. Measured: all four fields opened, 4/4 tests green, S14 FAIL. Classes now: 118 tested, 7 proved, 8 structural, 1 measured, of 134 units | |
| | *0D-10 landed:* the eighth split, `proxy.trust_configuration_state` — two owners, one proposition. **S16**'s hostile value is the EXACT inhabitant `new` excludes (the empty locator); **S15** is the case where two layers of privacy meet and only one is the claim — `kind` is bare-private AND its enum type is private, so the probe supplies `todo!()` rather than naming a variant, because naming one would be refused by E0603 for the TYPE's privacy and the lane would report a refusal about a boundary this unit does not claim. `proxy.trust_configuration_state_sole_producer` added (`structural`, high); both supporting theorems `supported_by` it. Measured: both fields opened, 15/15 tests green, both probes FAIL. Classes now: 118 tested, 7 proved, 9 structural, 1 measured, of 135 units | |
| | *0D-11 landed:* the ninth split, `proxy.custody_exposure` — whose own comment above its private `CustodyKind` states this record's thesis outright: "`pub` variants would let any of them assemble a custody state whose material no validator saw". `proxy.custody_exposure_sole_producer` added (`structural`, critical) with probe **S17**, attacking the FIELD as S15 does since the enum is private too. Measured: field opened, 13/13 tests green, S17 FAIL. NOTED, not fixed: the `tested` half carries no `mutation://` evidence — a pre-existing N1 gap the census counts, and 0E's business. Classes now: 118 tested, 7 proved, 10 structural, 1 measured, of 136 units | |
| | *0D-12 landed:* the tenth split, `proxy.continuation_materialization` — where sealing the STATE does not seal the PLAN. **S18** attacks `ContinuationControlState`; **S19** attacks `ContinuationControlPlan`, the value consumers actually read, whose `store: None` a caller could use to assert single-replica resolution WITHOUT touching the state it projects. `proxy.continuation_materialization_sole_producer` added (`structural`, high); the theorem's `supported_by` gains it beside its three existing units. Measured: both fields opened, 15/15 tests green, both probes FAIL. The lane refused S19's first draft as a MEASUREMENT FAILURE (`saw ['E0432']`, an unresolved import) — the second probe defect the error-code rule has caught. Classes now: 118 tested, 7 proved, 11 structural, 1 measured, of 137 units | |
| | *0D-13 landed — the campaign COMPLETE:* the eleventh and last unit-backed split, `proxy.admission_configuration_state`. **S20** the state, **S21** the six-field `EnforcedAdmission` view whose EXISTENCE is the enforcement fact (`enforced()` returns `None` otherwise). `proxy.admission_configuration_state_sole_producer` added (`structural`, high); no theorem owns either half, so both are `NOT-ROOT-REACHABLE` — which per Ruling 4 means only that no declared root depends on them. Measured: all seven fields opened, 8/8 tests green, both probes FAIL. **All 11 unit-backed sealed owners are now split, 21 structural probes live against 0B's five, and across the eleven the batteries stayed green 129 times out of 129 with the boundary open.** Classes now: 118 tested, 7 proved, 12 structural, 1 measured, of 138 units | |
| **0E** | `tools/verification/_assurance_graph.py`; `inherited_severity` and `effective_severity` derived (N3); N1's severity-gated obligation ACTIVATES; `config/assurance-obligation-debt.toml` baselined as a migration ratchet; `NOT-ROOT-REACHABLE` units reported (S5) | `review` prints a typed, severity-annotated root tree; the debt registry holds the real residue and may only shrink |
| | *0E landed:* `tools/verification/_assurance_graph.py` — N3's derivation, pure, read by BOTH the loader path and `review` so the two can never disagree. N1's severity-gated clause ACTIVE: `verify --manifests` fails on a `tested` proposition at effective Medium+ with no `mutation://` falsifier that is not a pre-existing row, and `scripts/assurance_obligation_gate.py` holds `config/assurance-obligation-debt.toml` (63 rows, baseline 2256cd74) as a shrink-only, closed-to-new-work migration ratchet. `review` prints the derived severities, the open obligations by severity, and the 43 `NOT-ROOT-REACHABLE` units — 28 of which owe. **No encoding bump:** the derivation decides OBLIGATION, not evidence, so no unit's fingerprint changes and no attestation is invalidated. Both defects proven by mutation: removing one debt row makes the loader and the ratchet fail independently | |
| **1** | examine the 12 roots **consequence-first**, decomposing downward — THM-0094, THM-0095, THM-0091 first, since each is one undecomposed unit | each root has a typed decomposition; each leaf has a named class and a stated obligation |
| | *Phase 1 mechanism landed:* **obligation SUCCESSION** (§9.4). Phase 1 could not otherwise start: a wide `tested` unit that owed a falsifier becomes several narrow ones that owe one each, and the 0E ratchet reads that as new work. A row may now carry `succeeds` and `decomposition_ref` under five clauses checked against `origin/main`; a malformed succession does not also buy growth, and the authorization is spent by the merge that uses it | |
| | *1-A landed — **THM-0094**, the Python SDK root.* One V0 unit over five files and 39 controls became **thirteen** propositions, ten of them the root's `supported_by` and three deliberately outside its closure (the read bound, the signer policy, the authorization binding — each returned by the inverse falsifier). `depends_on` was `[]` and is now `THM-0058/0059/0060/0061`: the SDK's whole cryptographic argument is the audited core's and the root did not name it. The headline correlation sentence was NARROWED — two of its three refusals are unreachable from `_exchange`, because the id handed to `take()` is the one `record()` just returned — and the promise is better supported for it, since it now names the binding that keeps it. **46 controls newly registered** under ADR-069, including seven for `sdk_python.nonce_floor`, a stated conjunct of a declared root whose predecessor unit declared no evidence at all. Two carriers found outside the graph entirely: the PyO3 binding (`sdk/python/src/*.rs`, 816 lines, no unit, no tests, outside every fingerprint) and `test_transport_e2e.py`, which skips whole because `importorskip("httpx")` names a package the lock replaced with `httpx2`. 97 declared ids, 97 passing. Packet: `verification/reviews/packets/thm-0094-consequence-decomposition-2026-09-18.md` | |
| | *1-D landed — the audit of the three DECOMPOSED critical roots, and its first finding is the largest in the estate.* `http_profile.verifier_results` is ONE class-V0 unit over **56 files and 73 controls**, and **TEN theorems** name it in `supported_by` — nine of them titled after one of the nine public operations `Verifier` exposes. The theorem layer did the decomposition; the unit layer never followed, and the unit's own description states the count ("the seven public verifier operations"). Three measured consequences: **THM-0017 and THM-0065 are attacked by NOTHING** while N1 reads them as satisfied, because N1 accounts per UNIT and ten claims share one — 068's own defect, one layer up, where the adjacency is between theorems rather than between checks; an edit to any of 56 files dirties all ten claims; and 38 of 73 controls are named by no probe, **18 of them a coherent credential-chain battery that is a different authority with no unit**. The 30 probes already carry a `theorem` field and partition cleanly, so the split is a re-partition of labelled evidence rather than new evidence. Stated, not taken: it invalidates ten claims' attestations at once and is Phase 2's first and largest item. Packet: `verification/reviews/packets/verifier-results-decomposition-2026-09-18.md` | |
| | *1-E landed — the seal census.* §2 named ONE theorem whose statement asserts a structural fact the registry records as `test://`, and called it this record's thesis. Measured across the estate: **five theorems and five units**, five of the six theorems `critical`. THM-0108 says *POSSESSION IS THE PROOF, three times*, in capitals, about three types — so three probes, not one. THM-0029/0031/0033 are one family making the CO-PROVENANCE argument 0D-9 met at `proxy.trust_plan`, and THM-0031 states what a behavioural control cannot reach: *that both predecessors ultimately arose from A connection establishes nothing; the defect this excludes is two honest products of two DIFFERENT connections.* The census's own control: the eleven 0D splits are correctly excluded, because each now carries a structural sibling. Explicitly NOT a worklist — bulk promotion is the converse of the error Ruling 3 forbids. Packet: `verification/reviews/packets/seals-stated-as-tested-2026-09-18.md` | |
| | *1-F landed — the root-set question.* §2 measured the non-root-reachable population and left it a number; 0E built the view and this reads it: **43 units, 28 owing**. The ratification permits changing the root set only for semantic reasons, and this finds ONE: **remote signing custody** — *a signature MCP-RE emits under non-exporting custody verifies under the public key that deployment advertises, and the seam carries a preimage in and a signature out and nothing else*. The tree names the gap itself — THM-0064 (root-reachable) promises the key never reaches this process and is silent about whether what comes back is under the advertised key, and THM-0116's consequence says *"this is the half THM-0108 states cannot be established at the seam."* Nine units, four theorems, five critical. **Stated and NOT added**: root membership is owner-ratified and `claim_surface_gate.py` requires a §2 claim row, so it is a two-document change. Also measured: **14 units no theorem names at all** — three critical, seven high — ADR-MCPRE-069's `new-proposition` arriving at the unit layer. Packet: `verification/reviews/packets/not-root-reachable-census-2026-09-18.md` | |
| **2** | discharge: formalize, structurally redesign, falsify, or measure, per leaf, as Phase 1 assigns | no Medium-or-higher root reads INCOMPLETE without a recorded, owner-approved obligation |

### 11.1 Two schema events, two flag days, and why they do not land together

A schema bump cannot be "loader only" when the loader makes the new keys required: a required
field must be populated in the same commit that requires it, or the tree does not load. So
each schema event is an **activation commit** — schema, loader, migrated registries, and
re-attestation, together. There are two, and neither is 0E.

**Flag day 1 — a bump invalidates the attestation estate, and it happens TWICE.**
`_manifest.load_verification` refuses a `schema_version` the tooling does not implement, in
its own words: *"A schema change alters what a fingerprint means, so it invalidates every
attestation and must be handled, not tolerated."* 0A is the first. 0C is the second, and it is
the more expensive one: `_fingerprint.assumption_digest` hashes the **whole** assumption
entry and feeds every in-scope unit's `trusted_assumptions` component, so typing all 47
records re-digests all 47 and dirties every unit in their scope. Two re-attestations is the
honest cost of not pretending one schema change is two.

**Re-attestation is not a source payload inside either commit.** It is a required lane run
against that exact commit, and if CI cannot produce fresh evidence for the new fingerprints
before merge, the commit does not merge.

**There is a THIRD re-attestation, and it belongs to 0D rather than to a schema event.**
Building 0B established it: a unit declaring `mutation://` fingerprints the probe ENTRIES and
the lane binary (`_fingerprint` encoding v5), because a suite that can silently shrink closes
no loop. The same is true of a `structural://` probe and a `measured://` measurement, so the
first unit to declare either scheme needs those components — and a new component is an
encoding bump, which invalidates the estate. 0B does **not** add them: no unit declares the
schemes yet, and adding a component that is empty for all 127 units would spend a whole
re-attestation on nothing. It lands with the declarations, in 0D, and it is a cost of 0D
rather than a surprise inside it.

**Flag day 2 — the adequacy rule turns a large backlog merge-fatal, and it lands at 0E.**
Every unit that is `tested` with effective severity Medium or higher and no registered
falsifier fails the merge under §9.3. That is up to 42 root-reachable units plus up to 33
unreachable ones — **75 of 127**. It cannot land before 0E because `effective_severity` does
not exist before 0E: 0A requires and populates the *direct* label, and N3's derivation is 0E's
deliverable. So **0A's loader enforces only the severity-independent half of registry
adequacy** — class present and in vocabulary, class↔evidence agreement, the measured fields
present when the class is `measured` — and N1's severity-gated clause activates at 0E,
against `config/assurance-obligation-debt.toml` generated in the same commit at the real
numbers rather than at §3.1's ceiling.

### 11.1.1 What a unit's class means at 0A, and why 0D is not a correction

A3 says the class is a declaration **checked against the evidence**. So at 0A a unit's honest
class is the one its *currently declared evidence* supports — and a unit declaring `test://`
and `mutation://` is `tested` at 0A whatever its proposition will turn out to be, because
that is what establishes it in the registry at that moment.

`http_profile.verifier_result_separation` is therefore `tested` at 0A and becomes
`structural` at 0D, when 0B has made a `structural://` URI declarable and its evidence changes
to name one. That is not the registry being corrected from a lie; it is the registry
following the evidence, which is the only order A3 permits. **This is also why 0B must
precede 0D and why no unit may declare `structural://` or `measured://` before its lane
exists and fail-closes on zero execution** — `_evidence.required_lanes` binds every declared
scheme and `decide_issuance` refuses a claimed lane with no record, so an early declaration
takes the unit out of the graph, and a lane that could be green having run nothing would put
it back in on the strength of no measurement at all.

Every 0D transition goes through the class-transition ratchet (§9.4) with a reclassification
record, which is what stops "following the evidence" from becoming a route to a silent
downgrade.

**The eight repairs come first and are not debt.** A registered probe that already attacks a
unit whose `evidence` omits it is a declaration error with the obligation already discharged.
They land in 0A, before anything is baselined, because baselining them as debt would make the
ratchet bless a registry statement known to be false.

**Does a debt registry repeat §1's "do not solve the count before the architecture"?** No, and
the order is what makes the difference: the architecture decides obligation *existence* first,
and the registry then baselines the mechanically computed residue. §1 refuses a worklist
derived from a raw alarm. This is a baseline derived from a rule — and it is generated at 0E,
after 0D has made every class honest, so it baselines real obligations rather than artefacts
of an unfinished classification.

### 11.2 The worked example the owner gave, kept as the Phase 1 template

One root, decomposed consequence-first, each leaf landing in whatever class is honest for it:

```
ROOT  client accepts only an answer to its own request
  request identity injectivity              proved
  response/request binding type             structural
  wire parser rejects a different request   tested + mutation
  cryptographic library behavior            external-boundary  (a premise, not a unit)
  production composition calls the binding  tested + mutation
```

Four participating units and one premise; **two** falsifiers. Manufacturing five would be
actively wrong.

---

## 12. The challenge set, measured

Revision 1 ended with a heuristic and a hypothesis. Ruling 3 turned the hypothesis into an
instruction, and the grill executed it. Both results below are measurements.

### 12.1 STRUCTURAL: 21 of 21 probes attack the wrong proposition — and the lane already exists

**The challenge set.** Ruling 3 named the sealed-owner units carrying a `mutation://` probe
and gave the adjudication test. All 21 probes over those eight units were read from
`verification/policy/mutation-probes.toml`. The result is unanimous, and it is one side of
the test rather than a mixture:

| unit | probes | what every probe does |
|---|---|---|
| `proxy.certificate_identity` | M25, M26, M27, M28, M30 | replace a field-selection or projection expression; expect named tests red |
| `proxy.peer_identity_value` | M29 | delete `if trimmed.chars().any(char::is_control) { return Err(…) }` |
| `proxy.credential_key_correspondence` | M31, M33, M34, M35 | `if false && …`; an error-mapping substitution; `unwrap_or(&[])`; a prefix-strip replacement |
| `proxy.ed25519_public_key` | M32 | replace the canonical SPKI prefix strip with a suffix slice |
| `proxy.delegated_resolver_materialization` | M36, M37 | `if false && …`; install a fresh default budget |
| `proxy.trust_configuration_state` | M63, M64, M65 | `if secs == 0` → `if false`; `if secs > ceiling` → `if false`; collapse a two-arm match |
| `proxy.trust_plan` | M66 | replace a projection with a constant |
| `proxy.client_credential_window` | M113, M114, M115 | `&& false` on two construction-time predicates; return the wrong field from a projection |

**Every one weakens a runtime expression and expects a behavioural test red. Not one alters a
visibility modifier, a field's privacy, a module boundary, or a constructor's reachability,
and not one asserts anything about compilation. Zero of 21 are structural falsifiers.**

Revision 1 named this as "the most likely place for this record's thesis to be WRONG". It
resolves in the thesis's favour, measured rather than argued.

**And it resolves into a sharper problem: the units are composite.** Take
`proxy.client_credential_window`. Two genuinely different facts hold up its sealed claim:

1. the fallible constructor **refuses** an illegal `(connection_age, cert_lifetime)` pair — a
   runtime predicate, and exactly what M113/M114 falsify. Honest class `tested`, with a real
   registered falsifier;
2. there is **no other producer** — the fields are private to the owner's module, so no
   caller can assemble one bypassing (1). A compile-time fact. Nothing attacks it.

These are not two evidences for one proposition; they are two propositions, and (2) is the one
CLAUDE.md's R-SEAL actually names: *can the check be deleted and still leave an invalid value
unconstructible?* Under A2, that is two units.

**Disposition.** Each composite sealed-owner unit splits into a `tested` predicate unit —
existing probes kept, untouched, because they are correct evidence for a real proposition —
and a `structural` sole-producer unit owing a compile-refusal probe. The rule reaches all
**14** unit-backed sealed owners, not just the eight measured; the **9** sealed owners with
no unit at all are coverage gaps, not reclassification candidates.

**The second finding, and it reverses part of the design.** Revision 1 assumed the repository
had no compile-refusal machinery. It has, and it is registered:

> `http_profile.verifier_result_separation` states *"the verifier's assurance products are not
> substitutable: a weaker product cannot be passed where a stronger one is required"*. Its
> three `tested_symbols` are `doc#` items whose doctests are ```` ```compile_fail ```` bodies
> — `verified_response/bound.rs:73` tries to pass a `CryptographicFloorVerifiedBoundResponse`
> where a `&VerifiedMcpResponse` is required. That is a hostile construction refused by the
> type system, running on the merge path, resolved by an existing lane
> (`verify-tests`'s `doc_matches`), bound into the unit's fingerprint — **and its evidence URI
> says `test://`.**

That is the best worked example of §3's defect in the repository. Under 0D the unit
reclassifies to `structural` and its URI becomes `structural://`; keeping `test://` under a
`structural` class would violate A3 and N4, whatever lane implementation is reused underneath.

**So `structural` has ONE lane and TWO probe kinds** — the class is one thing, compiler
refusal of an illegal inhabitant, and the sub-mechanisms differ in where the hostile
construction has to live:

| probe kind | witnesses | mechanism |
|---|---|---|
| `crate-boundary-compile-fail` | that a **downstream crate** cannot construct or substitute the value | the existing `compile_fail` doctest corpus; the `doc#` resolver already runs it |
| `in-crate-source-injection` | that a **sibling module in the owner's own crate** cannot | copy the crate to a scratch tree, inject the probe at a declared insertion module, `cargo check --message-format=json` under the pinned toolchain, require a specific rustc error code whose primary span is on the probe's marker line |

The second kind needs the source-injection mechanism for a reason that is itself the point:
`docs/dev/sealed-owners.md` correctly observes that with the representation private, *"there
is no file that could hold the negative case, because such a file would not build"*. The
scratch copy is the only place that file can exist.

**And that document's conclusion needs correcting, in this record's scope.** It goes on to say
`cargo check -p mcp-re-proxy --all-targets` passing **is** the witness, "a stronger one than a
single pinned case". It is not a witness at all under Ruling 3. It proves the current tree
contains no illegal construction; it cannot go red when the boundary is deleted. Make the
owner's field `pub(crate)`, or add a public constructor taking the same arguments unchecked,
and the build still passes every time — because nothing in the tree attempts the construction.
**An absence of counterexamples in a corpus nobody wrote a counterexample into is not a
refusal**, and treating it as one is §9.2's failure class for the fourth time. The document is
right about what a separate-crate case proves and wrong about what replaces it; 0B's landing
carries the correction.

**What the ratification added, and it is the substance of the accepted correction.** A
sealed owner is structurally established **only for the exact invariant for which its
construction boundary is closed** — not for the value, not for the type, and not for every
property the owner's documentation attributes to it. Private fields alone are insufficient.
The structural witness must account for **every producer path relevant to the claimed
invariant**:

| producer path | why it is on the list |
|---|---|
| module-tree visibility | `pub(crate)`, `pub(super)` and a sibling module inside the owner's own module tree all reach a "private" field; §12.1's whole reason for the in-crate probe kind |
| alternate constructors | a second `new_*`, a `From`, a `Default`, or a builder taking the same arguments unchecked closes nothing, however fallible the first constructor is |
| generated / deserialization routes | a derived `Deserialize`, a decoder, or any generated impl that fills fields positionally bypasses every checked constructor, and does so in code nobody reads |
| test-only construction | a `#[cfg(test)]` constructor or a test-gated `pub` field is a producer; it does not run in production, and it does prove the boundary is not closed, since the compiler admits the construction |

A probe that attacks one of these leaves the others unwitnessed, so the claimed invariant and
the attacked boundary must be **the same boundary**: the probe's hostile construction is
written against the exact producer path the invariant depends on, and the unit's structural
claim is worded to the invariant that path actually closes. This is why §12.1's disposition
splits the composite units rather than relabelling them — `proxy.client_credential_window`'s
sole-producer proposition is the one a compile-refusal probe can attack, and its
refuses-an-illegal-pair proposition is not.

The expected refusal is a specific rustc **error code** plus a span on the probe's marker
line, not merely "does not compile" — the weak form admits a typo, a missing import or a
broken fixture as evidence, and the toolchain is pinned in
`verification/policy/toolchains.lock.toml`, so code matching is stable. The lane's own
falsifier is a known-**compiling** fixture that declares an expected privacy error: the
self-test requires the runner to report FAIL on it. A runner that cannot go red when the
hostile construction compiles is measuring nothing.

**Sequencing.** No unit may declare `structural://` before 0B ships, because
`_evidence.required_lanes` binds every declared scheme and `decide_issuance` refuses a claimed
lane with no record. 0B-before-0D is therefore mandatory rather than merely the ruled order.

### 12.2 MEASURED: the repository already built one, without the vocabulary to say so

`conformance.verdict_vocabulary_scope` claims: *"How many files in this workspace decide what
an `mcp-re.*` verdict token says, **measured over every crate's source tree** rather than read
off a list of producers: exactly two."* Its evidence URI says `test://`. Its four
`tested_symbols` are not a drifted battery — read against Ruling 4 they are the measurement
and its three required elements:

| symbol | Ruling 4 element |
|---|---|
| `exactly_two_files_decide_what_a_verdict_token_says` | the **measurement** itself |
| `the_scanned_crate_set_is_the_workspace` | **scope identity** — derives the crate list from the workspace manifest, so a member cannot be scanned by nobody |
| `guard_inputs_are_non_empty` | **sensitivity control** — a walk that reads nothing would pass vacuously |
| `no_producer_outside_core_mints_a_wire_token` | the **superseded** hand-list scan the unit's own comment describes as replaced |

Three of the four are the apparatus Ruling 4 demands, already written. This is the same
discovery as §12.1 in the other class, and it is the strongest argument this record has that
the four classes describe something real rather than something proposed: the repository has
been producing `structural` and `measured` evidence for months and filing both under
`tested`, because `tested` was the only word available.

Under 0D the unit becomes `measured`, its three apparatus symbols become its
`measurement_scope` and `measurement_control`, and the superseded fourth is dispositioned
under ADR-069 rather than carried as though it were part of the census.

**Landed, with one addition the estate did not have.** Three of the four were the apparatus
and are now executed as one: the protocol runs the measurement together with its scope
identity, and the measurement asserts its own non-empty-input control. What no control
supplied was the sensitivity demonstration Ruling 4 actually asks for — *the number can still
MOVE* — so `the_measurement_moves_when_the_scanned_set_shrinks` was written for it. It
removes `mcp-re-core` from the scanned set and requires exactly one observation to change,
which a walk that had stopped reading anything could not satisfy.

### 12.2.1 What Phase 0B shipped, and what it deliberately did not

Two lanes, each a named required check on the merge path, each fail-closed on zero
execution, and no registry change — `verification.toml` is byte-identical in class terms and
no unit declares either scheme.

| | `structural://` | `measured://` |
|---|---|---|
| runner | `tools/verification/verify-structural` | `tools/verification/verify-measured` |
| registry | `verification/policy/structural-probes.toml` | `verification/policy/measurements.toml` |
| mechanism | inject the hostile construction into a scratch copy, `cargo check --message-format=json`, require the declared rustc error code with its primary span on the marker line | execute the protocol, preserve and digest the result, then `reproducibility` (two runs must agree) or `sensitivity` (`APPARATUS-MOVED: <n>`, n >= 1) |
| registered at 0B | **5 probes, all live**: S01/S02/S03/S05 crate-boundary over `http_profile.verifier_result_separation`, S04 in-crate over `proxy.client_credential_window_sole_producer` (over `proxy.client_credential_window` until 0D-3 split it). 0D-4 adds S06, in-crate over `proxy.delegated_resolver_materialization_sole_producer`; 0D-5 adds S07, in-crate over `proxy.ed25519_public_key_sole_producer`; 0D-6 adds S08, in-crate over `proxy.peer_identity_value_sole_producer`; 0D-7 adds S09–S11 over `proxy.credential_key_correspondence_sole_producer`; 0D-8 adds S12–S13 over `proxy.certificate_identity_authority_boundary`; 0D-9 adds S14 over `proxy.trust_plan_co_provenance`; 0D-10 adds S15–S16 over `proxy.trust_configuration_state_sole_producer`; 0D-11 adds S17 over `proxy.custody_exposure_sole_producer`; 0D-12 adds S18–S19 over `proxy.continuation_materialization_sole_producer`; 0D-13 adds S20–S21 over `proxy.admission_configuration_state_sole_producer` | **none**; the first corpus is 0D's §12.2 unit |
| its own falsifier | `test_structural_lane.py` compiles a construction that BUILDS and requires the runner to report FAIL | `test_measured_lane.py` runs a dead, a silent and an irreproducible apparatus |

**The boundary kind does not use rustdoc, and the reason is this record's own thesis.**
rustdoc can annotate a ```compile_fail doctest with an expected error code, but that check
runs only on nightly — so on the pinned stable toolchain `compile_fail,E0308` and bare
`compile_fail` are the same declaration, and a probe resting on it would have a declared code
nothing compares. The lane compiles the construction itself, as an integration test (a
separate crate linking the library, which is exactly the boundary condition), and compares
the code against diagnostics it read. The doctests remain; each boundary probe names the one
it corresponds to, and the lane refuses a probe whose documented case has drifted.

**`producer_paths` is the ratification made mechanical.** Every probe answers for all four
routes — module-tree visibility, alternate constructors, generated/deserialization routes,
test-only construction — including the ones that do not apply, and the loader refuses an
unanswered one. Private fields alone are not a seal, and a witness that attacks one route
while another stands open establishes nothing.

**One defect found by building it, and fixed.** `verify-mutations --probe M25` selected no
probe — every id there is `M25-<what-it-weakens>` — and reported `NOT_REQUIRED`, exit 0. An
empty SELECTION and an empty REGISTRY are different facts and only the second is quiet. All
three lanes now fail on a selector that matches nothing.

### 12.3 What Phase 0D still has to do

The heuristic revision 1 published — formal evidence ⇒ `proved` candidate, sealed-owner path
⇒ `structural` candidate, everything else `tested` — is retained only as a starting shape,
and it **classifies nothing**. A rule that reads a path list cannot know what proposition a
unit states, and 0D's job is exactly the judgement it skips. §12.1 and §12.2 are what the
judgement looks like when it is actually performed on two units, and both overturned the
heuristic's answer.

---

## 13. What this record does NOT decide

- **It does not decide any product claim.** No theorem statement, no root set membership, no
  product behaviour. Assurance TCB only.
- **It does not decide which units are reclassified where.** 0D measures; this record
  supplies the vocabulary and the rules for adjudicating disagreement. §12's two worked
  units are demonstrations of the method, and even they are 0D's to ratify.
- **It does not decide the 12 roots' severities.** S1 says they must be declared and that
  declaring one is security-sensitive. It does not pre-fill them, and the §3.1 estimate
  assumed all twelve are Medium-or-above solely to bound the cost.
- **It does not authorize a falsifier sweep.** N1 creates obligations that Phase 1 assigns
  per leaf. The 42 in §3.1 is a ceiling, not a backlog.
- **It does not decide whether more roots should be declared**, and the ratification
  forbids declaring any to absorb the 42. §10 S5 prices the `NOT-ROOT-REACHABLE` estate;
  Phase 1 changes the root set only for a semantic reason.
- **It does not reopen ADR-059 §8's single assumption direction** (B2), or §6.3's rule that a
  theorem names no path, symbol, feature, or assumption. Both survive this record intact.
- **It does not disposition the 626.** That is ADR-MCPRE-069.

---

## 14. The ratification record

Revision 2 listed six open owner calls. All six are **granted, with exact resolutions**
(§1.2), and three are granted in a stricter form than this record proposed. This section is
now the record of what was decided, so a later reader sees the disposition rather than the
question.

| # | revision 2's open call | ratified as |
|---|---|---|
| 1 | N3 broadens Ruling 1 from roots to all dependent propositions | **ACCEPTED, broadened.** Root-only severity is rejected outright; `direct` declared, `inherited` and `effective` derived and never independently editable (§9 N3) |
| 2 | §9.3 reshapes where §28.8 has jurisdiction | **SPLIT, not relaxed.** 059 keeps root completeness and its two modes; 068 owns evidence adequacy; malformed → ordinary FAIL, honest unmet → INCOMPLETE, incomplete declared root → binding in closure/release mode. §28.8 is not to become an everyday global completeness gate (§9.3) |
| 3 | 0B carries `measured://` as well as `structural://` | **ACCEPTED, with a second obligation.** Both lanes, distinct obligations, neither satisfying the other's — and each must **fail-close on zero execution** before any unit may declare its scheme (§4.1, §4.3, §11) |
| 4 | §10 S5 prices a large non-load-bearing estate rather than declaring roots | **ACCEPTED, and narrowed.** Do not manufacture roots. Reachability is a derived graph fact named `NOT-ROOT-REACHABLE`, meaning only that no declared root depends on the proposition; the obligation from the direct label stands regardless. Phase 1 changes the root set only for semantic reasons (§10 S5) |
| 5 | new protected registry vocabulary, incl. a **third** debt registry | **ACCEPTED, with the registry narrowed to a migration ratchet.** Pre-existing unmet obligations only; never an evidence class, exception, waiver or substitute; entries stay INCOMPLETE; one-way closure; exact owning proposition and effective obligation; no duplication of `assumptions.toml` (§9.4) |
| 6 | `docs/dev/sealed-owners.md`'s witness claim is corrected by §12.1 | **ACCEPTED, and sharpened.** Structural establishment is per-invariant, private fields alone are insufficient, and the witness must account for every relevant producer path — module-tree visibility, alternate constructors, generated/deserialization routes, test-only construction — with the probe attacking that exact boundary (§12.1) |

**ADR-MCPRE-069 is ratified as subordinate to this record** for the Gap-D authority, rather
than folded back in. The two keep a two-way cross-reference and no duplicated normative
authority: nothing in 069 restates a rule this record owns, and §8 here names 069 rather than
describing its remedy.

**What ratification does NOT move.** §13 is unchanged by it. No product claim, no theorem
statement, no root-set membership, and no unit's class changes because this record was
accepted; 0D still measures, and the severities populated in 0A remain a proposal the owner
may overturn per proposition.

---

## Appendix — how the figures were measured

Stated so the numbers can be recomputed and disagreed with, because a record that demands
falsifiability of everything else may not assert its own figures. Every figure in §2, §3.1
and §8 is computed by `tools/verification/evidence-class-census` from
`verification/policy/{verification,theorems,assumptions,mutation-probes}.toml`, and its
self-test perturbs a synthetic registry and requires each number to MOVE. A figure that
cannot move is not a measurement. §12's probe adjudication is a reading of all 21 probe
records, reproducible from `mutation-probes.toml` by filtering on the eight unit ids.

**Definitions, exactly as applied.**

- A root's **direct** support is the unit set named by that root theorem's own
  `supported_by`. Nothing below it.
- A root's **closure** is the transitive `depends_on` closure of the root theorem, and the
  union of every `supported_by` unit of every theorem in it.
- A unit **has a falsifier** iff some entry of its `evidence` list begins `mutation://`.
  Nothing else in the registry currently denotes one; `structural://` and `measured://` do
  not yet exist and are proposed by §4.
- A unit is **reachable** iff it appears in the closure of at least one declared root.
- The **obligated set** is: reachable, no falsifier, and carrying no `verus://` or `lean://`
  evidence — the last exclusion because a unit already bearing formal evidence is a
  reclassification candidate under N4 rather than a falsifier candidate.

**The one assumption, and what it costs.** The §3.1 figure of 42 assumes every declared root
is Medium-or-higher. If any root is Low, its exclusively-owned units leave the set. The
figure is therefore a **ceiling**, and it cannot be replaced by a real number until 0E
declares the severities. No work should be scheduled against it.

**What is NOT measured here, and must not be inferred from it.**

- Whether any existing `mutation://` probe actually attacks the production property its
  unit's claim depends on. §12.1 measured what 21 probes attack *structurally* — it did not
  verify that each attacks the right *tested* conjunct. Presence of a probe is a declaration,
  and N1 requires a *demonstrated* falsifier.
- Whether a unit's honest class is `tested` at all. Every count above treats the 127 units as
  tested-by-default because that is the only class the registry can express today. §12 shows
  two that are not, found by looking at two.
- Whether the 12 declared roots are the right 12. The 42 `NOT-ROOT-REACHABLE` units are evidence
  about the root set as much as about the units.
- Anything about `compile_fail` doctests in the §8 figure, which counts only `#[test]` and
  `#[tokio::test]`. ADR-069 widens it.

Phase 0A moved the census from `scripts/` into `tools/verification/evidence-class-census`,
beside the lanes whose registries it reads, resolving the policy directory from its own
location rather than from the working directory — a census that measures a different tree
depending on where it was started is not a measurement. Its self-test runs in `local_gate.sh`
stage 1 and as its own required CI step, because a number in a document is a claim and a
number a gate recomputes is a measurement, which is the same distinction this whole record is
about.
