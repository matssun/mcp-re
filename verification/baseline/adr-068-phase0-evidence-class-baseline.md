<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-068 Phase 0 — the evidence-class baseline

**Captured at:** commit `95a9f168` — the tree the r11 findings were measured against, and
the tree every figure below was computed from. The ledger record of their closure is
`2bb53d8d` (#964), where the r11 band reads

```
critical 0   high 0   medium 0   provisional 0      (149 low, 12 info)
```

Two SHAs rather than one, deliberately: a tree and a record ABOUT that tree are different
facts, and collapsing them would make this baseline claim the ledger was already closed
when the census ran.

**Captured on:** 2026-09-17.
**Reproduced by:** `python3 scripts/evidence_class_census.py` — every figure below is
computed from `verification/policy/*.toml` at `95a9f168`, not transcribed. The tool's
`--selftest` runs in `local_gate.sh` stage 1 and as its own required CI step, because a
census that printed the same number whatever the registry said would be a sentence with a
number in it.

**Assurance TCB, not a product claim.** This baseline sits where issue #739 sits: outside
the product theorem roots, inside the layer that decides whether the word `ESTABLISHED`
may be believed. Nothing here becomes a `THM-`.

---

## 1. Why this document exists before any Phase 0 code

ADR-MCPRE-068's premise is that the assurance model cannot say what KIND of thing supports
a claim. The moment Phase 0A adds `evidence_class`, that "before" is gone: every unit will
carry a class, and the question *what did the registry look like when it could not express
one?* stops being answerable from the tree.

This is the same reason `phase0-assurance-baseline.md` was written before any prover
existed. The comparison Phase 2 depends on cannot be reconstructed afterwards.

---

## 2. The registry as it stands

| quantity | value |
|---|---|
| review units | 127 |
| theorems | 130 |
| declared system roots | 12 |
| assumption records | 47 |
| `supported_by` edges | 164 — **all** of sort `unit://` |
| unit-to-unit `[[edge]]` declarations | 17 |
| evidence URIs | `test://` 131, `mutation://` 48, `verus://` 6, `lean://` 1 |
| unit classes | V0 120, V1 6, V2 1 |
| units with no evidence at all | 0 |
| registered mutation probes | 180 |

---

## 3. The falsifier gap, measured both ways

**Units carrying no `mutation://` evidence: 79 of 127.** The alarm that opened this work
said 80; one landed between the alarm and the measurement.

Per declared root, the reach of a falsifier, computed two different ways because they are
two different propositions:

| measure | value | roots |
|---|---|---|
| roots whose **directly supporting** units include no falsifier | **7** | THM-0075, THM-0076, THM-0094, THM-0095, THM-0077, THM-0091, THM-0071 |
| roots whose **entire transitive closure** reaches no falsifier | **3** | THM-0094, THM-0095, THM-0091 |

Both are true. The first says a root's own top-level support is unfalsified even where its
premises are well exercised; the second says the root is unfalsified end to end. Quoting
either as the other would be the defect ADR-068 exists to fix — a graph reading more
precisely than the measurement behind it — so both are recorded and the census prints both.

### 3.1 The three end-to-end cases

| root | sole supporting unit | class | files | controls | falsifier |
|---|---|---|---|---|---|
| THM-0094 — the shipped Python SDK accepts only an answer to its own request | `sdk_python.exchange_path` | V0 | 5 | 39 | none |
| THM-0095 — the shipped TypeScript SDK, same claim | `sdk_typescript.exchange_path` | V0 | 6 | 33 | none |
| THM-0091 — the sidecar signs only for a request its ingress policy admitted | `client.local_ingress_authority` | V0 | 7 | 16 | none |

"Undecomposed" is structural, not small: each is **one** V0 unit spanning five to seven
files with dozens of controls, carrying a root promise, with no theorem premises beneath it
and nothing demonstrating that any of its controls can fail.

**THM-0091 states a structural fact inside its own theorem text** — *possession of the
scope IS that permission; there is no other constructor.* That is a seal, asserted in a
system promise, recorded as `test://`, with no falsifier of any kind. Under ADR-068 §4 a
seal's falsifier is a construction that must not compile, and none exists. It is the
cleanest instance in the tree of a claim whose evidence class the model cannot express.

---

## 4. The four gaps, with their numbers

### Gap A — the evidence class is not machine-readable
Nothing in the registry distinguishes *proved* / *structural* / *tested* / *assumed* /
*external* / *review-obligation*. `class` (V0/V1/V2/V3) records a unit's ambition, not what
establishes it, and 120 of 127 units are V0.

**Measured consequence.** `docs/dev/sealed-owners.md` lists **23** sealed owners — values
where possession is the proof. **14** have a registry unit; **9** have none. All 14 of those
units are **V0 with `test://`/`mutation://` evidence and nothing else**. The strongest
propositions in the repository are recorded identically to behavioural checks.

Worse than indistinguishable: **mis-falsified**. Deleting a runtime check from a sealed
owner changes nothing, because the seal is the representation — so a probe that goes red is
measuring something other than the seal. Eight sealed-owner units carry a `mutation://`
probe: `proxy.peer_identity_value`, `proxy.certificate_identity`,
`proxy.ed25519_public_key`, `proxy.credential_key_correspondence`,
`proxy.delegated_resolver_materialization`, `proxy.trust_configuration_state`,
`proxy.client_credential_window`, `proxy.trust_plan`.

**This is where ADR-068 is most likely to be WRONG.** If those probes turn out to attack
exactly the right property, `structural` is not a distinct class and §4's table collapses.
Phase 0D must look at these eight first.

### Gap B — a theorem cannot express what kind of thing supports it
All 164 `supported_by` edges are `unit://`. Formal proof is *not* absent from the graph —
six units carry `verus://`, one carries `lean://`, and `[[edge]]` already distinguishes
`PROOF_DEPENDENCY` from `COMPILE_DEPENDENCY` and `CONTRACT_CONSUMES`. What is missing at the
theorem layer is **adequacy**: a theorem resting on a proved unit and one resting on a
tested-but-unfalsified unit are written identically, and no rule requires the class of the
support to match the severity of the claim.

### Gap C — assumptions are untyped
47 records, no machine-readable distinction between ASSUMED, EXTERNAL BOUNDARY and REVIEW
OBLIGATION. The connectivity is **not** missing: `_catalogue_views.assumption_consumers`
already derives scope → unit → theorem. But it stops at the directly supported theorem, and
reaching the **root** needs that composed with the `depends_on` closure that
`_review.root_completeness` already walks separately. Both halves exist; nothing composes
them. No new edge is required — one derived view is.

### Gap D — evidence that runs but nothing claims
Not in the original alarm; found by applying ADR-068's thesis to live r11 work.

| | count |
|---|---|
| test functions inside declared unit paths | 2168 |
| of those, in **no** unit's `tested_symbols` | **626** |
| units with at least one such function in their own paths | 54 of 127 |

The lane selects `tested_symbols` with `--exact`. A control outside every list runs, passes,
and is evidence for nothing — delete it and no fingerprint moves.

**And from a third side:** **56** distinct units are named by a registered probe, while only
**48** declare `mutation://` evidence. Eight units have a falsifier *running against them*
that their own evidence list does not claim: `client.local_ingress_authority`,
`proxy.admission_state_source`, `proxy.audit_record_coordinates`,
`proxy.continuation_leg_binding`, `proxy.continuation_materialization`,
`proxy.dispatch_commitment`, `proxy.outbound_destination`,
`proxy.remote_signer_egress_bound`.

So **"80 units need falsifiers" is wrong in both directions**: some of the 79 already have a
probe attacking them and it is not counted, and some of the 48 may be attacked in the wrong
place.

---

## 5. What N1 would cost

Under ADR-068 N1 — *a `tested` proposition at Medium-or-higher effective severity must name
a registered falsifier* — the obligated set, assuming for the estimate that all 12 declared
roots are Medium or above:

| | units |
|---|---|
| reachable from some declared root | 85 |
| …with a falsifier | 39 |
| …without | 46 |
| …of those, already carrying formal evidence | 4 |
| **obligated unless reclassified** | **42** |
| **not reachable from any declared root** | **42** (33 without a falsifier) |

Two things follow.

**The worklist is at most 42, against an alarm of 80**, and each has three legitimate exits:
add the falsifier, reclassify to a stronger class and satisfy *that* class's obligation, or
record an owner-approved review obligation that stays visible as debt.

**A third of the estate is not load-bearing for anything MCP-RE promises.** 42 of 127 units
are reachable from no declared root. That is not necessarily wrong — the root set is
deliberately partial — but no view says so, and it is evidence about the root set as much as
about the units.

The 42 is a **ceiling and an estimate produced by this record's own proposal**. It cannot
become a real number until Phase 0E declares the twelve severities. No work is to be
scheduled against it.

---

## 6. Fail-closed lane behaviour — demonstrated, not claimed

On 2026-09-17 the four pinned Node runtimes were absent from the verification box (removed
by the nightly disk reclaim). The TypeScript unit's battery therefore had no runtime, and
the lane **refused**: `1 of 127 unit(s) did not pass their declared test battery`, and the
gate failed. It did not report the unit as measured, and it did not skip it.

That is `_evidence.required_lanes` working as designed — it returns EVERY declared scheme
rather than the recognised subset, so a lane nothing measured refuses issuance instead of
falling through to a pass. It is the only *observed* instance of the property, and it is the
reason ADR-068 requires `structural://` to ship **with** its lane: declaring a scheme before
its lane exists takes every unit that declares it out of the graph.

The event also produced a repair, because the prerequisite was being remembered rather than
enforced: `scripts/node_matrix_state.py` reads the pinned set from the lock and
`verification_runner_preflight.sh` provisions absent runtimes before the lane starts.

---

## 7. What Phase 0 must do, in order

| phase | deliverable | done when |
|---|---|---|
| **0A** | `evidence_class` on `[[unit]]`; six values; loader validation; class↔evidence agreement | the loader refuses a disagreeing unit, and a self-test probe goes red on removal |
| **0B** | the `structural://` lane: a negative-compilation probe corpus and runner, as a named required check | a probe that *compiles* fails the lane |
| **0C** | `class` on `[[assumption]]` plus `boundary_owner` and a discharging event; all 47 typed | zero untyped records; the release view lists open review obligations |
| **0D** | reclassify all 127 units honestly — **the eight mis-falsified sealed owners first** | every unit classified; the `tested`-without-falsifier count is measured, not estimated |
| **0E** | severity on the 12 roots; inheritance computed; non-load-bearing units reported | `review` prints a typed, severity-annotated root tree |

Phase 0E blocks Phase 1: N1 and N3 cannot be evaluated at all until severity exists.

**Phase 0 changes no product claim.** Reclassification records what is already true about
each unit; it decides nothing about the product.

---

## 8. What this baseline does not decide

- Which units are reclassified where — 0D measures; the ADR supplies the vocabulary.
- The twelve root severities — S1 says they must be declared and that declaring one is
  security-sensitive. §5's estimate assumed all twelve are Medium-or-above solely to bound
  the cost.
- Whether any of the 620 unregistered controls should be registered. D2 refuses bulk
  registration outright: it would inflate every unit's apparent evidence without a single
  new proposition being stated.
- Whether `structural` is a distinct class at all. §4 records the measurement that would
  overturn it.
