<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 — Evidence that runs but nothing claims

**Status:** 📄 **PROPOSED** 2026-09-17. Not ratified, not implemented.
**Discussion:** [#968](https://github.com/matssun/mcp-re/discussions/968).
**Parent:** ADR-MCPRE-068 — *Evidence classes*
([discussion #967](https://github.com/matssun/mcp-re/discussions/967),
[`assurance-evidence-classes.md`](assurance-evidence-classes.md)). This record
is **subordinate** to it and was §8 of its revision 1. It is separated because it is a
different defect with a different deliverable, not because 068 grew too long.
**Predecessor:** ADR-MCPRE-059 (discussion #527, rev. 2 = the theorem registry). Nothing here
changes 059's model; this record uses it to ask a question 059 never asks.
**Assurance TCB — but with one exit that is not.** Three of this record's four dispositions
are registry bookkeeping. The fourth writes theorems, and a theorem is a product claim. §5
is where that boundary is drawn, and it is the reason this is a separate record.

---

## 1. The defect

> **A control can run, pass, and be evidence for nothing.** The verification lane selects a
> unit's `tested_symbols` with `--exact`. A test function that is not in that list executes
> on every CI run and participates in no claim: delete it and no unit's declared evidence
> changes, no ReviewFingerprint moves, and nothing goes red.

This is the **mirror image** of the defect ADR-068 exists to fix. There, evidence is
*claimed but not demonstrated* — a unit asserts a proposition and nothing shows the
proposition could fail. Here, evidence is *demonstrated but not claimed* — a control
demonstrates something real and no proposition is stated for it to be evidence of.

The two do not share a remedy. 068's remedy is an ontology: name the kind of thing that
supports a claim, and require the kind to be adequate to what the claim promises. This
record's remedy is a **census with a per-symbol disposition**, and one of its dispositions
creates propositions the registry does not currently hold.

---

## 2. What was measured

Measured by `tools/verification/evidence-class-census` over every `#[test]` / `#[tokio::test]`
function defined in a file some unit lists in `paths`, counting a function as unregistered
only when it appears in **no** unit's `tested_symbols`:

| | count |
|---|---|
| test functions inside declared unit paths | 2168 |
| of those, in no unit's declared battery | **626** |
| units with at least one such function in their own paths | 54 of 127 |

**The count is not the deliverable and must not be read as a worklist.** A file can sit in
several units' `paths`, and a test of a local helper is legitimately not a security claim's
evidence. Curation here is careful and reasoned where it has been done —
`proxy.continuation_correlation_store` annotates each registered symbol with the conjunct it
establishes, and that is the standard, not the exception.

### 2.1 The measurement is incomplete in a way that matters

The figure counts only `#[test]` and `#[tokio::test]`. It is therefore **structurally blind
to `compile_fail` doctests**, which are controls of exactly the same kind: they run in the
doc lane, they pass, and an unregistered one is evidence for nothing.

There are unregistered ones. `mcp-re-client-core/src/delegated_trust/mod.rs:52` and `:63`
each hold a hostile construction that must not compile — one proving `TrustedIssuerSet` no
longer hands out a resolver on its own, the other that the raw lifecycle lookup is no longer
public — and no unit names either. Under ADR-068 §4.1 those are `structural` controls, and
under this record they are unclaimed evidence. **This record's census must cover doctests,
and 068's did not.** That is recorded as a correction rather than a footnote, because a
census that cannot see a whole control kind will report a clean sweep over the wrong
population.

---

## 3. The worked instance

`mcp-re-proxy/src/continuation_store/mod.rs` holds seven test functions. Two are registered
under `proxy.continuation_correlation_store`
(`one_actors_entry_is_not_reachable_by_another`,
`peek_does_not_consume_and_consume_is_one_shot`). The other five were written for R11-348:

```
the_first_open_leg_stores
a_second_open_on_a_live_key_is_refused_and_changes_nothing
concurrent_creators_yield_exactly_one_stored
an_expired_key_may_be_established_again
a_backing_failure_is_unavailable_and_never_a_collision
```

Every one passes in CI. **None of the five is in any unit's `tested_symbols`.** Read
together they establish single-writer establishment semantics — first-writer-wins under
concurrency, a live key refusing a second open without side effects, expiry reopening the
key, and a backing failure reading as unavailable rather than as a collision.

That is a real security proposition. It is also a proposition **no unit claims and no
theorem names**. The honest reading is not that a list drifted: these controls answer a
question the graph has never been told to ask.

This is why the record exists, and why it cannot be folded back into 068's Phase 0D. Acting
on this instance means writing a theorem, and ADR-068 §13 says in terms that it decides no
product claim.

---

## 4. The dispositions

**Decision D1.** The census reports, per unit, every control in that unit's own declared
paths that no unit registers. Each one is dispositioned as exactly one of:

| disposition | meaning | what lands |
|---|---|---|
| `register` | it is this unit's evidence | the symbol joins that unit's `tested_symbols` |
| `reattribute` | it is another unit's evidence | the symbol joins the other unit's battery |
| `new-proposition` | it establishes something no unit claims | §5 |
| `not-evidence` | it is a local helper's control, not a security claim's | a recorded reason, and the symbol stays unregistered |

**The dispositions are the deliverable, not the count.** A phase that reports "626 → 0" while
having reached it by any mixture of the four has said nothing about whether the registry got
more honest.

**Decision D2 — no auto-registration, ever.** Bulk-adding 626 symbols to the batteries
nearest them would inflate every unit's apparent evidence without a single new proposition
being stated, and would destroy exactly the per-symbol reasoning that makes the existing
lists worth reading. This is the same refusal ADR-068 §1 makes about falsifiers: *do not
solve the count.*

**Decision D3 — `not-evidence` carries a reason, and the reason is checked for shape, not
for truth.** A disposition with no recorded reason is not a disposition; it is the symbol
still being unregistered, with a word next to it. The gate requires the field. No gate can
decide whether "a local helper's control" is true of a given function, and pretending
otherwise would be a gate satisfying itself.

**Decision D4 — a registered symbol's disposition is not re-litigated.** Once a control is in
a unit's `tested_symbols` it is that unit's declared evidence and moves that unit's
fingerprint; it leaves the census by construction. The census measures the unregistered
residue and nothing else.

---

## 5. `new-proposition` is where this record stops being bookkeeping

Three dispositions move symbols between lists. The fourth says *a proposition is missing*,
and discharging it means writing a `[[theorem]]`, a `[[unit]]`, or both — which is a product
claim, ratified under ADR-MCPRE-059 §28 like any other, at the altitude the ratification
assigns it.

So `new-proposition` is a **two-step** disposition and the steps have different owners:

1. **Identify** — this record's census records that a named set of controls establishes a
   proposition the graph does not hold, and states the proposition in prose. Assurance TCB.
2. **Ratify** — the proposition becomes a registered claim by the ordinary theorem-
   architecture route, or it does not. Product. **Not this record's to grant.**

A `new-proposition` disposition sitting at step 1 is **visible unresolved assurance debt**, in
the same sense ADR-068 N2 gives an owner-approved `review-obligation`: it is a recorded fact
that the graph is incomplete, and it is not equivalent to completed assurance. It is reported
in the release view until it is ratified or withdrawn.

**What this record must not do is quietly widen an existing unit to swallow the proposition.**
Adding the five continuation-store controls to `proxy.continuation_correlation_store` would
make that unit's battery cover single-writer establishment semantics while its declared
proposition still says nothing about them — a unit's evidence claiming more than the unit
claims. That is `register` misapplied, and it is strictly worse than leaving the five
unregistered, because it makes the graph look complete where it is not.

---

## 6. What this record does NOT decide

- **It does not decide any of the 626.** It supplies the four dispositions and the rules for
  applying them.
- **It does not ratify any new theorem.** §5, step 2.
- **It does not change the evidence-class ontology.** Every control in scope here is
  `tested` — or, after §2.1, `structural` — and its class is not in doubt. That is ADR-068's
  subject, not this one's.
- **It does not change the lane's `--exact` selection.** Exact selection is what makes an
  unregistered control detectable at all; loosening it would delete the measurement.

---

## 7. Relationship to ADR-MCPRE-068

**069 does not block 068's phase plan, and 068 does not block 069.** The 626 are discoverable
and dispositionable against the registry as it stands today, with no schema change. 068's
Phase 0D classifies units; it does not absorb the disposition campaign.

There is one ordering fact rather than a dependency: a `new-proposition` ratified under §5
lands as a unit, and a unit landing after 068's Phase 0A must carry an `evidence_class` and a
`direct_consequence_severity` like any other. That is 068's schema doing its job, not a
sequencing constraint on this record.

**The one thing 069 owes 068** is §2.1's correction: the doctest blind spot means 068's §8
figure describes a smaller population than the defect covers, and 068 records that.

---

## 8. Open questions

1. **Is `not-evidence` load-bearing enough to need a review record?** D3 requires a reason
   but no `review_ref`. A large `not-evidence` population is indistinguishable from a
   campaign that gave up, and nothing currently tells them apart.
2. **Does the census belong in the same tool as 068's?** Both read the registry and walk the
   tree. One tool with two reports keeps the walk honest; two tools keep the records
   independent. ADR-068 Phase 0A moves the census into `tools/verification/`, which is the
   moment to decide.
3. **What is the unit of a `new-proposition` disposition?** The continuation-store instance
   is five controls establishing one proposition. Nothing says a disposition may not be
   one-control-to-one-proposition, and at 626 symbols that would be a very different campaign
   from the one §3 illustrates.
