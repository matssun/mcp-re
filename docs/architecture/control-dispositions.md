<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 control dispositions

The durable records that `verification/policy/control-dispositions.toml` points at through
its `reason_family` and `proposition` fields. `tools/verification/control-census --gate`
fails when a cited record is absent, so a disposition points at a reason rather than at a
memory of one.

This is the same mechanism [ADR-MCPRE-061 §14](review-dispositions.md) uses for oversized
units, and a **separate register** for the reason the ADR-069 ratification gives: the two
authorities are different. 061 adjudicates *a unit that is too large*; 069 adjudicates *a
control that no proposition claims*. One register per authority is what keeps a record
citable by exactly one gate.

## What a record here settles, and what it does not

**A `not-evidence` family answers ADR-069 §8 question 1** — *is `not-evidence` load-bearing
enough to need a review record?* It is, and this is the record. D3 already requires a
reason and checks its shape; without somewhere durable to look the reason up, a large
`not-evidence` population and a campaign that gave up are the same artefact. A family
record states:

- what kind of control it covers, in terms a reader can check against a control;
- **why controls of that kind are not evidence for a security proposition** — which is a
  claim about the control's relationship to the production carrier, not about the control
  being unimportant;
- what would move a control OUT of the family, so the record is falsifiable.

**A record here grants nothing.** There is no exception state and nothing is excused from
the census: a `not-evidence` control is still measured, still enumerated, and still listed
under its family. What the record buys is that the reason is written once, reviewed once,
and cited by every row that relies on it — rather than retyped, slightly differently, 700
times.

**A `new-proposition` record is step 1 of ADR-069 §5 and no more.** It identifies a
proposition the graph does not hold and says what would establish it. It does not ratify a
theorem, and the campaign may not widen an existing unit to swallow it. Until the ordinary
ADR-MCPRE-059 §28 route registers it, it is visible unresolved assurance debt and the
census reports it as such.

---

## The families

## ND-001 — the assurance platform's own self-tests

**Covers:** every control carried by `tools/verification/test_*.py`.
**Scope:** `carrier-scope: admitted`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 1.

These are the controls that establish that a `verify` verdict means what ADR-MCPRE-059 says
it means: the verdict algebra, the invalidation rules, the measured-input closure, the
escape-hatch detector, the theorem loader and review model, the per-ecosystem lane adapters,
the structural and measured lanes' fail-closed-on-zero-execution behaviour, the premise
ontology, the severity derivation, and this census's own ability to see.

**Why they are not evidence for a security proposition, and the authority for saying so.**
ADR-MCPRE-068 states it directly:

> **Assurance TCB, not a product claim.** Everything here sits where issue #739 sits:
> outside the product theorem roots, inside the layer that decides whether the word
> `ESTABLISHED` may be believed. No entry in this record becomes a `THM-`.

That is the boundary, and it decides these controls. A test of `_verdict_algebra` does not
demonstrate anything about the proxy, the client or either SDK; it demonstrates that the
apparatus which reports on them computes what it says it computes. **Its failure invalidates
other evidence rather than falsifying a proposition** — which is exactly the relationship
that makes something an instrument rather than a witness. Nothing in the registry could
claim one of these without inventing a product promise about the measuring equipment, and
ADR-069 §5 forbids widening a unit to swallow a proposition it does not state.

**This is not the campaign giving up.** These controls are required on the merge path, they
are named one per line in `ci.yml` and `local_gate.sh` precisely so that
`scripts/merge_path_gate.py` can see them, and several of them are the only liveness a lane
has. What is being said is narrower and exact: *they are load-bearing for whether the
evidence may be believed, and they are not themselves evidence for any proposition the
product makes.*

**Why the disposition is carrier-scoped.** What makes these controls not evidence is a
property of the FILE's role — it measures the instrument — and that is true of every control
inside it and of the next one added. A control-scoped register here would record 595 copies
of one reason and would go stale the moment a lane grew a case. ADR-MCPRE-061's rule applies
unchanged: review granularity equals exception granularity, and the thing reviewed here is
the instrument.

**What would move a control out of this family.** Any control in one of these files that
demonstrates a property of a PRODUCT carrier — a proxy, client, core, http-profile or SDK
source file — rather than of the assurance platform. Such a control is misplaced rather than
misdispositioned: it belongs beside the carrier it is about, and its disposition is
`reattribute`, not this family.

## ND-002 — the SLO harness's own self-tests

**Covers:** every control carried by `tools/slo/test_*.py`.
**Scope:** `carrier-scope: admitted`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 1.

The load harness's host gate, environment preflight, run supervisor, evidence store, VM
participant and admission hook. Same boundary as ND-001 and a sharper instance of it: these
controls exist so that a measurement is refused when the box cannot support one — the
`ALLOW_NOISY_BOX` case — and refusing to measure is the opposite of establishing something.

**Not to be confused with a `measured://` apparatus control.** ADR-MCPRE-068 §4.1 makes an
apparatus control part of a measured unit's declared evidence: the demonstration that the
number can still MOVE. That is a different control from these. `MSR-0001` carries such a
control (`the_measurement_moves_when_the_scanned_set_shrinks`) and it is registered. If the
SLO measurement is ever registered as `measured://`, its `measurement_control` will be a
sensitivity or reproducibility control on the number — not a test that the harness declines
to run on a busy machine.

**What would move a control out of this family.** A control here that IS the reproducibility
or sensitivity control of a registered `measured://` record. That control is that unit's
declared evidence and leaves the census by being named in the registry.

---

## The propositions

*(None yet.)*
