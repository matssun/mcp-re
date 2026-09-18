<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — falsifying a source-text proposition, and the gate-control lane

This packet CORRECTS a conclusion recorded earlier in this campaign and then builds the one
piece that survived the correction. Both halves are measured; neither is asserted.

## What the earlier packet concluded

`verification/reviews/packets/residue-units-2026-09-18.md` reported that the Phase-1
one-owner-per-leaf residue was "ONE missing lane, not three units", on this argument:

> A source-text control cannot be falsified by a source-text mutation probe the way a
> behavioural one can: the probe edits the very text the rule reads, so a weakening that
> removes the matched substring turns the control red whether or not it changes behaviour,
> and a weakening that changes behaviour while preserving the substring does not.

That argument is sound, and it is about a narrower case than the packet applied it to.

## The distinction the argument turns on

It separates two things a source-text control can be doing.

**A source-text control standing in for a BEHAVIOURAL proposition.** Here the text is a
proxy, and the packet is right: redness under a text weakening measures the matcher, not the
behaviour, and reading it as evidence for the behavioural claim would be the false TESTED
classification this phase exists to remove.

**A source-text control measuring a SOURCE-TEXT proposition.** Here the claim IS about the
text, so a text weakening is not a proxy for the falsifier — it is the falsifier, and the
control going red is exactly the fact wanted.

Two of the three residue units are the second case, which is why they needed no new lane:

| unit | proposition | what it is about |
|---|---|---|
| `proxy.trust_composition_root` | THM-0067 — every field the root reads directly is a pinned ordinary parameter | which `values.<field>` reads exist in `app.rs` |
| `proxy.serving_trust_seam` | THM-0066 — the seam is built once from the materialized authority and holds no frozen map | what `app.rs` calls and captures |

Neither sentence quantifies over runs. Both quantify over the production text.

## Measured, not argued

Two ordinary probes, in the registry the campaign already has, against the controls the
units already declare:

```
ok   M149-composition-root-raw-read    THM-0067  red: tests/integration#composition_raw_read_test::
                                                      the_composition_root_reads_only_ordinary_validated_parameters
ok   M150-serving-seam-frozen-capture  THM-0066  red: tests/integration#serving_trust_seam_test::
                                                      the_seam_resolves_through_the_tier_rather_than_a_frozen_map
```

Both weakenings are the historical defect rather than a synthetic one. M149 reintroduces a
raw read of `max_clock_skew` — one of the six fields that LEFT the ordinary inventory on
measurement and became an owner (`FreshnessWindow`). M150 declares a `HashMap` in the seam
builder's body, which is the ADR-MCPS-021 defect by name: trust frozen at process start
behind a resolver chain whose guarantee is printed and dropped.

`proxy.trust_composition_root`'s N1 row is removed from
`config/assurance-obligation-debt.toml` as a consequence, and the gate — not this packet —
is what said it had to be: *"names an obligation that is no longer owed … Remove the row. A
dead row hides the next live one."* 75 open obligations became 74.

### What these probes do NOT establish

That the pattern is a faithful proxy for the behavioural property behind it. `app.rs` could
satisfy every rule and still compose the wrong thing. That gap is the premise the controls'
own module documentation already states — *"a scan is EVIDENCE for the composition, never
unconstructibility, and deleting it leaves the old defect compiling"* — and it is not
silently absorbed by a green probe.

## The third case is real, and the lane is for it alone

`proxy.dispatch_commitment` carries THM-0051 and THM-0052, whose production carriers are
`scripts/serving_product_provenance_gate.py` and `scripts/authorization_provenance_gate.py`.
`expect_red` may name only declared `tested_symbols`, and `verify-mutations` runs cargo. A
Python gate is neither, so the earlier packet's conclusion holds here exactly.

**The lane is a new kind of CONTROL, not a new evidence class.** The proposition shape is
unchanged — weaken production, require a declared control to go red — so it stays
`mutation://`, and N1 is satisfied honestly rather than by a vocabulary that makes the
obligation disappear. A unit declares `gate_controls`, a probe names `gate#<script>`, and the
lane runs the script over the weakened copy, translating its exit status into the same
`FAILED` / `ok` the adjudicator reads from a libtest line.

```
ok   M151-serving-product-second-verification  THM-0051  red: gate#scripts/serving_product_provenance_gate.py
ok   M152-authorization-transport-hint         THM-0052  red: gate#scripts/authorization_provenance_gate.py
```

A gate's own `--selftest` synthesizes violating text in a fixture, which says the matcher
works. These apply the regression to the REAL production tree, which is what says the rule is
load-bearing over it. The two are not substitutes.

### The false RED, which is sharper than the false green

The obvious runner records a non-zero exit as red. `python3 nothing.py` exits non-zero — so a
probe whose weakening DELETED or renamed the gate would be satisfied by the control's
disappearance. Measured on the first version of this runner, 2026-09-18, and now refused two
ways:

* a script that is not a file in the weakened tree is ABSENT, never red;
* a script whose stderr carries a traceback CRASHED rather than reaching a verdict, and is
  ABSENT too — the discriminator being the one thing a gate that reached a verdict never
  prints.

Absence is already a measurement failure in this lane. What was missing was the recognition
that absence can arrive wearing a red shirt. `test_a_gate_that_cannot_start_is_ABSENT_rather_than_RED`
and `test_a_gate_that_CRASHED_is_absent_rather_than_red` hold both.

Falsified in the other direction too: a weakening that introduces text the gate does not
refuse leaves the control green and the lane says so —

> M152 … but removing the check left every expected control green. The conjunct is NOT
> load-bearing in the declared battery — write a control, do not soften the statement.

## The ADR-MCPRE-069 disposition: REGISTER

Neither gate was named in any unit's `paths`. They are the production carriers of two
`critical` propositions, they run in `ci.yml` and in `local_gate.sh`, and until this change
softening a rule moved no digest and invalidated no attestation.

They are NOT added to `paths`, and the reason is recorded rather than left to be rediscovered:
a `.py` entry collapses a cargo unit's `unit_ecosystem` to `None`, and the test lane then
reports every one of that unit's `tested_symbols` as naming no runnable target — trading a
real defect for a larger one. The scripts enter the fingerprint as their own component,
present only on a unit that declares one, so the other 155 units' fingerprints do not move to
record an absence.

`_validate_gate_controls` then owes only what a digest cannot state: that the control exists
and can start. "Can start" is READABLE and not executable, measured rather than assumed —
both gates are invoked as `python3 <path>` by CI, by `local_gate.sh` and by this lane, and
`authorization_provenance_gate.py` is mode 100644 today and runs on every push. Demanding the
execute bit here would fail a control that starts perfectly well; that bit is
`merge_path_gate.py`'s question, about scripts invoked by path.

## The other gate carriers, and one disposition that is NOT REGISTER

A later Phase-1 root decomposition measured the same defect estate-wide: of 38 gate scripts,
ZERO are in any unit's `paths`, and SIX are named by a theorem, in its own text, as what
establishes it. The record is `gate-carriers-are-unowned-2026-09-18.md`. Four of the six are
registered here, each with its own falsifier:

| gate | unit | theorem | probe |
|---|---|---|---|
| `serving_product_provenance_gate.py` | `proxy.dispatch_commitment` | THM-0051 | M151 |
| `authorization_provenance_gate.py` | `proxy.dispatch_commitment` | THM-0052 | M152 |
| `serving_identity_provenance_gate.py` | `proxy.serving_identity_provenance` | THM-0080 | M153 |
| `refusal_provenance_gate.py` | `proxy.refusal_site_totality` | THM-0081 | M154 |

M153 discharges an N1 obligation that was open at `critical` — and discharges it against the
unit's OWN carrier rather than against whichever cargo control sat nearest, which is the thing
this phase exists to stop.

**The remaining two are a different disposition, and the earlier packet had it wrong.**
`python_runtime_gate.py` and `node_runtime_gate.py` are named by THM-0094 and THM-0095, and
that packet said REGISTER for all six. Measured: every `sdk_python.*` and `sdk_typescript.*`
unit is about a behavioural proposition of the transport — exchange binding, verdict delivery,
correlation lifecycle, nonce floor. **Not one states the runtime support claim**, which is
what those gates establish: that the interpreters a package claims to support do not exceed
the ones its battery is measured on, and that a deploy image installing the wheel names one of
them exactly.

So there is no unit to register them against. The ADR-MCPRE-069 disposition is **NEW
PROPOSITION**, not REGISTER — and the two are not interchangeable: REGISTER puts a control
inside an existing claim's closure, where NEW PROPOSITION says the estate is missing a claim.
Registering them against a transport unit would have put a support-claim gate inside a
behavioural proposition's fingerprint and called the graph more precise than it is.

Its own slice, and it is not merely bookkeeping: THM-0094 and THM-0095 are the two SDK system
roots, so the missing proposition sits directly under two `critical` roots.

## What this changes about the residue

The residue was three units. Two close with ordinary probes and no new machinery. One needed
the lane, and has it. The earlier packet's sentence "the three residue units and the two
orphaned gates close together" is superseded: they close, but in two groups and for two
different reasons, and conflating them would have built a new evidence class for a case that
did not need one.
