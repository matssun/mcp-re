<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-069 — six gates carry a theorem's proposition, and no unit's closure covers one

An estate-wide finding, produced by the Phase-1 root decompositions rather than by a search
for it. It supersedes the narrower version recorded in `residue-units-2026-09-18.md`, which
named two gates because two were what THM-0074's decomposition had reached.

## The measurement

Every `scripts/*_gate.py` in the tree, against every unit's `paths`:

```
total gate scripts:                                    38
gate scripts named in SOME unit's paths:                0
```

Zero is the whole finding for the build and process gates, and it is the correct answer for
most of them: `bazel_gazelle_gate.py` and `helm_render_gate.py` are not the production carrier
of any security proposition, and putting them in a unit's closure would say they were.

The question that matters is narrower: **which gates does a theorem name, in its own
statement, consequence or scope, as the thing that establishes it?** Measured over both
registries:

| gate | named by | that theorem's severity |
|---|---|---|
| `scripts/serving_product_provenance_gate.py` | THM-0051 | critical |
| `scripts/authorization_provenance_gate.py` | THM-0052 | critical |
| `scripts/serving_identity_provenance_gate.py` | THM-0080 | critical |
| `scripts/refusal_provenance_gate.py` | THM-0081 | medium |
| `scripts/python_runtime_gate.py` | **THM-0094** | critical — a declared system root |
| `scripts/node_runtime_gate.py` | **THM-0095** | critical — a declared system root |

Six carriers. None in any unit's `paths`, so none in any unit's fingerprint: **weakening a
rule in any of these six moves no digest and invalidates no attestation.** A standing PASS
survives the softening of the thing it was a PASS about.

## Why this is the sharp form of the defect

These are not gates that happen to be useful. Each is named by a theorem that also explains
why a TYPE could not do the job, and the explanations are specific:

* THM-0051 — `VerifiedMcpRequest` has public fields, and sealing is unavailable because the
  Verus obligation on `prepare_http_dispatch` reads `request_block` as a FIELD, which
  `#[verifier::external_type_specification]` refuses on a non-public field. A proved
  postcondition outranks a seal, so the seam stays open and the gate stands in the gap.
* THM-0081 — `ServedHttpResponse` is a wire frame that the async fleet, the blocking harness
  and external embedders all construct. "Privacy would buy nothing, and deleting the battery
  leaves an out-of-lifecycle exit compiling."

So in each case the gate is not a convenience over a seal that exists. It is load-bearing
*because* the seal is unavailable — which is exactly the situation in which it must be inside
the fingerprint, and is the situation in which it was not.

## The two that make this urgent rather than tidy

`python_runtime_gate.py` and `node_runtime_gate.py` are named by **THM-0094 and THM-0095**,
the Python and TypeScript SDK system roots — the two roots this campaign decomposed FIRST, and
the two Phase 2 was scheduled around. Their carriers have been outside every fingerprint in
the estate for the whole campaign.

## Disposition: REGISTER for four; NEW PROPOSITION for two

ADR-MCPRE-069 dispositions are REGISTER / REATTRIBUTE / NEW PROPOSITION / NOT EVIDENCE.

**A first version of this section said REGISTER for all six. That was wrong**, and the
correction is recorded here rather than quietly applied, because the two dispositions say
different things about the estate: REGISTER puts a control inside an EXISTING claim's closure;
NEW PROPOSITION says the estate is missing a claim.

### REGISTER — four, all done on the source-text falsifier branch

| gate | unit | theorem | falsifier |
|---|---|---|---|
| `serving_product_provenance_gate.py` | `proxy.dispatch_commitment` | THM-0051 | M151 |
| `authorization_provenance_gate.py` | `proxy.dispatch_commitment` | THM-0052 | M152 |
| `serving_identity_provenance_gate.py` | `proxy.serving_identity_provenance` | THM-0080 | M153 |
| `refusal_provenance_gate.py` | `proxy.refusal_site_totality` | THM-0081 | M154 |

Each already had an owning theorem and an owning unit, so nothing is reattributed and no
proposition is new. M153 also DISCHARGES an N1 obligation that was open at `critical`, against
the unit's own carrier rather than a probe pointed at whichever cargo control sat nearest — 75
open obligations to 73.

### NEW PROPOSITION — two, and this is why

`python_runtime_gate.py` and `node_runtime_gate.py` have no unit to be registered against.
Measured over every `sdk_python.*` and `sdk_typescript.*` unit: each is about a BEHAVIOURAL
proposition of the transport — exchange binding, verdict delivery, correlation lifecycle,
nonce floor, bounded read. Not one states the proposition these gates establish, which is a
SUPPORT claim: that the interpreters a package says it supports do not exceed the ones its
battery is measured on, and that a deploy image installing the shipped wheel names one of them
exactly.

Registering them against a transport unit would put a support-claim gate inside a behavioural
proposition's fingerprint and call the graph more precise than the measurement. The honest
disposition is that the estate is missing a unit.

Its own slice, and not bookkeeping: THM-0094 and THM-0095 are the roots directly above the
missing proposition.

## What this does NOT claim

That the other 32 gates should be registered. Most are not the carrier of any theorem, and
adding them would make the graph look more precise than the measurement. The criterion used
here is the one in the table: a theorem names the gate, in its own text, as what establishes
it. Four `*provenance*` gates match it and two runtime gates do; nothing else in the tree
does today.
