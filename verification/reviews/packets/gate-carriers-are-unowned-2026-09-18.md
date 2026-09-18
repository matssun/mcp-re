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

## Disposition: REGISTER, all six, by the mechanism now available

ADR-MCPRE-069 dispositions are REGISTER / REATTRIBUTE / NEW PROPOSITION / NOT EVIDENCE. This
is REGISTER for all six, and nothing else: each already has an owning theorem, so nothing is
reattributed and no proposition is new.

The mechanism is the `gate_controls` field and the `gate#` control form built on the
source-text falsifier branch, where the first two are registered against
`proxy.dispatch_commitment` with M151 and M152 as their falsifiers. The remaining four follow
the same shape:

| gate | unit to declare it | theorem |
|---|---|---|
| `serving_identity_provenance_gate.py` | `proxy.serving_identity_provenance` | THM-0080 |
| `refusal_provenance_gate.py` | `proxy.refusal_site_totality` | THM-0081 |
| `python_runtime_gate.py` | the THM-0094 SDK owner | THM-0094 |
| `node_runtime_gate.py` | the THM-0095 SDK owner | THM-0095 |

Not done in this packet, and deliberately: `gate_controls` does not exist on `main` yet, and
registering a field a branch has not landed would be a registry that names a schema the tree
does not hold. Sequenced behind the falsifier branch.

Note what registering these four also buys. `proxy.serving_identity_provenance` is currently
`tested` with no falsifier and an open N1 obligation at `critical`; a `gate#` falsifier over
its own carrier is the honest discharge of exactly that obligation rather than a probe pointed
at whichever cargo control sits nearest.

## What this does NOT claim

That the other 32 gates should be registered. Most are not the carrier of any theorem, and
adding them would make the graph look more precise than the measurement. The criterion used
here is the one in the table: a theorem names the gate, in its own text, as what establishes
it. Four `*provenance*` gates match it and two runtime gates do; nothing else in the tree
does today.
