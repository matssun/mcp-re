<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-103 residue — R2 referral packet: the fleet-strict replay store class

**Disposition:** R1 in part, R2 for the residue — and a MEASUREMENT CORRECTION on the record
itself. Three controls landed in `unit://http_profile.replay_key`. Two `[[disposition]]` rows
remain and NP-103's `[[proposition]]` entry and record stay in place.

## The measurement correction

The record's title was *dispatch admits only what verified*, and its statement *what reaches
dispatch is what verification admitted, with nothing re-derived between*. All five controls
measure REPLAY: three are replay-key discrimination, two are replay-tier store-class
refusals. Nothing in the record is about dispatch admission. A record whose title names one
authority and whose controls measure another is a claim exceeding its evidence, so the
record now says so at `docs/architecture/control-dispositions.md#np-103`. A correction is
not a resolution and buys nothing: the two remaining rows are still owed a theorem.

## What landed, and the clause that contains it

`http_profile.replay_key`, `description`, verbatim:

> The ADR-MCPRE-050 replay five-tuple and its injective pre-serialization onto the core
> cache's three slots: equality of the composite slots holds exactly when the full
> five-tuple is equal, and an admitted key is fresh once.

`duplicate_nonce_same_actor_audience_profile_is_replay` is the second clause;
`same_nonce_different_audience_does_not_collide` and
`same_nonce_different_resolved_actor_does_not_collide` are the first, beside the battery's
existing `every_component_discriminates`.

## The residue, and why this slice may not land it

`tests/dispatch_test#{fleet_strict_admits_durable_cache,
fleet_strict_rejects_single_process_reference_cache}`.

THM-0092's statement already contains the clause, verbatim:

> replay admission refuses before any store side effect when the deployment declares no
> replay tier, declares one below the strict-production minimum, or **wires a store that
> self-reports the single-process reference class**.

So this is **R2, not R6** — the theorem already promises it. The obstacle is location:
THM-0092's only unit is `proxy.replay_admission_gate`, in the `mcp-re-proxy` Cargo project,
and these two controls are in `mcp-re-http-profile`. A unit's battery may select controls
only inside the source it measures, in the project it measures it in
(`tools/verification/verify --manifests` refuses otherwise), so widening
`proxy.replay_admission_gate.paths` across the project boundary is exactly the widening
ADR-069 §5 and R4's boundary rule forbid.

## Proposed shape — ready to apply, out of this slice's charter

New `[[unit]]`:

```toml
id = "http_profile.fleet_strict_store_class"
class = "V0"
description = "A fleet-strict deployment refuses a replay store that self-reports the single-process reference class, and admits a durable one — the store-class half of THM-0092's pre-side-effect refusal, measured where the http_profile dispatch path wires it."
paths = ["mcp-re-http-profile/tests/dispatch_test.rs"]
evidence_class = "tested"
direct_consequence_severity = "critical"
tested_symbols = [
  "tests/dispatch_test#fleet_strict_admits_durable_cache",
  "tests/dispatch_test#fleet_strict_rejects_single_process_reference_cache",
]
```

plus one line in THM-0092's `supported_by` and one `[[probe]]`
`mutation://http_profile/fleet_strict_store_class/reference_cache_refusal`, anchored on the
`DurabilityClass::SingleProcessReference` refusal arm, `expect_red` naming
`fleet_strict_rejects_single_process_reference_cache`.

Subsumption, all four clauses: **(1)** only `supported_by` moves, which is not a review
fingerprint component; **(2)** strict decomposition of the quoted conjunct; **(3)** no new
promise, boundary, assumption or behaviour choice; **(4)** no other theorem-level edit.

This slice's charter says *no new `[[unit]]`*, so it is prepared rather than applied. It
belongs in the S2 slice with the other new units.

## N1

Two rows, unregistered. `replay_key` keeps `mutation://http_profile/replay/key_injectivity`.
The new unit arrives with its own probe and adds no debt row.
