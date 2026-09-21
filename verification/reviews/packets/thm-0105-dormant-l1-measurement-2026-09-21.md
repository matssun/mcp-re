# ADR-MCPRE-068 Phase-1 — THM-0105's disclaimer stated two things that were false

## Why this is investigated separately

`THM-0105` is the **second** theorem on this branch whose own `theorem_claim` moved, and a
dependency-correction record cannot cover it. It is not in any other theorem's dependency
closure — measured across all 130 registry theorems, **nobody** holds `THM-0105`, so it moves
only itself and starts no cascade.

## What changed: one paragraph of `scope`, inside a disclaimer

The paragraph is `NOTHING ABOUT THE DORMANT L1`, whose job is to state what the theorem does
**not** claim.

**Before** (`sha256:259d868c…`):

> NOTHING ABOUT THE DORMANT L1. `L1FastRejectStore` is defined and DORMANT — `app.rs` installs
> the L2 directly on every backend, nothing outside `async_replay_test` constructs an L1, and
> no configuration surface selects one. It is excluded from the owning unit's paths, and the
> `async_replay_test` battery is NOT cited here: all five of its controls construct an L1, so
> that battery cannot back a claim about the composition that ships. The L1's own
> never-`Fresh` invariant stays a documented property of dormant code, claimed by nothing.

**After** (`sha256:eca4e8b3…`): the same paragraph with two factual clauses corrected.

## Defect 1 — the installation site

The old text said *"`app.rs` installs the L2 directly on every backend"*. Measured: `app.rs`
does **not** install it. `mcp-re-proxy/src/app.rs:567` says so in its own words —
*"`replay_plane` only establishes it"*. The establishment lives at
`replay_plane/backends.rs` (`establish_etcd`, `establish_redis`) and the hand-over at
`replay_plane/materialized.rs` (`materialize` → `assert_durable` → `into_parts`).

The new text names those two sites.

## Defect 2 — "all five of its controls construct an L1"

Measured in `mcp-re-proxy/tests/integration_async/async_replay_test.rs`:

| control | line | constructs an L1? |
|---|---|---|
| `l1_fast_rejects_known_replay_without_consulting_l2_again` | 118 | **yes** (`L1FastRejectStore::new`, :125) |
| `l1_eviction_never_causes_a_false_fresh` | 154 | **yes** (`L1FastRejectStore::with_capacity`, :158) |
| `l2_outage_fails_closed_and_recovers_clean` | 188 | no — `FaultInjectingL2` over `DurableL2` |
| `cross_core_exactly_one_fresh_under_concurrency` | 226 | no — `DurableL2` |
| `distinct_keys_are_each_fresh_once` | 264 | no — `DurableL2` |

`grep "L1FastRejectStore"` over that file returns exactly **two** construction sites. "All
five" was false; it is **two of five**.

`DurableL2` is a double over `InMemoryAsyncAtomicReplayStore` that overrides
`durability_class()` to return `Durable` — the file's own doc comment calls it *"the reference
L2, declaring the durability posture the production composition ACCEPTS"*, because
`assert_durable` refuses a tier declaring `SingleProcessReference`. So the new text's
description — *"the other three drive the reference L2 behind a double declaring the accepted
durability class"* — is what the file does.

## Why correcting a disclaimer's justification does not narrow the disclaimer

This is the risk worth naming: **narrowing a disclaimer expands the claim.** It does not
happen here. The disclaimer's operative sentences are byte-identical:

- *"NOTHING ABOUT THE DORMANT L1"* — unchanged;
- *"It is excluded from the owning unit's paths"* — unchanged;
- *"the `async_replay_test` battery is NOT cited here"* — unchanged;
- *"so that battery cannot back a claim about the composition that ships"* — unchanged;
- *"The L1's own never-`Fresh` invariant stays a documented property of dormant code, claimed
  by nothing"* — unchanged.

What moved is the **measurement offered in support** of those sentences. The conclusion is
reached by a different and now-true route: previously *all five construct an L1, therefore the
battery is unusable here*; now *two construct an L1 and three drive a double rather than the
shipping composition, therefore the battery is unusable here*. The battery is cited by nothing
either way, and the L1 remains claimed by nothing.

Note that the corrected version is if anything a **stronger disclaimer**, because it concedes
that three controls do drive the reference L2 and still declines to cite them. It admits more
and claims less.

## Field-by-field derivation

| field | before → after |
|---|---|
| `statement` | **byte-identical** |
| `security_consequence` | **byte-identical** |
| `scope` | two factual clauses in the `DORMANT L1` disclaimer corrected; every operative sentence byte-identical |
| `depends_on` | **unchanged**, no edge added or removed |
| `review_requirement` | **unchanged** |
| `direct_consequence_severity` | `medium` → `medium` |
| `supported_by` | **unchanged** |

## Why the ruling covers it

Squarely the named case: *old wording overstates or misdescribes what production
establishes*. Both corrected clauses were false of the tree — one about where the store is
installed, one about how many controls construct an L1 — and neither weakens, removes nor
materially expands the accepted promise, because the promise is in the statement and the
consequence, both untouched.

## What this record is not

Not an owner specification review. `THM-0105` reports `STALE_CLAIM` after this correction, and
should: a human has not read this text. Merge path proceeds on the record; the release path
still asks.
