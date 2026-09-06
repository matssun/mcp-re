# The async replay store seam — the retention account, not the durability premise — 2026-09-06

The owner's ruling of 2026-09-06 names this the sensible next target after the #824
remeasurement: *"measure the shipping `AsyncAtomicReplayStore` composition directly; do not
cite dormant `L1FastRejectStore` composition as though it were deployed; exclude dormant
machinery honestly where appropriate; register the smallest owner; add only the missing
controls needed to distinguish the claim; create a subordinate theorem only if a useful
security proposition emerges from the measured seam."*

Baseline: main `af582442 (#825)`. Slice branch `assurance/async-replay-retention`.

## 1. What was already owned here, and what was not

| fact | owner before this slice |
|---|---|
| an unestablished replay state does not dispatch; the declared tier and the store's self-reported durability class both gate; outage is not replay | **THM-0092**, `unit://proxy.replay_admission_gate` |
| what a Redis acknowledgement or an etcd transaction durably established | **ASM-0040 / ASM-0041**, foreign premises registered per mechanism |
| the replay **stores** themselves — `async_replay/` (8 files), `shared_replay.rs`, `replay_tier.rs` | **nothing.** 0 of 10 files under any unit |

So the census phrase *"the durability-tier fail-closed claim has no theorem"* was already half
false when #824 re-measured it: THM-0092 states the gate's fail-closed order. What had no
owner is the **store seam's own contract** — and the part of that contract which is a
security proposition rather than a foreign premise is the **retention account**.

## 2. The measured composition, and the dormancy excluded from it

`app.rs` installs the L2 directly on every backend. Nothing outside `async_replay_test`
constructs an `L1FastRejectStore`, there is no configuration surface that selects one, and
the module documents this itself. **All five controls of `async_replay_test` — the named CI
release gate "§4 cross-core / cross-replica replay race" — construct an L1.** They are not
vacuous: the properties they exercise belong to the shared L2 beneath, and the L1 is
pass-through on a miss. But no control in that battery measures those properties on the
composition that ships, so **this unit does not cite it**, and `l1_fast_reject.rs` is
excluded from the unit's paths as dormant — the same precedent by which
`trust_plane/window_policy.rs` is excluded from `proxy.trust_plane_runtime`.

The L1's `L1-never-Fresh` invariant stays what it is: a documented property of
defined-but-dormant code, claimed by nothing.

## 3. The proposition that emerged, and the one that did not

**Did not.** A theorem over *"exactly one `Fresh` under concurrency"* would restate, at the
reference L2, what THM-0092 already governs at the gate and what ASM-0040/ASM-0041 carry for
the backends a production deployment actually selects. `app.rs` refuses any tier whose store
declares `SingleProcessReference`, so a claim proved only inside
`InMemoryAsyncAtomicReplayStore` would govern no deployment. Not stated.

**Did.** Retention is a **shared, bounded resource on every backend**, and only one of the
three backends has anything of its own to budget: Redis retention is a server-side
`SET NX PX` TTL and etcd's is a per-key lease, so neither holds a local set to bound. The
tier's ledger is therefore the **only** bound that governs the deployments that ship. That is
a security proposition — one signature-valid peer must not be able to deny replay protection
to every other signer on the replica — and it is measured.

**THM-0105.** *Replay retention is a bounded per-replica account, charged to the resolved
principal before the store is touched, and handed back only by an answer that proves this
insert retained nothing.*

## 4. The conjuncts, the controls, and the two controls that did not exist

Fifteen controls existed across these files and were named by **no unit**, so what they
measured was evidence for nothing. Registering them is most of this slice. Two conjuncts were
true and **unmeasured**, and each is a deletable line, so each gets a control and a probe.

| conjunct | control | probe |
|---|---|---|
| the charge is taken above the backend seam, before the round trip; an over-budget actor never reaches the store | `the_tier_budgets_a_durable_backend_that_budgets_nothing_itself` (the `dispatches()` count is the assertion) | M123 |
| charged to the RESOLVED PRINCIPAL, never the signer slot — one subject gets one budget however many keys it enrols | `one_subject_gets_one_budget_however_many_keys_it_holds` (**NEW**) | M121 |
| the share reserves headroom, so no number of actors can spend the reserve, and a quiet actor is still admitted while a greedy one is refused | `no_number_of_actors_can_spend_the_reserve`, `the_budget_reserves_headroom_and_splits_evenly`, `one_actor_cannot_spend_the_whole_ceiling_and_deny_another` | M123 |
| only an authoritative `Replay` hands a charge back | `a_replay_hands_the_charge_back` | M122 |
| a cancelled insert KEEPS its charge, on the entry's own `retain_until` timeline | `an_abandoned_insert_keeps_its_charge_because_the_write_may_have_landed`, `an_abandoned_insert_s_charge_expires_with_the_entry_it_may_have_created` | M122 |
| a store FAILURE is `Unavailable`, never a decision, and keeps its charge for the same reason | `a_store_failure_is_unavailable_and_keeps_the_charge` (**NEW**) | M122 |
| a charge is reclaimed when the retention it accounts for expires | `the_tier_releases_charges_once_their_retention_expires`, `a_committed_charge_is_returned_only_when_its_retention_expires`, `pruning_releases_the_per_actor_charge` | — |
| the reference L2 refuses rather than growing past its ceiling, evicts past `retain_until`, and refuses an already-stale `retain_until` pre-store | `the_async_store_refuses_rather_than_growing_past_its_ceiling`, `the_async_store_evicts_entries_past_their_retain_until`, `an_already_stale_retain_until_is_refused_pre_store`, `in_memory_store_is_fresh_then_replay_and_single_process` | — |

**Why the two new controls are not decoration.** Every pre-existing control in the module
presents **one key per actor** (`replay_key` builds `{actor}#key-1`), so a tier that charged
`key.signer` instead of `key.principal` would satisfy all fifteen — and enrolling keys is
cheap, so that defect hands one subject a fresh budget per key. And the error path had no
control at all: only cancellation was measured, so an implementation that released the charge
on `Err` — the exact "releasing on every non-`Fresh` exit" defect `charge.rs` documents —
went undetected. Both are the ADR-MCPRE-057 §17.6 shape: a conjunct a green battery holds
while nothing is load-bearing.

## 5. What THM-0105 does not say

Nothing about **cross-replica** durability, which is THM-0092's subject and ASM-0040 /
ASM-0041's premise. The account is **per replica** — it bounds the retention this node
admits, and the shared store's total is that bound times the fleet size — and the theorem
says so rather than reading as a fleet-wide bound.

Nothing about the deployable adapters' own behaviour: `async_redis_store.rs` and
`async_etcd_store.rs` remain unowned, and the honest reason the ledger sits above the seam is
precisely that neither bounds anything locally. Registering those adapters is the next item
on the ranked remainder, and it is an ASM-0040 / ASM-0041 question rather than this one.

Nothing about the dormant L1. Nothing about liveness: the claim is that an unfunded insert is
refused, never that a funded one succeeds.

Nothing about `shared_replay.rs` or `replay_tier.rs` — the SYNC twins. The async path is the
architecture (ADR-MCPRE-051); the sync tier is a separate composition with a separate
battery, and folding it in would make one unit's evidence answer for two authorities.

## 6. Composition — outside every root's closure, and why

No root's dispatch or response claim rests on how retention is apportioned between actors.
THM-0092's statement requires that an unestablished replay state does not dispatch; it does
not require the account that decides *which* actor gets to establish one. Asserting
`THM-0092 depends_on THM-0105` would move THM-0092's fingerprint and every ancestor's for an
edge the root does not need — the "missing-edge pass asks what the root requires" rule,
top-down and never registry-upward. So THM-0105 stands on the same footing as THM-0012 and
THM-0104: a real result, deliberately unattached.
