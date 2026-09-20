<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-146 / NP-197 — ratification packet: the budget-refusal report, and the dormant L1

**Disposition:** R6 for all four controls. Nothing landed. Three stay NP-146, whose record is
rewritten around what they actually are; one is split out under RR-002 C5 as **NP-197**.

The slice plan expected three of the four appended to `proxy.async_replay_retention` as a
`tested_symbols` addition, on the stated premise that both carrier files are already in that
unit's `paths`, with the instruction to verify it before adding anything. Verified, and it is
false.

## 1. The premise, measured

`proxy.async_replay_retention`'s `paths`:

```
mcp-re-proxy/src/async_replay/mod.rs
mcp-re-proxy/src/async_replay/bounds.rs
mcp-re-proxy/src/async_replay/charge.rs
mcp-re-proxy/src/async_replay/in_memory.rs
mcp-re-proxy/src/async_replay/local_refusals.rs
mcp-re-proxy/src/async_replay/retained_set.rs
mcp-re-proxy/src/async_replay/retention_ledger.rs
```

`async_replay/budget_report.rs` is not among them, and it exists — the directory holds
`budget_report.rs` and `l1_fast_reject.rs` beside the seven. So two of the three selectors
would name a module the unit does not measure, which `verify --manifests` refuses, and
widening the `paths` is outside this campaign's authority in terms. It is not that shape.

## 2. And the third would not have landed either

`lib#async_replay::retention_ledger::tests::a_budget_refusal_is_rendered_without_the_ledger_lock`
IS in a measured file, so the mechanism would accept it. The claim does not.

THM-0105 is the retention ACCOUNT, in four movements: charged first and to the principal, a
share that leaves an unspendable reserve, handed back only by an authoritative `Replay`, and

> Every refusal on this path — over budget, over ceiling, an already-stale `retain_until`, a
> poisoned lock — is `Unavailable`, never `Fresh`.

Which lock a DIAGNOSTIC is rendered outside of is not a conjunct of any of the four. The
operational test settles it: every clause of THM-0105 holds under an implementation that
renders its line inside the guard — the charge is still reserved before the store round
trip, still charged to the principal, still kept on an unknown outcome, and every refusal is
still `Unavailable`. What such an implementation would lose is that the diagnostic cannot
stall or poison the tier, which is this record's proposition and nobody else's.

Filing it with the other two is therefore correct rather than convenient: all three are one
proposition about the reporter, and C5's objection is to heterogeneous records, not to
coherent ones.

## 3. What the three are, restated honestly

The record's original title — *refusal reporting is bounded, counted in full, and never
panics* — reads as three separate properties. The carrier says why they are one:

> **Outside the guard.** Both callers decide under a mutex that every serving core shares. A
> blocking stderr write inside it serialises the whole tier behind a file descriptor the
> proxy does not control, in a future with no await point, on a path any signature-valid
> peer can drive.

> **Non-panicking.** `eprintln!` panics when the write fails — a closed pipe, a full buffer
> with a dead reader. Unwinding at the refusal site would do it with the guard held,
> poisoning the mutex permanently, after which every reserve on the replica refuses for the
> process lifetime.

One proposition: the line that makes a budget refusal distinguishable from a store outage
must not be able to take the control down. The pacing clause is the same shape — an
over-quota peer drives the refusal per request, and one line per refusal hands that peer the
write rate of the process's stderr — with the counting half as its non-vacuity condition:
suppressing output must not suppress the count.

## 4. Why it is not ND-014 either

S-11 creates a `not-evidence` family for an inert measurement apparatus no production path
reads. These three are NOT admitted by it, and stating that is part of founding the family.
Conjunct 1 fails: the output is not elapsed time or counts about the process's own
execution, it is a sentence about why a SECURITY CONTROL refused, and the wire token
deliberately does not carry it (*"The wire token is frozen and says only
`replay_cache_unavailable`, which is also what a genuine backend outage says"*). Conjunct 3
fails too: the reporter is not something an operator switches on — the first refusal is
always reported.

RR-002 closes the other direction before it opens. A family built around what a blocking
write costs a shared tier would have an admission test turning on throughput and
concurrency, which is the axis that review forbids a family to be created or widened along.
A proposition is the only honest place left.

## 5. NP-197 — split under RR-002 C5

`lib#async_replay::l1_fast_reject::tests::l1_fast_reject_never_fresh_and_evicts_fifo`.

THM-0105's scope excludes it by name and explains the exclusion at length:

> NOTHING ABOUT THE DORMANT L1. `L1FastRejectStore` is defined and DORMANT — `app.rs`
> installs the L2 directly on every backend, nothing outside `async_replay_test` constructs
> an L1, and no configuration surface selects one. It is excluded from the owning unit's
> paths, and the `async_replay_test` battery is NOT cited here: all five of its controls
> construct an L1, so that battery cannot back a claim about the composition that ships. The
> L1's own never-`Fresh` invariant stays a documented property of dormant code, claimed by
> nothing.

That last sentence is this record: the property is real, the scope names it, and nothing
claims it. It is a different proposition from the reporter's — dormant code's invariant
versus a live path's diagnostic — so C5 forbids one disposition over the pair.

It is deliberately NOT dispositioned `not-evidence` under ND-011 (*a carrier the legality
model admits no deployment to reach*). The L1 is not refused by the legality model; it is
simply not wired. The day `app.rs` installs one, the invariant becomes load-bearing on the
serving path, and a family that had absorbed it would have to be unwound. A proposition
that says "claimed by nothing, and here is what it is" survives that transition unchanged.

## 6. What would discharge each

**NP-146.** A theorem over the refusal diagnostic: that the mechanism which makes one
over-quota actor visible cannot itself stall or poison the tier it reports on. Its battery
is the three controls above, and registering it would also need `budget_report.rs` brought
into some unit's `paths` by the owner rather than by a campaign.

**NP-197.** Either a theorem over the L1's own invariant, or the L1's deletion — and the
second is the better outcome while nothing constructs it.
