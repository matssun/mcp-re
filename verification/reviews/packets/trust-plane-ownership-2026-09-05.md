<!-- SPDX-License-Identifier: Apache-2.0 -->
# Census packet — the runtime trust plane: ownership and measurement

**One subject: what the request-trust plane establishes, who owns it, and what the word
"proved" was standing on.** ADR-MCPRE-059 §28 / ADR-MCPRE-061 §8. Layer 1 — evidence about
the tree, not an approval and not authoritative state. **No theorem is allocated here.**

The census finding this answers: `trust_plane/**` and `trust_epoch.rs` implement
security-bearing cross-replica trust behaviour; no assurance unit owned that runtime plane;
`docs/PROJECT_STATUS.md` described cross-replica trust revocation as proved. The two
acceptable ends were an owner with evidence for a bounded claim, or the documentation no
longer saying proved. This slice delivers the owner and the measurement, and narrows the
documentation to what was measured. Whether a theorem should exist is §15, and it is a
recommendation only.

Measured on branch `assurance/trust-plane-ownership` off `main` @ `26409b31`, 2026-09-05.

---

## 1. The production path

The plane is materialized once, by `TrustPlane::materialize` (`trust_plane/mod.rs`), from a
`TrustPlan` the configuration authority produced. In order:

| step | file | what it does |
|---|---|---|
| read `--trust` | `trust_plane/snapshot.rs` → `trust_document.rs` | one read, two products: an `InMemoryTrustResolver` and the `kid -> signer` map, published together as one `ReloadingTrustStore` snapshot (`reloading_trust.rs`) |
| build the channel | `trust_plane/mod.rs::build_trust_epoch_channel` → `trust_epoch.rs` | under `TrustEpochPlan::Redis`: `RedisEpochReader::connect` (an EAGER read; an unreadable or absent key refuses startup), one `TrustEpochSource` shared between a poller thread (`trust_epoch_poller_body`, cadence `TRUST_EPOCH_POLL_SECS = 5`) and the request path (`SharedEpochChannel`) |
| wrap the store in the tier | `trust_plane/revocation_resolver.rs` | `BoundedCache{T}` → `BoundedTrustCache`; `Live` → `LiveTrustResolver`; `Push{T}` → `PushInvalidationTrustCache` over the channel (or the inert `InMemoryInvalidationChannel` when none is planned) |
| start the reload | `trust_plane/reload.rs` | re-read `--trust` every `R` seconds, swap the snapshot atomically, keep last-good for at most `TRUST_RELOAD_FAILURE_BUDGET = 5` consecutive failures, then `mark_stale`; halt or panic → `mark_stale_permanently` |
| guard on freshness | `trust_plane/freshness.rs` | `StaleFailsClosed` wraps the tier resolver OUTSIDE the cache and answers `Unavailable` while the latch is stale |
| hand out | `trust_plane/mod.rs` | `resolver()` (the guarded, tier-wrapped resolver) and `signers()` (the read-only directory); `Drop` stales permanently, then halts the workers |

The request path: `app.rs::build_actor_resolver` (owned elsewhere) calls
`signers.signer_for(kid)` and then `request_trust.resolve(signer, kid)` per Request-slot
resolution. `Unavailable` crosses the seam as `ResolverOutcome::Unavailable`
(`mcp-re.trust_resolver_unavailable`); every other error is `NotTrusted`
(`actor_binding_failed`). Under the push tier, `resolve` first drains the channel
(`drain_pending`, a mutex take and no I/O), applies every event to the cache, then consults
the cache, then — on a miss — the snapshot.

**The counter has a second reader.** `signing_plane/mod.rs::DelegatedEpochWatch` reads the
same Redis key over its own connection, on the rotation loop's cadence, and turns the value
into the label delegated credentials are minted under (`<base>#<counter>`). That is the
RESPONSE side of the same operator action and it is not in this unit (§3, §13).

## 2. The state model the code holds

There is no single `TrustState` type. The semantic state of one replica is the product of
four separately owned pieces, each with its own transition authority:

**S — the store snapshot** (`ReloadingTrustStore`). A map `(signer, kid) -> Active(key) |
Revoked | absent`, plus `kid -> signer`. Transition: `store(next)` — the reload worker
only, on a successful read of `--trust`. Monotonicity: none; a reload may add, remove,
re-add or revoke. That is the operator's authority, exercised through the file.

**F — freshness** (`TrustStoreFreshness`), three states:

```text
Fresh ──(5th consecutive failed read)──▶ RecoverableStale ──(successful read)──▶ Fresh
  │                                             │
  └──(Drop / reload panic / halt observed)──▶ TerminalStale ◀────────────────────┘
                                                  (absorbing: mark_fresh is a no-op)
```

Read on every resolution by `StaleFailsClosed`. Terminal is terminal by construction:
`mark_fresh` checks the `terminal` flag first, and a straggling reload landing after `Drop`
cannot revive the resolver (measured, four ways).

**C — the cache** (`BoundedTrustCache`), per `(signer, kid)`:

```text
Absent ──(miss, store answers)──▶ Serving{outcome, deadline = now + ttl}
Serving ──(now ≥ deadline)──▶ Absent            (expired entries are ignored, then swept)
Serving ──(evict | FlushAll)──▶ Invalidated{deadline}   (deadline KEPT)
Invalidated ──(miss, store answers)──▶ Serving{deadline = min(now + ttl, old deadline)}
```

`Unavailable` is never stored. `ttl = T` for Active/Revoked and the short negative TTL for
NotFound/MalformedKey. The invariant the whole tier rests on: **a binding's deadline is
tighten-only** — no flush, eviction or re-resolution can move it later. Past the deadline,
with the store unable to answer, the resolver fails closed.

**E — the epoch source** (`TrustEpochSource`): `last_seen: Option<i64>`, `healthy`,
`pending: Vec<FlushAll>`, `last_poll`, `liveness_bound`.

```text
poll: read Ok(v), last_seen = None    → last_seen = v            (baseline; no event)
poll: read Ok(v), v ≠ last_seen       → push FlushAll; last_seen = v
poll: read Ok(v), v = last_seen       → nothing
poll: read Err                        → healthy = false; last_seen UNCHANGED
poller thread dies                    → healthy = false; last_poll = None
is_healthy = healthy ∧ polled within liveness_bound (4 × interval)
```

`v ≠ last_seen` is deliberately not `v > last_seen`: a regressed counter flushes. Rollback
is therefore **not representable** on this side — there is no high-water mark, and the
source cannot decline a value. The signing-side reader holds the opposite rule (refuse a
regression, never rebase) because minting under a lower epoch would resurrect credentials;
flushing under one can only tighten. Both are the fail-safe direction for their own
decision.

**Live tier**: no C at all; every resolution is `S` through `F`.

### What decides refusal versus continued service

| condition | outcome | owner |
|---|---|---|
| F stale (recoverable or terminal) | `Unavailable`, every request | freshness |
| C hit, within deadline, not invalidated | served from cache, store not consulted | cache |
| C miss / expired / invalidated, S answers | S's answer, re-cached under the ceiling | cache + store |
| C miss / expired / invalidated, S `Unavailable` | `Unavailable`, not cached | cache |
| E read error, E dead, E never polled | **no change to serving**; no flush; bounded by the deadline | source |
| `--trust-epoch-redis-url` set, key absent or store unreachable at startup | startup refused | materialization |

The last-but-one row is the finding that most changes the wording. `is_healthy()` is
consumed by **no production code** (`channel_is_healthy` has zero callers outside tests).
"Reverts to the bounded-staleness guarantee on a read outage" is not a transition the
resolver makes; it is the same deadline the entry carried while the source was healthy. The
health signal is a **witness** — it exists so a test and an operator can see the poller is
alive — not a **control**. That is honest, and it is now measured as such
(`a_source_outage_flushes_nothing_and_the_deadline_still_governs`).

### Is there an implicit state machine?

Yes, and it is per replica, distributed across four owners, related by call order in
`resolve` (drain → cache → freshness is actually freshness → drain → cache, since
`StaleFailsClosed` is outermost) and by the tighten-only ceiling. There is **no singular
semantic authority** over the product state and this slice does not invent one. The four
pieces have clear boundaries, each one's transitions are owned by exactly one writer, and
the only cross-piece invariant (the ceiling survives invalidation) lives in the cache and is
probed. Nothing here needs restructuring to be owned; it needed to be written down and
registered.

## 3. The semantic owner

`unit://proxy.trust_plane_runtime`, class V0, in `verification/policy/verification.toml`.
Closure: `trust_plane/{mod,trust_cache,push_trust,live_trust,invalidation_channel,
revocation_resolver,freshness,reload,snapshot,delivered_window}.rs`, `trust_epoch.rs`,
`reloading_trust.rs`. Deliberately excluded, with the reason at the entry:
`trust_plane/window_policy.rs` (no caller, no input), `trust_document.rs` (the parser — a
separate authority, and **owned by no unit today**), `signing_plane/**` (the response-side
reader), `startup_plan.rs`'s `TrustEpochPlan` and `app.rs`'s `build_actor_resolver` (owned
by the configuration and composition units). Evidence: `test://` and `mutation://`,
`test_features = ["redis_replay"]` so the reader's controls exist in the measured crate.

It is one replica wide by design. A "distributed trust" unit would own nothing the tree
holds.

## 4. The local property the unit establishes

For ONE replica, over its own store snapshot `S`, cache `C`, freshness `F` and source `E`:

1. A cached positive binding answers for at most `T` from the instant it was first cached,
   and never past that deadline, whatever is done to it in between.
2. A change of the epoch value **this replica's reader returns** strips every cached
   binding's authority before the next lookup, so the next answer for any binding is `S`'s.
   The flush revokes nothing by itself: over an unchanged `S` the same key re-caches under
   the old deadline.
3. A read failure, a dead poller, or a poller that never ran flushes nothing, changes
   nothing about serving, and holds the baseline so an advance during the outage is caught
   on the first successful read afterwards.
4. A regressed counter is a change and flushes.
5. `S` that has stopped being maintained (five consecutive failed reads; the plane dropped;
   the reload thread dead or halted) refuses with `Unavailable`; the terminal cases cannot
   be revived by a straggling reload.
6. Past its deadline, with `S` unable to answer, the resolver refuses; `Unavailable` is
   never cached.
7. The window the operator is told is `R + T` (or `UNBOUNDED` with no cadence), and under
   the push tier "within one poll interval" names a poller that reads at once and then on
   its cadence.

The request path performs no store I/O for the epoch and does not wait on a stalled read.

## 5. The foreign premise it requires

Exactly one, and only for the fleet-shaped sentence the code prints:

**ASM-0044** — a read of the trust-epoch key over a replica's own connection, issued after
an operator's `INCR` was acknowledged, returns a value different from every value that
replica read before the `INCR`. Read-your-writes across connections against one primary.
Not durability, not ordering between replicas, not simultaneity. A read that fails or
regresses is outside the premise and handled locally (§4.3, §4.4); a read that returns the
OLD value is the case the premise excludes.

What is NOT registered, because nothing in the tree claims over it: that the same
`--trust` document reaches every replica. `S` is per replica, read from a per-replica
file. Whether two replicas hold the same `S` is a property of the deployment's document
distribution (a ConfigMap mount, a rollout), and no MCP-RE code observes it. Any
cross-replica revocation claim would need this premise too, and it belongs to a boundary
the model does not declare (the filesystem / deployment renderer, which §4 of the security
boundary places outside the runtime roots).

## 6. Boundary mapping

- ASM-0044 → `boundary.shared_state_store`. `trust_epoch.rs` was **not** among that
  boundary's paths although `RedisEpochReader` holds a Redis connection of its own; it is
  now listed (a trust-inventory correction of the same kind as the 2026-08-11 clock
  correction, with the cap already at V0).
- `trust_plane/trust_cache.rs` already crosses `boundary.clock` (declared).
- `trust_epoch.rs` uses `Instant` for the liveness bound and `Duration` sleeps for the
  cadence: `boundary.monotonic_clock`, whose paths do not name it. No premise is registered
  because no claim above V0 rests on it; recorded here as the place one would attach.

## 7. Evidence inventory

Classification key: **U** unit/integration (in-process, default or feature lane);
**N** mutation / negative control; **L** live evidence (needs a provisioned backend);
**P** foreign premise (registered, not evidence).

| behaviour | evidence | class | lane |
|---|---|---|---|
| epoch advance → flush | `epoch_advance_emits_a_single_flush_all`; `an_observed_advance_makes_the_next_lookup_the_stores_answer` (NEW, source + cache composed); e2e `epoch_advance_on_redis_is_detected_as_flush_all` | U, U, L | lib; lib; `integration_ext` nightly |
| stale replica served until the advance | `channel_failure_falls_back_to_bounded_t_…`; negative control inside the new composition test; e2e step 2 | U, U, L | lib; lib; nightly |
| rollback / regression | `a_regressed_counter_flushes_rather_than_being_adopted_silently` (NEW) + probe M97 | U, N | lib |
| shared-store read outage | `read_error_marks_unhealthy_and_emits_nothing`; `recovery_after_outage_…`; `a_source_outage_flushes_nothing_and_the_deadline_still_governs` (NEW) + probe M96 | U, N | lib |
| push / live tier divergence | `revocation_resolver` wiring tests; `live_trust` tests; X8 (an epoch source under a non-push tier is unbuildable) | U | lib; `proxy.trust_configuration_state` |
| bounded staleness `T` | `no_indefinite_stale_active_past_window_fails_closed`; `active_re_resolves_after_window`; probes M94, M95 | U, N | lib |
| poll-interval bound | `the_poller_body_reads_at_once_then_on_its_cadence_and_stops_when_asked` (NEW — the body had **no test**) | U | lib |
| restart / rejoin | `first_poll_establishes_baseline_without_flush`; `restart_empty_cache_with_source_down_fails_closed`. A restarted replica re-reads `--trust` and starts with an empty cache, so there is nothing to flush; the baseline is adopted. No live restart evidence for this side | U | lib |
| cross-replica convergence | **none for the request-trust cache.** The e2e's "sibling" is one replica plus an admin connection; GKE Proof 2 is the signing-side label | — | — |
| invalid / missing epoch data | `an_absent_epoch_key_is_a_read_failure_not_epoch_zero` (NEW, `redis_replay`); e2e deletes the key and asserts the startup refusal | U, L | lib (feature); nightly |
| refusal when trust cannot be established | freshness transition tests, handle-lifetime tests, `a_frozen_store_stops_answering…` + probe M98; reload budget + probe M99; startup refusal (e2e only) | U, N, L | lib; nightly |
| dead poller | `a_poller_whose_read_panics_reports_the_source_unhealthy_at_once` (NEW); `a_source_that_stops_being_polled_stops_reporting_healthy` | U | lib |
| what an `INCR` means to another connection | ASM-0044 | P | — |

**Not in the battery, deliberately:** the Redis e2e self-skips by returning `ok` without a
store, so a `test://` member naming it would be a green that measured nothing. It is binding
only in `live-infra-e2e.yml` (nightly, `MCP_RE_REQUIRE_LIVE_INFRA=1`, not a required
check). It also drives `poll_once` by hand rather than the poller thread, so it does not
measure the poll-interval bound.

## 8. New negative controls

Eight mutation probes, M92–M99, each deleting one conjunct of the unit description and each
observed to turn a named control red (`tools/verification/verify-mutations`):

| probe | weakening | red control |
|---|---|---|
| M92 | drain not applied before the lookup | pushed-invalidation, flush-all, composition |
| M93 | an invalidated entry keeps answering | flush-all, evict, composition |
| M94 | the ceiling is not inherited | the three deadline tests |
| M95 | the window never closes | past-T fail-closed, re-resolve, fallback, outage composition |
| M96 | a failed read leaves `healthy` true | read-error, recovery, outage composition |
| M97 | `!=` becomes `>` | regression flush |
| M98 | the freshness guard is inert | frozen store, straggler, two handle-lifetime tests |
| M99 | the budget is off by one | exactly-the-fifth |

Five new tests, listed under NEW in §7. Nothing else was added; in particular no test was
written to make the documentation sentence true.

## 9. What cross-replica behaviour is demonstrated today

For the **request-trust cache: none with two replicas.** What exists is one replica whose
cache is flushed by an `INCR` from a different connection (live, nightly), and the
in-process composition of the same types. For the **delegated-signing epoch**: the GKE
Proof 2 shows a sibling refusing a credential minted under the pre-bump label, which is a
verifier-side `accepted_epochs` check against the label the signing plane minted — a
different mechanism with a different owner, and the status prose had folded it into this
bullet.

## 10. Revocation-lag bounds

The only bound the tree establishes is the one the code prints and `delivered_window.rs`
states as arithmetic: a key removed from `--trust` stops resolving within **`R + T`** (five
cadences more while reloads fail, then fail-closed), or **never** without a cadence. The
epoch does not shorten it: a flush observed before the reload lands re-caches the still-
active key under the original deadline (tighten-only keeps the deadline, but the deadline
was `T` from the first caching). Only an `INCR` polled AFTER the reload swapped `S` makes
the removal visible before `T`. So "flush within one poll interval of an advance" is a
bound on the **flush**, established by the poller test plus ASM-0044, and not a bound on
the **revocation**, which stays `R + T`. The startup line already says both; the status
bullet said less.

## 11. Same state, or constrained projections?

Constrained local projections. Two replicas share nothing but the counter's value, and the
value is not trust state — it is an opaque change signal that does not name what changed.
Each replica holds its own `S` (its own file), its own `C`, its own `last_seen`, its own
`F`. Two replicas may legitimately differ in all four. The relation the code allows between
two healthy replicas after one `INCR`: each flushes within one poll interval of its own
read returning the new value (ASM-0044), and after that each answers from its own `S`.
Nothing relates the two `S`. The event that closes the `C` divergence is each replica's own
poll; the event that closes the `S` divergence is outside MCP-RE.

## 12. Does "proved" survive?

**No — overstated and narrowed.** Of the four classifications offered:

- *supported as an executable/assumption-composed invariant*: the one-replica property is,
  now, under `proxy.trust_plane_runtime` with ASM-0044 for its fleet-shaped sentence;
- *supportable after one missing result*: a cross-replica statement about the CACHE would
  need (a) the per-replica document premise of §5 registered against a boundary that does
  not exist, and (b) evidence with two real replicas — two results, not one;
- *overstated*: "across replicas", "proves", "reverting … on a read outage" as if it were a
  transition, and the conflation with the signing-side GKE proof;
- *false*: nothing in the bullet was false of one replica.

`docs/PROJECT_STATUS.md` now says what §4 says, names the unit and the premise, and states
that no two-replica behaviour of the cache is demonstrated. The section header no longer
says the fleet "proves" its coherence guarantees; which guarantees are claims is the
security boundary's, and the replay one is (THM-0092).

## 13. Duplicated authority, rollback paths, fail-open

- **One foreign fact, two acquisitions.** `TrustEpochSource.last_seen` and
  `DelegatedEpochWatch.high_water` are two baselines over the same key, read over two
  connections on two cadences (5 s; the rotation loop), with opposite regression rules
  (flush; refuse). There is no invariant relating the two observations and nothing orders
  "stop minting under the old epoch" against "flush the request cache". Reported as ADR-061
  §8 question 10 (a fact represented twice), **not** as a defect: the two decisions are
  independent, each rule is the fail-safe direction for its own consumer, and forcing one
  reader would couple the response plane's minting to the request plane's poller. No
  restructuring is proposed.
- **Rollback**: not representable on the request side (§2); refused on the signing side
  (measured there, `a_regressed_counter_is_refused_not_rebased`, outside this unit).
- **Fail-open**: none found. The one place that looked like one — an unhealthy source
  changing no behaviour — is bounded by the deadline in both states and is now pinned.
- **A produced-but-unconsumed value**: `channel_is_healthy` / `is_healthy` — WITNESS.
- **An owner-less parser**: `trust_document.rs` belongs to no unit. Recorded; not absorbed.
- **A boundary path omission**: `trust_epoch.rs` under `boundary.shared_state_store`,
  corrected.

## 14. Recommended assurance class

The tree's vocabularies (no lettered scheme exists in the repository; stated in both that
do):

- ADR-MCPRE-059 §9 class: **V0**, and V0 is the honest ceiling. The load-bearing facts are a
  tighten-only integer comparison and a three-state latch — proof-shaped — but they are
  woven through `Mutex`/`RwLock`/thread state that neither lane models, and the property
  a reader cares about is the composition, not the arithmetic.
- §28 terminal, if a packet ever attaches it: the one-replica property is **STRUCTURAL +
  tested** with a real owner; the fleet-shaped sentence is **ASSUMED** through ASM-0044;
  the cross-replica cache property is **OUT_OF_SCOPE** of any claim the tree can state
  today, and would be a **GAP** if a root were ever ruled to require it.

## 15. Should a theorem exist later?

**Yes, one, narrow, and not yet.** A theorem stating §4 items 1–6 for one replica —
"a request-signer binding this replica serves is one its current trust snapshot admitted
within the last `T` seconds, or a live answer; an unmaintained snapshot serves nothing" —
would have a real owner, a closed evidence closure, and no foreign premise for its
statement (ASM-0044 attaches only to the poll-interval sentence). It would compose under
THM-0074 (the request-pipeline root) beside THM-0092 in the same shape: a local
fail-closed claim with the store's meaning carried per mechanism.

**Not** a cross-replica theorem. The census candidate "cross-replica trust-epoch
propagation" names a property the tree cannot state without a per-replica document premise
against an undeclared boundary and two-replica evidence that does not exist. Ruling it in
would create a GAP with no owner able to close it; leaving it as a census finding is the
honest state, and §4 of the security boundary already says exactly that.

The theorem waits for an owner ruling on this packet. Nothing in this slice pre-empts it.

---

## Amendment — 2026-09-05, the one-replica theorem (THM-0097)

Owner ruling on this packet: accepted; one subordinate theorem authorized for §4 items 1–6,
strictly local, composing under THM-0074, with ASM-0044 kept OUT of its closure.

Assumption reach is derived scope → unit → theorem, so a theorem supported by a unit that
holds `trust_epoch.rs` would carry ASM-0044 whatever the theorem said. §3's closure is
therefore split: `proxy.trust_plane_runtime` keeps the plane, the tiers, freshness, the
reload, the snapshot types and the `InvalidationChannel` seam — the REACTION to an event —
and the new `proxy.trust_epoch_source` owns `trust_epoch.rs` alone, the PRODUCTION of an
event from a foreign read, with ASM-0044 scoped to it and probes M96/M97 re-homed. The
runtime unit's closure now names no assumption. Everything else in this packet stands.

THM-0097 is registered with `depends_on = []` and added to THM-0074's `depends_on`. That
edge moves THM-0074's `theorem_dependencies` component, so its standing specification review
no longer covers its fingerprint until the owner records a dependency-only re-affirmation,
as was done for THM-0077 on 2026-09-03. The claim-surface gate refuses the tree until then;
the theorem PR is meant to stop there.
