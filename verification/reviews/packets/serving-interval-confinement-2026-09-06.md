# Serving-interval confinement — 2026-09-06

Backlog item 3 of the v0.17 AFK mandate. The item's name has no single origin in the tree;
it was read as **the R + T exposure window a replica prints at startup** — the "serving
interval" the trust-plane census of 2026-09-05 (§4 item 7, §10) states as arithmetic and
that THM-0097 deliberately left outside its statement ("nothing here says how fast a change
to `--trust` reaches the snapshot — that is the reload cadence `R`"). The other candidate
reading, the propagation window `P` of a degraded admission verdict (theorem-architecture
packet O-11, THM-0005's scope), is an admission property with no trust-plane dependency
and is not this slice; it is listed under remaining gaps in the consolidated report.

Baseline: `assurance/asm-0029-local-discharge` head `a74f3a67` (#818: THM-0099) on main
`4c3ec92d` (#817: THM-0098). Slice branch `assurance/serving-interval-confinement`.

## 1. What was unstated

The startup transcript prints "worst case R + T" (`delivered_window.rs`), and the census
ruled that ceiling accepted. But the `R` in it named nothing measured: `trust_reload_loop`
had tests for its halt exit, for one cycle's swap and for the failure budget, and none for
the cadence itself. A loop that slept `10R` would have passed every control while the
transcript promised `R + T`. That is the same shape as the poller body before #815 — a
printed bound whose mechanism had no test.

## 2. What the loop is

```
loop {
    if halt.sleep(R) { freshness.mark_stale_permanently(); return }   -- exactly R, halt-aware
    consecutive_failures = trust_reload_cycle(...)                     -- one read
}
cycle: Ok  -> store.store(resolver, signers); mark_fresh; 0
       Err -> failures + 1; at 5 -> mark_stale (THM-0097's budget)
```

The first read is materialization's (`load_trust_snapshot`); every later read is one sleep
of `R` after the previous cycle completed. A panic in the worker marks the store stale
permanently (THM-0097's terminal case).

## 3. The theorem

THM-0100, "A replica's exposure to a key its document no longer enrols is confined to the
serving interval it prints". Owner `proxy.trust_plane_runtime`, `depends_on = [THM-0097]`,
composed at THM-0074 beside THM-0097/0098/0099. No assumption: the bytes at the path at read
time are the input, and when an operator's write reaches the path (a ConfigMap remount, a
volume sync) is outside the replica and said so. The sleep crosses
`boundary.monotonic_clock`, already declared for the unit.

| conjunct | control | probe |
|---|---|---|
| each cycle is one sleep of exactly `R` then one read, until halted | `the_reload_loop_reads_on_its_cadence_until_halted` (NEW: R = 1 s, a rotated key lands within 2.5 s, halt freezes the store) | M107 (sleep `10R`) |
| a successful cycle swaps the snapshot the resolver and directory answer from | `a_reload_cycle_replaces_the_map_the_resolver_answers_from` + the new control | M108 (swap deleted) |
| the printed window is `R + T` / `R` / `UNBOUNDED` | `a_caching_tier_states_the_cache_lifetime_on_top_of_the_store_cadence`, `a_store_that_is_never_re_read_delivers_an_unbounded_window` | M109 (`R` alone) |
| a removed pair is served at most `T` past the read that dropped it; the budget is five | THM-0097 | M92–M95, M98, M99 |

The exposure bound follows: `R + T` while reads succeed, `5R + T` across a failing stretch,
closed thereafter, and unbounded with no cadence — which is what the transcript says.

## 4. Non-claims

The read's own duration is not modelled (a read longer than `R` delays the next cycle by
that much). Nothing about the epoch counter or the push tier's flush, which can only shorten
the exposure. Not a liveness claim about requests. Nothing cross-replica: each replica's `w`
— the instant the new bytes are readable at its path — is its own.

## 5. Establishment

Probes M107–M109 red-verified on this tree. The merge condition is #817's and #818's:
ordinary CI green on the merge tree, then locally 99/99 theorems established and 12/12 roots
complete.
