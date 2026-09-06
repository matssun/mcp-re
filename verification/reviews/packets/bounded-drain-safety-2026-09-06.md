# Bounded drain — the safety half, separated from timing — 2026-09-06

Backlog item 6 of the v0.17 AFK mandate: "bounded-drain safety, separated from
timing/liveness". MCPRE-115 / ADR-MCPRE-051 §6 specified the bounded graceful drain and its
battery has been a **named release gate** in `ci.yml` ever since. What was missing is that
the battery belonged to no `[[unit]]`, so what it measured was evidence for nothing, and no
statement anywhere said which half of it is a safety property and which half is a stopwatch.

Baseline: `assurance/tls-propositions` head `254c7e3e` (#821: THM-0102/THM-0103) on main
`8695d06c`. Slice branch `assurance/bounded-drain-safety`.

## 1. The mechanism

```text
shutdown signalled
  → the accept loop exits              (no request admitted after the signal)
  → admission.drain(drain_grace)       while in_flight_requests > 0, poll
  → the core's runtime is dropped      tasks still at an await point are cancelled there
```

`InFlightGuard` is taken in `async_serve/request.rs` **before the body is read** and released
by `Drop` when the task ends. Its construction is the only increment and its `Drop` the only
decrement, so the count cannot disagree with reality in either direction. A request stalled
in its body read therefore counts as in flight — which is why the grace exists at all.

## 2. The two halves, and which one is a theorem

| control | asserts |
|---|---|
| `in_flight_request_completes_during_drain_zero_abandoned` | **safety** — status 200 for a request in flight at the signal (+ a wall-clock tail) |
| `saturated_drain_completes_all_in_flight_zero_abandoned` | **safety** — all *n* answered (+ a wall-clock tail) |
| `a_request_abandoned_by_the_grace_never_reaches_the_handler` | **safety** — handler entry count is 0 after the join, and still 0 after holding the connection open 300 ms longer |
| `the_handler_entry_counter_moves_for_a_request_that_is_not_abandoned` | the **vacuity control** (ADR-MCPRE-057 §17.6) — without it a handler that was never wired satisfies the row above by running nothing |
| `idle_drain_returns_promptly` | **timing** — `join < 3 s` |
| `stuck_request_cannot_delay_exit_past_grace` | **timing** — `join < grace + 3 s` |

THM-0104 claims the safety half only: **every admitted request ends answered or never
executed; there is no third state in which the handler ran and the client was not answered.**
The scope names the three wall-clock bounds, says they are measurements on the box that ran
them, and says a red from one of them is a statement about the machine rather than about the
property. The bounded-exit guarantee an operator configures (`drain_grace` under a Kubernetes
termination grace period) is that timing property, and is therefore **not** claimed.

The cancellation half is **structural** — a task suspended at an await point when its runtime
is dropped is not polled again — so it has no deletable check and carries no probe. Said so
in the scope rather than left for a reader to notice.

**Outside every root's closure**, on THM-0012's precedent: no root's dispatch or response
claim rests on what shutdown does to work already admitted, and an edge asserted for
tidiness would make a root's closure claim support it does not have.

## 3. A platform defect the slice uncovered, and fixed

The first probe over this battery returned:

```
MEASUREMENT FAILURE — expected control(s) [...] were never reported by the run.
The lane cannot say the weakening broke a test it did not watch execute.
```

`verify-mutations` built its battery command without `--features`, so a unit declaring
`test_features` had its controls compiled to **zero tests**: `cargo test` exited 0 having run
nothing, and the adjudicator correctly refused to call that a red. The lane was blind to
every feature-gated battery, and reported its own blindness as a failure of the probe.

It never made a probe pass wrongly — the refusal is the right behaviour given the input — but
it made a whole class of conjunct unprobable. `verify-mutations` now passes the unit's
`test_features` exactly as `verify-tests` already did, for the reason stated there: Cargo
compiles a different crate per feature set, so a control behind `#[cfg(feature = …)]` does
not exist without it.

This is the same defect class the project already records twice — `tls_load_harness_bench`
selecting zero tests and exiting 0, and `async_drain_test` compiling to nothing under a plain
`cargo test --workspace`. Consequence: the lane's own digest moved, so every unit carrying
`mutation://` evidence re-attests. All fourteen `tools/verification/test_*.py` suites were
re-run.

`proxy.trust_epoch_source` is the only other unit declaring `test_features`; its probes
M96–M97 name controls that exist without `redis_replay`, which is why they passed before.

## 4. Lane identity, measured rather than assumed

The battery exists only under `async_serve`; the unit names it in `test_features`. The Bazel
target additionally sets `RUST_TEST_THREADS=1`, which is a property of a binary. Measured on
2026-09-06, the battery passes identically both ways — 9 tests, 0.88 s and 0.93 s parallel,
2.77 s serial — so registering it under the cargo lane does not import the timing fragility
that setting exists to avoid. The bounds the timing controls assert (3 s, 5 s, grace + 3 s)
sit far above the whole battery's runtime.

## 5. Evidence

| conjunct | control | probe |
|---|---|---|
| the drain waits while any request is in flight | the two zero-abandoned controls | M119 (`while false`) |
| a request is counted in flight from before its body is read | the same two | M120 (the guard's increment deleted) |
| an abandoned request never reaches the handler | `a_request_abandoned_by_the_grace…` + the vacuity control | structural (task cancellation) |

No production code changed and no test was added.

## 6. Recorded, not absorbed

The three non-UTF-8 header controls in the same test binary
(`a_non_utf8_header_value_is_refused_at_the_boundary`,
`a_duplicated_non_utf8_header_is_refused_rather_than_silently_deduplicated`,
`ordinary_header_values_still_reach_the_handler`) are a **boundary-refusal authority sharing
a binary**, not drain evidence. They belong to no unit. Recorded here as a separate finding
rather than absorbed to make this unit's battery look complete.
