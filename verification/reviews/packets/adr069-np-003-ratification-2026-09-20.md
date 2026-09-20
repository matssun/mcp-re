<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-003 — R6 ratification packet: every long-lived worker's lifetime is an owned value

**Disposition:** R6, referred with eight of nine controls. The ninth,
`gate#scripts/owned_worker_gate.py`, is re-dispositioned `not-evidence` under the EXISTING
family ND-007 (architecture shape rules) and is argued in §3 below.

**8 controls**, `mcp-re-proxy`, rust unit tests, **default cargo lane**, carrier
`mcp-re-proxy/src/managed_worker/`:

- `lib#managed_worker::halt::tests::a_raised_halt_never_becomes_unraised`
- `lib#managed_worker::halt::tests::either_source_alone_raises_the_halt`
- `lib#managed_worker::tests::a_worker_also_stops_when_the_deployment_stops`
- `lib#managed_worker::tests::a_worker_that_ignores_the_halt_is_bounded_and_named`
- `lib#managed_worker::tests::an_interrupted_sleep_reports_that_it_was_cut_short`
- `lib#managed_worker::tests::dropping_the_set_stops_a_worker_the_deployment_flag_never_stopped`
- `lib#managed_worker::tests::reclaiming_twice_is_harmless`
- `lib#managed_worker::tests::the_halt_stays_raised_after_the_set_is_gone`

Lane measured, not assumed: `cargo test -p mcp-re-proxy --lib -- --list` selects 1498
controls and all eight are among them.

## 1. What the carrier owns

`managed_worker/mod.rs` states its own contract and bounds it:

> 1. **Structural halt is raised for every owned worker.** Unconditional.
> 2. **Reclamation is bounded**, not guaranteed. Workers that stop within
>    [`JOIN_DEADLINE`] are joined; the deadline itself always terminates.
> 3. **A worker that does not stop in time is surfaced by name**, not silently detached.

and then says what it is NOT:

> (2) and (3) cannot both be absolute for an ordinary blocking OS thread ... A named
> straggler after a real attempt is a different thing from the silent detachment this
> type replaces, but it is not the same as "all workers are joined", and the docs and
> tests here must not claim that it is.

The eight controls are that contract's clauses, plus the two-halt-source separation
(`deployment` vs `owner`) and the late-straggler property the module documents.

## 2. Why THM-0104 does not reach it — the slice plan's expectation, and why it fails

The plan assigned these rows to THM-0104. THM-0104's subject is REQUESTS in the async
serving path. Its statement opens:

> ADMISSION STOPS. The accept loop exits before the drain begins, so no request admitted
> after the signal exists.

and continues about an `InFlightGuard`, a count, and a bounded drain. Its scope closes the
door explicitly:

> ONE core, and the async path.

A `WorkerSet` worker is neither an admitted request nor a per-core runtime task, and the
gate that guards this very invariant says the two are different lifetime questions:

> Tokio tasks on the per-core serving runtimes are a different lifetime question — the
> fleet owns its runtimes and joins them on drain — and are deliberately out of scope.

The operational test settles it in one line: every clause of THM-0104 holds under a build in
which `WorkerSet` does not exist and every background thread is detached. Nothing about
admission, the in-flight count, the bounded drain or terminal cancellation changes.

## 3. No other ratified theorem contains it either — measured

All 130 `[[theorem]]` rows were swept for `thread`, `worker` and `teardown` vocabulary
across `title`, `statement` and `scope`. Nine matched, and eight match on unrelated senses
of the words. The one that is genuinely adjacent is THM-0012, and this record already
excluded it before the slice began. THM-0012's scope:

> Establishes what the RECORD can say.

That is the boundary NP-003's own root relationship names: a recorded terminal `Stopped`
that leaves threads minting keys is the thing THM-0012 is ABOUT, and is not what it STATES.
Subsumption clause 2 requires a proposition contained in a ratified claim. There is none, so
a unit here would be a twenty-first theorem-less unit, which C1 forbids.

## 4. The gate is ND-007, and the register's own secondary test is why

`scripts/owned_worker_gate.py` is re-dispositioned `not-evidence` under ND-007 rather than
referred. The register's criterion is whether a violation changes what the SHIPPED SYSTEM
admits, emits, signs or exposes, with the secondary reading:

> Can the gate go red on a weakening that leaves runtime behaviour unchanged? If yes it
> is a shape or a mirror rule, not a behavioural carrier.

Yes, in both directions, and the gate's own docstring is the evidence. It refuses two
spellings wherever they appear:

> That is a syntactic check on two spellings, and the claim stops there.

so a spawn whose `JoinHandle` IS owned and joined still goes red — which is why the gate has
to carry the sound sites in a hand-maintained allowlist, and why that allowlist distinguishes
"satisfies §9 by hand" from "out of §9's scope". And it passes real detachment written any
other way:

> A helper that wraps the spawn, a type alias, a re-export, a `tokio::spawn` or
> `Runtime::spawn` task, or a thread started inside a dependency all pass it untouched.

What the gate protects is the reviewability of the ownership argument — the same property
ND-007 already covers for `semantic_altitude_gate.py`, `lifecycle_purity_gate.py` and the
Core purity firewall. ND-007's exit condition applies unchanged: a demonstration that a
violation admits, emits or signs something the system does not today.

This is not a claim that the underlying invariant is a shape rule. It is not — that is
exactly what the eight controls above measure, and they stay a proposition.

## 5. What would discharge this record

A theorem over background-worker lifetime: that a long-lived worker's stop is observable and
its lifetime is an owned value, with the bounded-not-guaranteed reclamation stated as the
claim rather than as a caveat. It would be ADR-MCPRE-056 §9's proposition, and the eight
controls above are already its battery.
