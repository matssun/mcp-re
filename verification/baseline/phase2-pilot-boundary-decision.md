<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 2 decision: should the runtime lifecycle become a crate?

**Question:** ADR-MCPRE-059 §18, made checkable — *would we want `runtime_state` in a small
pure crate if Verus disappeared tomorrow?*

**Answer: no.** **Option B**, owner-approved:

> **ADR-059 Phase 2 pilot decision.** Do not extract the runtime lifecycle solely to obtain
> a smaller Verus verification unit. Select a security-significant unit in `mcp-re-core`
> whose actual production dependency boundary already coincides with the trusted
> `boundary.crypto_primitives` surface. Defer formal verification of `RuntimeLifecycle`
> until its production crate boundary becomes naturally appropriate, or verifier
> granularity improves.

That is not rejecting lifecycle verification. It is protecting the production architecture
from the proof tool. `runtime_state.rs` is architecturally pure; Verus's crate-level
verification boundary simply does not coincide with that architectural boundary.

Written before any code moves, as required. Read-only investigation; nothing here changes
production.

## What the Option B target must establish before implementation begins

Five conditions, all of which the Phase 2 write-up must satisfy:

1. **Meaningful security property.** Not "this helper returns what it computes", but an
   invariant whose violation would matter to MCP-RE security.
2. **Existing production boundary.** No new abstraction created primarily for Verus.
3. **Small, explicit TCB.** Anything treated as external must coincide with an
   already-declared trusted boundary such as `boundary.crypto_primitives` — not a
   convenient collection of unrelated code.
4. **Negative proof control.** Name the violating implementation *before* writing the
   proof, and demonstrate Verus rejects it.
5. **Refactor survival.** Change the implementation without changing the contract, and
   show the proof survives or needs only understandable repair.

Candidate assessment against these is in §"Consequence for the first Verus pilot" below;
conditions 4 and 5 are discharged during Phase 2 itself, not here.

---

## The seven questions

### 1. Who consumes `RuntimeLifecycle` today?

Three modules, all inside `mcp-re-proxy`:

| Consumer | Use |
|---|---|
| `app.rs` | 3 lines — `new()`, `ValidationSucceeded`, `PlanBuilt` |
| `materializing_runtime.rs` | owns the `Materializing` span; applies started / succeeded / failed |
| `materialized_runtime.rs` | serving and teardown; applies the remaining six events |

Nothing outside `mcp-re-proxy` references it — not another crate, not an integration test.

### 2. What does `runtime_state.rs` itself require?

**No production module.** No workspace crate, no third-party crate, no `crate::` or
`super::` path. 436 lines: ~212 of production code and ~223 of test. Its entire external
dependency set is `std::fmt`, for rendering `InvalidTransition` in an error message.

The two `use` lines it contains are `use RuntimeEvent as E;` and `use RuntimeState as S;`,
inside `transition`, shortening the module's *own* type names so the 110-pair match fits on
a screen. They name nothing outside and are not dependencies.

> **Two corrections, both found by tooling rather than by re-reading.**
>
> The first draft said "zero `use` statements", from a line-anchored grep that missed two
> indented lines inside a function body. The purity gate caught it on its first run.
>
> The second draft said "no `std` import" — also wrong. `impl std::fmt::Display for
> InvalidTransition` reaches the standard library with no `use` at all, so a `use`-based
> check could not see it. Rewriting the gate to compute the dependency *set* rather than
> count `use` lines found it immediately.
>
> Both errors came from measuring a syntactic correlate instead of the proposition, which
> is the same mistake that made a `pgrep` liveness check report on watcher shells rather
> than the process being watched. Recorded rather than edited away, because the pattern is
> the point: the property is "depends on no production module", and every cheap proxy for
> it has been wrong so far.

It is a pure leaf. That is the strongest fact in this investigation, and it cuts both ways
— see §7.

### 3. Would moving it create a natural layering direction?

Yes, trivially: a zero-dependency crate is a leaf, so the direction would be
`mcp-re-proxy → mcp-re-runtime-model` and nothing else. Clean, but only because there is
nothing to tangle.

### 4. Circular or awkward dependencies?

None possible. A crate with no dependencies cannot participate in a cycle.

### 5. Is the lifecycle contract meaningful outside `app.rs`?

Meaningful outside `app.rs` — yes; the two runtime-ownership modules are its real
consumers and `app.rs` barely touches it.

Meaningful outside **`mcp-re-proxy`** — **no.** The states are this proxy's lifecycle:
`Materializing`, `Serving`, `Draining`, `Transitioning`, `Stopped`, `FailedToStart`, and
events like `FleetDrained`. It is not a general runtime model that another component could
adopt. It is a precise description of one program's startup and teardown.

### 6. Can it be tested independently today?

Yes, and it already is. The tests are pure — no fixture, no I/O, no clock, no network —
including the exhaustive 110-pair transition test. Extraction would not improve
testability, because nothing about the current location constrains it.

### 7. Does extraction reduce authority or dependency surface with Verus deleted?

This is the decisive question, and the honest answer is **no, it slightly increases the
nominal surface.**

Today the types are `pub(crate)`: reachable by `mcp-re-proxy`'s ~60 modules, and by
nothing else. As a crate they become `pub`: nominally reachable by the whole workspace.
Practically narrower (three consumers either way), nominally wider.

There is no authority reduction. `RuntimeLifecycle` holds no key, no socket, no capability
— it is a value describing which transitions are legal. Moving it moves no authority.

---

## Verdict

The crate fails the reuse test that justifies a crate. It would be:

- ~212 production lines,
- with three consumers, all siblings inside one crate,
- modelling states that describe that same crate's program,
- with no independent versioning story,
- and the only single-consumer crate in the workspace.

`mcp-re-core` and `mcp-re-http-profile` are crates because they are *firewalls* — a
security core deliberately kept free of networking, async, and filesystem access, consumed
by several components. `mcp-re-runtime-model` would be a crate because a verifier prefers
small crates. That is the distortion §18 forbids, and Operational Rule 11 now names.

## But one real architectural good is hiding in the proposal

The zero-dependency purity of `runtime_state.rs` is currently maintained by **discipline
alone**. Nothing prevents a future edit adding `use tokio::...` or reaching into
`crate::app`, and the moment that happens the module stops being a value and starts being
a component — quietly, in a diff that looks like a convenience.

`mcp-re-core` does not rely on discipline for this; its Cargo manifest enforces it, per
ADR-MCPS-011/012. That enforcement is the part worth keeping.

It does not need a crate. This repository already enforces a dozen structural properties
with gates (`seam_posture_gate.py`, `bazel_srcs_gate.py`, `owned_worker_gate.py`,
`check_port_registry.py`, …). A gate asserting that `runtime_state.rs` imports nothing is
a handful of lines, costs no build graph, widens no API surface, and states the invariant
more precisely than a crate boundary would:

> The lifecycle relation is a value. It imports nothing, so it cannot acquire behaviour.

Recommended alongside Option B, and cheap enough to land with the pilot.

## Consequence for the first Verus pilot

`runtime_state.rs` stays where it is, so it cannot be the first Verus pilot: proving it
would require opting in `mcp-re-proxy` (49 768 lines, tokio, rustls, FFI) and marking
essentially all of it external — Option C, already ruled out.

**Recommended replacement: a unit inside `mcp-re-core`.**

The argument is about the trusted computing base, not about convenience. `mcp-re-core` is
2 933 lines — seventeen times smaller than `mcp-re-proxy` — and its six external
dependencies are `serde`, `serde_json`, `ed25519-dalek`, `sha2`, `base64`, `thiserror`.
Marking those external does **not** inflate the TCB into unknown territory: it coincides
with `boundary.crypto_primitives`, which `verification/policy/trust-boundaries.toml`
already declares as trusted. The external surface of the pilot would be a boundary the
repository had already named and accepted, rather than 49 000 lines of runtime marked
external to get a green.

That is the difference between a proof whose trusted basis is understood and one whose
trusted basis is "everything else".

**Primary candidate — `mcp-re-core/src/time.rs`** (329 lines, one internal import, no
external dependencies at all), against the five conditions:

| | |
|---|---|
| 1 — meaningful property | Canonical-model theorem 4: *after a freshness boundary, no future decision admits an action on the stale basis*. It is the clock-skew and expiry rule the whole replay tier stands on; violating it re-opens a replay window. |
| 2 — existing boundary | `parse_rfc3339_utc` / `unix_to_rfc3339_utc` are the production freshness seam already. Nothing new is introduced. |
| 3 — small explicit TCB | Zero external dependencies, so the module contributes nothing to the TCB. The crate's six deps coincide with `boundary.crypto_primitives`, already declared trusted. |
| 4 — negative control | To name in Phase 2. The obvious one: accept a timestamp at exactly `expires_at + skew + 1` and show the proof fails. |
| 5 — refactor survival | To demonstrate in Phase 2: re-implement the parse without changing the admissibility contract; source digest moves, contract digest does not, proof re-runs. |

**Stretch candidate — the `mcp-re-core/src/replay.rs` decision rule**: *a nonce admitted
once is never admitted again within its window*. A stronger property against condition 1,
but `InMemoryReplayCache` holds a `Mutex`, so condition 3 depends on how the pinned Verus
release handles interior mutability. Decide at Phase 2 entry against the tool as pinned,
not the tool as assumed.

## What this does not close

The lifecycle FSM remains unproven, and that is a genuine loss — it is the ADR-MCPRE-057
centerpiece and the unit with the best independent evidence (the exhaustive 110-pair
test). This decision is about the **first** pilot, not forever. If `mcp-re-proxy` is ever
decomposed for reasons that stand on their own, the lifecycle becomes an excellent Verus
target at that point, and the 110-pair test will still be there to be complemented.

Recording it as deferred rather than rejected, so a future decomposition has a reason
waiting for it instead of having to rediscover one.
