<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase 2 decision: should the runtime lifecycle become a crate?

**Question:** ADR-MCPRE-059 §18, made checkable — *would we want `runtime_state` in a small
pure crate if Verus disappeared tomorrow?*

**Answer: no.** Recommend **Option B** — extract nothing, and pick a different first Verus
pilot. The purity the extraction was reaching for is worth having and is obtainable without
a crate.

Written before any code moves, as required. Read-only investigation; nothing here changes
production.

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

**Nothing from outside itself.** No external crate, no `std` import, no `crate::` or
`super::` path. 436 lines: ~212 of production code and ~223 of test.

The two `use` lines it does contain are `use RuntimeEvent as E;` and `use RuntimeState as
S;`, inside `transition`, shortening the module's *own* type names so the 110-pair match
fits on a screen. They name nothing outside and are not dependencies.

(An earlier draft of this document said "zero `use` statements". That was wrong — it came
from a line-anchored grep that missed two indented lines inside a function body. The
purity gate written alongside this decision caught it on its first run, which is a small
argument for the gate.)

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
external dependencies at all). The property is canonical-model theorem 4: *after a
freshness boundary, no future decision admits an action on the stale basis*. Real
security content — it is the clock-skew and expiry rule the whole replay tier stands on.

**Stretch candidate — the `mcp-re-core/src/replay.rs` decision rule**: *a nonce admitted
once is never admitted again within its window*. A stronger property, but
`InMemoryReplayCache` holds a `Mutex`, so it depends on how the pinned Verus release
handles interior mutability. Decide at Phase 2 entry against the tool as pinned, not
against the tool as assumed.

## What this does not close

The lifecycle FSM remains unproven, and that is a genuine loss — it is the ADR-MCPRE-057
centerpiece and the unit with the best independent evidence (the exhaustive 110-pair
test). This decision is about the **first** pilot, not forever. If `mcp-re-proxy` is ever
decomposed for reasons that stand on their own, the lifecycle becomes an excellent Verus
target at that point, and the 110-pair test will still be there to be complemented.

Recording it as deferred rather than rejected, so a future decomposition has a reason
waiting for it instead of having to rediscover one.
