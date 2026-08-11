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

> **CORRECTED after Phase 2 — see "The granularity claim was wrong" below.** The paragraph
> that follows reasons from crate size to trusted-computing-base size. That inference is
> false, and measurement falsified it. The *conclusion* — start in `mcp-re-core` — was
> still right, for the reasons in the table beneath it. The argument for it was not.

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

---

## Phase 2 entry findings (measured, not predicted)

Recorded on first contact with the pinned toolchain rather than reasoned about in advance.

### The toolchain works, and so does the negative control

`verus 0.2026.08.09.92f466f` at `/opt/verification/verus/...`, not on `PATH`. Against a
standalone file carrying the target's shape — a freshness window with a skew bound, plus
the boundary theorem — it reports:

```text
verification results:: 2 verified, 0 errors
```

And with the violation named in advance (admit one second past the boundary):

```text
error: postcondition not satisfied
verification results:: 1 verified, 1 errors
```

So conditions 4 and 5 are reachable. The theorem shape is not hypothetical.

### `cargo verus verify` exits 0 having verified nothing

`cargo verus verify -p mcp-re-core` compiles the crate, prints **no**
`verification results::` line at all, and **exits 0**. It discharged zero proof
obligations, because the crate contains no `verus!{}` block yet.

A lane trusting that exit code would report PASS for a repository containing no proofs.
This is the "exits 0 having measured nothing" failure in the one place it would be
load-bearing, and it is the third instance of that family found in this work.

`verify-verus` therefore gates on `verified_something`, which requires a results line with
`verified > 0` and `errors == 0`. The exit code alone is not evidence. Cases covered:
compiled-only, `0 verified`, non-zero errors, and a genuine pass — plus the real
`mcp-re-core` output, which the guard rejects.

Related: Verus itself exits 1 on a failed proof, but piping through `tail` masks it to 0.
The lane must check the tool's own status, never a pipeline's.

### A second pure machine now exists, and it changes the candidate ranking

`mcp-re-proxy/src/request_state.rs` — the per-request lifecycle plus the continuation and
backend machines it interacts with (ADR-MCPRE-057 §4). Zero production dependencies, same
as `runtime_state.rs`, and the purity gate now covers both.

Against condition 1 it is materially stronger than `time.rs`. Its theorem is not "this
parses correctly" but:

```text
state >= Dispatched  =>  no refusal from that state may report the action as unexecuted
continuation spent AND state < Dispatched  =>  the refusal states a recovery obligation
```

The second is a property whose ABSENCE was a live defect: a refusal landing between the
continuation retirement and the inner dispatch destroyed a human approval, never ran the
action, and reported a status clients retry. It is closed in code, with a non-vacuity
control alongside — but the closure currently rests on tests, which is precisely the
distinction ADR-MCPRE-059 exists to make.

It is **not** promoted to first pilot, for the reason this document already gives: it lives
in `mcp-re-proxy` (49 768 lines, tokio, rustls, FFI), so proving it means Option C's
external surface, which is ruled out. The Option B answer stands unchanged. What changes is
the *value* of the deferred target: the argument for eventually decomposing `mcp-re-proxy`
is now stronger than it was, because two zero-dependency security relations sit inside it
carrying properties worth proving and no crate boundary that a verifier can address.

Recorded so that a future decomposition inherits the reason rather than rediscovering it.

### The open question, narrowed

Not "can Verus run here" — it can. It is: **adding a `verus!{}` block to `mcp-re-core`
introduces a `vstd`/`builtin` dependency into a crate whose purity is enforced by its Cargo
manifest** (ADR-MCPS-011/012: no networking, async, or filesystem) and whose BUILD file is
generated. Whether that dependency belongs there, is confined to a `cfg`, or means the spec
lives beside rather than inside the crate, is the next decision — and it is the same class
of question as the one this document already answered for the lifecycle: do not let the
verifier reshape production to suit itself.

---

## Phase 2 result (measured)

The pilot is **`core.time_rfc3339`**, declared V1 in `verification/policy/verification.toml`.
`tools/verification/verify --gate` is green, and CI now runs the gating form.

### The theorem, stated honestly

The candidate assessment above claimed condition 1 for `time.rs` by citing the
replay-tier freshness rule. **That claim was too strong, and the module's own header says
so:** under ADR-MCPRE-050 the live freshness gate is `check_params` in
`mcp-re-http-profile/src/verify.rs`, working on `Signature-Input` sf-integers. Nothing on
the served path calls `time.rs`. It parses the RFC 3339 timestamps in evidence
*artifacts* — manifests, pins, retained records.

So the proved property is the one `time.rs` actually carries:

```text
for every byte string whatsoever, parse_rfc3339_utc returns — no index out of
bounds, no arithmetic overflow — and every admitted value is a representable
civil instant in [-62167219200, 253402387199]
```

Totality is the part no test suite can supply: it quantifies over all inputs, and the
inputs here are attacker-supplied bytes inside signed artifacts. The bound is what lets a
caller compare the result against a freshness boundary and know it is comparing an
instant rather than an overflowed wraparound.

The freshness rule itself remains unproven, and `check_params` is now the obvious next
Verus target: it is pure integer arithmetic over `created`, `expires`, `now`, `skew`, and
`max_signature_validity`, and it *is* the live admission decision.

### Conditions 4 and 5, discharged

* **Negative control**, named before the proof was written: relax the day check to
  `day > max_day + 1`, which admits 2026-02-30. Verus reports
  `precondition not satisfied ... failed precondition: day <= 31`, `4 verified, 1 errors`.
  The existing tests catch it too (2 failures) — worth stating plainly rather than
  claiming the proof found something tests could not.
* **Refactor survival**: `days_from_civil`'s era arithmetic was restructured (named
  `shifted_year` / `shifted_month` / `leap_days` bindings) with the contract untouched.
  `5 verified, 0 errors` with **zero** edits to any specification, and 67/67 tests green.

### Cost, in the numbers that were asked for

| | |
|---|---|
| proof LOC | 21 specification lines + a 12-line lemma; ~2.5% of the module |
| verification time | 1.6 s warm for the unit; ~20 s cold including vstd |
| production dependency impact | **none** — `cargo tree -p mcp-re-core --edges normal` contains no verus crate |
| production build/test | unchanged; 67/67 cargo tests, 81/81 Bazel targets |
| registered assumptions | 4 (ASM-0001 … ASM-0004) |
| unregistered assumptions | 0 |

### How zero production impact was achieved, and what it cost

Specifications ride `#[cfg_attr(feature = "verify", verus_spec(...))]`; `vstd`,
`verus_builtin`, and `verus_builtin_macros` are **optional** dependencies pinned to the
same release as `toolchains.lock.toml`. Feature off — every production build — and the
attributes expand to nothing, the imports vanish, and Cargo never resolves the prover.
There is one implementation, not two: the ADR's "no proof-only shadow implementation" rule
is satisfied because the proof constrains the shipping function itself.

The price is attribute-style Verus, which is weaker than a `verus!{}` block. Four things
were measured rather than predicted:

1. **Ref patterns are unsupported.** `for &b in …` and `Some((&b'Z', digits))` had to
   become `for b in …` / a guard on `*last`. Behaviour-identical, but it is the verifier
   reaching into production idiom, and it is recorded rather than smoothed over.
2. **vstd does not specify open-ended slicing.** `&bytes[19..]` has no discharge-able
   precondition; `&bytes[19..bytes.len()]` does.
3. **`i64::from(u8)` has no specification**, so the byte's value was lost. `as i64` is
   specified natively.
4. **Loop invariants cannot be expressed at all** in attribute style — there is no way to
   name the iteration ghost state. This is the reason ASM-0001 exists: `parse_fixed_digits`
   is trusted rather than proved. That is the honest cost of keeping the prover out of the
   production dependency graph, and it is the first thing to revisit if that trade is ever
   reconsidered.

### Two lane defects the pilot exposed

Both are the same family as the `cargo verus verify` finding recorded above — a lane
reporting on something other than the thing it claims to measure.

* **`check-assumptions` scanned `verification/` only**, on the reasoning that production
  Rust is not a proof surface. This pilot makes it one. The gate reported PASS with four
  escape hatches live in `mcp-re-core/src/`. It now scans every path a unit declares, and
  additionally **fails** on Verus specification text in any file no unit declares —
  otherwise a specification could be weakened where no lane would ever look.
* **Cargo's fingerprint cache silenced the prover.** The second consecutive lane run
  printed `Finished` with no `verification results::` line and exited 0 — byte-for-byte
  the signature of a crate containing no proofs. The `verified_something` guard caught it
  on its first real use. The lane now discards the crate's own artifacts before each run
  and builds into a dedicated target directory.

---

## Second unit: the live freshness gate

`http_profile.freshness_window`, V1, over `check_params` in
`mcp-re-http-profile/src/verify.rs` — the target the section above named as the obvious
next one, taken once the mechanism was known to work. Unlike `core.time_rfc3339`, this is
the admission decision **every served request passes through**.

### The theorem

```text
check_params returns Ok  ==>
      created - skew(policy) <= now
  &&  now < expires + skew(policy)
  &&  created < expires
  &&  min(expires - created, i64::MAX) <= max_signature_validity(policy)
```

`skew` and `max_signature_validity` are **uninterpreted**: the theorem holds for whatever
a deployment configures. That is the property worth having, because the attacker chooses
`created`/`expires` and the operator chooses the policy, and neither may be assumed
cooperative.

The width clause carries its saturation explicitly. `expires - created` does not fit in an
i64 for a hostile pair, and a theorem that pretended otherwise would be false exactly
where it is load-bearing — `expires.saturating_sub(created)` clamps to `i64::MAX`, so the
comparison the code performs is the clamped one, and the specification says so.

### Controls

* **Negative control**, named in advance: delete the `expires <= created` disjunct, so a
  degenerate window is admitted. Verus: `postcondition not satisfied`, `1 verified,
  1 errors`. The crate's 183 unit tests **all still pass** — one integration test
  (`chain_reconstruction_test`) catches it. So the proof is not finding something the
  suite cannot; it is finding it at the unit boundary, from the specification, instead of
  incidentally three layers up.
* **Refactor survival**: the three-way condition rewritten as named `not_yet_valid` /
  `already_expired` / `degenerate` bindings. `2 verified, 0 errors`, zero specification
  edits, all tests green.

### Cost

| | |
|---|---|
| proof LOC | 22 specification lines over a 26-module crate |
| verification time | ~2 s warm |
| production dependency impact | none — `cargo tree -p mcp-re-http-profile --edges normal` contains no verus crate |
| registered assumptions | 6 (ASM-0005 … ASM-0010) |

Opting in a 26-module crate with `coset`, `ciborium`, `p256` and `serde` cost nothing:
unannotated items are external by default, so the crate processed clean on first contact.
That is the useful generalisation from this second unit — the expensive part is not the
crate's size, it is each `std` item the proved function touches.

Four new tool findings, all measured:

1. **vstd specifies saturating arithmetic for unsigned integers only.** `i64::saturating_add`
   and `saturating_sub` needed assumptions (ASM-0005/0006), stated as the exact clamp.
2. **`&'static str` consts must spell their lifetime.** `pub const PROFILE_TAG: &str`
   fails Verus's const rewriting with a lifetime error; `&'static str` verifies. Clippy
   then calls that redundant, so the `allow` is part of the cost.
3. **Opaque types cannot be constructed.** `HttpProfileError` had to be transparent,
   because the proved function builds refusals; `ProfileAlgorithm` and `VerifierPolicy`
   stayed opaque, which keeps the algorithm registry and transport policy out of the proof.
4. **`assume_specification` demands the exact generic signature** — `Option::<String>::as_deref`
   is rejected; `Option::<T: Deref>::as_deref` is accepted.

### A third lane defect, from the same family

The lane reported `5 verified` for **both** units. `cargo verus verify -p X` verifies X's
dependencies too, each printing its own results line, and the guard was reading the first
line it found — so `http_profile.freshness_window` was passing on `mcp-re-core`'s proofs.

Fixed by attributing each results line to the crate cargo announced before it, and
requiring a line **for the unit's own crate** with `verified > 0`. Two sub-defects fell
out of that fix and are worth recording, because both would have made the attribution
silently wrong rather than visibly broken:

* cargo writes its crate banners to **stderr** and Verus writes results to **stdout**, so
  capturing them separately and concatenating puts every result before every banner. The
  streams must be merged to preserve the interleaving.
* `check-assumptions`, once it scanned production files, flagged the English word "admit"
  in a comment. Production files are now matched against the code forms of each
  mechanism — the verus spellings, and `assume`/`admit` only as calls. A gate that cries
  wolf about prose teaches people to ignore it.


---

## The granularity claim was wrong

The reasoning above ran: the module lives in a 49 768-line crate → opting that crate into
Verus makes ~49 768 lines external → the trusted computing base becomes enormous → bad
pilot boundary.

**The middle step does not follow, and Phase 2 measured it.**

`mcp-re-http-profile` — 26 modules, 14 818 lines, with `coset`, `ciborium`, `p256` and
`serde` — was opted in and processed clean on first contact: `0 verified, 0 errors`, no
markup required anywhere. Unannotated items are external by default, and external-by-
default items that no theorem calls are not trusted. They are *absent*. They enter no
dependency cone and contribute nothing to any trusted computing base.

What actually grew the freshness theorem's trusted frontier was six small items the proved
function touches: two signed saturating operations vstd does not specify, two policy field
reads, one algorithm resolver, and one `Option` combinator. Six, in a 14 818-line crate.
Crate size predicted none of it.

So three things this document treated as one are three:

* **crate** — where cargo and the prover operate. A build fact.
* **unit** — what is proved. An assurance fact.
* **dependency cone**, and within it the **trusted frontier** — what the theorem rests on
  without proving. The security fact, and the only one of the three that is a TCB.

Recorded as ADR-MCPRE-059 Operational Rule 17, and in `verification/model/vocabulary.md`.

### What this does and does not reopen

It does **not** vindicate extracting `runtime_state.rs` into a crate. Option B stands, the
seven questions that produced it stand, and "would we still want this crate if Verus
disappeared tomorrow?" remains the right rule — it was answering a question about
production architecture, not about tooling, and it was right for reasons this error never
touched. Had we reacted to the misunderstanding by splitting the crate, we would have
distorted the architecture to satisfy a constraint that did not exist.

It **does** reopen proving the lifecycle and exchange machines *in place*. The stated
technical objection was the external surface, and that objection is now known to be
weaker than assumed. The next step for those targets is not a decision; it is a
measurement — point Verus at the relation where it already lives and read the actual
trusted frontier. If it reaches only its own enums, its transition function and small
`core` primitives, proving it in place is straightforward.

That measurement is scheduled after the current units, and it is the deferral this
document already recorded — now with a reason to revisit it rather than a reason to wait.

### The lane changes that came with the correction

Reading `verus --output-json` instead of the human-readable log removed the attribution
guesswork entirely: symbols are fully qualified, so which crate proved what is *read*
rather than inferred from output order. Three checks became possible that the log could
not support, and each closes a false green:

1. **The prover's identity, as the prover reports it.** The lane no longer trusts that the
   binary at the pinned path is the pinned build; the report's commit must equal the lock's.
2. **`is-verifying-entire-crate`.** A `focus`-style partial run can no longer be mistaken
   for an authoritative one (Operational Rule 5).
3. **Declared theorems.** Units now name their `proved_symbols`, and the manifest refuses a
   V1/V3 unit that does not. Deleting one specification of two used to leave the other to
   answer for it — the crate still verified, the count stayed healthy, the lane said PASS.
   Now the absent symbol fails the lane. Demonstrated end to end: the deletion **exits 0**
   and the lane reports FAIL.

`proved_symbols` is also a fingerprint component (encoding version 2), so removing a
theorem invalidates the unit's evidence rather than merely un-checking it.

The cross-crate control you asked for exists at both levels: as fixtures in
`tools/verification/test_verus_lane.py` (12 cases, one per false-green shape found so far,
run in local-gate stage 1), and demonstrated end to end — crate A sound, crate B's theorem
broken → A PASS, B FAIL, aggregate FAIL.
