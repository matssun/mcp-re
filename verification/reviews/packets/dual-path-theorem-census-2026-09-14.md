<!-- SPDX-License-Identifier: Apache-2.0 -->

# T7 — the dual-path theorem census, and why no current claim justifies one

ADR-MCPRE-059 §10.3 / §20 Phase T7, issue [#543](https://github.com/matssun/mcp-re/issues/543).
Run once [#541](https://github.com/matssun/mcp-re/issues/541) closed and the `lean://` lane
became real; before that there was no second path to be dual with.

**Outcome: B — no theorem in the current tree honestly warrants dual-path evidence.**

The issue names that as a valid and reportable result, and it is the one the measurement
supports. What follows is the census, the candidate that survived longest, and the precise
reason it was rejected — because a finding whose reasoning is not written down is a finding
somebody re-litigates in six months.

## The rule this census was held to

> The justification must be written down before the work starts, naming the distinct failure
> class each path reduces. **"Two provers are better than one" is not sufficient
> justification, and neither is demonstrating that both can turn green.**

And its companion: never invent a theorem or weaken a claim to demonstrate two green
provers.

## The candidate population, measured

| lane composition | units |
|---|---:|
| `test` only | 67 |
| `test` + `mutation` | 38 |
| `test` + `verus` | 5 |
| `test` + `mutation` + `verus` | 1 |
| `test` + `lean` | 1 |
| **`verus` + `lean`** | **0** |

Sixteen theorems carry a formal path today: fifteen over the six Verus units, one over the
single Lean unit. A dual-path candidate must be a theorem BOTH toolchains can reach, so the
population is the union of those sixteen.

| | theorem(s) | formal unit |
|---|---|---|
| Verus | THM-0001, THM-0002, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 | `core.time_rfc3339`, `http_profile.freshness_window`, `http_profile.admission_currency`, `http_profile.artifact_typing`, `http_profile.continuation_unbypassability`, `http_profile.continuation_binding` |
| Lean | THM-0128 | `core.time_civil_from_days` |

## Elimination 1 — thirteen theorems are outside the extraction subset

Every `http_profile.*` theorem is eliminated by a measured property of the toolchain, not by
an opinion about difficulty. `verification/baseline/extraction-pilot-measurement-2026-08-30.md`
established that the Charon → Aeneas pipeline reaches pure sequential Rust inside a
supported subset, and that reaching the production target at all required `--start-from` to
keep extraction **off** `ed25519-dalek` and `sha2`.

The admission, artifact-typing, continuation and verifier-result theorems are all stated
over structures whose meaning is decided by signature verification and digest comparison.
The extraction cannot enter that code, so there is no Lean path to be dual with. **Not a
candidate — one of the two paths does not exist.**

## Elimination 2 — THM-0002 would run through the Aeneas library's own `sorry`s

THM-0002, *RFC 3339 parsing is total and range-bounded*, is the nearest miss on the Verus
side: it is in `mcp-re-core`, the same crate the Lean pilot reached, and it is pure
sequential arithmetic — except that it parses a **string**.

Measured, not assumed — the pinned Aeneas Lean backend carries four `sorry`s of its own:

```
warning: Aeneas/Std/Slice.lean:363:4:      declaration uses `sorry`
warning: Aeneas/Std/Slice.lean:586:8:      declaration uses `sorry`
warning: Aeneas/Std/StringIter.lean:12:4:  declaration uses `sorry`
warning: Aeneas/Std/StringIter.lean:15:4:  declaration uses `sorry`
```

A Lean proof about a string parser runs through `StringIter`. `sorry` is the absence of a
proof: this repository's lane fails closed on it and refuses to let it be registered as an
assumption. So the Lean half of a THM-0002 dual path is either unprovable or provable only
by reaching a hole the lane exists to refuse. **Rejected.**

## The surviving candidate — THM-0128, and the reason it is still rejected

THM-0128 is the strongest candidate in the tree and the one worth the argument.

It is over `mcp-re-core/src/time/format.rs`, a file that **already carries a Verus proof**
next door (`core.time_rfc3339`), so the crate is set up for the `verify` feature and Verus
can physically reach the function. Its own `security_consequence` says the absence of the
panic *"was an ARGUMENT: a `#[allow(clippy::arithmetic_side_effects)]` whose justification
is a chain of bounds a reader must follow"* — exactly the kind of chain Verus discharges.

So both paths are physically available. The four questions:

**What failure class does Verus reduce?** *The proof is about a different program than the
one that ships.* Verus proves in place, over the actual Rust, through the compiler's own
types.

**What distinct failure class does extracted-model + Lean reduce?** *The property is not
expressible.* Lean reasons over an extracted model with a full proof assistant behind it,
so it can carry induction and deep arithmetic an SMT encoding may not close.

**Would requiring both add assurance rather than duplicate one path?** **No**, and this is
where the candidate dies. Three measured reasons:

1. **For this proposition, one path strictly dominates.** Verus's weakness is the model
   boundary it does not have; Lean's stated open edge is precisely a model boundary —
   THM-0128's own scope records that *"THE DOMAIN IS A HYPOTHESIS, NOT A DERIVATION … the
   link from 'any i64 a caller passes' to 'a value in this range' runs through `div_euclid`,
   which the extraction leaves uninterpreted"*. A Verus proof over the shipped Rust does not
   have that gap. Adding Lean beside it would attach a weaker witness of the same statement
   and make the theorem go unestablished whenever the extraction toolchain drifts —
   fragility with no assurance gain.

2. **Closing that gap would require broadening the claim.** The interesting Verus statement
   is *total for every `i64` a caller can pass*; THM-0128's statement is *total on this
   stated closed interval*. Those are different human theorems. Making them one means
   restating THM-0128 over the caller domain — broadening a security claim so that a
   dual-path demonstration becomes possible. #543 forbids exactly that, and a broadened
   claim is an owner decision rather than a census outcome.

3. **The residual argument is the one the issue rejects by name.** What survives after (1)
   and (2) is *two provers have disjoint trusted bases, so a Z3 soundness bug would not
   affect the Lean kernel*. That is "two provers are better than one" with a mechanism
   attached. This repository already treats prover identity as a **pinned, measured
   premise** — `[verus.binaries]` names three binaries by digest, `[verus.z3].identity` is
   the solver binary's digest, and `[lean].kernel_axioms` is recorded against the pinned
   toolchain — rather than as an assumed-sound oracle. Duplicating a proof is not how that
   premise is managed here.

## What was NOT done, deliberately

No theorem was invented. No statement was broadened or weakened. No production Rust was
reshaped for a prover. No second `lean://` unit was declared to enlarge the candidate pool,
and no Verus proof was attempted whose only purpose would have been to make a second lane
green.

## When to re-run this census

The population is small and its boundaries are toolchain facts, so the census goes stale in
exactly three ways:

* **the extraction subset widens** — if Charon/Aeneas gain the crypto or trait-heavy code the
  `http_profile.*` theorems live over, elimination 1 is no longer true;
* **the Aeneas library's `sorry`s are discharged upstream** — elimination 2 reopens THM-0002;
* **a new theorem is stated over pure sequential arithmetic that Verus cannot close but Lean
  can** — that is the shape a genuine dual-path claim would have, and it is the one to watch
  for: not a proposition both can prove, but one where each closes what the other cannot.

Re-run it when any of those moves. Not on a schedule: a census re-run with no changed
premise produces the same answer and teaches the reader that the answer is a formality.
