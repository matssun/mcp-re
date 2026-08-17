<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-058 — the request pipeline, closed

> All twelve request stages have identified evidence for their contracts. Five stages whose
> local decisions establish or alter an independent security boundary have direct contract
> tests with verified negative controls; the remaining seven are constrained by existing
> targeted or end-to-end tests.

Worded exactly that way on purpose. Saying "twelve stages individually tested" would be
false. The evidence has two shapes, and the wording keeps them distinct:

| Direct contract test + verified negative control | Existing targeted / end-to-end evidence |
|---|---|
| replay admission | verify |
| continuation retirement | admission currency |
| retention reservation | continuation preparation |
| transport binding | reply classification |
| answerability / signature lifetime | reply signing |
| | open-leg recording |
| | forward-body preparation |

The five were selected because each establishes or alters an **independent security
boundary** — not for numerical completeness. The seven were each traced to a specific
existing test rather than inferred from filenames; duplicating them with artificial unit
tests to make the matrix symmetrical would add no evidence.

The last two cover different kinds of correctness, which is why both were worth adding:

```text
transport binding   evidence absence must not become authorization
answerability       authorization lifetime must not become an overclaim
```

One governs whether execution may proceed; the other governs what the proxy may truthfully
attest afterward.

## What `handle` became

`http_profile_serve::handle` went from 525 lines to 206 (151 non-comment). That number is
not the result. The result is that it stopped being the place where twelve security
decisions, their ordering, and their refusal semantics were all implicitly encoded, and
became the composition of a request machine.

The ladder it now makes visible, which previously had to be recovered by reading 525 lines
in execution order:

```text
verify                    refusal free — nothing has happened
transport binding         refusal free
admission                 refusal free
prepare continuation      cannot fail; peek only, never consumes
replay admission          refusal free — the nonce is burned strictly last
answerable                refusal free — which is the whole point of asking here
retire continuation       free of EXECUTION, but consequence already exists
forward body              free of execution; the approval may already be spent
reserve retention         THE LAST FREE REFUSAL
=================== execution threshold ===================
classify reply            NOT free — the action already ran
sign reply                NOT free
record open leg           NOT free
```

The interesting states are the exceptions, not the obvious ones. `retire continuation` and
`forward body` differ from both neighbours, and that is exactly where the defect lived.

## The four independent constraints

None substitutes for another.

| Constraint | Answers | Held by |
|---|---|---|
| state relation | which transitions exist | exhaustive 21x18 grid, complement included |
| consequence monotonicity | transitions cannot erase irreversible history | exhaustive over 21x4x22 |
| stage obligations | implementations satisfy local contracts | 5 contract tests, 5 verified controls |
| failure semantics | outward claims derive from exchange truth | posture derived from the machine only |

## Three defects, all found by modelling rather than by testing the code as written

1. **A spent approval reported as retry-safe.** A refusal between the continuation
   retirement and the dispatch destroyed a human's approval, never ran the action, and
   returned a retryable-looking 503. The retry passes replay admission on a fresh nonce and
   then fails as already-answered.
2. **The notification terminal was missing.** The 202 arm left the machine at `Dispatched`
   and reached no terminal. It is now `AcknowledgedNotification`, reachable only from the
   execution threshold, reading as possibly-executed — because "no ordinary result" is not
   "nothing happened".
3. **Consequence could move backward.** `Consumed -> Recorded` was reachable on any
   multi-round-trip conversation and weakened the exchange's claim. Fixing it exposed the
   deeper fault: `Recorded` was a variant no production code ever read. See operational
   rule 13.

## The authority change

Stages return a `Refusal` descriptor; one `refuse()` renders and signs it. Precisely what
that did and did not achieve:

- eleven stages no longer exercise signing;
- refusal semantics became a value that can be asserted on without a signer;
- one method owns rendering and signing;
- stages can no longer manufacture a retry posture — `RequestProgress` left their
  signatures entirely;
- two stages became independent of `Exchange`.

It is **not** Rust capability reduction. Every stage is still a private method taking
`&self` and could reach `self.signer`. The compiler does not prevent it; the architecture
does.

## Evidence

| Lane | Result |
|---|---|
| `local_gate.sh --fast` (stages 1-2) | PASS — static gates + full cargo battery |
| `local_gate.sh --fast --from 3` (stage 3) | PASS — 81 Bazel tests, 73 fresh |
| `//mcp-re-proxy:async_drain_test` | PASSED in 4.1s, **not cached** |
| `//mcp-re-proxy:mrt_continuation_serving_test` | PASSED in 4.5s |

Stage 3 was run separately and deliberately: `--fast` reports `PASS (stages 1-2)` with
Bazel `SKIPPED`, and `async_drain_test` is `#![cfg(feature = "async_serve")]`, so the cargo
lane compiles it to zero tests. A pass that did not include stage 3 would say nothing about
drain or teardown. Stage 4 (the SLO lane) was not run and is not required for this claim.

## What this does not close

- **Seven of twelve stages have no direct contract test.** Each was traced to specific
  existing evidence, so this is a stated shape of the argument rather than a gap — but the
  evidence is end-to-end, and an end-to-end test constrains a stage's contract only
  incidentally.
- **The conversation/MRTR topology machine does not exist.** `ContinuationState` is now
  honestly scoped to one axis — the fate of the approval this exchange spent — which makes
  the absence of a topology machine clearer rather than fixing it. It is persisted, cyclic,
  and cross-replica, and it is where the security audit previously found an actor able to
  complete another actor's approval.
- **`unsigned_error` still collapses two causes.** The response half is built — as a region
  of the exchange machine rather than a second machine beside it — but four response kinds
  exist and one of them, `unsigned_error`, carries no signature at all, so a request
  terminal maps one-to-many onto what the client can trust. Its two causes (no delegated
  key; signing the rejection itself failed) remain collapsed into identical bytes.
- **`parse_args`** (~1058 lines) remains the other ADR-MCPRE-058 target.
