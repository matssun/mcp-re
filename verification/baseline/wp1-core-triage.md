<!-- SPDX-License-Identifier: Apache-2.0 -->

# WP1: what attribute-style Verus can and cannot reach

**ADR-MCPRE-059, work package 1.** Measured against the pinned prover
(`0.2026.08.09.92f466f`) on `mcp-re-core`, with two findings that bound every later work
package.

Written as measurement, not opinion: each claim below is a command that was run and an
error message that came back.

---

## Finding 1 — the loop ceiling was a loop *shape*, and it is not a ceiling

The Phase 2 report said attribute-style Verus "cannot express loop invariants at all", and
ASM-0001 exists because of it. That was too strong.

An **index-based** loop carries its invariant normally. The full digit-bound theorem —
the one ASM-0001 currently assumes — verifies when the loop is written `while i < n`:

```text
verification results:: 4 verified, 0 errors
```

with `invariant i <= n, value < spec_pow10(i)`, `decreases n - i`, and a small
`reveal_with_fuel` lemma for the recursive `spec_pow10`.

What genuinely cannot be expressed is the ghost state of an **iterator-based** `for` loop:
`for b in &bytes[start..start + n]` gives no way to name how many elements have been
consumed, because the `for x in it: ...` binding is `verus!{}` syntax with no attribute
equivalent.

**Consequence.** ASM-0001 is dischargeable, at the price of one production idiom change
(slice-iterator → index loop) made for no reason except the verifier. That is precisely
the Rule 11 trade this ADR reserves to the owner, so it is recorded here rather than
taken. The crate has exactly **one** loop in it, so the stake is small — but the rule the
answer sets is not.

## Finding 2 — trait impls are unreachable in attribute style, and that is structural

```text
error: In order to verify any items of this trait impl, the entire impl must be
verified. Try wrapping the entire impl in the `verus!` macro.
```

Confirmed twice: annotating one method fails, and annotating **every** method of the impl
fails identically. The requirement is not "all methods annotated" but "the impl inside a
`verus!{}` block".

And a `verus!{}` block cannot be feature-gated. The macro must exist at compile time, so
its crate is a hard dependency; gating the block behind `cfg` would mean a second copy of
the implementation for the unverified build, which Rule 11 forbids outright.

So the constraint that keeps the prover out of the production dependency graph — the
explicitly chosen posture — **costs exactly the trait impls**.

### What that costs, counted

| crate | free fns | inherent methods | trait-impl methods |
|---|---:|---:|---:|
| `mcp-re-core` | 20 | 25 | 6 |
| `mcp-re-http-profile` | 163 | 74 | 5 |
| `mcp-re-client-core` | 29 | 31 | 6 |
| `mcp-re-policy` | 3 | 7 | 1 |
| `mcp-re-transport` | 12 | 14 | 9 |
| **pure tier** | **227** | **151** | **27** |

**378 of 405 functions — 93% — remain reachable.** The 27 are not evenly distributed
in importance, though, and that is the whole problem: MCP-RE's *injected security seams*
are traits by architectural mandate (ADR-MCPS-011/012 — the core takes `TrustResolver` and
`ReplayCache` from the embedder rather than owning them). The 7% that is unreachable is
disproportionately the part where a contract-per-implementation proof would be worth most,
and it is the shape ADR-MCPRE-059 names as ideal for contract sealing:

```text
implementation A ----\
implementation B -----+--> same trait contract --> callers
implementation C ----/
```

That is the trade to rule on, and it is not mine to take: the zero-production-dependency
constraint was set deliberately, and this is its price becoming visible.

### The options, with what each actually costs

1. **Hold the line.** Trait impls are OUT-OF-REACH; 93% of the pure tier stays reachable.
   `InMemoryReplayCache`'s `check_and_insert` — *a nonce admitted once is never admitted
   again* — cannot be proved. Cost: the strongest replay property stays test-only.
2. **Relax per crate.** Allow `verus!{}` in `mcp-re-core` alone, making `vstd` and the two
   builtin crates non-optional there. They are ghost-erased, so the shipped artifact is
   unchanged in behaviour — but the dependency graph and the generated Bazel BUILD are
   not, and `mcp-re-core`'s manifest purity is itself a control under ADR-MCPS-011/012.
   Cost: the thing you said you did not want, in one crate, knowingly.
3. **Prove the trait's contract instead of its impls.** Specify the trait once (in
   `verification/verus/`) and verify each implementation against it — which still needs the
   impl in a `verus!{}` block, so it does not escape the trade. Records here only so it is
   not mistaken for an unexplored option.

Recommendation if you want one: **1 for now, revisit at WP3.** The exchange and lifecycle
machines are plain enums and free functions, not trait impls, so the highest-value
remaining theorems in the repo are unaffected by this limit.

## Finding 3 — one measurement blocked, honestly unmeasured

Whether Verus reaches through `std::sync::Mutex` is **still unknown**. The probe on
`InMemoryReplayCache::prune` (inherent, so not blocked by Finding 2) stopped earlier, on a
closure pattern:

```text
error: The verifier does not yet support the following Rust feature:
only variables are supported here, not general patterns
```

`|_, &mut retain_until| retain_until >= now_unix` destructures in the closure argument.
So the Mutex question is unanswered rather than answered negatively, and no claim either
way belongs in the record until it is measured.

---

## `mcp-re-core` triage

51 non-test functions. One loop in the entire crate.

| module | fns | classification |
|---|---:|---|
| `time.rs` | 6 | **PROVED** — 2 declared theorems; 1 ASSUMED (ASM-0001, dischargeable per Finding 1) |
| `replay.rs` | 13 | **OUT-OF-REACH** for `check_and_insert`/`durability_class` (Finding 2); inherent methods pending the Mutex question (Finding 3) |
| `resolver.rs` | 8 | **OUT-OF-REACH** for the `TrustResolver` impl (Finding 2); `compose_key` injectivity is reachable and worth proving |
| `crypto.rs` | 10 | **NOT-WORTH-IT** below `boundary.crypto_primitives` — the properties that matter are the primitives', which are trusted by declaration; `ensure_ed25519_alg` is reachable |
| `hash.rs` | 2 | `parse_hash_id` reachable; `sha256_hash_id`'s meaning lives beyond the trusted boundary |
| `encoding.rs` | 2 | reachable — round-trip `b64url_decode ∘ b64url_encode == id` is a real theorem |
| `audit.rs` | 8 | **NOT-WORTH-IT** — total functions over a closed enum, already exhaustive by construction |
| `error.rs`, `wire.rs`, `ids.rs` | 2 | **NOT-WORTH-IT** — wire-token mapping, covered by frozen-taxonomy tests |

Nothing here is unexamined. Where the answer is "not proved", the reason is recorded, which
is the property this triage exists to establish (Operational Rule 14: coverage is not a
vanity metric).

## Lane state at the end of WP0

Reading `verus --output-json` replaced log parsing entirely. Per unit the lane now checks
the prover's self-reported identity against the lock, that the whole crate was verified,
that error counts are zero, and that **every declared theorem is present by name**. Twelve
false-green shapes are fixtures in `tools/verification/test_verus_lane.py`, running in
local-gate stage 1; the cross-crate control is demonstrated end to end as well as in
fixture form. `proved_symbols` is a fingerprint component at encoding version 2, so
deleting a theorem invalidates the unit's evidence rather than silently reducing it.
