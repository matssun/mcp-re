# ADR-MCPRE-068 Phase 2, slice 16 — the joins, the clock, and the lock that recovers

Three probes, `M234`–`M236`. One control was measuring the wrong delimiter, and the weakening
that found it is the same shape as slice 14's.

## 1. A control that tested a delimiter production does not use

`composite_key_is_injective_across_delimiter_containing_pairs` used `("a#b", "c")` against
`("a", "b#c")` — the pairs a naive **DID-shaped `#` join** collides. `compose_key` does not
join on `#`:

```rust
format!("{}:{}|{}:{}", signer.len(), signer, key_id.len(), key_id)
```

So under `M234`'s weakening — a bare `{signer}|{key_id}` join — those two pairs stay distinct
and the control passed. The characters that can tell the length-prefixed form from a bare join
of the same two fields are the ones the function **itself** joins on: `:` and `|`. The control
now includes them.

What the length prefix buys: two different `(signer, key_id)` pairs cannot compose to one
lookup key, so one tenant's binding can never resolve a key enrolled under another's. Every
gate around it passes — the resolver is asked a well-formed question and answers with a
genuinely enrolled key.

## 2. The weakening that is the historical defect, restored exactly

`M235` puts back `-(secs as i64)`. `(2^63 + 1) as i64` wraps to `i64::MIN + 1`, whose negation
is `i64::MAX` — so a clock set unrepresentably far **before** the epoch reports the furthest
instant in the **future**, which every freshness window accepts. The magnitude must be refused
before it is negated, and `try_from` rather than an `as` cast is the whole content of the
function.

Nothing downstream is a second carrier: a freshness window is handed an `i64` and has no way
to ask whether it was fabricated.

## 3. Not panicking is not the same as not admitting

`M236` replaces the poisoned-lock refusal with `unwrap_or_else(|e| e.into_inner())` — the
tempting weakening, because it does not panic and so satisfies every *no panic on the serving
path* reading of the contract. What it does instead is **admit**: a cache whose invariant a
panic elsewhere already broke answers `Fresh`, and a nonce that is not reliably retained can
be replayed.

The seam's rule is two properties, not one — *an error value* **and** *never an allow* — and
this weakening keeps the first while discarding the second. The entry ceiling below is a
sibling conjunct on the same rule, not a second carrier: it refuses when the cache is full and
says nothing about a cache whose lock is poisoned.

## 4. A local gate condition, recorded

`check-generated` reports the Lean model stale in this workspace, because the extraction stamp
under the ignored `.verification/` predates this slice's edit to `mcp-re-core/src/resolver.rs`
— the whole crate is in the extraction cone. The stamp is not committed; the verification
workflow regenerates the model before composing its verdict, so this is a property of the
local run rather than of the tree. Every other gate is green here.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `core.trust_resolver_seam` | `M234` | critical |
| `host.request_freshness_inputs` | `M235` | critical |
| `core.replay_seam` | `M236` | critical |

N1 moves 48 -> 45; the probe registry 255 -> 258. One control repaired.
