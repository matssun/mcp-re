<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 split — offline receipt verification, as six owners

**ADR-MCPRE-068 Phase 1**, second on the campaign ruling's scheduler after the verifier:
highest semantic fan-out among what remained, at `high`, inside THM-0072's closure.

`http_profile.scitt_receipt_offline` was one unit over 14 files and 24 controls whose **own
description named six propositions** — *the statement's own signature and its CWT
attribution, the receipt's shape, the RFC 9162 inclusion fold, the transparency service's
signature over the root that fold DERIVED, the position commitment where the pinned profile
binds one, and algorithm agreement on both signatures.* ADR-MCPRE-061 question 2, answered in
the unit's own text.

---

## 1. Six owners, and the altitude they sit at

```
THM-0041  an offline-verified receipt proves registration, and its root was never supplied
  ├── scitt_statement_attribution   the statement is attributed by its signature, not its claim
  ├── scitt_receipt_shape           what a receipt IS before anything is folded
  ├── scitt_inclusion_fold          the RFC 9162 fold itself
  ├── scitt_derived_root            the root was DERIVED, and the service signed it
  ├── scitt_position_commitment     a bound profile refuses a receipt that commits to no position
  └── scitt_algorithm_agreement     the protected `alg` and the resolved key agree, exhaustively

THM-0072  …on the service THIS DEPLOYMENT PINNED
  ├── depends_on THM-0041
  └── scitt_service_pin             the one thing it adds
```

**THM-0072 was rewired down, not up.** It already depended on THM-0041, so restating the six
under it would have duplicated a closure it already reaches. What it keeps is
`scitt_service_pin` — *the key it verifies under, its leaf profile and its position profile
all came from that one reviewed document* — which is its whole distinguishing sentence.

**No intermediate theorem is invented.** Each unit's description states its proposition, and
a `THM-` is for a claim that is a reusable premise across a theorem boundary or needs owner
specification review. None of these is.

---

## 2. Two probes for six propositions, and what the other four found

The unit carried **M78** and **M79**. Splitting made the other four merge-fatal instead of
invisible — the same thing the verifier split did for THM-0017 — so **M72–M75** were written.
Two of the six runs failed, and both failures were correct.

### 2.1 M78's control was in the wrong unit

M78 attacks *the fold's output compared against the root the receipt commits to*, and expected
`an_unbound_receipt_still_refuses_a_forged_path_on_the_derived_root_alone` — which the first
partition had put in `scitt_inclusion_fold`. The lane refused: *a control outside the battery
is not evidence*.

It was right, and the control belongs to `scitt_derived_root`: **detached is where "derived,
never supplied" is unambiguous**, because there is no root in the receipt to compare against,
so the fold's output IS what the service signature is checked over. Moved, and M78 passes.

### 2.2 M73 found a control that tests a copy of production

The one that matters. `a_leaf_index_outside_the_tree_is_refused_before_any_fold` — the control
for *RFC 9942 §5.2, quoting RFC 9162: a leaf index at or beyond the tree size fails proof
verification* — stayed **green** with the production guard deleted.

Twice. First when the probe attacked the guard in `rfc9162_root_from_inclusion_proof`, which
turned out to be defence in depth (the parser refuses first). Then again when it was re-aimed
at the parser itself, where the refusal actually happens.

The cause, in the test module:

```rust
fn decode(bytes: &[u8]) -> Result<InclusionProof, HttpProfileError> {
    …
    let leaf_index = as_u64(leaf_index)?;
    if leaf_index >= tree_size {                      // ← a SECOND COPY of the guard
        return Err(HttpProfileError::MalformedEvidence(
            "scitt inclusion proof leaf index outside tree",
        ));
    }
    …
}
```

**The test re-implemented the parser inside its own module** — the same destructuring, the
same `as_u64`, and the same refusal, written out a second time — and asserted against the
copy. It said nothing whatever about production. Deleting the production guard could not fail
it, because the control never executed production code.

This is the repository's own named hazard, one layer over: the R9-C094 case the Python SDK
unit records, where *a fake with short-read semantics `http.client` lacks* made a control
unable to fail over a property that was false. Here the fake was a copy of the function under
test.

**Fixed**: `decode` now builds the real `COSE_Sign1` the production path parses, with the
unprotected inclusion-proof header the reader looks for, and calls `read_inclusion_proof`
itself. The control passes; M73 turns it red.

**Nothing but a falsifier could have found this.** The control was green, correctly named,
well commented, and in the battery of a unit under a declared root. Reading it would not have
helped — the copy is faithful.

---

## 3. What the split buys

- six propositions, six owners, six falsifiers where there were two;
- `THM-0041`'s conjuncts are attacked one at a time, each by a probe naming it;
- a control that established nothing now establishes what it says;
- `scitt_inclusion_fold` is isolated as **pure RFC 9162 tree mathematics** — the one
  proposition here a prover could take, and a Phase-2 `proved` candidate rather than a
  `tested` one.

## 4. What it does not

The six share `scitt/mod.rs` and `wire.rs`, and three of them share `cose_key/`. That is
honest: the COSE reader is read by the statement, the service signature and the algorithm
agreement alike.

`scitt_position_commitment` is kept separate from `scitt_derived_root` although both live in
`offline.rs`, because they fail independently — a receipt can verify against a correctly
derived root while its position is unchecked, which is exactly the pre-v2 contract
`a_receipt_restated_at_another_position_is_refused_only_when_the_position_is_bound` contrasts.

## 5. Measured

```
[manifests] PASS — 164 unit(s), 130 theorem(s)
verify-mutations: PASS — M72, M73, M74, M75, M78, M79, each turning a declared control red
claim-surface gate: OK   ·   check-generated: VERDICT: PASS
cargo test -p mcp-re-http-profile --lib scitt:: — 43 passed
clippy -D warnings: clean   ·   21 platform suites: 0 failure(s)
obligations: 75, unchanged — every one of the six discharges N1
```
