<!-- SPDX-License-Identifier: Apache-2.0 -->
# HP-3 — The bytes signed are the bytes the caller wrote, or the body is refused

R6 referral (**residue** of NP-088), `http_profile` cluster. `SOURCE_REVISION: cdb28a93`.
Read-only. **This packet carries two reclassifications OUT of R6 — read §2.**

**Filed as** `verification/reviews/packets/adr069-np-088-ratification-2026-09-19.md` — the
`http_profile` R6 cluster's packet **HP-3**. Sibling handles `HP-4`…`HP-8` name packets for
records this slice did not register, and are not filed here.

## 1. The question

Does the owner ratify a theorem stating that this profile REFUSES a body it cannot carry
through its own JSON round trip unchanged — rather than rewriting it — so that the bytes
covered by a signature are the bytes the caller wrote? Or decline it, leaving 14 controls at
ADR-069 §5 step 1?

## 2. Records covered, control count, and two reclassifications

**NP-088 residue.** NP-088 holds **19** rows at `cdb28a93` (`CD-14012…CD-14030`, all
`mcp-re-http-profile`; 5 in `lib#body::decimal_token::tests::*`, 14 in `lib#body::tests::*`),
counted from `control-dispositions.toml` via `tomllib`. The analysis proposes R2 for 3 and
R6 for 16. **Re-testing moves two more to R2, so this packet is 14, not 16.**

### 2.1 Reclassified R2 — `lib#body::tests::insert_preserves_existing_meta_entries`

Contained by **THM-0125**, statement, quoted verbatim and match-verified against
`git show cdb28a93:verification/policy/theorems.toml`:

> The caller's own `params._meta` survives signing unchanged, and the MCP-RE evidence block
> lands at the body root rather than inside the caller's content.

The control (`git show cdb28a93:mcp-re-http-profile/src/body/mod.rs:106-112`) inserts a block
into a body already carrying `_meta.other` and asserts `_meta.other` survives beside
`_meta["k.demo"]`. That is the composer-level mechanism of THM-0125's clause, at the root
rather than under `params`. **Clause 2 passes** (strict decomposition), clauses 1, 3 and 4
pass (a `supported_by` append is not a fingerprint component). It is campaign work under
THM-0125, not an owner decision.

**Caveat the implementing slice must not skip:** THM-0125's only unit today is
`client.request_construction`, in `mcp-re-client-core`. This control is in
`mcp-re-http-profile` and must go into a **new** http-profile unit appended to THM-0125's
`supported_by` — never into `client.request_construction` by widening its `paths` across the
Cargo project line.

### 2.2 Reclassified R2 — `lib#body::tests::insert_then_extract_roundtrips`

The positive control for block extraction. Contained by **THM-0015**, statement,
match-verified: *"the request evidence block parsed and validated under the profile tag"*.
It belongs with the three the analysis already routes to the proposed
`http_profile.evidence_block_closure` unit — `foreign_field_fails_closed`,
`non_object_body_fails_closed`, `absent_block_is_missing_evidence` — as their anti-vacuity
partner. Registering the three refusals without the round trip would leave a battery in which
`extract_meta_block` returning `Err` unconditionally is green.

### 2.3 The 14 in this packet

| family | controls |
|---|---|
| representability refusal (7) | `a_decimal_the_round_trip_would_alter_is_refused_not_rewritten`, `an_integer_the_round_trip_would_alter_is_refused_not_rewritten`, `a_representable_decimal_keeps_its_value_through_the_composer`, `a_wide_but_exactly_carried_decimal_is_composed_not_refused`, `representable_numbers_still_compose`, `the_boundary_still_refuses_what_the_carrier_alters`, `the_representability_scan_never_reads_past_the_body` |
| decimal-token algebra (5) | `a_wide_significand_is_compared_digit_for_digit`, `an_unstateable_exponent_is_none`, `numbers_that_differ_are_not_equal`, `one_number_written_many_ways_is_one_value`, `what_is_not_a_number_is_none_and_never_a_value` |
| duplicate member names (2) | `a_duplicate_member_name_is_refused_and_lookalikes_are_not`, `an_escaped_duplicate_member_name_is_refused_like_a_plain_one` |

**Is this one proposition or several?** The task requires a heterogeneous residue to be split
before disposition. Tested: the decimal-token algebra is **not** a separate authority — it is
the comparison `reject_unrepresentable_json` is defined in terms of ("a number the round trip
would alter" is exactly "the token before and the token after are not the same value"), and
its five controls are unreachable as a proposition without the refusal they implement. The
duplicate-member arm is the same predicate over a different JSON construct: a body whose
round trip would silently drop a member is a body the carrier alters. One proposition:
*what the carrier cannot carry unchanged does not get signed*. No split.

## 3. Why existing authority does not answer it

**No theorem in the registry states a composition-side refusal over the body.**

- **THM-0014**, statement, match-verified: *"the covered `Content-Digest` agreed with the
  body"*. Verification-side, and about a digest over bytes already fixed. It is silent on how
  those bytes came to be.
- **THM-0015**, statement, match-verified: *"the request evidence block parsed and validated
  under the profile tag"*. The BLOCK, not the body around it. Its scope, match-verified,
  narrows further: *"It does not establish that the artifact material the caller supplied is
  the credential the peer actually holds — only that the binding verified against what was
  supplied."*
- **THM-0125**, scope, match-verified: *"THE SHAPE, NOT THE SIGNATURE'S CORRECTNESS. That the
  RFC 9421 signature base is composed correctly and verifies is the carrier's, under the
  http-profile units."* THM-0125 owns one clause of the body's treatment (the `_meta`
  survival reclassified in §2.1) and explicitly hands the rest here.
- **THM-0065 / THM-0075** (`http_profile.response_emission_binding`) are response emission:
  the unit's `paths` is the single file `mcp-re-http-profile/src/sign.rs`, and neither theorem
  mentions number representability.

Nothing quoted above contains *"a number the carrier's round trip would alter is REFUSED,
NOT REWRITTEN"*, and no keyword sweep over the 130 theorems for representability, round trip
or decimal returns a carrier-side hit.

## 4. Which subsumption clause fails

**Clause 3 fails, and it is the strongest clause-3 failure in this cluster.** This is the
proposition that makes *"the signature covers what the caller sent"* true. Every other claim
in the profile is conditional on it: THM-0014's digest agrees with **the body**, and if the
composer may rewrite `9007199254740993.0` to `9007199254740992` on the way in, the digest
agrees with a body the caller never wrote. That is an independent, externally meaningful
product promise, and it is one an integrator designs around — it is why a MCP-RE client
refuses at the call site rather than sending something a verifier will attribute to the
caller.

**Clause 2 fails** against THM-0014's verification-side phrasing and THM-0125's explicit
handoff.

**Not because the controls sit in a shared `paths` tail — and here the tail is the widest in
the cluster.** Measured at `cdb28a93`, `mcp-re-http-profile/src/body/mod.rs` appears in the
`paths` of **eleven** units and `src/body/decimal_token.rs` in **eleven**; **neither appears
in any unit's `tested_symbols`**. This is the `http_profile.verifier_results` 1→10 split's
22-shared-path residue in its purest form: the unit layer was partitioned, the shared bottom
was left in every partition's `paths` and in no partition's battery. Every one of the eleven
successors could "accept" these 14 on a `paths` argument, and none of their `description`
sentences contains the proposition — `http_profile.request_floor_result`'s, match-verified,
is *"What a successful `Verifier::verify_request_floor` return ESTABLISHES about the request
supplied…"*, which is the wrong direction (a successful return, not a refused composition).
**"It is in the paths" is the argument this packet exists to refuse.**

## 5. Proposed theorem text

- **statement** — Before this profile signs a body, it scans the body for values its own JSON
  round trip would not carry unchanged, and REFUSES rather than rewriting: a decimal or
  integer whose reparsed value differs from the written one, and a duplicate member name —
  whether written plainly or through an escape — make the body uncomposable. The refusal is
  exact rather than conservative: width does not decide it, a wide significand that is
  carried exactly still composes, and representable numbers and lookalike member names are
  unaffected. The underlying comparison is a decimal token compared digit for digit, in
  which one number written many ways is one value, numbers that differ are unequal, an
  exponent the token cannot state is no value at all, and what is not a number is never
  silently treated as one. The scan is bounded: it reads no byte past the body it was given,
  for any prefix of any input.
- **security_consequence** — The excluded outcome is a signature that covers bytes the caller
  did not write. Every downstream claim in this profile is conditional on the body: THM-0014's
  covered `Content-Digest` agrees with **the body**, so a composer that rewrites
  `9007199254740993` to `9007199254740992` produces evidence that faithfully attributes to the
  caller a value the caller never sent — and the tamper-detection machinery agrees, because
  nothing was tampered with after composition. The alternative to refusing is not a benign
  normalisation; it is a silent semantic edit performed by the party about to vouch for the
  result. The bound on the scan is the second half: an unbounded or over-reading scan on
  attacker-supplied bytes is a parser primitive in the signing path.
- **scope** — COMPOSITION, NOT VERIFICATION AND NOT CONTENT. It establishes nothing about
  whether a signature verifies, what the evidence block contains, or whether the caller's
  content means anything — the block's own closure is THM-0015's and the wire surface is the
  carrier-closure claim's. It is not a claim that the profile's JSON encoder is correct in
  general: what is claimed is that values it would alter are refused, which is a statement
  about the boundary rather than about the encoder's coverage. It says nothing about response
  bodies emitted by `sign.rs` (THM-0065/THM-0075) beyond what the shared composer gives them.
  It does not establish that the caller's `_meta` survives — that clause is THM-0125's and is
  reclassified there.
- **depends_on** — `[]`. It is consumed by THM-0014 and THM-0015 rather than consuming them;
  an edge would invert the dependency.
- **review_requirement** — `Owner security-specification review`.

## 6. Units that would support it

One, and it takes both files because the algebra and the boundary are one authority (§2.3).

| unit | paths | test_features | symbols | exist today |
|---|---|---|---|---|
| `http_profile.body_representability_boundary` | `mcp-re-http-profile/src/body/mod.rs`, `mcp-re-http-profile/src/body/representable.rs`, `mcp-re-http-profile/src/body/carried_number.rs`, `mcp-re-http-profile/src/body/decimal_token.rs` | none (default lib lane) | the 14 in §2.3 | yes, all 14 |

`evidence_class = "tested"`; `direct_consequence_severity` **critical** — the registry's value
for NP-088, unchanged: a signature over bytes the caller did not write is an attribution
failure, not a robustness one.

**N1, effective severity critical ⇒ a demonstrated falsifier. Two, because the arms are
independently deletable:**

| probe | anchor | weakening | expect_red |
|---|---|---|---|
| `mutation://http_profile/body/representability_refusal` | the `reject_unrepresentable_json` call in `insert_meta_block` | `let _ = reject_unrepresentable_json(...)` — compose anyway | `a_decimal_the_round_trip_would_alter_is_refused_not_rewritten`, `an_integer_the_round_trip_would_alter_is_refused_not_rewritten`, `the_boundary_still_refuses_what_the_carrier_alters` |
| `mutation://http_profile/body/duplicate_member_refusal` | the duplicate-member-name detection in the body scan | accept the last occurrence | `a_duplicate_member_name_is_refused_and_lookalikes_are_not`, `an_escaped_duplicate_member_name_is_refused_like_a_plain_one` |

**An adequacy warning the owner should weigh before granting.**
`the_representability_scan_never_reads_past_the_body` (`body/mod.rs:369-388`) is a bounded
fuzz over 12 seeds × every prefix. It is real coverage, but it establishes the bound only for
those seeds; no probe can make it red by deleting a bound it does not assert positively. If
the owner wants the bound IN the statement — this packet puts it there — the honest reading
is that the clause is evidenced at class `tested` by a small corpus, not proved. Removing the
clause from the statement is the alternative, and it is cheaper than over-claiming it.

## 7. Lane correspondence — measured, not assumed

`mcp-re-http-profile/src/lib.rs:54` is a bare `pub mod body;` — no feature gate. Measured
with `grep -cE '#\[cfg\(feature|#\[ignore'`:

| file | gates/ignores | `#[test]` count |
|---|---:|---:|
| `src/body/mod.rs` | 0 | 14 |
| `src/body/decimal_token.rs` | 0 | 5 |

Crate features at `cdb28a93` are `verify` alone (the Verus lane). All 14 controls compile and
run under `cargo test -p mcp-re-http-profile --lib` with `test_features` unset — the lane the
proposed unit names. **None compiles to zero tests in that lane.**

## 8. Fingerprint consequence

New theorem, `depends_on = []`, one new unit. `_dependency_closure`
(`tools/verification/_fingerprint.py:683-704`) walks downward only; `fingerprint_theorem`
(`:707-727`) excludes `supported_by`. **Granting this packet moves ZERO existing
fingerprints.**

The two reclassifications in §2 are also fingerprint-free: both are `supported_by` appends
(THM-0125 and THM-0015), and `supported_by` is not one of the five components.

Conditional cost, priced and not proposed: `THM-0014 depends_on <new>` would move THM-0014
and, transitively, THM-0015 and everything above it. This packet does not propose that edge —
see the `depends_on` rationale in §5.

## 9. What the owner is NOT being asked

Not to rule on `insert_preserves_existing_meta_entries` or `insert_then_extract_roundtrips`
(§2.1, §2.2 — campaign work). Not to rule on block closure (THM-0015's). Not to claim the
JSON encoder is complete or correct in general. Not to merge this with HP-1: the wire surface
and the body are adjacent and distinct, and one statement covering both would need an "and" —
the ADR-061 question-1 signal.

## 10. If declined

The 14 controls stay `new-proposition` at ADR-069 §5 step 1. The terminal state: the
proposition that makes every other http-profile claim mean what it appears to mean — *the
bytes signed are the bytes the caller wrote* — remains tested on every PR, sitting in eleven
units' `paths`, and claimed by nothing.
