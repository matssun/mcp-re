<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-048 — ratification packet: the record contract at the store, and the archive that is not it

**Disposition:** R2 for three of four — registered as `unit://proxy.retained_record_at_the_store`
under **THM-0112**, falsifier **M348**, demonstrated red in the default cargo lane. R6 for the
fourth, which stays NP-048 and whose record is rewritten to describe exactly it.

## Registered (3)

`mcp-re-proxy`, rust unit tests, **default cargo lane** (measured: all three are among the
1498 controls `cargo test -p mcp-re-proxy --lib -- --list` selects; no `test_features`
declared and none would be true), carrier `mcp-re-proxy/src/transparency/durability.rs`:

- `lib#transparency::durability::tests::only_the_signed_headers_are_retained`
- `lib#transparency::durability::tests::a_record_without_the_schema_token_is_refused`
- `lib#transparency::durability::tests::a_retained_exchange_comes_back_byte_identical`

### The subsumption argument, clause by clause

**Clause 1 — no fingerprint field moves.** `statement`, `security_consequence`, `scope`,
`depends_on` and `review_requirement` of THM-0112 are byte-identical to `origin/main`.
Verified by recomputing all 130 theorem fingerprints over those five fields: 0 of 130 moved.

**Clause 2 — strict decomposition of a contained proposition.** Three clauses, quoted:

> A retained request or response keeps the headers named inside the ONE `Signature-Input`
> dictionary member the verifier checked

> The stored form carries a schema token and refuses a record naming a different one,
> refuses a record carrying a field it does not know, and refuses a body that does not
> decode

> A record this implementation writes reads back as the bytes it was written from.

The three controls are those three clauses performed by the live retention authority rather
than by the encoder in isolation. `proxy.retained_record_content` measures them over
`retained_record.rs` and `covered_set.rs`; it cannot cite these, and its own battery comment
already records why — `transparency/durability.rs` is not in its `paths`, and a unit may not
select a control whose source it does not measure, because such a control can be rewritten
under the same name without moving the fingerprint.

**The scope sentence, and the reading taken.** THM-0112's scope says:

> NOT A CLAIM ABOUT THE STORE. Content addressing, durability, capacity and the fail-closed
> serving posture are elsewhere.

The reading taken — stated here and beside the unit, and NOT by editing the scope, which is
a fingerprinted field and outside campaign authority — is that the sentence ENUMERATES, and
the enumeration is the store's STORAGE properties: how an object is named, whether the write
survives, how many fit, and what a full volume does. The new unit claims none of the four,
and says so in its own description: *"It claims nothing about how the object is NAMED,
whether the write is durable, how many objects fit, or what a full volume does."* What it
claims is that the record contract the statement already carries is what the store performs
— and the statement's own last clause is about exactly a write and a read, so a reading on
which the contract stopped at the encoder would make that clause claim nothing.

The two readings are separable by a test rather than by preference. Under the enumerating
reading, NP-047 (retaining twice yields one object) is REFUSED, because content addressing
is the first item in the enumeration — and it is refused, in its own packet. A reading that
admitted everything the store does would have taken NP-047 too.

**Clause 3 — no new product promise.** No trust boundary, no external assumption, no choice
between product behaviours. The unit measures the same contract at a second point on the
same path.

**Clause 4 — theorem-level change is `supported_by` only.** One entry added.

### The falsifier

**M348** weakens `retained_request` in `transparency/retained_record.rs` from
`covered_headers(&request.headers, REQUEST_LABEL)` to `request.headers.clone()` and expects
red on `only_the_signed_headers_are_retained` and `a_retained_exchange_comes_back_byte_identical`.
`VERDICT: PASS`, both red, in the default lane.

The placement is the argument. A probe inside `durability.rs` would have to pretend the
store has a filter of its own, which it has not. Weakening the encoder one module away and
watching the STORE's controls go red is what establishes that the store performs the same
rule and has not acquired a second one — which is the whole of this unit's proposition.

## Referred (1), and it stays NP-048

`lib#transparency::retained_archive::tests::an_object_that_is_not_a_retained_record_is_refused`.

Reaching it would need `retained_archive.rs` in the new unit's `paths`. The file's own header
refuses that before any registry does:

> One fact, and it is not the one [`super::durability`] owns.

and records the separation as an ADR-MCPRE-061 §8 question 2 finding, with the concrete cost
of having had them merged — an auditor that could not run against a read-only mount, held
write access to the evidence it was attesting, and started a thread that never received a
job:

> independently describable, and the second one's consumer needs none of the first's

A unit about what the WRITER performs may not swallow the reader. The control's two in-file
siblings — `a_read_only_archive_opens_where_the_retention_authority_refuses` and
`a_missing_hop_is_absent_rather_than_an_error` — are the rest of that authority, and no
theorem in the estate states it.

## What would discharge the remainder

A theorem over the read-only archive: what an auditor's projection may be opened against,
and what it refuses. Its battery is the three controls in `retained_archive.rs`, of which
this is one.
