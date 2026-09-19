<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-037 — R6 ratification packet: a guard's declared inputs resolve, or the guard fails loudly

**Disposition:** referred, in part. Six controls, six `[[disposition]]` rows, one record kept
and rewritten. Three of the record's original nine landed under THM-0111 in the same change
and are not part of this referral.

## Provenance

Filed by the ADR-MCPRE-069 Batch 8 census over `mcp-re-test-paths` as one record of nine
controls across three declaration tables and a resolver. Split under RR-002 C5 during the
RM-S2 slice, which found the record holding two independently describable authorities.

## What landed, and why the rest could not follow it

THM-0111's scope states the walk it runs in two clauses:

> The control walks every crate's source tree, takes each file's production half, and asserts
> the set of files holding a verdict literal is exactly the two frozen vocabularies.

`audit_vocabulary_guard_test::minting_files` resolves each tree through
`mcp_re_test_paths::resolve_runfile`, whose cargo fallback consults `source_trees::sentinel_for`
and then walks the sentinel's PARENT. The three `src/source_trees.rs` controls are therefore a
premise of that clause in terms, and they are now
`unit://conformance.scanned_tree_declaration`, falsified by `M325`.

The other six are about tables the walk never reads:

| control | table | who reads it |
|---|---|---|
| `lib#tests::an_unknown_key_is_refused_rather_than_resolved` | the resolver's terminal refusal | every consumer of `resolve_runfile` |
| `lib#tests::no_key_is_declared_twice` | `SOURCE_FALLBACKS` | the guards that parse a fixture FILE |
| `lib#tests::the_fallback_table_names_only_files_that_exist` | `SOURCE_FALLBACKS` | the same |
| `lib#tests::no_binary_key_is_also_a_source_fallback` | `BINARY_KEYS` | the proxy and auditor integration lanes |
| `lib#traceability_sources::tests::every_witness_names_a_file_that_exists` | `TRACEABILITY_SOURCES` | the security-traceability manifest guard |
| `lib#traceability_sources::tests::no_witness_is_declared_twice` | `TRACEABILITY_SOURCES` | the same |

## Why this is R6 and not a widening

The operational test is the one this campaign uses everywhere: *can the proposition be false
while every clause of the candidate theorem stays true?* It can, trivially. Point
`MCP_RE_PROXY_CLI` at a binary that is not built, or let a `TRACEABILITY_SOURCES` witness name
a file that has moved, and THM-0111's walk is untouched — it resolves no binary key and reads
no witness. Every clause of THM-0111 remains true, and the proposition is false.

The tempting registration is therefore the one to name and refuse. `conformance.scanned_tree_declaration`
could be given `paths = ["mcp-re-test-paths/src/source_trees.rs", "mcp-re-test-paths/src/lib.rs"]`
and would then select all six. That is a unit's battery reaching outside the source its own
theorem measures, which ADR-069 §5 holds to be strictly worse than leaving a control
unregistered — the unit's fingerprint would move for edits THM-0111 has no opinion about, and
THM-0111 would appear to establish a resolver property it never asked a question about.

`mcp-re-test-paths/src/lib.rs` is entry 134 of `config/unit-closure-exclusions.toml` and stays
there, correctly: it is reachable from a measured unit's closure and answered for by no unit's
`paths`. This packet is the record of why, rather than a memory of it.

## Why no other theorem contains it either

Every theorem whose evidence resolves through this crate was checked. They are statements
about what a proxy, a client or a carrier REFUSES; the resolver is the thing that finds the
binary the lane then drives, and its failure mode is upstream of every one of them. That is
the asymmetry: a broken resolver does not make any of those theorems false, it makes their
evidence vacuous. A proposition whose falsehood turns a lane green rather than red is not a
decomposition of what that lane establishes.

The record's own "if false" states the class and names its two measured instances in this
repository — a `tests/` glob that silently exempted a crate from the srcs gate for a whole
campaign, and an empty join that read as a clean tree.

## Proposed shape for ratification

A theorem over the EVIDENCE PLATFORM rather than the product, owned by a new unit over
`mcp-re-test-paths/src/lib.rs`, `src/source_fallbacks.rs` and `src/traceability_sources.rs`:

> Every env key a guard may present resolves to a declared path or is refused BY NAME. No key
> is declared twice, no binary key is shadowed by a source entry, and every declared fallback
> and witness names a file that exists — so a lane that reports a clean tree has read one.

Its dependents are the integration lanes and the traceability manifest guard, not the
verification theorems, which is the correct direction and the reason it could not be folded
into any of them. It is the natural sibling of `conformance.scanned_tree_declaration`, which
this slice registered, and of `conformance.production_half_definition`: together the three are
the apparatus the evidence estate measures itself with, and two of the three now have owners.

## N1

Nothing registered from this half. No unit changed by it, and no obligation moves. The two
units this slice DID register each carry a demonstrated-red falsifier (`M324`, `M325`), and
`scripts/assurance_obligation_gate.py` reports 0 open N1 after the change.
