<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-097 residue — R6 ratification packet: two SCITT parse propositions with no owner

**Disposition:** R4 then R1 in part. NP-097 was one row over five independently
describable SCITT owners (ADR-MCPRE-061 question 2), so it is split at registration and
never registered as one unit. Three controls landed; three `[[disposition]]` rows remain and
NP-097's `[[proposition]]` entry and record stay in place.

## What landed

| control | unit | `description` sentence, verbatim |
|---|---|---|
| `scitt::receipt::tests::a_leaf_index_outside_the_tree_is_refused` | `http_profile.scitt_receipt_shape` | *"…and a leaf index that names a position the tree has."* |
| `scitt::merkle::tests::the_tree_size_determines_the_leaf_index_within_every_ambiguity_class` | `http_profile.scitt_inclusion_fold` | *"…a path of the wrong length does not reach the root…"* |
| `scitt::statement::tests::editing_a_decoded_view_does_not_change_what_was_signed` | `http_profile.scitt_statement_attribution` | *"A Signed Statement is attributed by its own COSE signature and its CWT claims, not by what it says about itself"* |

## The residue, and why each is outside every ratified theorem

| rows | clause | nearest unit/theorem, and why it does not contain it |
|---|---|---|
| `scitt::retained::tests::{a_token_names_a_digest_only_when_it_is_one, one_digest_has_one_spelling}` | a retained digest TOKEN is canonical: one digest has exactly one spelling, and a token that is not a digest is not read as one | `http_profile.scitt_retained_correspondence` claims commitment EQUALITY — *the commitment a Signed Statement carries equals the one recomputed* — which is silent about the token's spelling. Canonicality is the premise equality rests on, not equality itself. |
| `scitt::cose_key::tests::a_malformed_p256_key_is_refused_at_construction` | a COSE key is well-formed at CONSTRUCTION or does not exist | `http_profile.scitt_algorithm_agreement` claims AGREEMENT — *a disagreement between the header and the key is refused rather than resolved in the key's favour* — which presupposes a key and says nothing about whether a malformed one can be built. This is the R-SEAL shape: the check belongs to the value, and no theorem states it. |

## Proposed shape

One theorem — *a SCITT value's identity is canonical at construction: a digest token has one
spelling and a key that is not a well-formed P-256 key cannot be constructed* — over
`src/scitt/{retained,cose_key}`, `tested`, direct severity `high`. It is the premise both
existing SCITT theorems consume, so it is stated once rather than twice.

## N1

Three rows, unregistered. No obligation moves.
