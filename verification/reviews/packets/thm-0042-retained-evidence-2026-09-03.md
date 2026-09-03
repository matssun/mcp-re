<!-- SPDX-License-Identifier: Apache-2.0 -->
# Owner review packet — THM-0042, retained-evidence correspondence (#740)

**One subject.** ADR-MCPRE-059 §14.7 / §28. Layer 1: evidence about the tree, not an
approval and not authoritative state. THM-0095 is not in this packet.

THM-0042 is a **reopened** root, not a new one. It has no new theorem identity: the root was
declared, the statement changed under the submitted-hop identity correction, and the record
went `STALE_CLAIM`. It sits in `docs/spec/security-boundary.md` **§4 as NOT CURRENTLY
CLAIMED** and returns to §2 only after establishment *and* this review — and it is not to be
weakened to make it green.

What follows is what the claim now says, what changed to make it say that, what evidences
it, and what is still outside.

---

## 1. The claim

### Title

Retained evidence is the evidence the statement was made about

### Statement

If `verify_retained_evidence` returns `Ok`, then the commitment carried by the statement
equals the commitment recomputed from the presented reconstruction together with its
optional binding and verified-context commitments. So the presented reconstruction is the
one that statement committed to, and the `ChainLabel` the commitment embeds is the label of
THAT reconstruction — including, when it is incomplete, which hop was missing and why.

The equality is over EVERY field the commitment carries, and `submitted_commitment` is one
of them. It is the only field that reaches the hops AFTER the verified prefix: every other
identity field is derived from that prefix, so on an `Incomplete` record the unverified tail
contributes to none of them. A statement that carries no submission identity therefore
cannot bind one, and `Ok` is not returned for it — neither for a retained record that claims
one, nor for a retained record that claims none. Both are the same record: one whose tail
this comparison does not reach, and for which `Ok` would report a binding it does not have.

### Security consequence

Retained evidence cannot be swapped under a receipt, and a truncated call cannot become
COMPLETE: the label is inside what the commitment covers, so a record that says complete and
a record that says incomplete-because-hop-3-was-unverifiable are different commitments.

Nor can the unverified tail of an `Incomplete` record be substituted. An archivist holding a
statement about `[h0, h1, h2-tampered]` cannot present `[h0, h1, h2']`: the verified prefix,
the shape digest and the `incomplete:1:<reason>` label all still match, and **only the
submission identity separates them**. A record that identifies no submission is refused
rather than reported as bound on the strength of its prefix — the archivist is exactly who
would benefit from the weaker answer being indistinguishable from the stronger one.

Establishes **no confidentiality**. The receipt does not itself carry the retained call
bytes, and that is all: not unlinkability, not resistance to inference from the digests, and
not resistance to guessing a low-entropy reconstruction and confirming it against the
commitment.

### Scope

Correspondence only. It does not establish that the retained bytes are themselves valid
evidence, that the call described ever happened, or that the reconstruction is complete —
only that whatever was reconstructed is what was committed to. It does not establish
registration (that is THM-0041), and it does not establish that the commitment function is
collision-resistant; the digest is an opaque primitive here.

### Dependencies and owner

`depends_on = []`. Owner unit `http_profile.scitt_retained_correspondence`.
`review_requirement = "Owner security-specification review"`.

---

## 2. What changed, and why the record went stale

The correction is #736's, and it is the reason this packet exists rather than a re-run of
the old one.

`submitted_commitment` was taken over a **curated field list** that omitted
`signature-input`. Two submissions differing only in that header produced the same
submitted-hop identity, so the one field that reaches past the verified prefix did not
distinguish the records it exists to distinguish. It is now taken over a **closed canonical
representation** — the retained request and response, entire, destructured exhaustively, so
a field added later cannot silently fall outside the identity. That closed `R9-C074` and
`R9-C075`.

The statement above is the post-correction statement: it names `submitted_commitment`
explicitly and states the refusal for a record that identifies no submission. **A statement
that changed is a claim that has not been reviewed**, which is why the root is in §4 and why
approving the old text would approve a different theorem.

---

## 3. The zero-verified-hop hole, closed

`attest_chain` issued Signed Statements for records with **no verified hop** and skipped the
self-check on exactly those records. The reasoning was that a reconstruction which breaks at
hop 0 names no call — two empty handles and a fold over nothing, the same three values for
every unrelated submission that failed the same way.

That reasoning is **right about the identity fields and wrong about the submission**.
`submitted_commitment` is call-specific there too, and skipping left the one binding field
unexercised on precisely the records an auditor investigates. Closed by #763 (`R9-C103`,
`R9-C128`): the self-check runs on every record, and the resulting `RetainedCorrespondence`
is returned beside the statement rather than discarded — so a caller is told **which**
binding was established (`BoundToSubmissionOnly` for such a record) instead of having to
recover it by decoding the chain label of the statement it just published.

The seam does not weaken the verdict. `BoundToSubmissionOnly` means *these are the bytes the
issuer saw and no hop verified*, which is what the label already reports and what a reader
must not read as more.

---

## 4. The corpus — and the vector that was deliberately NOT regenerated

The interesting decision here is a refusal.

`s01` in `interop/manifest.json` records `produced_by: "@transmute/cose 0.3.0 + node crypto
Ed25519"`. **No MCP-RE code produced any of it**, and that is the whole value of the vector:
it shows a foreign implementation's statements are readable by ours. Its retained artifact
records *handles* rather than the submitted messages, so the submitted digest is not
reproducible from it at all — it cannot evidence this claim.

It **stays as it is, demoted in place.** Regenerating it would destroy a real interop claim
to fix a different one. It evidences receipt, statement and key-pin interoperation, and the
scope says so in as many words.

What evidences this claim instead is `conformance.retained_corpus`: a signed multi-hop
exchange **this implementation produced**, whose statement binds to the verified call its
retained messages reproduce. It is the only place the verdict is reached over an artifact on
disk rather than over a value a test constructed.

Its writer follows the established `--ignored` pattern (`write_http_profile_fixtures`,
`write_delegation_fixtures`): `write_retained_corpus -- --ignored --exact` regenerates the
corpus and `the_committed_bytes_are_the_ones_this_implementation_produces` compares the
committed bytes against a fresh generation. Committed bytes are therefore **compared, not
assumed**, and the commitment is reproducible across runs and versions.

---

## 5. Evidence and fingerprints

Three units, all class V0, 19 declared controls, no assumptions in the closure.

| unit | controls | what it holds |
|---|---|---|
| `http_profile.scitt_retained_correspondence` | 10 | the comparison itself, and every way it must refuse |
| `http_profile.submitted_hop_identity` | 4 | the closed representation the submitted digest is taken over |
| `conformance.retained_corpus` | 5 | the on-disk artifact, and that it is not a happy path |

**The negative controls are the substance**, and they are named individually because each is
a distinct way `Ok` could be returned for a record it does not describe:

- `a_truncated_chain_is_refused_even_though_hop_zero_matches`
- `a_substituted_unverified_tail_is_refused_even_though_the_verified_prefix_matches`
- `a_statement_with_no_submission_identity_cannot_bind_retained_bytes`
- `a_statement_that_identifies_no_submission_binds_nothing`
- `a_record_with_no_verified_hop_is_bound_by_its_submission_and_says_only_that`
- `a_record_with_no_verified_hop_has_no_identity`
- `absent_bindings_do_not_satisfy_a_commitment_that_names_them`
- `a_verified_receipt_does_not_imply_the_evidence_is_retained`
- `the_two_evidence_roles_are_not_interchangeable`
- `header_order_is_part_of_the_submission_identity`
- `every_retained_header_is_inside_the_submitted_identity`
- `the_response_status_is_inside_the_submitted_identity`
- `the_empty_submission_has_an_identity_of_its_own`
- `a_tampered_retained_body_no_longer_corresponds`
- `a_truncated_corpus_no_longer_corresponds`

The last two are the corpus's own anti-happy-path controls, and
`the_committed_bytes_are_the_ones_this_implementation_produces` plus
`the_manifest_describes_the_committed_artifacts` keep the artifact honest about itself.

Measured at merged `main` `25269c12`:

```
THM-0042  sha256:9d769c2c98f65716b1a4706bb3cde2fe6d76e49fd989851fe802310b69d03c6f
  theorem_claim         sha256:46063fead69687158424fe4f17ece7bb319c15d850e64a4f0305a5f915333bdb
  theorem_dependencies  {}
  review_requirement    Owner security-specification review

unit://http_profile.scitt_retained_correspondence
          sha256:82bd4cf18a4ad7e5b744243fa7ebf87eda78dea8b44b9abc8de736064fb320d0
unit://http_profile.submitted_hop_identity
          sha256:f5eb2ac66cbb0114cc909bd48fab816325b2f48a867d02267c6ca3d79d091c5b
unit://conformance.retained_corpus
          sha256:c3ad94a80d46cebeb4bfdb0cdf2618f0f5e3f52f7e827db648b4a3932790b446
```

The **unit** fingerprints moved with #799's prover identity and will move again on any
toolchain pin; the **theorem** fingerprint has no toolchain component and is what a review
record binds. Sign against the theorem fingerprint.

Batteries: `cargo test -p mcp-re-http-profile -p mcp-re-conformance` — all suites pass, 0
failures, measured 2026-09-03 at this tree.

Specification review: `UNREVIEWED`. Assumption axis: nothing in the closure.

---

## 6. What is still outside

Registration — whether any transparency service ever saw the statement — is THM-0041, under
THM-0072. The `position_profile` rows on the service pin (`R9-C085` / `C086` / `C098` /
`C102` / `C112`) are THM-0068 under THM-0072 and are a different claim; they are not closed
by this packet and are not weakened by it.

Collision resistance of the commitment digest. The digest is opaque here, deliberately: this
theorem is about equality of a computed value, and an adversary who can produce two
reconstructions with one commitment defeats it without contradicting anything stated above.
That obligation lives at `boundary.crypto_primitives`.

Confidentiality of the retained bytes, in every form — see §1.

---

## 7. The one action this packet does not take

**Restoring THM-0042 to `docs/spec/security-boundary.md` §2.** The boundary states the
precondition in its own words: *"the corrected `submitted_commitment` proposition must be
independently reviewed and established against genuine retained-evidence correspondence
evidence before it returns to §2. The theorem is not to be weakened to make it green."*

Establishment is a lane result; the independent review is a signature. Neither is this
session's to record, so §4 stands and the move is left as the single act that follows
approval.
