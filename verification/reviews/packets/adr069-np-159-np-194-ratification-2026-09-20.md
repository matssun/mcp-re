<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-159 and NP-194 — R6 ratification packet: the root-rotation ceremony, and the §11.3 question closed

**Disposition:** R2 for one row, R6 for ten. One of NP-159's eleven controls —
`root_issuance_failure_serves_until_delegated_key_expiry_then_fails_closed` — joins
`unit://proxy.delegated_signing_credential`'s battery under THM-0062. One more is split out
as **NP-194** under RR-002 C5. Nine remain in NP-159, whose `[[proposition]]` entry and
record stay in place with the title corrected to what the nine actually state.

## The lane, measured — and a correction to the brief

The work package's defining premise was that every record in this slice is in a non-default
feature lane. That is true of NP-114 and NP-158 and **false of NP-159**:

| selection | tests | of which `root_key_lifecycle_test::` |
|---|---|---|
| `cargo test -p mcp-re-proxy --test integration_async -- --list` | 167 | **10** |
| `cargo test -p mcp-re-proxy --features async_serve --test integration_async -- --list` | 197 | **10** |

`root_key_lifecycle_test.rs` and `root_authority_manifest_test.rs` carry no `#![cfg]`, so
all eleven controls select in the default cargo lane. `async_serve` adds thirty tests to the
target and none of them are these. Declaring `test_features = ["async_serve"]` here would
have entered a build configuration into the fingerprint that measures nothing, which
`_validate_test_features` exists to refuse — so none is declared, and the appended selector
carries the measurement in a comment beside it.

## What landed, and the clause that contains it

THM-0062, statement, verbatim:

> An issuance failure serves the still-valid key and then fails closed at its expiry rather
> than extending it, and the retry schedule never sleeps past a still-valid key.

`root_issuance_failure_serves_until_delegated_key_expiry_then_fails_closed` is that sentence
driven through the public `DelegatedRotor`/`DelegatedServerSigner` API with a root issuer
that answers the first mint and then nothing: K1 is kept through the overlap window, serves
to `NOW + 300 - 1`, and `current(NOW + 300)` is `None`. The unit already declares the
reader-level twin `issuance_failure_serves_the_valid_key_then_fails_closed_at_expiry`; what
this adds is that the COMPOSITION fails closed, not merely that the reader does.

It is appended to the owner unit's `tested_symbols` rather than carried by a new twin. The
unit's `paths` already contain `delegated_server_signer/mod.rs` and `signing_plane/rotation.rs`,
the two modules this control drives, so there is no §5 widening to avoid and no
`_validate_in_crate_selectors` refusal to route around — an integration-test selector enters
the fingerprint as its own source component. `test_source_patterns` for
`mcp-re-proxy/tests/integration_async` is already covered by `verification.yml`'s filters in
both blocks, so the trigger set still covers the fingerprint set.

No mutation probe is added: the rule is that a new `tested` unit at effective Medium or above
owes a falsifier, and no unit is created here. `proxy.delegated_signing_credential` already
carries `mutation://proxy/signing/delegated_credential_lifecycle`.

## The NP-159 residue

**9 controls**, `mcp-re-proxy`, rust integration test, default cargo lane, carrier
`mcp-re-proxy/tests/integration_async/root_key_lifecycle_test.rs`:

- `root_a_credential_accepted_while_a_is_current`
- `during_overlap_both_roots_are_accepted`
- `after_overlap_old_root_rejected_new_root_accepted`
- `retirement_window_boundary_is_inclusive_then_closes`
- `unknown_issuer_is_rejected`
- `empty_trust_anchor_set_trusts_no_root`
- `revoking_one_root_does_not_disturb_the_other`
- `a_revoked_root_fails_closed_and_the_split_seam_is_gone`
- `revoked_issuer_invalidates_all_descendants_before_exp`

## `PKT-COMPOSITION` §11.3, closed

The open question was whether the rotation ceremony is
`http_profile.delegated_signing_custody`'s authority, so that these ten could land with it.
The answer is **no**, on three independent grounds, given in order of weight.

### 1. That unit carries no ratified theorem

Measured over `verification/policy/theorems.toml`: no `[[theorem]]` names
`http_profile.delegated_signing_custody` as `owner` or in `supported_by`. It is one of the
twenty theorem-less units this campaign holds at 20 and may not raise. Clause 2 of the
subsumption test requires the unit to be *a strict decomposition of a proposition already
contained in the RATIFIED THEOREM's claim, its scope, or existing subordinate authority*.
There is no claim, so the clause cannot be satisfied by any argument whatsoever. Landing
these rows there would require minting a `[[theorem]]`, which every slice of this campaign
is explicitly forbidden to do.

### 2. The unit's declared proposition is the other axis

`http_profile.delegated_signing_custody`, description, verbatim:

> The delegated-signing credential lifecycle: the root is never touched within a key's life,
> a successor is minted in the overlap window and under an advanced trust epoch, a signature
> window never outlives the credential it was issued under, and an issuance that fails after
> expiry fails closed rather than continuing on the predecessor.

Four clauses, and the first one states the boundary in terms: *the root is NEVER TOUCHED
within a key's life*. Everything this unit claims is about the delegated key under a root
held fixed. The nine residue rows are about the root CHANGING — which set of trust anchors a
verifier admits at each instant of the ceremony, and what a revocation reaches. That is not
a decomposition of the custody claim; it is the claim the custody unit holds constant in
order to make its own.

The carrier's own header draws the same line:

> The complement to the delegated-KEY lifecycle: a delegated key rotates every few minutes
> under ONE root (the hot path, covered elsewhere); this proves the RARE, high-stakes
> ceremony of rotating the ROOT the whole fleet chains to, with a controlled overlap, and
> revoking a root outright.

### 3. The lane could not run it anyway

The unit's `paths` are four files under `mcp-re-http-profile/src/custody/`, so
`test_package_for` resolves to `mcp-re-http-profile`. A `tests/integration_async#` selector
names a `mcp-re-proxy` test target that package does not have, and `group_by_target` would
report it as naming no runnable target. The battery would refuse to start.

This is recorded **last and weighted least on purpose**. A mechanical refusal is not a
judgement about authority — one could always be dissolved by moving a file — and the
judgement is reason 2. Recording it first would be the defect S-08 corrected for NP-076,
where a correct verdict was resting on a false mechanical premise.

### And no other ratified theorem takes them

The verification side of all nine is `mcp_re_client_core::verify_delegated_response` against
a `TrustedIssuerSet`. The nearest ratified statement is THM-0057, scope, verbatim:

> Establishes what the document says and for how long. It does not establish that a response
> verified under one of these anchors is an answer to this request (THM-0058, THM-0059),
> that the publisher's key management is sound, or that a revocation list is complete — only
> that an identifier it names cannot resolve.

The document at rest, and its own validity window. Not which roots a live exchange is
admitted under at each instant of an overlap, not that a retirement boundary is inclusive
and then closes, and not that a revoked issuer reaches its descendants before their own
`exp`. Its owner `client.trust_manifest_lifecycle` declares six paths in
`mcp-re-client-core`, so the package refusal of reason 3 applies identically there.

**The question does not need asking a third time.**

### Kept as ONE proposition

All nine answer *which roots does the verifier admit, now* over one ceremony, and all nine
fail in one of the two directions the record names: a gap in which nothing verifies, or a
withdrawn root that is still accepted. They share one fixture, one issuer seam and one
`TrustedIssuerSet` value.

**Severity:** `critical`.

## NP-194 — split out under RR-002 C5

**1 control**, `mcp-re-proxy`, rust integration test, default cargo lane, carrier
`mcp-re-proxy/tests/integration_async/root_authority_manifest_test.rs`:

- `root_rotation_via_signed_manifest_with_auto_provisioned_roots`

It is a different authority from the nine above, which is why it does not stay with them.
The nine are about the admission decision a verifier makes given a set of anchors; this one
is about the HIGHER AUTHORITY that produces the set — a `TestRootAuthorityProvider` that
mints Root B on the fly with no human or console step, an org manifest-signing key a serving
proxy cannot forge, the A → A+B → B → A-revoked sequence carried in the signed document, and
manifest rollback protection. Filing it with NP-159 would be a record spanning two
propositions, which C5 forbids.

THM-0057 states the document half:

> Anchors are released only from a manifest whose signature verified under a trusted signer
> kid that the signature itself covers, whose profile is this one, and whose version is not
> below the monotone floor — a floor that rises on load and cannot be read as zero when it
> cannot be read at all.

That is the manifest's own integrity, and it is close. It is still not this: the theorem says
nothing about a PROVIDER that creates the root the manifest then names, which is the "no
human creates a root" property this control exists for, and its scope stops at *"Establishes
what the document says and for how long."* The same `mcp-re-client-core` package refusal
applies to its owner.

**Severity:** `critical`.
