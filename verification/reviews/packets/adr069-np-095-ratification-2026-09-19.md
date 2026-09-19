<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-095 residue — R6 ratification packet: the delegation ISSUANCE signer seam

**Disposition:** R1 in part, R6 for the residue. Five controls landed —
`lib#delegation::verify::tests::{a_cnf_that_names_another_key_is_an_invalid_credential,
a_stale_trust_epoch_is_its_own_refusal, each_scope_failure_names_what_it_is,
revocation_is_consulted_with_every_identifier_the_credential_carries}` into
`unit://http_profile.delegated_credential_chain`, and
`tests/delegation_e2e_test#custody_signed_response_verifies_via_attestation_chain` into
`unit://http_profile.delegated_signing_custody`. Four `[[disposition]]` rows remain and
NP-095's `[[proposition]]` entry and record stay in place.

## What landed, and the clause that contains it

`http_profile.delegated_credential_chain`, `description`, verbatim:

> What an inline delegation credential must be before any response proposition may rest on
> it: three segments under the profile's own algorithm, type and key use; a root signature
> that verifies under an issuer key the trust seam resolved for the Response slot; inside
> its own nbf/exp window under a clamped skew; scoped to this verifier's audience; at an
> accepted trust epoch; and named on no revocation list by delegated kid, issuer kid or jti.

Each of the four is a clause of that sentence, and each has an in-battery twin already:
`cnf_kid_not_delegated_kid_is_credential_invalid`, `stale_trust_epoch_is_rejected_without_revocation`,
`wrong_profile_is_profile_mismatch` / `wrong_audience_hash_or_server_signer_is_audience_mismatch`
/ `wrong_key_use_is_key_use_invalid`, and `revoked_by_jti_is_revoked`.

## The residue, and why it is outside every ratified theorem

| rows | what they measure | nearest theorem, and why it does not contain them |
|---|---|---|
| `delegation::tests::{seam_minted_credential_verifies_to_the_root, seam_propagates_a_backend_failure, seam_rejects_a_non_64_byte_signature, signer_seam_is_wire_identical_to_the_in_process_path}` | the credential ISSUANCE signer seam: a remote signer's result is wire-identical to the in-process path, a backend failure propagates rather than degrades, and a signature of the wrong length is refused at the seam | THM-0019/0020 are about what a PRESENTED credential must be, not about how one is minted. THM-0108 is the nearest seam theorem and excludes these by locality: its scope says **"THE SEAM, NOT THE PROVIDERS"** over `proxy.kms_ed25519_seam`, a unit in a different Cargo project, so its `paths` may not reach `mcp-re-http-profile/src/delegation/mod.rs`. |

This is NP-102's proposition, not NP-095's: *the signer seam takes a preimage in and a
signature out, and carries nothing else across.* The two records should be ratified
together.

## Proposed shape

One theorem — *a delegated credential minted through a remote signer is the credential the
in-process path would have minted, and a signer failure is a refusal rather than a weaker
credential* — with one `tested` unit `http_profile.delegation_issuance_seam` over
`src/delegation/{mod,issue}.rs`, direct severity `critical`, and one `mutation://` probe on
the 64-byte length check. It subsumes NP-102's `tests/signer_seam_test.rs` six controls.

## N1

Nothing in the residue is registered, so no obligation moves. The unit, when it exists,
arrives with its falsifier; `config/assurance-obligation-debt.toml` is not touched.
