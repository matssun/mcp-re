<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-098 residue — R6 ratification packet: the RFC 9421 wire surface refuses rather than normalises

**Disposition:** R1 in part, R6 for the residue. Seven controls landed — six into
`unit://http_profile.request_floor_result` and one into
`unit://http_profile.bound_response_seam_result`. Ten `[[disposition]]` rows remain and
NP-098's `[[proposition]]` entry and record stay in place.

## What landed, and the clause that contains it

`http_profile.request_floor_result`, `description`, verbatim:

> What a successful `Verifier::verify_request_floor` return ESTABLISHES about the request
> supplied: the covered `Content-Digest` agreed with the body, the RFC 9421 signature
> verified over the reconstructed base under a policy-accepted algorithm, the parameters
> were admitted as current, and the presented keyid resolved through the trust seam for the
> Request slot.

* the three `algorithm_confusion_test` controls give *"policy-accepted algorithm"* its
  content — the battery already holds `an_ed25519_signature_declaring_ml_dsa_is_rejected`;
* `unsigned_request_fails_closed` is the signature clause's negative;
* `verified_request_exposes_resolved_actor_identity` and
  `same_keyid_different_slots_do_not_collapse_actor_id` are the trust-seam/Request-slot
  clause, beside the battery's existing `resolver_returning_wrong_slot_is_rejected`.

`http_profile.bound_response_seam_result`, `description`, verbatim: *"the presented keyid
resolved through the trust seam for the Response slot, and the actor the seam returned IS
the accepted signer"* — which is `verified_response_exposes_resolved_server_actor` exactly.

## The residue, and why each is outside every ratified theorem

| rows | clause | nearest theorem, and why it does not contain it |
|---|---|---|
| `verify::floor::sf_dictionary::tests::{an_empty_dictionary_member_is_refused_not_ignored, dictionary_member_spacing_is_refused_not_normalised}`, `verify::floor::signature_input::tests::{alternate_signature_input_spellings_are_refused_not_normalised, a_space_inside_a_quoted_parameter_value_is_kept}`, `verify::floor::signature_parameters::tests::negative_zero_is_not_an_sf_integer` | **refused, not normalised**: two wire forms never become one base | THM-0014 names the base only as the OBJECT of verification — *"the RFC 9421 signature verified over the reconstructed signature base"* — and states nothing about which spellings reconstruct to it. Parser-differential resistance is a distinct product promise. Same family as NP-090; ratify together. |
| `tests/proof_path_test#duplicate_authorization_fails_closed` | a duplicated covered header is refused at SIGNING | the test calls `sign_request`, not `Verifier::verify_request_floor`. It is outside the unit's declared subject entirely, whatever its clause. Belongs with the wire-surface family above. |
| `tests/proof_path_test#content_encoding_fails_closed` | a content coding makes the body-as-written ambiguous, so it is refused | THM-0014's body clause is *"the covered `Content-Digest` agreed with the body"*. Absence of a content coding is a different fact — it is what makes *the body* well defined. NP-088's family (*the body is signed as written, or refused*). |
| `lib#verify::bound_request::tests::a_request_with_no_signature_input_has_no_handle` | `request_evidence_of` yields no handle without a signature input | the unit's description names `Verifier::verify_request_floor`. This measures a different function, and the handle proposition is NP-100's, which THM-0010 excludes by name. |
| `tests/proof_path_test#foreign_tag_fails_closed` | a foreign evidence tag is refused | NP-087's injectivity/closure family; see the evidence-block packet. |
| `tests/proof_path_test#signer_and_verifier_derive_the_same_evidence_handle` | signer and verifier agree on the handle | NP-100's headline clause, which **THM-0010 declines in its own words**: *"It does NOT establish collision-resistant separation between roles."* |

## Proposed shape

One theorem, **P-WIRE**: *the RFC 9421 structured-field surface this profile admits is
closed and canonical — an input that differs on the wire never reconstructs to the same
signature base, and a spelling the profile does not define is refused rather than
normalised.* Carrier `src/verify/floor/{sf_dictionary,signature_input,signature_parameters}.rs`
plus the signing-side duplicate-header check; `tested`, direct severity `critical`; one
`mutation://` probe weakening the spacing refusal to a trim. NP-090 and NP-089's residue
join it.

## N1

Ten rows, unregistered. The two extended units keep their existing probes
(`mutation://http_profile/request_floor/what_a_successful_return_establishes`,
`mutation://http_profile/bound_response/trust_seam_authorization`) and no debt row is added.
