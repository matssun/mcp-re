<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-100 residue — R6 ratification packet: the evidence handle, and the proxy-meta strip

**Disposition:** R4 then R1 in part. NP-100 was one row over seven files and three security
stories, so it is split at registration and never registered as one unit. Six controls
landed; ten `[[disposition]]` rows remain and NP-100's `[[proposition]]` entry and record
stay in place.

## What landed

| controls | unit | `description` sentence, verbatim |
|---|---|---|
| `digest::tests::{digest_round_trip, tampered_body_fails_closed, sha256_member_absent_from_present_header_is_malformed}` | `http_profile.request_floor_result` | *"the covered `Content-Digest` agreed with the body"* |
| `policy::tests::{an_algorithm_without_a_verifier_cannot_be_allowlisted, the_registry_maps_tokens_to_implemented_verifiers}` | `http_profile.request_floor_result` | *"under a policy-accepted algorithm"* |
| `replay::tests::the_principal_slot_is_the_subject_without_its_keyid` | `http_profile.replay_key` | *"its injective pre-serialization onto the core cache's three slots"* |

## The residue, and why each is outside every ratified theorem

| rows | clause | nearest theorem, and why it does not contain it |
|---|---|---|
| `evidence::tests::{handle_is_split_form_and_deterministic, handle_is_not_a_bare_digest_of_the_base, different_base_different_handle, label_and_input_cannot_be_confused, roles_are_domain_separated_over_identical_bytes}` | the handle is DOMAIN-SEPARATED and derived, never a bare digest | **THM-0010 excludes this by name.** Scope, verbatim: *"Assumes only that the labeled digest IS A FUNCTION of (label, bytes) — ASM-0023. It does NOT establish collision-resistant separation between roles; that obligation stays at `boundary.crypto_primitives` and is not discharged here."* Registering them under THM-0010's units would claim exactly what the theorem declines. |
| `context::tests::{strip_removes_proxy_keys_and_preserves_application_meta, a_meta_containing_only_proxy_keys_is_removed_entirely, strip_is_noop_without_meta}` | the proxy's own `_meta` keys are removed and the application's preserved | No theorem in the registry names `context.rs`, the proxy-meta strip, or `_meta` at all. This is an authentication-bypass guard (a caller seeding a reserved key) and it is the profile-side twin of the §10 PEP-owned strip already named as residue in the NP-129 packet. |
| `artifact::tests::bearer_token_extraction` | `Authorization: Bearer` is case-sensitive and a `Basic` header yields nothing | `artifact_verification_boundary` claims *"a binding reported verified matched one explicitly supported typed verification branch and satisfied that branch's required binding form"*. This control names no artifact type and no binding: it measures a string parser that `body::authorization_bearer_bytes` happens to call. Registering it would be a stretch, so it is not R1. |
| `authoritative_admission::record::currentness::tests::every_class_has_a_distinct_index_inside_the_published_count` | the refusal classes are a bijection onto `0..COUNT` and each renders distinctly | `admission_state_provenance` claims what an AUTHORITATIVE ADMISSION STATE is — authenticated, bound, current. A refusal-enum discriminant bijection is diagnosis hygiene (the once-per-class latch cannot report two classes as one) and the description does not state it. Same family as NP-144's residue. |

## Proposed shape

Two theorems, because the residue is two authorities plus two orphans:

1. **The evidence handle is domain-separated by construction.** Carrier `src/evidence.rs`;
   `tested`, direct `critical`; one `mutation://` probe whose anchor is the role label in
   the handle preimage, weakened to drop the label. It DISCHARGES what THM-0010 declines,
   so THM-0010's scope sentence should be re-read (not edited here) once it exists.
2. **The PEP-owned `_meta` strip removes what the proxy owns and nothing else.** Carrier
   `src/context.rs`; `tested`, direct `critical`. Ratify with NP-129's body-boundary residue
   — they are the same clause on two sides of the boundary.

The two orphans are cheaper: `bearer_token_extraction` is a candidate for a review call on
`artifact_verification_boundary`'s description, and the refusal-index control for a
diagnosis-vocabulary theorem shared with NP-144.

## N1

Ten rows, unregistered. `request_floor_result` and `replay_key` keep their existing probes
and no debt row is added.
