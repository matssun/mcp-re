<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-129 residue — R6 ratification packet: the serving path signs and decides once

**Disposition:** R2 in part, R6 for the residue. Four controls landed as
`unit://proxy.pre_dispatch_refusal_precedence` under THM-0078 (probe
`M283-pre-dispatch-envelope`). Thirteen `[[disposition]]` rows remain and NP-129's
`[[proposition]]` entry and record stay in place.

## What landed, and the clause that contains it

THM-0078, statement conjunct 1, verbatim:

> If an inbound exchange fails to establish a required pre-dispatch obligation, it reaches a
> declared refusal terminal before backend dispatch, and cannot fall through into a
> success-path dispatch or a success response.

The four controls are strict decompositions of it: a document that is not an MCP message
(400), a body the profile cannot carry unchanged (400, before the nonce is burned and the
approval retired), an unrepresentable body before any reserialization, and a saturated
inner plane before a byte is transmitted.

## The residue, and why each is outside every ratified theorem

| rows | clause | nearest theorem, and why it does not contain it |
|---|---|---|
| `reply::an_uncorrelated_reply_is_refused_before_anything_signs_it`, `reply::an_unrecognized_result_type_is_never_signed` | nothing is signed that was not classified and correlated | THM-0075 is `No unearned response attribution` and is about WHOSE capability signed and WHAT the evidence is bound to. Protocol legality of the signed payload is not in its statement, and its scope narrows it to "SECURITY-BEARING SIGNED evidence only". Refusing to sign an unclassifiable result is a claim about what MCP-RE vouches for, which no theorem states. |
| `reply::a_jsonrpc_error_is_a_terminal_answer_and_not_a_malformed_one`, `reply::an_open_leg_yields_the_state_its_answer_re_presents`, `reply_assembly::the_reply_carries_the_class_the_classifier_read` | the reply class is read once and travels | THM-0101 owns which TRANSITION the machine learns; the reply's CLASS is a different value with a different single-reader argument. THM-0126 is the same proposition on the client side and is scoped to the shipped client proxy. |
| `request_admission::a_notification_and_a_request_are_told_apart_once`, `pre_admission::the_carrier_holds_the_terminal_selected_by_the_request` | the terminal is selected once, by the admission decision | THM-0083 contains *the outstanding id that selects its terminal is established by that one validation ... no production serving code reads the id again*. This is the nearest fit in the tree and it is arguably R2 under THM-0083 — but `proxy.outstanding_id_provenance` is already THM-0083's serving-path unit, and deciding whether these two rows are a second unit under it or belong in that battery is a scope call the campaign may not make for an existing unit. **Recommended first item for the owner.** |
| `request_admission::the_audience_the_store_keys_under_is_the_one_the_verifier_enforces` | one audience value, one projection | THM-0079 (distinct replay keys) and THM-0015 (audience binding) both speak about the audience; neither states that the CORRELATION STORE keys under the verifier's own value rather than a second copy. |
| `pre_admission::standing::the_binding_prerequisite_and_the_assertion_coordinate_are_different_facts`, `…::the_binding_stage_hands_on_the_fact_rather_than_a_unit` | a prerequisite is handed on as a fact, not reconstructed | This is the R-COMPOSE rule as a serving-path property. No theorem states it. |
| `body_boundary::application_meta_survives_the_pep_owned_strip`, `body_boundary::request_state_is_read_only_as_a_string_under_params` | the §10 PEP-owned strip removes what it owns and nothing else | The strip is an authentication-bypass guard (a caller seeding the reserved verified-context key). No ratified theorem names it. **Highest-consequence residue item.** |
| `continuation::open_leg::a_collision_fails_the_leg_closed_without_retrying` | a leg-key collision fails closed | THM-0087 and THM-0093 own continuation reachability and binding; neither states the collision disposition. |

## Proposed shape

Two theorems rather than one, because the residue is two authorities:

1. **What MCP-RE puts its signature behind is a reply it classified.** Carrier
   `http_profile_serve/reply.rs` + `reply_assembly/mod.rs`; unit
   `proxy.signed_reply_classification`; falsifier — accept an unrecognized `resultType` and
   the two never-signed controls go red.
2. **The enforcement boundary forwards the caller's body and only removes what it owns.**
   Carrier `http_profile_serve/body_boundary.rs`; unit `proxy.forwarded_body_boundary`;
   falsifier — strip the whole `_meta`, or stop stripping the reserved key.

The remaining four rows (terminal single-decision, audience projection, the two standing
prerequisites) are best resolved by an owner ruling on whether THM-0083's serving-path half
extends to them; all four are `supported_by`-only work if it does.

## Fingerprint

No ratified theorem's fingerprint moves. Attaching
`proxy.pre_dispatch_refusal_precedence` to THM-0078 changed `supported_by` only, which is
not a fingerprint component under ADR-MCPRE-059 rev2.
