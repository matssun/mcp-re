<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-106 — R6 ratification packet: the Ed25519 floor accepts the material it is supposed to accept

**Disposition:** SPLIT. Five of the original thirteen controls registered under THM-0014 as
`unit://core.ed25519_primitive`; three are referred here; three more are referred as NP-170,
NP-171 and NP-172, each with its own packet. Residue 0 — every one of the thirteen is either
in a unit battery or on a `[[disposition]]` row.

## What was scheduled, what was done, and what was corrected

RM-S1 scheduled NP-106 as R1 under THM-0014 and filed it WHOLE: all thirteen controls into one
new unit. An adversarial review of PR #1018 refused that, and it was right to. THM-0014's claim
is about an admitted request's signature having verified under the resolved key; signing,
determinism of a signature for a fixed seed, a response-side variant mapping, an error-taxonomy
mapping and a key-encoding round-trip are each a different proposition, and RR-002 C5 forbids
filing a record whose controls span more than one describable proposition whole, whatever the
classes then turn out to be.

The review also named the contradiction that settles it without argument. The SAME commit
refers NP-107 to R6 on the ground that *base64url is the exact encoding in both directions* is
not contained in THM-0014, and then registers `verification_key_round_trips_bytes_and_b64url`
under THM-0014 anyway. One commit cannot hold both. The NP-107 referral is the half that
survives — its hex-swap test is decisive and THM-0055 is narrower — so the registration is what
gives way.

## ANNOTATION — two of the thirteen controls no longer exist

Added after the fact; the derivation below is **not** rewritten, because a review record states
what was decided on the day it was decided.

`ensure_ed25519_alg_rejects_unknown_alg_with_supplied_error` and
`ensure_ed25519_alg_accepts_the_supported_alg` were deleted with their subject: measured on the
tree, `ensure_ed25519_alg` had **no production caller** and gated on `SIG_ALG_ED25519` =
`"Ed25519"`, a token the RFC 9421 carrier never emits and which
`mcp-re-http-profile/src/policy.rs` pins as NOT accepted. The CONTAINED verdict in the table
below therefore rested on a premise that was false of the tree — falsifying that gate could not
have admitted anything, because nothing consulted it.

THM-0014's clause *"under an algorithm the verifier's policy accepts"* is owned by
`http_profile.request_floor_result` and carried there by six registered controls. **THM-0014's
own claim, dependencies, scope and review requirement are untouched**, and its owner-reviewed
fingerprint `sha256:f88e7b44…` is unchanged — asserted, not assumed, by
`tools/verification/review --fingerprint THM-0014` before and after.

`CD-16003` is retired rather than left pointing at a control that no longer exists.

## The derivation, control by control

THM-0014, in full:

> If `Verifier::verify_request_floor` returns Ok, then for the request supplied: the covered
> `Content-Digest` agreed with the body, the RFC 9421 signature verified over the
> reconstructed signature base under an algorithm the verifier's policy accepts, the
> signature parameters were admitted as current, and the presented keyid was resolved through
> the trust seam for the Request slot.

It is a conditional over SUCCESSFUL returns. Its security consequence is stated wholly in the
negative — what an attacker cannot obtain. So containment is one question asked thirteen times:
**does a world in which this control is false contain a successful `verify_request_floor`
return for which one of those clauses is false?** If the only effect of falsifying a control is
that fewer requests are admitted, the theorem is untouched and the control is not contained.

| control | verdict | deciding clause |
|---|---|---|
| `wrong_key_fails` | CONTAINED | clause 2's verb — a signature that "verified" under a key that did not produce it |
| `tamper_preimage_fails` | CONTAINED | clause 2's verb, over the reconstructed base |
| `malformed_signature_base64_fails` | CONTAINED | clause 2, at the decode arm — Ok on input never decoded |
| `wrong_length_signature_fails` | CONTAINED | clause 2, at the `try_into` arm — 64 bytes is what the value IS |
| `ensure_ed25519_alg_rejects_unknown_alg_with_supplied_error` | CONTAINED | clause 2's qualifier "under an algorithm the verifier's policy accepts", and the consequence's second limb verbatim |
| `ensure_ed25519_alg_accepts_the_supported_alg` | not contained | vacuity: reject `Ed25519` too and there are no successful returns; the theorem names no token |
| `raw_primitive_verifies_without_any_alg_plumbing` | not contained | same; a single `is_ok()` on genuine material, protecting the ADR-MCPS-02 layering ergonomics |
| `sign_then_verify_round_trip` | not contained | same; the completeness half, and THM-0014 has no completeness clause |
| `signature_is_deterministic_for_fixed_seed` | not contained → NP-170 | a property of SIGNING; the theorem constrains a verifier and names no signer |
| `malformed_key_b64url_maps_to_actor_binding_failed` | not contained → NP-171 | the theorem has no failure clause; clause 4's key arrives through the trust seam, not `from_b64url` |
| `malformed_key_bytes_map_to_actor_binding_failed` | not contained → NP-171 | same, at `from_bytes` |
| `response_variant_maps_to_response_sig_invalid` | not contained → NP-171 | response path; clause 4 is the Request slot in terms |
| `verification_key_round_trips_bytes_and_b64url` | not contained → NP-172 | the NP-107 premise on a second carrier; it cannot be outside THM-0014 in `encoding.rs` and inside it in `crypto.rs` |

Five contained, eight not. The count the review estimated was seven; the two it did not reach
are `ensure_ed25519_alg_accepts_the_supported_alg` and
`raw_primitive_verifies_without_any_alg_plumbing`, and the review said in terms that its list
was not exhaustive. They fall out for exactly the reason it gave for `sign_then_verify_round_trip`
— which is the point: applied consistently, the rule that removes one removes all three, and
`raw_primitive_verifies_without_any_alg_plumbing` and `sign_then_verify_round_trip` are very
nearly the same test.

## This record's own proposition, and why R6

The three controls here state one thing: **material this system produced under the one
supported algorithm is ACCEPTED** — through the request wrapper, through the raw primitive with
no gate in front of it, and past the gate when the gate is there.

No theorem in the registry claims it, and the reason is structural rather than accidental.
Every theorem over the verification path is an `Ok ⟹ …` conditional, because that is the shape
a security claim takes: it constrains what an admission MEANS. A conditional of that shape is
satisfied by a floor that admits nothing. What this record holds is the anti-vacuity arm — the
evidence that the floor THM-0014 constrains is not the empty floor — and that is a proposition
about the system continuing to work, not about what it refuses.

It is therefore a genuine candidate for its own theorem rather than for a clause of an existing
one, and the shape would be:

> `verify_ed25519` returns Ok for every `(preimage, signature, key)` where the signature is
> the one `SigningKey::sign` produced over that preimage under the key's own secret, and
> `ensure_ed25519_alg` returns Ok for `Ed25519`.

Its dependents are every theorem that is vacuously true without it. Whether this repository
wants completeness theorems alongside its soundness theorems is a ratification decision and not
a worker's, which is why this is R6 and not a registration.

## N1

Nothing new is registered by this packet. `core.ed25519_primitive` is `tested` with a
`mutation://` battery and already carried its obligation before the narrowing; the narrowing
removes controls from a battery and adds none, so no obligation moves and the open N1 count is
unchanged.
