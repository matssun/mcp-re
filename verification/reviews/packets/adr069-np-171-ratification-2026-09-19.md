<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-171 — R6 ratification packet: the crypto primitive never invents an error variant

**Disposition:** referred. Three controls, three `[[disposition]]` rows, one record. Nothing
registered.

## Provenance

Split out of NP-106 by RR-002 C5 during the RM-S1 repair. Three of the thirteen controls filed
whole under THM-0014; the adversarial review of PR #1018 named all three.

## The three controls, and why they are ONE proposition and not three

- `malformed_key_b64url_maps_to_actor_binding_failed`
- `malformed_key_bytes_map_to_actor_binding_failed`
- `response_variant_maps_to_response_sig_invalid`

They are one proposition because the module states them as one rule, in one place, as a
deliberate design decision:

```
//! # Error mapping (deliberate)
//! - A resolved-but-malformed verification key (bad length / not a valid point)
//!   is a trust-binding failure, so `VerificationKey::from_bytes` /
//!   `VerificationKey::from_b64url` map to `McpReError::ActorBindingFailed`.
//! - On the request path, ANY verification failure … maps to
//!   `McpReError::InvalidSignature` via `verify_ed25519`. The response path needs
//!   the SAME failure to surface as `McpReError::ResponseSigInvalid`; rather than
//!   duplicate the logic we expose a single error-agnostic core,
//!   `verify_ed25519_with`, that takes the error to return.
```

Stated without an "and": **every failure this module reports is the variant its own layer owns
— the primitive invents none.** Key construction owns `ActorBindingFailed` because a
resolved-but-malformed key is a trust-binding fact, not a cryptographic one; the verification
core owns nothing at all and returns what its caller supplied, which is why the response path
gets `ResponseSigInvalid` without a duplicated implementation. One authority, one rule, three
instances. The C5 question is whether more than one authority is describable inside the record,
and here there is one: this module's error rendering.

`response_variant_maps_to_response_sig_invalid` opens with a positive `is_ok()` on genuine
response-path material. That line is setup, not a second proposition: it establishes that the
`ResponseSigInvalid` the test then observes is caused by the tamper and not by the path, which
is the anti-vacuity arm of the assertion that follows it.

## Why THM-0014 does not contain them

THM-0014 is a conditional over successful `verify_request_floor` returns and has **no failure
clause at all**. It says what an admission means, never what a refusal renders as. Falsify any
of these three and not one request is admitted that was not admitted before; the only change is
what an operator, an audit record or a peer is TOLD about why the refusal happened.

Two further clauses decide the individual rows:

- The key controls. THM-0014's clause 4 speaks of a keyid *"resolved through the trust seam for
  the Request slot"*. The seam is upstream of `VerificationKey::from_bytes` /`from_b64url`;
  these constructors are not the resolution the clause names.
- The response control. THM-0014 is the REQUEST floor and its clause 4 says "Request slot" in
  terms.

## THM-0021 was read as the second candidate, and declines it

THM-0021 is the response-side theorem and would be the natural home for anything about the
response path:

> If any of `Verifier::verify_bound_response_floor`, `Verifier::verify_bound_response` or
> `Verifier::verify_delegated_bound_response` returns Ok, then for the response supplied: the
> covered `Content-Digest` agreed with the body, the signature parameters were admitted as
> current under an algorithm the verifier's policy accepts, and the RFC 9421 signature verified
> over a base whose `;req` components were resolved against the concrete request supplied to
> the call, under the verification key of the accepted signer the operation returns.

It is the same shape: an `Ok ⟹ …` conditional, indifferent to which sentinel a failure carries.
A world in which `verify_ed25519_with` ignored its `on_error` argument and always returned
`InvalidSignature` falsifies this control and leaves every clause of THM-0021 true.

The precise argument is the one this campaign already used for NP-109's
`fixed_digit_fields_are_total_outside_the_parser_widths`, and it has the same shape here. What
THM-0021 would contain is *a tampered response fails*. What this control STATES is *the failure
renders as the caller's sentinel*, and a control cannot be split. A proposition orthogonal to a
contained one is not a strict decomposition of it, so clause 2 is not satisfied and registering
it would widen the unit past what the theorem claims.

## Why it matters, stated without overreach

This is not a soundness proposition and this packet does not present it as one. Nothing is
admitted that should not be. What it holds is the distinguishability of two operationally
different failures: a malformed key means the trust seam handed over something unusable, and a
bad signature means the presented material did not verify. An alarm that renders them as one
token sends the responder to the wrong system. MCP_RE_SPEC §6 fixes the key case, which is why
that half has an external reference and the response half has only the module's own reasoning.

## Proposed shape for ratification

A taxonomy proposition rather than a verification one, and adjacent to THM-0111 rather than
inside it — THM-0111 owns the frozen RENDERING of each variant in `mcp-re-core/src/error.rs`,
while this owns which SITE chooses which variant, which is a ratified owner decision no guard
can see:

> Each failure site in `mcp-re-core/src/crypto.rs` reports the variant its own layer owns:
> key construction reports `ActorBindingFailed`; the verification core reports the sentinel
> its caller supplied, and chooses none itself.

Whether this repository wants theorems over refusal ATTRIBUTION alongside its theorems over
refusal OCCURRENCE is the ratification question, and it is not a worker's to answer.

## N1

Nothing registered. No unit changed. No obligation moves.
