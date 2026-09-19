<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-172 — R6 ratification packet: a verification key round-trips through its raw bytes and its Base64URL spelling

**Disposition:** referred, and referred DELIBERATELY TOGETHER WITH NP-107. One control, one
`[[disposition]]` row, one record. Nothing registered.

## Provenance, and why this one is the load-bearing correction

Split out of NP-106 by RR-002 C5 during the RM-S1 repair. Of the thirteen controls filed whole
under THM-0014, this is the one whose registration made the commit contradict itself, and the
adversarial review of PR #1018 said so.

The same commit referred NP-107 to R6 on this finding:

> Replace base64url with hex at every site on the floor path and every clause of THM-0014 still
> holds, so the codec is a premise the claim USES, not one it contains.

and then registered `verification_key_round_trips_bytes_and_b64url` under THM-0014. One commit
cannot hold both. The referral is upheld — its hex-swap test is the correct application of
clause 2, and THM-0055 was separately checked and declines NP-107 — so the registration is the
half that gives way.

## The control and what it states

`lib#crypto::tests::verification_key_round_trips_bytes_and_b64url` asserts two inverse pairs on
`VerificationKey`: `to_bytes` / `from_bytes`, and `to_b64url` / `from_b64url`, each rebuilding a
key holding the same 32 bytes.

The proposition: **the key's two projections are lossless and agree.**

## Why it is outside THM-0014

Apply exactly NP-107's test. Replace `b64url_encode` / `b64url_decode` with hex inside
`VerificationKey::to_b64url` / `from_b64url`. Nothing in THM-0014 moves: the covered
`Content-Digest` still agrees with the body, the signature still verifies over the reconstructed
base under an accepted algorithm, the parameters are still admitted as current, and the keyid is
still resolved through the trust seam for the Request slot. The theorem does not name an
encoding, and clause 4 speaks of a key RESOLVED THROUGH THE SEAM, which is upstream of the
constructor this control exercises.

The `to_bytes` / `from_bytes` pair is not even about an encoding: it is about dalek's compressed
point representation surviving a round trip, which is a property of a dependency this project
did not write — the same objection THM-0055's scope raises against NP-107 (*"every property here
is a property of code this project wrote"*).

## Proposed shape for ratification: with NP-107, not separately

NP-107's packet proposes one theorem owned by a new `core.base64url_codec` unit over
`mcp-re-core/src/encoding.rs`:

> Every MCP-RE signature and hash value has exactly one spelling. `b64url_encode` emits the
> URL-safe alphabet with no padding; `b64url_decode` accepts that form and no other, refusing
> padding and non-alphabet characters; the two are mutual inverses on arbitrary bytes.

This control is that proposition measured through the key type. The right outcome is that the
NP-107 theorem, when it is written, takes this control as its application to
`VerificationKey` — which means a unit over `mcp-re-core/src/crypto.rs` in that theorem's
`supported_by`, or the selector moving into the codec unit if the reviewer prefers one carrier.
Either is a ratification decision. What is NOT available is registering it under THM-0014 while
NP-107 stands referred, and that is the whole content of this packet.

## N1

Nothing registered. No unit changed. No obligation moves.
