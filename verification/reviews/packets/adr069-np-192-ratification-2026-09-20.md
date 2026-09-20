<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-192 — R6 ratification packet: the bearer credential's residency

**Disposition:** R6, referred entire. One control, split out of NP-114 under RR-002 C5 when
that record's twenty-three rows were measured and found to span three propositions.

**1 control**, `mcp-re-proxy`, rust unit test, `gcp_kms_keysource` lane, carrier
`mcp-re-proxy/src/gcp_kms_keysource.rs`:

- `lib#gcp_kms_keysource::tests::the_access_token_is_moved_out_of_the_parsed_document`

It selects in the `gcp_kms_keysource` lane and in no other: the default lane's 1498 lib
controls contain none of the thirty-nine `gcp_kms_keysource::` tests.

## What it asserts

`take_access_token` moves the credential out of the parsed `serde_json::Value`, and the
control asserts the document afterwards holds `Some("")` where the token was. The file's own
comment states the failure it closes:

> Reading it out with `as_str().to_string()` leaves the `Value`'s own owned `String` to drop
> unscrubbed — a second copy of a token that authorizes Cloud KMS `asymmetricSign` on the
> root key, sitting in freed heap for the process lifetime.

## Why THM-0117 does not reach it

THM-0117 governs this exact file, and its scope opens:

> THE LIFETIME, NOT THE CREDENTIAL'S POWER.

Where a copy of the credential RESIDES is neither of those. The companion sentence points
the same way:

> NOT A CLAIM ABOUT THE ISSUER. That the issuer's stated expiry is honest, and that the
> token it returns is the one it minted, are the provider's; what is established is that
> this implementation never reads more lifetime out of an answer than the answer states.

Everything the theorem establishes is about READING an answer. What is left behind in memory
afterwards is outside every clause, and the operational test confirms it: replace the move
with a clone and every sentence of THM-0117 still holds — the expiry is still stated, still
never extended, still floored when unreadable, still fetched once between concurrent callers.

There is not even a twin to argue from. `proxy.aws_sts_credentials`, THM-0117's own owner
unit, carries twenty-six controls and no counterpart: the AWS path holds its response in a
`Zeroizing<String>` rather than a parsed document, so the defect this control closes cannot
arise there and no control asserts its absence.

## Why no other theorem takes it, and why no `not-evidence` family does either

No theorem in this tree states a memory-residency property for secret material. The nearest
neighbours are about what a value PRINTS — NP-185's *a secret string prints neither its value
nor its length at the consumer* is itself an unratified proposition — and printing is a
different exposure than a freed allocation.

Nor is it `not-evidence`. It is a real security property with a real failure mode (a core
dump, or any heap-reading defect elsewhere in the process, reaching a live Cloud KMS signing
credential), asserted over production behaviour, and none of the thirteen families describes
it. This slice may not mint a fourteenth, and stretching one to absorb it would be the
disposition-layer version of widening a unit.

## Filed alone rather than with NP-114's residue

NP-114's seven remaining controls answer *what does a token refusal cost, and what does it
discard*. This one is about a credential that was never refused and whose handling succeeded.
The two share a file and nothing else; folding them together would produce a record whose
answer to *what single security fact does this unit own* needs an "and".

**Severity:** `high`.
