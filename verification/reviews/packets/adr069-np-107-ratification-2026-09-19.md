<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-107 — R6 ratification packet: base64url is the exact encoding, in both directions

**Disposition:** referred WHOLE. Nothing was registered and nothing was removed. All seven
`[[disposition]]` rows, the `[[proposition]]` entry and the record stay in place.

## What was scheduled, and why it was judged rather than executed

RM-S1 scheduled this as R2 under THM-0014: a new `[[unit]] core.base64url_codec` over
`mcp-re-core/src/encoding.rs`, appended to THM-0014's `supported_by` alongside the Ed25519
primitive (NP-106). The work package flagged it as the weakest subsumption in the batch and
required a judgement. This is that judgement, and it is negative.

## The candidate: THM-0014

Statement, in full:

> If `Verifier::verify_request_floor` returns Ok, then for the request supplied: the covered
> `Content-Digest` agreed with the body, the RFC 9421 signature verified over the
> reconstructed signature base under an algorithm the verifier's policy accepts, the
> signature parameters were admitted as current, and the presented keyid was resolved through
> the trust seam for the Request slot.

The codec is genuinely on that path. `verify/floor/signature.rs:69` re-encodes the presented
signature with `mcp_re_core::b64url_encode`, `crypto::verify_ed25519_with` decodes it with
`b64url_decode` before reaching `verify_strict`, and `keyid.rs:41` derives every keyid as
`b64url_encode(Sha256::digest(…))`. Being on the path is not the test.

### Clause 2 — strict decomposition of a CONTAINED proposition

The operational question that separates a decomposition from a premise: *can the theorem's
claim be stated without it?*

- **NP-106 cannot be.** THM-0014's own verb carries it. "The signature VERIFIED" is false if
  the primitive accepts a wrong key or a tampered preimage; the primitive's exactness is what
  the word means. That is why NP-106 landed.
- **NP-107 can be.** Replace base64url with hex at every site named above and every clause of
  THM-0014 still holds, unchanged and unweakened. A proposition the claim survives the
  deletion of is a premise the claim USES, not one it contains. ADR-069 §5's prohibition on
  widening a unit past what it claims is the same rule read from the other side.

### Clause 3 — no independent externally meaningful product promise

Two of the seven controls fail this outright, and they fail it on the face of the module:

```
//! Base64URL (no padding) encoding helpers (MCP_RE_SPEC §3).
//!
//! All MCP-RE signature and hash values are Base64URL WITHOUT padding.
```

`encode_has_no_padding` and `encode_uses_url_safe_alphabet` measure that sentence. It is a
promise to a PEER about the bytes on the wire — an independently, externally meaningful
product promise in clause 3's exact words — and it is owned by a specification, not by
THM-0014. `decode_rejects_padding` is the canonicality half of the same promise: what it
forbids is two spellings of one value both decoding, which is a proposition about the wire
form and not about whether `verify_request_floor` returned Ok.

Failing clause 3 routes the item to R6 on its own, independently of clause 2.

## The second candidate: THM-0055, also declined

THM-0055 is the only theorem in the registry that states anything about this encoding:

> The keyid's base64url-no-pad encoding is injective over the fixed 32-byte width of a
> SHA-256 output.

Three reasons it does not take NP-107.

1. **It is narrower.** Injectivity at ONE fixed width is a corollary of the codec being
   exact; the converse does not hold, and five of the seven controls (alphabet, padding
   absence, padding rejection, empty input, known answer) say nothing about it.
2. **Different carrier.** Its unit is `http_profile.keyid`, whose `paths` do not include
   `mcp-re-core/src/encoding.rs`. Reaching the selector means a `paths` widening, which RM-S1
   forbids and which ADR-069 §5 forbids for the same reason.
3. **Its scope forbids the reading.** *"Its unit, `http_profile.keyid`, carries no assumption
   at all: every property here is a property of code this project wrote."* The codec is
   `base64`'s `URL_SAFE_NO_PAD` engine, code this project did not write; the module is the
   choke point that FIXES the engine choice in one place. Making the codec a component of
   THM-0055 would put a third-party primitive inside a theorem that says it contains none.

## Proposed shape for ratification

One theorem, owned by a new `core.base64url_codec` unit over `mcp-re-core/src/encoding.rs`:

> Every MCP-RE signature and hash value has exactly one spelling. `b64url_encode` emits the
> URL-safe alphabet with no padding; `b64url_decode` accepts that form and no other, refusing
> padding and non-alphabet characters; the two are mutual inverses on arbitrary bytes.

`tested`, direct severity `high`, seven controls, one `mutation://` falsifier over the engine
constant. Its `security_consequence` is the one the record already states: a comparison over
the encoded form means what a comparison over the bytes would. Its natural `depends_on` is
nothing; its natural dependents are THM-0014 and THM-0055, which is the correct direction and
the reason it could not be folded into either.

## N1

Nothing registered. No unit changed. No obligation moves.
