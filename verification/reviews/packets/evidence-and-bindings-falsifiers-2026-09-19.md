# ADR-MCPRE-068 Phase 2, slice 28 — binding to nothing, and retaining too much

Two probes, `M268` and `M269`, and one unit deliberately left open with its reason recorded.

## 1. Two ends digesting two different strings

A DPoP artifact binding digests the **bearer token**; a non-DPoP header binding digests the
header value **verbatim**, because for those the whole value is the artifact. One `if`, two
artifact classes — and `M268` collapses the first into the second.

The result is a binding to nothing: the client digests `"Bearer abc…"` while the verifier
digests `abc…`, so every request carries an artifact binding that can never match. No signature
breaks and nothing fails locally; the exchange is refused at the boundary as a binding mismatch,
and the operator reads it as the peer disagreeing about their credential.

The sibling control — *a non-DPoP header binding digests the value verbatim* — is what says
which arm is which, and it stays green.

## 2. Retaining more is not harmless

A decoy dictionary member verifies exactly as it would without it: the signature over **this
label's** components is unaffected, so the exchange is genuine either way. That is what makes
`M269` a retention proposition rather than a verification one.

What changes is what gets **retained**. A record built from the union of every member's
component list retains headers the signature base never named — and a reconstruction re-verifies
the record, so a header that was not covered arriving as though it were makes a valid hop
unreproducible in one direction and over-claims coverage in the other. The unit's sentence is
*exactly the headers its own signature base names*, and **exactly** is the whole of it.

## 3. `proxy.evidence_attestation` — open, and why

Not discharged, and not blocked on anything outside this campaign:

- its declared battery is an async e2e that supplies **no** commitments, so weakening the
  pairing of `bindings_commitment` and `verified_context_commitment` is a **no-op mutation** —
  the lane correctly reported that the probe demonstrated nothing;
- the other half of the conjunct — the self-check running on records with no verified hop, the
  R9-C103 / R9-C128 repair — needs the reconstruction's own API to restore the old skip, and the
  first attempt did not build.

Both are adjudication problems rather than missing carriers. Discharging it means either a
control that supplies real commitments through the e2e, or a weakening that expresses the skip
without guessing at the API — its own slice, and the obligation stays open until then.

## 4. A unit whose paths do not reach its battery

Worth recording while it is in view: `client.deployment_config` declares
`mcp-re-client/src/config/mod.rs`, and two of its controls exercise code in `config/local.rs`
(`deny_unknown_fields` on `LocalConfig`) and `config/validation.rs` (the unsent-header refusal).
`M268` had to move to a conjunct whose carrier is inside the declared path.

That is a scope question rather than a falsifier one — widening the paths moves the unit's
fingerprint — so it is recorded here rather than acted on.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `client.deployment_config` | `M268` | high |
| `proxy.retained_record_content` | `M269` | high |

N1 moves 15 -> 13; the probe registry 289 -> 291.
