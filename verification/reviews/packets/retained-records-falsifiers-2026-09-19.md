# ADR-MCPRE-068 Phase 2, slice 26 — every message genuine, the record still a lie

Three probes, `M262`–`M264`. The first two share a theme worth stating once: **a set of
individually valid things is not a valid set**, and nothing about the individual validity can
establish the set.

## 1. A curated field list is how an identity comes to omit something

`M262` drops one field — the response status — from the submitted commitment. The hop is still
retained whole; only its **identity** stops depending on the status.

What that admits: a 200 and a 409 over identical bytes become indistinguishable to anything
that identifies a submission by this value. Two submissions that are not the same submission,
answering to one commitment.

The destructuring in that function is what makes the closure checkable — adding a field to
`RetainedHop` breaks the pattern rather than silently leaving the new field outside the
identity. The other three controls stay green, correctly: each names a different retained fact,
and this weakening drops one.

## 2. Per-turn binding does not prove a chain is whole

Given hops R0→S0 and R2→S2 with R1→S1 missing: **every retained message still verifies on its
own**, every signature is genuine, and every per-hop check passes. Only the continuation
comparison — each hop's carried predecessor digests against the hop actually before it —
refuses the set as a record.

`M263` weakens it, and a chain with a hole reconstructs as **Complete**: an auditor reading the
label is told the call record is whole while the turn that authorized the work is absent from
it.

The signature verification the hops already passed is not a second carrier. It is what makes
each surviving message trustworthy, which is exactly what makes the gap invisible.

`M263` was re-adjudicated twice — first at the empty-chain arm, which no declared control names,
then at the wrong file. The battery covers the holes an attacker can make, not the degenerate
input, and the probe moved to where the battery actually reaches.

## 3. A pin that means two things is a pin nobody reviewed

An `EdDSA` pin carrying a `y` is not an Ed25519 key with a harmless extra field. It is an ES256
key mislabelled, or a pin built by something that did not know which curve it had — and the
document is what the operator **recorded and reviewed**.

The algorithm comes from the DOCUMENT and never from a receipt, which is the confusion this
whole seam avoids: letting an incoming receipt nominate the algorithm it is verified under is
how a transparency pin stops pinning anything. `from_b64url` below is not a second carrier — it
accepts the `x` coordinate either way and says nothing about the `y` beside it.

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `http_profile.submitted_hop_identity` | `M262` | high |
| `http_profile.retained_chain_record` | `M263` | high |
| `http_profile.scitt_service_pin` | `M264` | high |

N1 moves 21 -> 18; the probe registry 283 -> 286.
