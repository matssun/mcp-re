# ADR-MCPRE-054 — Portable audit receipts on SCITT (RFC 9943) + COSE Receipts (RFC 9942)

**Status:** Accepted (roadmap design + offline-verifiable prototype), 2026-07-17.
Issue #434. Derived from Discussion
[#414](https://github.com/matssun/mcp-re/discussions/414) rev 2 §3.5/§2.4, which
names IETF SCITT (RFC 9943, June 2026) with COSE Receipts (RFC 9942) as the
preferred Layer 5 realization — "prefer that shape over inventing a new receipt
format."

This is roadmap design, NOT v0.13-blocking. It delivers the mapping, the
retained-vs-committed split, an offline-verifiable prototype, and the
incomplete-chain representation. It does not deliver a production ledger.

## Context

Layer 5 today is the frozen audit-evidence vocabulary (ADR-MCPS-035) and
delegated-signed rejections. Portable receipts and tamper-evident logs were
explicitly deferred. A signed response proves the server said something; it does
not give an auditor an independent, portable, tamper-evident record that a
statement about a call was registered at a point in time. SCITT is that shape, and
#414 says to adopt it rather than invent one.

## Decision

### 1. MCP-RE evidence → SCITT Signed Statement (§4.6 mapping)

The Layer 3 evidence (#415 §4.6) maps onto a SCITT Signed Statement whose payload
is an `EvidenceCommitment`:

| §4.6 evidence | Commitment field |
|---|---|
| request evidence handle | `request_evidence` |
| response evidence handle | `response_evidence` |
| artifact bindings | `bindings_commitment` (digest, optional) |
| verified context | `verified_context_commitment` (digest, optional) |
| continuation chain | `chain_label` + `chain_commitment` |

The Signed Statement is the COSE_Sign1 analog: the issuer signs the canonical
statement bytes.

### 2. Retained vs committed (§4.6)

The statement carries **hash commitments, never evidence**. The full messages,
bindings, and chain stay in the evidence store (retained); the statement commits to
their digests (committed). So a receipt is small and portable and discloses nothing,
and an auditor with the retained evidence recomputes the digests and checks they
match. This is the §4.6 split made concrete.

### 3. Incomplete chains are first-class (the #431 seam)

The commitment embeds the `ChainLabel` from `reconstruct_chain`, serialized so
`incomplete:<hop>:<reason>` survives into the receipt. A receipt therefore commits
to a COMPLETE or an explicitly-INCOMPLETE record, and the two are distinguishable
in the verified statement. A receipt can never launder a truncated call into a whole
one — the label it commits to names the missing hop. This is why #431 was shaped so
its output could be committed to.

### 4. The COSE Receipt and offline verification

A `Receipt` (RFC 9942) proves registration: leaf index, an RFC 6962-style SHA-256
inclusion proof, and the transparency service's signed tree head.
`verify_receipt_offline` checks, **contacting no service**: the issuer's signature
over the statement, that the inclusion proof re-derives the signed root, and the
TS's signature over `(tree_size, root)`. That offline path is #434's testable
acceptance property, and the reason a SCITT receipt is worth more than a signed log
line — inclusion is checkable without trusting the log to replay honestly.

## What is faithful, and what is a stand-in

Called out so nobody mistakes the prototype for the product:

- **Faithful:** the cryptographic content — Ed25519 signatures over the statement
  and the tree head, RFC 6962 Merkle inclusion proofs, all verified offline; the
  §4.6 evidence mapping; the retained/committed split; the incomplete-chain
  representation.
- **Stand-in:** the SERIALIZATION is JSON, not the CBOR/COSE_Sign1 of RFC 9052/9942
  — the fields map one-to-one and production swaps the encoder. And
  `PrototypeTransparencyService` is an in-process Merkle log, not a running SCITT
  Transparency Service.

Because the serialization is an explicit stand-in, **no frozen conformance vectors
are added for SCITT** — pinning stand-in bytes would falsely certify a format that
is not the wire format. The conformance corpus pins real profile bytes only. SCITT
is unit-tested as a prototype until the production encoding is chosen.

## What remains open

- **Wiring against an existing SCITT transparency service** (the #434 scope's "no
  bespoke ledger" — DataTrails / the scitt-community reference). This needs an
  external service reachable from CI, a true external dependency. The mapping and
  offline verification are done; the registration hop against a real TS is the
  remaining integration.
- **CBOR/COSE encoding** to RFC 9052/9942, replacing the JSON stand-in.
- **The retained-evidence store** that holds what the commitments point at — a
  Layer 5 storage concern, separate from the receipt shape decided here.

## Proven by

`scitt.rs` tests: one call's evidence registered and its receipt verified offline;
inclusion across many statements; an incomplete-chain record distinguishable in the
receipt (and not launderable by it); tampered statement, forged inclusion path, and
untrusted issuer/TS all fail closed.
