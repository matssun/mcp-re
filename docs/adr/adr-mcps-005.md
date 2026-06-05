<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-005: JCS-Safe JSON Value Domain with Fail-Closed Canonicalization

## Status

Accepted

## Context

Derived from PRD; tightly coupled to ADR-MCPS-004. The entire security model rests on the signer and verifier producing byte-identical canonical preimages. RFC 8785 / JCS builds on the I-JSON subset and ECMAScript primitive serialization, so an honest, untampered message can fail verification if it carries values that two implementations canonicalize differently (notably numbers, duplicate keys, and invalid Unicode). For a signature profile, interop failure is a security failure.

## Decision

MCP-S Core restricts protected-message JSON to a JCS-lossless value domain — unique object member names; valid UTF-8 with no unpaired surrogates; integer numbers only, within ±(2^53 − 1); no non-finite or non-integer numbers; no Unicode normalization or parser repair/coercion — and rejects anything outside it with `mcps.canonicalization_failed` before signature verification; values needing greater range or precision (large IDs, decimals, nanosecond timestamps, monetary amounts) MUST be carried as JSON strings, and the JSON-RPC `id` SHOULD be a string.

## Rationale

If two honest implementations can produce different preimages for the same apparent value, the profile is not production-ready. Duplicate-key rejection is the critical case: without it, two implementations can verify *different semantic objects from the same bytes*. Number constraints prevent the IEEE-754-double round-trip from changing a large integer's serialization. Forbidding Unicode normalization avoids adding an interop surface JCS does not require.

## Alternatives Considered

- **Document JCS limits but don't validate**: rejected — a legitimate large-integer request fails as `mcps.invalid_signature` (looks like an attack), and an intermediary re-serializing a float silently breaks a valid signature.
- **Sign-and-transmit canonical bytes (no re-canonicalization)**: rejected — turns MCP messages into opaque canonical blobs, fights ordinary JSON-RPC plumbing that parses and re-serializes, and undercuts the transport-agnostic strategy.

## Consequences

### Positive
- Signer/verifier byte-identity is guaranteed and survives intermediary parse-and-re-emit.

### Negative
- Tool authors must encode big numbers, decimals, and money as strings.

### Neutral
- Fail-closed: ambiguous input is rejected, never coerced.

## Compliance and Enforcement

Conformance vectors JCS-01…JCS-08 (duplicate key, unsafe integer in `id` and in arguments, non-integer number, non-finite number, unpaired surrogate, invalid UTF-8, and a large-id-as-string success). Implementations MUST use a parser mode that detects duplicate object member names.

## Related

- PRD: (author's private monorepo)
- Tightly coupled: ADR-MCPS-004 (signing rule)
