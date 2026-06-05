<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-004: Ed25519-over-JCS Signing Rule for the Whole JSON-RPC Object

## Status

Accepted

## Context

Derived from PRD; depends on ADR-MCPS-002. MCP-S secures the MCP JSON-RPC object itself so that protection is transport-agnostic across `stdio` and Streamable HTTP. This requires a precise, reproducible signing rule that integrity-protects the whole invocation, not just the security envelope.

## Decision

MCP-S signs the complete JSON-RPC object (with `signature.value` removed and `signature.alg` + `signature.key_id` retained) as the RFC 8785 / JCS canonical UTF-8 byte sequence, directly with Ed25519 and no pre-hashing; signatures and hashes are encoded Base64URL without padding, hashes are identified as `sha256:<base64url-no-pad>`, and `request_hash` is defined as the SHA-256 of the verified request signing preimage (the JCS canonical bytes after `signature.value` removal).

## Rationale

Signing the whole object integrity-protects the tool name, arguments, ordinary `_meta`, the JSON-RPC `id`, and the MCP-S envelope together — a tampered argument or `id` invalidates the signature. Ed25519 over the canonical bytes (no prehash) is the standard EdDSA construction; unknown algorithms are rejected unless a future profile negotiates them. Defining `request_hash` over the *preimage* (not the transmitted JSON) makes response→request binding reproducible regardless of transmitted formatting.

## Alternatives Considered

- **Pre-hash then sign**: rejected — Ed25519 signs the message directly; pre-hashing is a different (Ed25519ph) scheme and is forbidden here.
- **Sign only the MCP-S envelope**: rejected — leaves tool name and arguments unprotected.
- **JWS / COSE wrappers**: rejected — heavier, JSON/transport-foreign, and pull more dependencies into a crate that must stay pure.

## Consequences

### Positive
- Tamper-evidence over the entire invocation with a minimal crypto surface.

### Negative
- Correctness depends entirely on deterministic canonicalization (addressed by ADR-MCPS-005).

### Neutral
- Responses use the symmetric transformation.

## Compliance and Enforcement

Conformance vectors (valid signed request/response, tampered-argument, and the signed wrong-request-hash "Vector 4B") gate `cargo test -p mcps-core`. All published vectors must be regenerated against the frozen vocabulary and identifier before they are authoritative.

## Related

- PRD: (author's private monorepo)
- Depends on: ADR-MCPS-002
- Tightly coupled: ADR-MCPS-005 (JCS-safe value domain)
