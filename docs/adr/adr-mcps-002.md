<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-002: Frozen Public Envelope Vocabulary

## Status

Accepted

## Context

Derived from PRD; depends on ADR-MCPS-001 (clean-room firewall). The planning brief proposed an envelope vocabulary (`actor`, `on_behalf_of`, `capability_hash`, `audience`, `trust_label`, `server_actor`). Several of those terms collide with this monorepo's resolved glossary (`Actor` is overloaded, `Capability` is an orchestration term) and, more importantly, several mis-cue a public reviewer. Because the firewall (ADR-MCPS-001) keeps internal terms out of the wire format, the public names must be chosen on their own merits.

## Decision

The frozen MCP-S Core wire vocabulary is — request: `signer`, `on_behalf_of`, `audience`, `authorization_hash`, `nonce`, `issued_at`, `expires_at`, `signature{alg,key_id,value}`; response: `request_hash`, `server_signer`, `issued_at`, `signature` — with `trust_label` excluded from Core entirely.

## Rationale

- `actor` → **`signer`**: cryptographically precise (the identity whose key signed), sheds the agent-system and internal `Actor` overload.
- **`on_behalf_of`** kept: the RFC 8693 / OAuth on-behalf-of framing, directionally clear, maps cleanly to the glossary `Subject` in the adapter. `principal` rejected (overloaded auth term-of-art, ambiguous between glossary Subject/Principal); `subject` rejected (less directionally clear, collides with token `sub`).
- `capability_hash` → **`authorization_hash`**: `capability_hash` over-commits Core to an object-capability model that OAuth-bound delegation does not fit; `authorization_context_hash` rejected (re-imports the overloaded "context" word, mis-cues toward ambient/posture state); `authority_hash` rejected (reads as issuer/CA). The field asserts *binding only*, never that Core granted authorization.
- `server_actor` → **`server_signer`**: symmetry with request `signer`.
- **`trust_label` removed**: a free-form server opinion that misreads as a Core verification verdict (a footgun), with no artifact behind it.

## Alternatives Considered

- Keep the brief's `actor` / `capability_hash` / `trust_label`: rejected for the overload and footgun reasons above.
- Keep `trust_label` as signed-but-opaque metadata (symmetric with `authorization_hash`): rejected — unlike `authorization_hash` (a commitment to a real artifact a profile can check), `trust_label` has nothing behind it and invites consumers to trust a verdict Core never made.

## Consequences

### Positive
- A neutral public vocabulary, firewalled from the internal glossary; symmetric request/response naming.

### Negative
- Invalidates the brief's precomputed signatures/hashes — all conformance vectors must be regenerated with the new names.

### Neutral
- Output classification is deferred to a future Response Classification Profile (which must define vocabulary, issuer, verification rules, consumer obligations, downgrade behavior).

## Compliance and Enforcement

`CONTEXT.md` carries the envelope→glossary mapping table. The regenerated conformance vectors are the authoritative oracle for wire field names; any divergence fails `cargo test -p mcps-core`.

## Related

- PRD: (author's private monorepo)
- Depends on: ADR-MCPS-001
- Siblings: ADR-MCPS-003 (signing locus), ADR-MCPS-007 (trust resolution)
