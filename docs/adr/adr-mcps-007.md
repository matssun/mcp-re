<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-007: Trust Resolution, Key Rotation, and Revocation Model

## Status

Accepted

## Context

Derived from PRD; depends on ADR-MCPS-001 (TrustResolver as a public trait). The brief's trust-resolution section is thin: it resolves `(signer, key_id) → key` but says nothing about key rotation, revocation, resolver outages, or caching. Core's only time control is `expires_at`, so a compromised key has no Core revocation primitive — this must be a conscious decision, not an omission.

## Decision

Core resolves `(signer, key_id) → verification key` through a caller-supplied `TrustResolver` that is authoritative at verification time, represents rotation as multiple `key_id`s per signer and revocation as removing/disabling a mapping, maps not-found/revoked/disabled/malformed results to `mcps.actor_binding_failed` and resolver operational failure to a new `mcps.trust_resolver_unavailable`, permits only bounded-TTL caching of resolver results, and defines no revocation list, OCSP, transparency log, or key-validity interval in Core.

## Rationale

This keeps Core's identity story abstract (per brief §9) without being naive: it names the revocation mechanism (drop the mapping → next request fails `mcps.actor_binding_failed`), the exposure window (`resolver_cache_ttl + max_request_lifetime + max_clock_skew`), and the operational distinction between "key invalid" and "cannot establish trust state" — the latter needs different logs, alerts, and retry, and must fail closed (never fall back to allow). Short request lifetimes are recommended.

## Alternatives Considered

- **Add a Core revocation / key-validity mechanism in v1**: rejected — expands Core scope and adds a freshness surface the brief defers to later identity profiles.
- **Opaque resolver with no guidance**: rejected — leaves the compromised-key story undefined and invites unsafe aggressive caching that silently extends exposure.

## Consequences

### Positive
- Small but honest Core; immediate revocation is possible by updating the resolver.

### Negative
- Revocation latency is bounded by configured cache TTL + request lifetime + skew, not zero.

### Neutral
- Amends the brief's §13 error taxonomy with `mcps.trust_resolver_unavailable`; resolver may be backed by local memory, a refreshed snapshot, or a remote service.

## Compliance and Enforcement

`TrustResolver` trait with a `TrustResolverError` enum and the documented error mapping; conformance binding-failure and resolver-unavailable vectors.

## Related

- PRD: (author's private monorepo)
- Depends on: ADR-MCPS-001
- Siblings: ADR-MCPS-003 (signing locus), ADR-MCPS-006 (replay)
