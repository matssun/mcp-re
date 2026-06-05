<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-006: Freshness and Replay Model — Injected ReplayCache, No sequence in Core v1

## Status

Accepted

## Context

Derived from PRD. Core must reject replays and expired invocations, but `mcps-core` is specified to stay pure — no networking, async runtime, or filesystem — which collides with the fact that replay protection is inherently stateful. The brief lists nonce/expiry checks in Core but leaves cache scope, persistence, and ordering open (open decisions #18.3, #18.4, #18.5).

## Decision

Core enforces freshness via `issued_at` / `expires_at` with a symmetric `max_clock_skew`, and replay protection via a caller-injected `ReplayCache` trait whose atomic check-and-insert is keyed by `(signer, audience, nonce)`, invoked after signature verification, and retained until `expires_at + max_clock_skew`; Core ships only an in-memory reference implementation, cache operational failures fail closed (distinct from a replay verdict), horizontally-scaled verifiers MUST share replay state or use sticky routing, and a `sequence`/ordering field is excluded from Core v1.

## Rationale

Injecting the cache keeps `mcps-core` pure while keeping replay in Core (mirrors the `TrustResolver` pattern). Inserting only *after* signature verification prevents an attacker from burning nonces with invalid-signature garbage. Keying on `(signer, audience, nonce)` is multi-tenant safe. `sequence` would force per-signer last-seen ordering state that produces false rejections under concurrent/out-of-order delivery and bottlenecks scaled verifiers — deferred to a future Ordering Profile. Short request lifetimes are recommended to bound the replay window.

## Alternatives Considered

- **Replay check entirely outside Core**: rejected — a Core-only integrator silently gets no replay protection (contradicts the brief).
- **Core mandates a concrete durable store (Redis/sled)**: rejected — violates the no-deps/no-async/no-fs rule and blocks non-Rust bindings.
- **Include `sequence` in Core**: rejected — false rejections under concurrency and a shared-counter scaling bottleneck.

## Consequences

### Positive
- Pure core with pluggable durability; bounded replay window via short lifetimes.

### Negative
- Distributed deployments must provide shared/sticky replay state — Core documents this requirement but does not solve it.

### Neutral
- `nonce` is an opaque string with ≥128 bits of entropy; `ReplayCache` returns `Result<ReplayDecision, ReplayCacheError>`.

## Compliance and Enforcement

Conformance replay, expiry, and clock-skew vectors; `ReplayCache` trait plus an `InMemoryReplayCache` reference implementation (deterministic, e.g. `BTreeMap`-backed).

## Related

- PRD: (author's private monorepo)
- Siblings: ADR-MCPS-004/005 (signing/canonicalization), ADR-MCPS-007 (resolution)
