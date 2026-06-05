<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-015: Client Host-Session Architecture

## Status

Proposed

## Context

PRD requires turning the client side from a bare signing primitive into a usable, safe host layer for single-node deployments. Today `HostSigner` is a deterministic primitive: it holds the key and signs caller-supplied envelope fields (nonce, `issued_at`, `expires_at`, id), returning wire bytes, with no key accessor (per ADR-MCPS-003 signing locus). Response verification is `mcps-core`'s stateless `verify_response`. This forces every integrator to hand-roll the security-sensitive parts: nonce generation, freshness windows, and binding each response to the request that produced it (`request_hash` correlation). Scattering that logic across integrators is the failure mode the PRD calls out. A decision is needed on where this behavior lives without breaking the auditable, key-free, model-facing boundary established in Core.

## Decision

Add a thin, stateful `HostSession` layered on the unchanged `HostSigner`; `HostSession` owns nonce generation, `issued_at`/`expires_at`, configured request lifetime, `request_hash` correlation by JSON-RPC id, response verification against the stored `request_hash`, duplicate-id rejection, and pending cleanup, with Clock and RNG injected; `mcps-host` remains transport-free, and client-side Streamable HTTP/mTLS is deferred to a future `mcps-host-transport` crate.

## Rationale

The freshness + binding logic is exactly the part that must not be reimplemented inconsistently by each integrator, so it belongs in one audited place. Layering on top of the unchanged `HostSigner` preserves the Core property (the model can drive signing but never reads the key or forges a signature) and keeps the deterministic primitive available for tests and low-level integrations. Clock/RNG injection keeps `HostSession` deterministic under test, consistent with Core pushing timestamps to callers (ADR-MCPS-006) and the proxy taking an injected `ReplayCache`. Keeping `mcps-host` networking-free preserves a minimal, auditable model-facing surface; remote transport (TLS client, server-cert validation, connection lifecycle) is a separate concern that would pull async/sockets into the signing library and is therefore isolated in a future crate.

## Alternatives Considered

- **Keep `HostSigner` stateless; integrator owns freshness + correlation** — rejected: leaves the easiest-to-get-wrong security logic scattered (the PRD's "still a primitive" trap), and makes "verify response bound to the correct request hash" unmeetable inside the library.
- **Put freshness/correlation in the future transport crate** — rejected: that crate is deferred, which would leave this project unable to demonstrate end-to-end response-binding verification at all; correlation is a crypto-binding concern, not a wire concern.
- **Add transport (stdio/HTTP/mTLS) directly into `mcps-host`** — rejected: breaks the transport-free, auditable boundary; pulls async/sockets/TLS into the model-facing library.
- **Ambient clock/RNG inside `HostSession`** — rejected: non-deterministic, hard to vector and test.

## Consequences

### Positive
- One audited home for client-side freshness, replay-window, and request/response binding.
- Core's key-free, model-facing guarantee preserved; `HostSigner` untouched.
- Deterministic under injected clock/RNG; testable and vector-able.
- `mcps-host` stays minimal and transport-free.

### Negative
- `mcps-host` is no longer purely stateless — `HostSession` holds pending-request state that long-lived applications must clean up (`expire_pending` / `cancel_request`).
- Two client entry points (primitive vs session) is a slightly larger API surface.
- Remote (non-local) client transport is unavailable until the deferred crate exists; only caller-managed stdio to a local proxy is supported now.

### Neutral
- The trust resolver for response verification is supplied by the caller per call (data, not networking).

## Compliance and Enforcement

Tests must prove: nonce generation; timestamp-from-injected-clock; `request_hash` storage by id; verify-by-stored-hash; wrong-hash / unknown-id / duplicate-id rejection; pending cleanup; no key accessor; determinism under injected providers. A guard that `mcps-host`'s dependency set carries no networking/async crates enforces the transport-free rule. Reviewed against this ADR.

## Related

- PRD: (author's private monorepo)
- Prior ADRs: ADR-MCPS-003 (signing locus), ADR-MCPS-006 (freshness/replay), ADR-MCPS-008 (verified-context propagation)
- Code: `components/mcps/mcps-host` (best-effort; expect rot)
