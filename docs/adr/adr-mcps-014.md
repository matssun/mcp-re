<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-014: Phase 6 — Rust-Native Transport Hardening (RustlsDirectProvider, mTLS Channel Binding; Granian Decoupled)

## Status

Proposed

## Context

MCP-S Phase 6 adds higher-assurance production hardening on top of the object-level security profile. The planning brief (§14, Phase 6) listed "mTLS binding for Streamable HTTP" and the original plan was to *consume* the verified client certificate from a host server — specifically the Granian ASGI-TLS extension being contributed upstream. That extension is an **unreleased** submitted PR, and a standing project rule is to never base security on an unreleased fork.

A design decision (2026-05-29) changes the architecture: rather than depend on an external TLS-terminating host, **MCP-S terminates TLS itself and becomes the Policy Enforcement Point**. This removes Granian from the MCP-S critical path entirely (the Granian ASGI-TLS upstream PR continues independently for other consumers and is untouched by this work), removes the unreleased dependency, and reduces moving parts.

Object-level MCP-S signatures remain mandatory; `authorization_hash` still requires the Phase 5 policy layer (ADR-MCPS-013). **mTLS is additional hardening, not the whole security model** — it binds the signing identity to the transport channel, it does not replace signing.

## Decision

Phase 6 is implemented as **Rust-native transport hardening inside `mcps-proxy`**, with no dependency on Granian or any external TLS terminator.

1. **TLS-terminating Streamable HTTP server, blocking, no async runtime.** A `std::net::TcpListener` + `rustls` (0.23, `ring` crypto provider) server connection, thread-per-connection, blocking IO. NO `tokio`/async — this mirrors the existing `std::net` conformance HTTP harness philosophy and keeps the isolated `crates_mcps` hub free of an async runtime.

2. **`TransportBindingProvider` abstraction; `RustlsDirectProvider` is the production target.** The provider terminates TLS, verifies the client certificate against a configured client-CA (rustls `WebPkiClientVerifier`), and extracts the **verified client identity** from the leaf certificate. `ReverseProxyMtlsProvider` (identity from a trusted header set by an upstream terminator) is a documented LATER integration option — NOT built in this phase.

3. **Verified client identity extraction.** From the leaf (chain[0]) verified client certificate: first **URI SAN** (SPIFFE-style) → first **DNS SAN** → **CN**, via `x509-parser`. Extraction runs once per connection.

4. **`TransportBindingPolicy` abstraction comparing request `signer` to the verified transport identity.** Default `ExactMatchBinding` (request `signer` must equal the verified transport identity); `MappedBinding` (injected `signer → {allowed transport identities}`) for cross-namespace deployments (e.g. DID signer vs SPIFFE cert). A binding mismatch, or a required-but-absent/invalid client certificate, fails closed with `mcps.transport_binding_failed` — the code already reserved in the Core taxonomy. Enforcement happens **at the proxy** (which holds the connection); `mcps-core` stays pure and unchanged.

5. **`KeySource` abstraction.** `FileKeySource` + `EnvKeySource` now; HSM is a documented future implementation (NOT a `NotImplementedError`-style stub). Loads the Ed25519 server signing key, the TLS server certificate + private key, and the client-CA trust anchors.

6. **Durable `ReplayCache`.** A file-backed reference implementation (append + prune-by-expiry, no external service) behind the existing `mcps_core::ReplayCache` trait, so a multi-instance deployment survives restarts without running Redis. Redis / other backends are future implementations behind the same trait.

7. **`mcps-proxy` production CLI** (folds in MCPS-018) wiring `KeySource` + `TrustResolver` + durable `ReplayCache` + Phase-5 `PolicyEvaluator` + `RustlsDirectProvider` + Streamable HTTP server mode + an inner-command subprocess.

### Firewall refinement (amends ADR-MCPS-011/012)

- `mcps-core` **remains PURE**: no networking, async, filesystem, TLS, or x509 — unchanged.
- `mcps-proxy`'s transport layer MAY use `std::net` + `rustls` + `rustls-pemfile` + `rustls-pki-types` + `x509-parser` (added to the isolated `crates_mcps` hub). **No `tokio`/async runtime** (blocking IO + threads). No dependency on Granian or any in-repo non-MCP-S crate. The hub remains isolated from `crates` / `crates_rust_components`.

## Rationale

Making the proxy the TLS terminator and PEP removes an unreleased external dependency, reduces moving parts, and gives one place that authenticates the channel, verifies the object signature, evaluates authorization, and binds signer↔channel. `rustls` 0.23 with the `ring` provider is already proven to build in this Bazel/crate-universe toolchain (Granian via `rustls-ring`, pyreqwest, nautilus_trader), so the dependency is low-risk. Blocking `std::net` + threads keeps the hub free of an async runtime, consistent with the Phase 3 transport philosophy.

## Alternatives Considered

- **Consume Granian's ASGI-TLS extension (original plan).** Rejected: unreleased dependency; more moving parts; couples MCP-S security to an external host's release cadence.
- **`tokio` + `tokio-rustls` async server.** Rejected: introduces an async runtime into the isolated hub, breaking the std-only transport philosophy established in Phase 3; thread-per-connection is sufficient for a sidecar PEP.
- **`aws-lc-rs` crypto provider.** Rejected in favour of `ring`: `ring` is what the proven-building Granian path uses and avoids the heavier C/assembler hermetic build of aws-lc.
- **Redis-first durable replay cache.** Rejected as the first impl: adds an external service, against the "fewer moving parts / Rust-native" goal. Kept as a future backend behind the trait.
- **`MappedBinding` as the default.** Rejected as default: exact match is the strongest Zero-Trust default; mapping is opt-in for cross-namespace deployments.

## Consequences

### Positive
- MCP-S is a self-contained Policy Enforcement Point: channel auth + object signature + authorization + transport binding in one place, no external TLS terminator.
- No unreleased dependency; Granian is fully decoupled from the MCP-S critical path.
- Strong channel binding: the entity holding the signing key must also present the bound client certificate.

### Negative
- The isolated `crates_mcps` hub gains a TLS stack (`rustls` + `ring`) and an x509 parser — a meaningful dependency increase for what was a near-std workspace.
- Thread-per-connection (blocking) is simple but not the highest-concurrency model; acceptable for a sidecar PEP, revisitable later.

### Neutral
- Durable replay is file-backed first; Redis and others are future trait implementations.
- `ReverseProxyMtlsProvider` remains available as a later option for deployments that terminate TLS upstream.
- `mcps.transport_binding_failed` (already in the Core taxonomy) is now actually emitted — by the proxy, not Core.

## Compliance and Enforcement

- `bazel test //components/mcps/...` remains the gate; new targets cover mTLS and transport binding.
- A firewall test asserts `mcps-core`'s dependency set is unchanged (no rustls/networking leaks into Core).
- mTLS tests: missing client certificate, wrong/untrusted client certificate, and `signer`↔transport-identity mismatch all fail closed with `mcps.transport_binding_failed`; a correctly-bound request passes.
- Object-level signature verification (Phase 1–4) and Phase-5 authorization remain mandatory and are unaffected — transport binding is an additional gate, not a replacement.

## Related

- PRD: MCP-S (Discussion #3763)
- Prior ADRs: ADR-MCPS-011/012 (workspace firewall — refined here to admit a no-async TLS stack in the proxy), ADR-MCPS-013 (Phase 5 delegated authorization), ADR-MCPS-007 (TrustResolver — reused for request signers).
- Decoupled from: the Granian ASGI-TLS upstream PR (`feat/asgi-tls-extension`) — that work continues independently and is NOT touched by Phase 6.
- Code: `components/mcps/mcps-proxy/` (transport layer + CLI), `components/mcps/Cargo.toml` + `crates_mcps` hub (rustls/x509 deps).
