<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-019: Phase 7 External Backends (stub)

## Status

Implemented; ADR write-up not finalized as a public discussion in the source
monorepo (referenced inline in `Cargo.toml` and source comments). Recorded here
for completeness; expected to be ratified and published as a full ADR in a
future revision of this repository.

## Context

Phase 7 introduced the three high-assurance external-backend integrations the
production `mcps_proxy_ext` artifact ships with — and which the lean default
`mcps_proxy` does **not** link in. The decision codified by ADR-MCPS-019 is
the closure-discipline rule for these backends: they are gated at the cargo
feature level so the default (Mac dev) build's runtime closure stays minimal,
but they are declared NON-optional at the workspace cargo manifest so the
dependency graph is reproducible from a single `Cargo.lock`.

## Decision

The three Phase 7 backends are:

1. **HSM/KMS key custody via standard PKCS#11** (`pkcs11_keysource` feature,
   `cryptoki-sys` crate). Vendor-neutral PKCS#11 binding; tested against an
   in-tree mock PKCS#11 provider (hermetic `cdylib`, no external token).
2. **Shared atomic ReplayCache** via Redis (`redis_replay` feature, `redis`
   crate, `default-features = false`, sync-only, no async runtime). Server-side
   atomic insert-if-absent with a real-clock TTL window (see audit-v0.2
   findings H-8/H-9/H-10).
3. **Online OCSP/CRL revocation** (`online_ocsp` feature, `x509-ocsp` + `ureq`
   sync HTTP). Full RFC 6960 §3.2 trust chain — responder signature, responder
   identity, CertID binding, freshness window, request-bound nonce (see
   audit-v0.2 Critical findings C-1…C-4 and High findings H-2…H-7).

Each backend is `#[cfg(feature = "...")]`-gated so a build without the feature
links no Redis / no PKCS#11 / no OCSP code at all. A CI guard
(`lean-closure job`) uses `bazel cquery` to enforce this for the default
`mcps_proxy` binary.

The Linux-only kernel sandbox (`sandbox_linux` — Landlock fs ruleset + seccomp
egress) is also a Phase 7 capability but is target-gated, not feature-gated,
and is excluded from non-Linux builds entirely.

## Compliance and Enforcement

- Lean-closure CI guard asserts the default `mcps_proxy` binary does not pull
  in `redis`, `cryptoki-sys`, `x509-ocsp`, `landlock`, or `seccompiler`.
- The `mcps_proxy_ext` production artifact enables `redis_replay`,
  `pkcs11_keysource`, `online_ocsp` together and is the only binary expected
  to be deployed in a multi-node or HSM-backed configuration.
- Source references: `Cargo.toml` Phase 7 dependency block; `mcps-proxy/src/`
  modules `ocsp.rs`, `redis_store.rs`, `pkcs11_keysource.rs`, `sandbox_linux.rs`.

## Related

- ADR-MCPS-014 — Phase 6 transport hardening (predecessor).
- ADR-MCPS-018 — CI reproducibility posture (closure discipline rationale).
- audit-v0.2 — first formal review of the Phase 7 implementation; all
  critical/high/medium findings remediated in v0.2.0 (see
  [`../security/remediation-v0.2.md`](../security/remediation-v0.2.md)).
