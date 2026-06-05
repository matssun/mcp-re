<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-017: Single-Node Production Claim Ceiling and Deferred Enterprise Capabilities

## Status

Proposed

## Context

MCP-S Core + Phase 5 + Phase 6 + 6.1 are merged. The follow-up project (PRD #3844) must decide what "production" means for this delivery. The merged work already carries a user-approved claim ceiling: *"production-hardened for single-node Rust-native deployments."* The original brief's "full-blown" checklist mixed single-node-completable items with enterprise / horizontal-scale items (shared atomic replay, HSM/KMS, CRL/OCSP, reverse-proxy mTLS) that are each distributed-systems or enterprise-IAM sub-projects with their own threat models. A decision is needed to bound the project and keep the security claim honest.

## Decision

This project's Definition of Done is single-node production-hardened plus external-readiness; horizontal-scale replay, enterprise key custody (HSM/KMS), online certificate revocation (CRL/OCSP), reverse-proxy mTLS, kernel/filesystem/network containment, signed tool manifests, offline-hermetic builds, client-side remote transport, and committed production rollout are explicitly deferred as named follow-ups — each requiring its own ADR / threat model — and must not be folded into this project's claims.

## Rationale

The merged work already approved a single-node ceiling; this project's job is to make that claim fully true (CI-proven, host-usable, isolated, documented, dogfooded) rather than chase enterprise features. Each deferred item is independently substantial: shared atomic replay is a distributed-systems problem; HSM/KMS is key-custody integration; CRL/OCSP is online-revocation infrastructure; reverse-proxy mTLS is an ingress integration. Bundling any of them would balloon scope and tempt over-claiming. Naming them as tracked follow-ups preserves honesty and keeps the project bounded — the security-boundary document is the enforcement artifact.

## Alternatives Considered

- **"Full-blown" / enterprise scope in this project** — rejected: unbounded; mixes implementation readiness with enterprise adoption; risks claims the system can't back.
- **Leave scope implicit** — rejected: invites scope creep and over-claiming; the whole point is an explicit ceiling.
- **Pick one enterprise item (e.g. horizontal replay) to include** — rejected: even one is its own sub-project; would gate the single-node baseline on distributed-systems work.

## Consequences

### Positive
- Bounded, shippable project; honest, defensible security claim.
- Each enterprise capability gets proper ADR / threat-model treatment instead of a rushed checkbox.

### Negative
- MCP-S cannot be described as multi-node / enterprise-ready after this project; consumers needing scale must wait for the named follow-ups.
- Requires discipline to keep deferred items off the claim surface.

### Neutral
- Follow-ups are pre-filed (#3837–#3842 plus OS-sandbox and signed-tool-manifest issues), so the roadmap is visible.

## Compliance and Enforcement

The security-boundary document (`security-boundary.md`) is a merge/release gate (per the PRD) and must state the allowed claim and the forbidden claims verbatim. The deferred capabilities are tracked as GitHub issues. Code review rejects any document or PR asserting a deferred capability as delivered.

## Related

- PRD: (author's private monorepo)
- Prior ADRs: ADR-MCPS-013 (Phase 5 delegated authorization), ADR-MCPS-014 (Phase 6 transport hardening)
- Follow-ups: (shared replay), (HSM/KMS), (CRL/OCSP), (reverse-proxy mTLS), (crates isolation), (strict mode)
