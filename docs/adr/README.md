<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Architecture Decision Records

The ADRs now live as **GitHub Discussions** in the [**ADRs** category](https://github.com/matssun/mcp-re/discussions/categories/adrs) — that is the single source of truth for both the decision text and its current status. This file is a generated index; the committed `adr-*.md` bodies were retired on 2026-07-10 (recover any from git history if needed).

## Track status at a glance

Every ADR discussion carries the `adr` label plus one status label. Filter:

- [All ADRs](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr)
- [✅ Accepted](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr+label%3Astatus%3Aaccepted) · [✅ Implemented](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr+label%3Astatus%3Aimplemented) · [🟡 Proposed](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr+label%3Astatus%3Aproposed)
- [↩️ Superseded](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr+label%3Astatus%3Asuperseded) · [🗄️ Deprecated](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr+label%3Astatus%3Adeprecated)

## Index

| ID | Title | Status |
|---|---|---|
| [ADR-MCPS-001](https://github.com/matssun/mcp-re/discussions/350) | Clean-Room Public Protocol — Vocabulary Firewall and Public TrustResolver Trait | ✅ Implemented |
| [ADR-MCPS-002](https://github.com/matssun/mcp-re/discussions/351) | Frozen Public Envelope Vocabulary | ✅ Implemented |
| [ADR-MCPS-003](https://github.com/matssun/mcp-re/discussions/352) | Signing Locus — What signer and a Signature Prove | ✅ Implemented |
| [ADR-MCPS-004](https://github.com/matssun/mcp-re/discussions/353) | Ed25519-over-JCS Signing Rule for the Whole JSON-RPC Object | 🗄️ Deprecated |
| [ADR-MCPS-005](https://github.com/matssun/mcp-re/discussions/354) | JCS-Safe JSON Value Domain with Fail-Closed Canonicalization | 🗄️ Deprecated |
| [ADR-MCPS-006](https://github.com/matssun/mcp-re/discussions/355) | Freshness and Replay Model — Injected ReplayCache, No sequence in Core v1 | ✅ Implemented |
| [ADR-MCPS-007](https://github.com/matssun/mcp-re/discussions/356) | Trust Resolution, Key Rotation, and Revocation Model | ✅ Implemented |
| [ADR-MCPS-008](https://github.com/matssun/mcp-re/discussions/357) | Verified-Context Propagation to Inner MCP Servers | ✅ Implemented |
| [ADR-MCPS-009](https://github.com/matssun/mcp-re/discussions/358) | Fail-Closed Message Constraints — Batch, Notification, Unknown-Field Rejection | ✅ Implemented |
| [ADR-MCPS-010](https://github.com/matssun/mcp-re/discussions/359) | Incubation Strategy, Extension Identifier, and Preimage-Stability Rule | ↩️ Superseded |
| [ADR-MCPS-011](https://github.com/matssun/mcp-re/discussions/360) | Workspace Structure, Phased Delivery, and Conformance-as-Specification | ✅ Implemented |
| [ADR-MCPS-012](https://github.com/matssun/mcp-re/discussions/361) | Project Placement & Build Integration — components/mcps as an Isolated rules_rust Workspace | ✅ Implemented |
| [ADR-MCPS-013](https://github.com/matssun/mcp-re/discussions/362) | Delegated Authorization — AuthorizationProfile Abstraction and the Reference Signed Authorization Profile (Phase 5) | ✅ Implemented |
| [ADR-MCPS-014](https://github.com/matssun/mcp-re/discussions/363) | Phase 6 — Rust-Native Transport Hardening (RustlsDirectProvider, mTLS Channel Binding; Granian Decoupled) | ✅ Implemented |
| [ADR-MCPS-015](https://github.com/matssun/mcp-re/discussions/364) | Client Host-Session Architecture | ✅ Implemented |
| [ADR-MCPS-016](https://github.com/matssun/mcp-re/discussions/365) | Inner-Server Isolation Boundary | ✅ Implemented |
| [ADR-MCPS-017](https://github.com/matssun/mcp-re/discussions/366) | Single-Node Production Claim Ceiling and Deferred Enterprise Capabilities | ↩️ Superseded |
| [ADR-MCPS-018](https://github.com/matssun/mcp-re/discussions/367) | CI Reproducibility Posture and Conformance-Manifest Authority | ✅ Implemented |
| [ADR-MCPS-019](https://github.com/matssun/mcp-re/discussions/368) | Phase 7 External Backends (stub) | ✅ Implemented |
| [ADR-MCPS-020](https://github.com/matssun/mcp-re/discussions/369) | Distributed Atomic Replay Store — Durability Contract for Horizontally-Scaled Replay Safety | ✅ Implemented |
| [ADR-MCPS-021](https://github.com/matssun/mcp-re/discussions/370) | Shared Trust State — Bounded Trust-Propagation Window for Revocation and Rotation | ✅ Implemented |
| [ADR-MCPS-022](https://github.com/matssun/mcp-re/discussions/371) | Signing Key Custody at Scale — Per-Node Keys, Explicit Anchor, Optional KMS | ✅ Implemented |
| [ADR-MCPS-023](https://github.com/matssun/mcp-re/discussions/372) | Ingress and Reverse-Proxy mTLS — End-to-End Binding vs. Trusted-Ingress Re-Assertion | ✅ Implemented |
| [ADR-MCPS-024](https://github.com/matssun/mcp-re/discussions/373) | Replay Safety Under MCP Multi Round-Trip Requests (SEP-2322) | ✅ Implemented |
| [ADR-MCPS-025](https://github.com/matssun/mcp-re/discussions/374) | Untrusted Transport Routing Headers — MCP-S Composition with SEP-2243 | ✅ Implemented |
| [ADR-MCPS-026](https://github.com/matssun/mcp-re/discussions/375) | Signing Scope Versus Stateless Per-Request `_meta` (SEP-2575) | ✅ Implemented |
| [ADR-MCPS-027](https://github.com/matssun/mcp-re/discussions/376) | Extension Identifier Reassignment to `se.syncom/mcps` | ✅ Implemented |
| [ADR-MCPS-028](https://github.com/matssun/mcp-re/discussions/377) | Native Cloud-KMS Response Signers — AWS KMS and GCP Cloud KMS (Ed25519, non-exporting) | ✅ Implemented |
| [ADR-MCPS-030](https://github.com/matssun/mcp-re/discussions/378) | MCP-S Core Is Method-Transparent — Tool Catalog Integrity Is Excluded | ✅ Implemented |
| [ADR-MCPS-031](https://github.com/matssun/mcp-re/discussions/379) | MCP-S 0.5 Is a Proposal-Readiness Release Over a Frozen draft-01 Envelope | ✅ Implemented |
| [ADR-MCPS-032](https://github.com/matssun/mcp-re/discussions/380) | Documentation Consolidation for 0.5 — One Canonical Boundary, One Docs Root, Redirect Stubs | ✅ Implemented |
| [ADR-MCPS-033](https://github.com/matssun/mcp-re/discussions/381) | v0.5 Claim Matrix — Two Cross-Linked Sections; NSA Matrix Derived From §A | ✅ Implemented |
| [ADR-MCPS-034](https://github.com/matssun/mcp-re/discussions/382) | Method-Transparency Is CI-Enforced — Behavioral Equivalence Test + Static Drift Guard | ✅ Implemented |
| [ADR-MCPS-035](https://github.com/matssun/mcp-re/discussions/383) | MCP-S Audit-Evidence Vocabulary Is Derived From the Frozen Error Taxonomy | ✅ Implemented |
| [ADR-MCPS-036](https://github.com/matssun/mcp-re/discussions/384) | Proposal-Readiness Is a Dual Gate — Mechanical CI + Owner HITL — Over One Evidence Spine | ✅ Implemented |
| [ADR-MCPS-037](https://github.com/matssun/mcp-re/discussions/385) | Draft-02 Canonical Number Domain — Integer-Only, With a Documented Float Limitation | ✅ Implemented |
| [ADR-MCPS-038](https://github.com/matssun/mcp-re/discussions/386) | Draft-02 Envelope Identifiers and Canonical Preimage Field Set | ✅ Implemented |
| [ADR-MCPS-039](https://github.com/matssun/mcp-re/discussions/387) | Draft-02 Authorization-Evidence Binding | ✅ Implemented |
| [ADR-MCPS-040](https://github.com/matssun/mcp-re/discussions/388) | Draft-02 Fail-Closed Error Taxonomy | ✅ Implemented |
| [ADR-MCPS-041](https://github.com/matssun/mcp-re/discussions/389) | Draft-01/Draft-02 Migration and Dual-Verifier Release Posture | ✅ Implemented |
| [ADR-MCPS-042](https://github.com/matssun/mcp-re/discussions/390) | Draft-02 Conformance Corpus and Cross-Implementation Interop Oracle | ✅ Implemented |
| [ADR-MCPS-043](https://github.com/matssun/mcp-re/discussions/391) | MCP-S Discovery, Capability Advertisement, and Enforcement Policy | ✅ Accepted |
| [ADR-MCPS-044](https://github.com/matssun/mcp-re/discussions/392) | Client-Side MCP-S Integration Model | ✅ Accepted |
| [ADR-MCPS-045](https://github.com/matssun/mcp-re/discussions/393) | End-to-End Walkthrough — Tiered E2E Ladder and Client-Proxy Wire Interop | ✅ Implemented |
| [ADR-MCPS-046](https://github.com/matssun/mcp-re/discussions/394) | Signed Rejection Receipts | ↩️ Superseded |
| [ADR-MCPS-047](https://github.com/matssun/mcp-re/discussions/395) | Stateless Multi-Round-Trip Continuation Evidence | ✅ Implemented |
| [ADR-MCPS-048](https://github.com/matssun/mcp-re/discussions/396) | Generated-First Build Graph — Cargo Manifests Are the Source of Truth, Bazel BUILD Files Are Generated and CI Staleness-Gated | ✅ Implemented |
| [ADR-MCPS-049](https://github.com/matssun/mcp-re/discussions/397) | Horizontally-Scaled Fleet Deployment Posture — Lifting the Single-Node Ceiling Over Proven Coherence | ✅ Accepted |
| [ADR-MCPRE-050](https://github.com/matssun/mcp-re/discussions/398) | Standards-Aligned HTTP Profile — RFC 9421 + RFC 9530 as the Cryptographic Carrier for HTTP Transports | ✅ Implemented |
| [ADR-MCPRE-051](https://github.com/matssun/mcp-re/discussions/399) | High-Throughput Serving Architecture — Per-Core Async Data Plane, Stateless Streamable-HTTP Inner Plane, Authoritative Replay Tier, Delegated Signing Custody | ✅ Accepted |
| [ADR-MCPRE-052](https://github.com/matssun/mcp-re/discussions/400) | Delegated Signing-Key Attestation — a JOSE/JWS Delegation Credential Carried in the RFC 9421 HTTP Evidence | ✅ Implemented |

## Active vs Legacy

The current MCP-RE worldview is frozen in [`docs/design/active-profile-and-legacy-quarantine.md`](../design/active-profile-and-legacy-quarantine.md) and summarized in [`docs/CURRENT_ARCHITECTURE.md`](../CURRENT_ARCHITECTURE.md). In short:

- **Active production evidence profile:** ADR-MCPRE-050 (RFC 9421 + RFC 9530 HTTP profile — the one carrier), ADR-MCPRE-051 (serving architecture), ADR-MCPRE-052 (delegated signing via a JOSE/JWS credential in the HTTP evidence), and later `ADR-MCPRE-*` records.
- **Deprecated:** the Native JCS / object profile — ADR-MCPS-004 (Ed25519-over-JCS), ADR-MCPS-005 (JCS canonicalization), and the draft-01/02 native-envelope material (`status:deprecated`). These are **historical**: not a security mechanism, not an alternative carrier, not a fallback. They MUST NOT be the foundation for new evidence, delegated signing, runtime profiles, SEP/IG proposals, or production design.

## Conventions

- One decision per ADR discussion, titled `ADR-<TAG>-<NNN>: <title>`. Historical IDs are preserved: `ADR-MCPS-001…049` keep the `MCPS` tag; `ADR-MCPRE-050+` use `MCPRE`.
- Status label values: `status:proposed`, `status:accepted`, `status:implemented`, `status:superseded`, `status:deprecated`, `status:withdrawn`, plus `status:needs-review` for uncertain ones. Update the label when a decision changes state.
- A decision that changes an earlier one supersedes that ADR with an explicit note in both discussions and flips the older one to `status:superseded`.

## Provenance

ADR-MCPS-001 through ADR-MCPS-018 were originally published as GitHub Discussions in the maintainer's private monorepo, later copied into this repo as files, and are now re-published here as Discussions. ADR-MCPS-019 was implemented but not previously written up; its stub records the rule as applied in the v0.2.0 release.
