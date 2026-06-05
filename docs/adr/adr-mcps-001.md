<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-001: Clean-Room Public Protocol — Vocabulary Firewall and Public TrustResolver Trait

## Status

Accepted

## Context

Derived from PRD (MCP-S — Zero Trust Security Profile for MCP). MCP-S could be built either as the on-the-wire serialization of this monorepo's existing Zero Trust trust model (ATPA, `EntityIdentity`, the tripartite Subject/Principal/Actor in `execution_context.py`) or as a clean-room public protocol. It is intended to be proposed upstream to the open-source MCP community. `CONTEXT.md` records the monorepo Ubiquitous Language; this decision settles whether that language governs MCP-S, and how the two integrate.

## Decision

MCP-S Core is a clean-room public protocol profile — compatible with but not defined by the monorepo Zero Trust model; the `mcps-core` crate depends on no internal trust concepts, and the monorepo integrates only through adapter/mapping layers in `mcps-host`/`mcps-proxy` that implement the public `TrustResolver` trait.

## Rationale

A protocol proposed to an external community cannot require reviewers to first learn an internal trust architecture; coupling the wire format to internal jargon would block adoption. The monorepo Python defaults (ABC interfaces, opaque ID types, OpenAPI-first, SQLAlchemy persistence) explicitly **do not** govern `mcps-core`, which is a pure Rust crate — this is a novel-domain decision, not a ratification of those defaults. Integration is preserved without coupling by making the monorepo `EntityIdentity` resolver one implementation of the abstract public `TrustResolver` trait `(signer, key_id) -> verification key`.

## Alternatives Considered

- **Wire serialization of the internal model** (envelope field names match the glossary; resolver is the Entity Identity resolver): rejected — couples a public protocol to internal vocabulary and makes upstream review require internal context.
- **Fully independent, no integration contract**: rejected — leaves the eventual ATPA ↔ MCP-S integration unspecified and lets the two trust models drift.

## Consequences

### Positive
- Publishable upstream without internal context.
- `mcps-core` is reusable by sidecars, hosts, conformance runners, and future non-Rust bindings.

### Negative
- Requires a maintained mapping layer (`mcps-host`/`mcps-proxy`) and a small binding spec between envelope fields and glossary terms.

### Neutral
- `CONTEXT.md` carries a firewall entry recording that the glossary does not govern MCP-S public names.

## Compliance and Enforcement

`mcps-core` MUST NOT import or reference `ATPA`, `EntityIdentity`, `provider_identifier`, `ISubjectID`, `execution_context`, or the Subject/Principal/Actor tripartite terms. Enforced by crate dependency boundaries plus review. The `CONTEXT.md` "MCP-S envelope vocabulary" flagged-ambiguities entry records the firewall and the envelope→glossary mapping.

## Related

- PRD: (author's private monorepo)
- Siblings: ADR-MCPS-002 … ADR-MCPS-011
- Source: `documents/mcps/# MCP-S Project Planning Brief.md`
