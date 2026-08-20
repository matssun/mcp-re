<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Architecture Blueprint

This directory is the hierarchical architectural map for MCP-RE. It is intentionally structured like the implementation we want: one concise top-level authority document, subordinate component blueprints with narrow responsibility, and deeper documents only when a component genuinely needs another level.

The purpose is not to replace accepted ADRs. Existing ADRs remain authoritative for the decisions they own. This blueprint connects them into one reviewable architecture and supplies the implementation contracts needed for continued refactoring.

## Document hierarchy

```mermaid
flowchart TD
    A[ADR-MCPRE-061\nHierarchical Authority Architecture]
    B[Implementation Blueprint\nRefactoring Method]
    C[Component Blueprint Template]

    T[Trust & Revocation]
    TLS[TLS & Transport Identity]
    V[Evidence Verification]
    E[Exchange Lifecycle]

    A --> B
    A --> T
    A --> TLS
    A --> V
    A --> E
    B --> C
```

## Top-level documents

- [`ADR-MCPRE-061-hierarchical-authority-architecture.md`](../adr/drafts/ADR-MCPRE-061-hierarchical-authority-architecture.md) — proposed durable architectural decision.
- [`implementation-blueprint.md`](implementation-blueprint.md) — current execution method for the refactoring campaign.
- [`component-blueprint-template.md`](component-blueprint-template.md) — standard anatomy for subordinate component design documents.

## Initial component blueprints

- [`components/trust-and-revocation.md`](components/trust-and-revocation.md)
- [`components/tls-and-transport-identity.md`](components/tls-and-transport-identity.md)
- [`components/evidence-verification.md`](components/evidence-verification.md)
- [`components/exchange-lifecycle.md`](components/exchange-lifecycle.md)

These are first-pass architectural documents, not declarations that every boundary is already final. The shallow-module census and subsequent investigation may refine the tree. Refinement must preserve the governing rule: **one authority, narrow facade, private subordinate implementation tree**.

## Existing ADRs this hierarchy composes

```mermaid
flowchart LR
    A55[ADR-055\nTLS session resumption]
    A56[ADR-056\nRuntime architecture]
    A57[ADR-057\nHierarchical state machines]
    A58[ADR-058\nState-driven decomposition]
    A59[ADR-059\nTheorem registry & assurance graph]
    A61[ADR-061\nHierarchical authority architecture]

    A55 --> A61
    A56 --> A61
    A57 --> A61
    A58 --> A61
    A59 --> A61
```

ADR-061 does not restate those decisions. It defines how their responsibilities are arranged into a reviewable hierarchy.

## Navigation principle

A reviewer should be able to move top-down:

```text
system architecture
    -> authority domain
        -> subordinate authority
            -> implementation module
                -> theorem / test / evidence
```

No reviewer should have to begin by reading a thousand-line implementation file to discover what the component is supposed to mean.
