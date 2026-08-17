<!-- SPDX-License-Identifier: Apache-2.0 -->

# `verification/model/` — the canonical security model

One file: [`vocabulary.md`](vocabulary.md). It holds MCP-RE's foundational security
concepts, relations, candidate long-lived theorems, and the A/B/C layering rule.

## Ownership

This directory is centrally owned. A change to it is a change to what MCP-RE's proofs
mean, so it is security-sensitive under ADR-MCPRE-059 §11 even when no executable Rust
moves. Changing a definition here can silently change the content of every theorem that
consumes it.

## What belongs here

Definitions that more than one proof depends on, and statements that should outlive the
implementation.

## What does not

- Anything MCP-specific enough to belong in a protocol profile. The core model is
  ontologically agnostic (§10) and must stay that way; the generic engine that will later
  be promoted to the main codebase must not learn about MCP requests, actors, RFC 9421, or
  a particular proxy lifecycle state.
- Predicates only one proof uses. Those live next to that proof until a second consumer
  appears — at which point they move here rather than being copied.
- Anything derived. This directory is source.
