<!-- SPDX-License-Identifier: Apache-2.0 -->

# Theorem-architecture packets

Proposal and review artifacts for the top-down proof architecture — ADR-MCPRE-059 §28.

A packet is where a proof tree is **designed and ratified**. It is not an authority over
theorems, and nothing here is read by any tool.

```text
DESIGN / RATIFICATION        verification/reviews/packets/theorem-architecture-<date>.md
                             temporary node names allowed: R1, R1.1, …
        │ owner ratification
        ▼
AUTHORITATIVE GRAPH          verification/policy/theorems.toml
                             permanent THM ids · statements · owners
                             depends_on · supported_by · root_theorems
        │ generated
        ▼
VIEWS                        verification/generated/theorem-*.md
```

**No second graph.** A packet SHALL NOT become a parallel statement/edge registry: no
`proof-tree.toml`, no `system-theorems.toml`, no per-node file that a tool could read
instead of `theorems.toml`. Once a decomposition is ratified, the nodes that earn permanent
identity are allocated `THM-NNNN` in the registry, the roots are declared in
`root_theorems`, and the packet stops being consulted for anything but its reasoning.

**Temporary names are temporary.** `R1.2` is a handle for a review conversation. It never
appears in the registry, in code, or in a review record.

## What a packet must contain

- the root security propositions, stated in the safety direction (§28.9) and quantified
  over the obligations a validated deployment selects (§28.10);
- the decomposition — for each non-leaf node, the children its proposition logically
  requires (§28.2, §28.4);
- for every branch, exactly one terminal, and no implicit ends (§28.5):

  | terminal | how it is encoded once ratified |
  |---|---|
  | `PROVED` | an existing `THM-NNNN`, attached to the lowest node it honestly establishes |
  | `STRUCTURAL` | the owner's type/state/construction closure and its evidence; a permanent THM only where the fact is a reusable premise across a theorem boundary or itself needs owner specification review (§28.6) |
  | `ASSUMED` | an `ASM-NNNN`, reached through the review unit's assumption closure — never a direct theorem→assumption edge |
  | `GAP` | a ratified `THM-NNNN` with a **real owner** and no sufficient support closure; its unestablished state is derived, never stored |
  | `OUT_OF_SCOPE` | the parent's mandatory `scope` sentence, which stays authoritative |

- the **owner** of every node, named as a real `[[unit]]`. A proposition with no semantic
  authority that can honestly own it is an **architecture gap**, not a manifest
  inconvenience: it stays in the packet, and no unit is invented to satisfy the schema.

## Reviews, not packets

`verification/reviews/specification/` holds the review records — evidence about a
fingerprint (§14.7). Those are JSON, they are read by the tooling, and they are the only
thing in `verification/reviews/` that is.
