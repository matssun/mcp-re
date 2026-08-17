<!-- SPDX-License-Identifier: Apache-2.0 -->

# `verification/verus/` — Rust-coupled proofs

ADR-MCPRE-059 §7. Verus is the primary tool for security properties tightly coupled to
executable Rust: preconditions and postconditions, state-transition legality, type and
representation invariants, ownership and resource protocols, data-structure invariants.

Verus is not "the easy prover" and not a universal default. The selection criterion is the
relationship between the assurance claim and executable Rust — nothing else.

## Layout

```
specs/               specifications for units under verification
predicates/          reusable predicates, consumed rather than redefined
state_machines/      transition-system definitions and their invariants
trusted_interfaces/  external/assumed specifications — every file here is TCB
```

`trusted_interfaces/` deserves the emphasis. Anything placed there is trusted, not proven.
Adding or widening a file in it grows the trusted computing base and requires a registered
entry in `../policy/assumptions.toml`.

## Status

Empty. No Verus toolchain is pinned (`../policy/toolchains.lock.toml` `[verus] state =
"unresolved"`), so no proof in this tree could be checked, and an unchecked proof is not
evidence.

The pilot candidate is `mcp-re-proxy/src/runtime_state.rs`, with the crate-granularity
obstacle recorded in `../baseline/phase0-assurance-baseline.md` §6.1. Read that before
starting Phase 2 — the obstacle is real and its resolution is a decision, not a detail.

## Rules that apply here

**No proof-only shadow implementation** (§"No proof-only shadow implementation"). MCP-RE
does not keep one Rust implementation for production and a second, easier-to-prove one for
Verus. The proof must constrain the code that matters. An abstraction layer is acceptable
only when production uses that same layer as its authoritative boundary.

**`cargo verus focus` is never authoritative** (Operational Rule 5). It is a local
productivity tool. The merge and release gates run full verification for the selected
scope. A local `focus` pass followed by a full-verify failure is a CI failure, and a full
verify that was not run at all is also a failure — not an absence of evidence.

**Specification changes are security changes** (§11). Weakening a postcondition,
strengthening a precondition to make a proof go through, deleting an invariant, changing
the abstraction a proof views the state through, or adding an `assume` are all
security-sensitive even when no executable Rust moves. A proof is not accepted because the
prover printed success; CI must also establish that the proposition being proven and its
trusted basis did not change without review.

**When a proof is hard**, the permitted responses are: improve the specification, derive a
lemma, expose a genuinely cleaner architectural seam, switch to the complementary tool,
register a carefully scoped assumption, or leave the unit at a lower verification class.
Weakening the security property until the tool turns green is not on the list.
