<!-- SPDX-License-Identifier: Apache-2.0 -->

# `verification/lean/` — extracted-model proofs

ADR-MCPRE-059 §8. The Aeneas + Lean 4 path carries properties where a separately
inspectable mathematical model is worth having: long-lived protocol theorems, inductive
reasoning, and semantic properties that should survive substantial implementation
refactors.

## The pipeline

```
Rust source  →  Charon  →  LLBC  →  Aeneas  →  generated Lean model
                                                       ↓
                                          handwritten MCP-RE theorems
```

Extraction is authoritative. A Lean model used to claim a proof *about Rust* is derived
from the Rust source through the pinned pipeline. A handwritten Lean model may exist for
the normative specification, but it is not proof of the implementation unless a checked
refinement relationship connects the two.

## Layout

```
generated/  machine-owned. Never hand-edited. Stale content fails CI.
models/     handwritten external models for definitions Aeneas cannot extract. TCB.
specs/      normative specifications, written from the security concept
theorems/   the proofs
tactics/    shared proof automation
```

`models/` is trusted computing base unless a separate argument connects a model to the
external implementation it stands for. Changing a file there is a security-sensitive
assumption change and needs a registered entry in `../policy/assumptions.toml`.

`generated/` is machine-owned in the strongest sense: a hand-edit that makes a proof pass
is not evidence, it is a forged artifact. Operational Rule 6.

## Status

The package is established: `lean-toolchain` pins the Lean the Aeneas backend declares,
`lakefile.toml` builds the generated model and the theorems as two libraries, and
`tools/verification/verify-lean` elaborates them and accounts for every axiom.

`lakefile.toml` requires the Aeneas Lean library by ABSOLUTE PATH, and resolves its
dependencies out of that package's own directory rather than fetching them again. Both are
consequences of where this lane runs: inside the image pinned as `[extraction_container]`
and nowhere else, because Charon links the private rustc crates and does not build on the
macOS host. A relative path or an environment lookup would make the package resolvable in
environments whose identity nothing records; a second mathlib checkout would be a mathlib
whose revision nothing pins, and a theorem proved with a different mathlib is a theorem
proved in a different environment.

## Pilot

`mcp-re-core/src/time/format.rs::civil_from_days`, and the proposition is TOTALITY:

> for every `i64` in the domain its caller can supply, the extracted model evaluates to
> `ok` — every intermediate `i64` operation is in range and both narrowing casts succeed.

That is what `format.rs` currently asserts **in prose**, under a
`#[allow(clippy::arithmetic_side_effects)]` whose justification is an argument about the
argument's provenance plus two `i64`-extreme unit tests. Turning that argument into a
machine-checked one is the pilot.

The proposition follows the tool rather than the other way round, and it is not the one
this file used to name. The 2026-08-30 measurement
(`../baseline/extraction-pilot-measurement-2026-08-30.md`) ran the pinned pipeline over
this module and found `civil_from_days` extracts **fully transparent** — every one of its
`i64` operations appears in the model, inside Aeneas' `Result` monad where each `←` may
fail — while `alloc.fmt.format` extracts as an **uninterpreted axiom**. So a formatter's
output is an arbitrary `String` in the model, and any claim quantified over the bytes it
produces would be a claim whose evidence establishes nothing about it.

The keyid injectivity theorem this section used to propose is exactly such a claim.
`canonical_ed25519_jwk` is a `format!`, so its result is that same uninterpreted `String`.
The claim itself is not wrong and it is not abandoned — it is measured, as
`http_profile.keyid`'s declared battery, by the lane that can actually reach it.

## Scope discipline

The first pilot stays inside the subset Aeneas documents as supported *at the time of
implementation*, not the subset assumed when the ADR was written. Unsafe code and
concurrency are on the tool's own limitations list. The proxy, async serving, and the
PKCS#11 FFI are explicitly not first-pilot targets — and `mcp-re-core/src/replay.rs` was
considered and set aside because `InMemoryReplayCache` holds a `Mutex`.
