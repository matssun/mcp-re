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

Empty, and deliberately incomplete.

`lakefile.toml` and `lean-toolchain` are **absent**, not empty. They are toolchain pins,
and a placeholder pin is worse than a missing one: an empty `lean-toolchain` reads as
"pinned" to a tool that will then resolve whatever it finds. Their absence makes
`tools/verification/verify-lean` refuse to run, which is the correct behaviour while no
Lean toolchain is pinned. They are created by the toolchain-installation work, together
with the `[lean]` and `[aeneas_lean_backend]` entries in
`../policy/toolchains.lock.toml`.

## Pilot candidate

`mcp-re-http-profile/src/keyid.rs` — 75 lines, pure, safe, sequential, no interior
mutability. The theorem is that `canonical_ed25519_jwk` is injective: two distinct
base64url key encodings never produce the same JWK byte string.

That theorem needs no cryptographic model at all, which is what makes it a good first
pilot. SHA-256 collision resistance stays outside the proof as a registered assumption
with a named external model. Proving what is provable and declaring what is assumed — with
the boundary visible — is the demonstration Phase 3 exists to produce.

Rationale and alternates: `../baseline/phase0-assurance-baseline.md` §6.2.

## Scope discipline

The first pilot stays inside the subset Aeneas documents as supported *at the time of
implementation*, not the subset assumed when the ADR was written. Unsafe code and
concurrency are on the tool's own limitations list. The proxy, async serving, and the
PKCS#11 FFI are explicitly not first-pilot targets — and `mcp-re-core/src/replay.rs` was
considered and set aside because `InMemoryReplayCache` holds a `Mutex`.
