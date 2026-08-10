<!-- SPDX-License-Identifier: Apache-2.0 -->

# `verification/` — formal verification and the security evidence graph

Implements ADR-MCPRE-059. This tree holds the policy, model, and proofs; the executable
wrappers live in [`tools/verification/`](../tools/verification/).

Nothing here changes production behaviour. Verus specification and proof code is ghost
code that does not execute in the shipped binary, and the Aeneas/Lean path is entirely off
the runtime. That is an intention, not a measurement — ADR-MCPRE-059 §17 requires the
first pilot to *measure* dependency closure, binary size, and hot-path effect rather than
assert them.

## Why this exists

MCP-RE's Security Review Funnel is expensive and adversarial, and it should stay that way.
The problem is not that it thinks too much; it is that a diff-oriented invocation has only
a weak representation of what previous security evidence survives a change.

> A security review unit is fresh only while the exact evidence, assumptions, contracts,
> configuration, and toolchain on which its prior security conclusion depended remain
> valid.

An incremental compiler for security evidence. A formally verified, unchanged contract is
what lets source-level dirtiness stop propagating at a producer instead of sweeping
through its consumers.

Formal proof is not complete security. A prover establishes that an implementation
satisfies property `P`; it cannot notice that the architect should also have specified `Q`.
Missing properties, confused-deputy risks, API ambiguity, deployment mistakes, resource
exhaustion, and model-versus-protocol divergence are exactly why the funnel remains
necessary and remains authoritative.

## Layout

```
baseline/    the Phase 0 assurance baseline, captured before any tool was installed
policy/      authoritative manifests: units, assumptions, trust boundaries, toolchain pins
model/       the canonical security vocabulary and the candidate long-lived theorems
verus/       Rust-coupled proofs
lean/        extracted-model proofs via Charon → Aeneas → Lean
```

## Current status

Phase 0 complete, Phase 1 structural. No toolchain is pinned, so no proof exists, so no
unit is above V0.

```console
$ tools/verification/verify
[manifests]       PASS
[assumptions]     PASS      0 registered, 0 escape hatches
[generated-model] SKIPPED   nothing to drift
[verus]           SKIPPED   toolchain unpinned
[lean]            SKIPPED   pipeline unpinned
VERIFICATION: INCOMPLETE — no lane produced formal evidence. This is not a pass.
```

`INCOMPLETE` rather than `PASS` is deliberate. A skipped lane never counts toward a pass
— this repository has already been bitten once by a lane that exited 0 having selected
zero tests.

**Next:** pin the toolchains (`policy/toolchains.lock.toml`, every entry currently
`state = "unresolved"`). Every lane refuses while its tools are unpinned rather than
running against whatever is on `PATH`, because a proof checked by a prover of unknown
identity is not evidence.

## Two lanes, because the toolchains do not live in the same place

The platform is one manifest and one verdict, but two execution lanes:

| Lane | Tools | Where | Feedback |
|---|---|---|---|
| **local** | Verus, vstd, Z3 | this machine, pinned in `policy/toolchains.lock.toml` | immediate — edit, `verify-verus`, repeat |
| **CI** | Charon, Aeneas, Lean, the Aeneas Lean backend | self-hosted Actions runner, inside the pinned container | per push |

This is a real constraint, not a staging preference: Charon does not build here without
Nix, and installing Nix on this machine is out of scope. So the extracted-model pipeline
runs only on the runner.

Three consequences worth stating, because each is a way to get a false green:

1. **The container digest is a pin.** What identifies an extraction is the pair *(tool
   commit, image digest)*, not the commit alone. Two runners on the same Aeneas commit
   and different images are two different extractions, and the evidence engine must be
   able to tell them apart.
2. **A lane that cannot run is not a lane that passed.** The Lean lane is absent locally,
   so `verify` reports it `SKIPPED` and the umbrella reports `INCOMPLETE`. A local run is
   never evidence about V2 units, and the split must not become a way for Lean evidence to
   be quietly assumed because the machine that could check it was elsewhere.
3. **Local Verus is still not authoritative on its own.** `cargo verus focus` is a
   productivity tool; the merge gate runs full verification. The lane split changes where
   tools run, not what counts as evidence.

## Verification classes

| Class | Meaning | Evidence |
|---|---|---|
| `V0` | ordinary code | tests, conformance, Security Review Funnel |
| `V1` | executable security boundary | Verus proof, plus the above |
| `V2` | semantic/algorithmic security core | Aeneas/Lean theorem, plus the above |
| `V3` | exceptional high-assurance boundary | deliberately complementary independent evidence |

Most code should stay V0. `V0` is a valid assurance class, not a backlog item, and
"percentage formally verified" is explicitly not a project target. `V3` requires stating
which *different* failure classes the two approaches close — "two provers are better than
one" is not a reason.

## The rules that matter most

1. **Unknown is dirty.** Missing input, unparsable metadata, an unrecognized edge, an
   absent proof artifact, or a cache of unestablished provenance is never freshness.
2. **A proof result is inseparable from the proposition and assumptions it proved.**
   Green is not a verdict on its own.
3. **Changing a specification is at least as sensitive as changing its implementation.**
   Weakening a postcondition needs the review that weakening the code would need.
4. **No LLM decides that LLM review is unnecessary.** Agents may propose specifications,
   write proofs, and challenge a result. Invalidation is deterministic tooling over
   explicit inputs, and an agent must never edit an attestation or baseline to make a gate
   pass.
5. **`cargo verus focus` is never authoritative CI evidence.**
6. **Generated Lean is never hand-edited evidence.**
7. **No unregistered `assume`/axiom/external-body shortcut may merge.**
8. **A sealed contract edge must be declared before it can stop invalidation** — never
   inferred afterwards from the observation that a consumer "probably only depended on the
   contract".
9. **Tests are evidence; weakening evidence is not a clean change.** Deleting a security
   test must never make its claim look fresher.
10. **Do not formalize unstable thousand-line legacy functions.** Formalize the stable
    seams the ADR-MCPRE-057/058 refactor created.
11. **Verification-boundary extraction must pass an architecture-without-the-verifier
    test.** A production boundary may be introduced to enable formal verification only
    when it is independently justified by ownership, authority, state, purity, reuse, or
    testability. If the boundary would not be wanted with the verifier gone, choose a
    different verification target rather than distort production architecture. This is
    ADR-MCPRE-059 §18 made operational, and the first pilot is already testing it.
12. **Verification granularity is part of trusted-computing-base design.** A formally
    attractive unit sitting inside a huge verification crate is not thereby a good
    verification unit. Proving a small relation while marking a large surface external
    produces a green verifier over an inflated TCB, and the green means less than it
    appears to. Choose the unit and the crate together.

## Running it

```sh
tools/verification/verify              # report-only, the whole platform
tools/verification/verify --gate       # authoritative: a failing lane fails the build
tools/verification/verify --manifests  # validate policy files only
tools/verification/check-assumptions   # the proof escape-hatch gate
tools/verification/fingerprint         # deterministic ReviewFingerprint per unit
tools/verification/evidence-graph      # declared units and typed edges
tools/verification/review-frontier     # minimum review obligation (Phase 4)
```

Report-only is the Phase 1 posture on purpose: a verification lane that can fail the build
before it has ever produced a proof is a lane that gets disabled. CI flips `--gate` when
the pilots land.

## Related

- `baseline/phase0-assurance-baseline.md` — what security assurance cost before this
  existed, and the two named pilot candidates.
- ADR-MCPS-048 — generated-first build graph; verification Bazel metadata is generated
  from the manifest rather than hand-maintained across the tree.
- ADR-MCPRE-057 / ADR-MCPRE-058 — the refactor that created the seams being verified.
