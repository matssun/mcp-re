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

What that runner must provide — the repository it is registered to, and the job PATH the
service hands its steps — is
[`docs/dev/verification-runner.md`](../docs/dev/verification-runner.md). Both lanes start
with `scripts/verification_runner_preflight.sh`, so a rebuilt host reports the missing
prerequisite instead of failing later inside Verus or a TOML parse.

### Extraction identity is a tuple, not a pair

An earlier draft of this file said the identity was *(tool commit, image digest)*. That is
directionally right and too narrow. Charon and Aeneas are version-coupled — Aeneas
maintains a Charon pin and expects the compatible revision — and the Lean backend needs
its matching Lean toolchain and Aeneas Lean package. The identity of an extraction is:

```text
ExtractionIdentity =
      repository source digest
    + relevant Cargo features / configuration
    + Rust toolchain
    + Charon commit
    + Charon preset / options
    + Aeneas commit
    + extraction-container digest
    + Lean toolchain
    + Aeneas Lean backend / package revision
    + verification schema + formal-model revision
```

The strongest arrangement, and the one to build toward: the container *contains* exactly
the pinned Rust, Charon, Aeneas, Lean and Aeneas Lean libraries, and CI additionally
checks that the tools inside the image report the identities `toolchains.lock.toml`
expects. That gives two independent checks —

```text
expected identity in repository  ==  actual identity inside pinned image
```

— rather than trusting the image tag to mean what it meant last week.

### Reproducibility and CI trust are different concerns

Two things the container is easy to conflate:

- **Formal-environment reproducibility** = source + config + exact toolchains + container
  digest. The container solves this. Ubuntu upgrades on the runner cannot silently change
  extraction or proof semantics.
- **CI trust boundary** = the runner infrastructure capable of executing that container. A
  container does not make a compromised host trustworthy; a hostile runner can falsify
  outputs before GitHub ever sees them.

The operating assumption, recorded so it is a deliberate decision rather than an
Actions default inherited by accident:

> The self-hosted formal-verification runner is trusted CI infrastructure. Untrusted
> contributions do not acquire merge authority by executing there: the repository owner is
> the sole merge authority and performs security review before accepting external changes.
> Untrusted code is untrusted wherever it runs — hosted execution changes the containment
> boundary and blast radius, not the nature of the code.

Containment hygiene follows from that rather than from fear: no secrets the job does not
need, no repository write credentials in the verification job, container pinned by digest,
unprivileged, no Docker socket inside the job, clean workspace, controlled cache reuse.

### Two further consequences

1. **A lane that cannot run is not a lane that passed.** The Lean lane is absent locally,
   so it reports `NOT_REQUIRED` while no V2 unit is declared and `UNAVAILABLE` once one
   is. Both keep the aggregate below PASS. The split must never become a way for Lean
   evidence to be assumed because the machine that could check it was elsewhere.
2. **Local Verus is still not authoritative on its own.** `cargo verus focus` skips
   dependency re-verification and stores partial artifacts; full `cargo verus verify` runs
   before commit and in the gate. The lane split changes where tools run, not what counts
   as evidence.

### Three meanings of "authoritative"

Worth separating, because they are routinely conflated:

| Claim | Requires |
|---|---|
| local iteration | `cargo verus focus` — convenience only, never evidence |
| authoritative **Verus evidence** | full `cargo verus verify` under the pinned environment — may run locally or in CI |
| authoritative **repository verdict** | every required lane for the manifest fingerprint has completed |

So a Mac reporting *full Verus PASS, Lean unavailable* has produced valid Verus evidence
and an `INCOMPLETE` repository verdict. There is nothing contradictory about that, and the
docs should not let anyone read the first as the second.

### The verdict algebra

Five lane verdicts, because three collapsed two pairs of genuinely different situations:

```text
NOT_REQUIRED   the manifest asks nothing of this lane          legitimate
PASS           executed and satisfied
FAIL           executed and not satisfied
UNAVAILABLE    required, but could not execute
SKIPPED        required, could have run, deliberately did not
```

Aggregated:

```text
every required formal lane PASSed            -> PASS
any required lane FAILed                     -> FAIL
any required formal lane absent/unavailable  -> INCOMPLETE
no formal lane required at all               -> INCOMPLETE
```

The last line matters most. Lanes are **formal** (Verus, Lean, generated-model — they
produce evidence) or **hygiene** (manifest validation, the assumption/TCB gate — they are
preconditions for trusting evidence). A hygiene lane can withhold a pass by failing, but
its passing proves nothing about the code, so it can never carry the aggregate. A
repository with green hygiene gates and no proofs is `INCOMPLETE`.

The algebra is `_manifest.aggregate_verdict`, and `test_verdict_algebra.py` pins it —
including the two directions of `NOT_REQUIRED`, which is the subtle one: it must not hold
a V1-only scope back, and it must not itself count as evidence.

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
12. **Verification granularity is trusted-computing-base design. Evaluate the proved unit
    together with its actual proof dependency cone and every external/trusted item it
    reaches. Crate membership alone does not establish TCB size.** This rule replaces an
    earlier one that measurement falsified — that a small proof inside a large crate leaves
    a large surface external and therefore trusted, so unit and crate had to be chosen
    together. Unannotated items are external *and irrelevant*: they enter no theorem's
    cone. What to count is the trusted frontier — the nodes in the cone where proving stops
    and assuming begins. `http_profile.admission_currency` proves a property of the §7
    admission decision with a frontier of four registered items, inside a 14 800-line
    crate, and the JWS verifier it calls is not one of them.
13. **Model consequence separately from topology, and check what actually reads each
    field.** A monotonic security consequence — what an exchange must still admit has
    happened — is not the same object as the operational state that produced it. Forcing
    coexisting facts into one mutually-exclusive enum does one of two harmful things: it
    manufactures illegal *backward* transitions, or it silently discards information. The
    instance: `ContinuationState` carried both "this exchange spent an approval" and "this
    exchange opened a new leg", which coexist on any multi-round-trip conversation. Only
    the first was ever read, and the second made a backward consequence transition look
    legal. A security-state field or variant must have an identified authoritative
    consumer: if no production decision, invariant, evidence record, or external contract
    depends on it, determine whether it represents real state or merely an unowned claim.
    (Diagnostic-only data is legitimate — the test is ownership, not readership.) A
    monotonicity property stated over the whole reachable space is what surfaces both
    faults, and neither is visible to a happy-path test.

14. **A negative control must create an observable distinction between correct and broken
    implementations.** A fixture in which both produce the same observable state is vacuous
    evidence *even when the target code executes* — coverage reports the line, and the line
    decides nothing. Two ways this fails, both encountered here:

    *The mutation never reaches the defect.* A first attempt to simulate "the replay nonce
    is burned before the continuation binding check" routed through a path that refused the
    binding **before** the burn, so nothing was burned and the test passed — which would
    have been recorded as "the test does not detect this." Prove the mutation violates the
    invariant, and require the test to fail on ITS OWN assertion, not on a panic in the
    scaffolding.

    *The fixture makes the invariant mathematically irrelevant.* The delegated signature
    window is `min(now + sig_ttl, credential.exp)`. With a harness where the response TTL
    and the credential's remaining life are both 300, `min(300, 300)` and an unclamped
    `300` are indistinguishable — the clamp executes and decides nothing. The fixture must
    separate them (`sig_ttl = 300`, credential remaining `= 40`, expected `now + 40`) before
    it can discriminate.
15. **Assert the protected property, not the outcome.** Identical outward results can sit
    over opposite security states. The instance: a retention outage returns HTTP 503 whether
    or not the backend already ran — good implementation, 503 with zero backend
    invocations; broken implementation, 503 with one. Only the invocation count witnesses
    that the execution threshold was not crossed, so a status-code assertion would have
    passed against the defect it was written to catch.
16. **Moving code that carries formal annotations moves its verification ownership with
    it. A file split is incomplete until the new path belongs to every verification
    unit, fingerprint, and trigger set whose proposition depends on it.** This is the
    formal-verification analogue of moving a Rust function without moving its tests, and
    ordinary Rust tooling cannot see the omission: the code compiles, the tests pass, and
    `cargo clippy` is clean, because the loss is in what the manifest *declares*, not in
    what the compiler *checks*. Splitting `ArtifactBinding` out of
    `mcp-re-http-profile/src/block.rs` into `block/artifact_binding.rs` produced both
    halves of the failure at once — `check-assumptions` found a Verus annotation in a file
    no unit declared, and `verify-verus` found the new module missing the `vstd` prelude
    the old one had. A path list in `verification/policy/verification.toml` is part of the
    proposition; a refactor that leaves it stale narrows the proved unit silently.

## Running it

```sh
tools/verification/evidence --gate     # the whole pipeline: verify -> attest -> graph -> frontier

tools/verification/verify              # report-only, the whole platform
tools/verification/verify --gate       # authoritative: a failing lane fails the build
tools/verification/verify --manifests  # validate policy files only
tools/verification/check-assumptions   # the proof escape-hatch gate
tools/verification/fingerprint         # deterministic ReviewFingerprint per unit
tools/verification/attest              # issue freshness records from measured evidence
tools/verification/evidence-graph      # declared units and typed edges
tools/verification/review-frontier     # minimum review obligation (Phase 4)
```

Report-only is the Phase 1 posture on purpose: a verification lane that can fail the build
before it has ever produced a proof is a lane that gets disabled. CI flips `--gate` when
the pilots land.

### The pipeline, and why its phases are separate programs

```text
1. VERIFY     lanes run; each declares its own verdict
                  ↓  machine evidence record, bound to the fingerprint MEASURED AT
2. AGGREGATE  PASS / FAIL / INCOMPLETE — only PASS may produce freshness
                  ↓
3. ATTEST     the issuer RECORDS what phases 1-2 established. It measures nothing.
                  ↓
4. GRAPH      freshness recomputed from attestations + declared dependencies
                  ↓
5. FRONTIER   minimum candidate review closure (advisory during Phase 5)
```

`attest` is a consumer of evidence and must never become a verifier (ADR-MCPRE-059
Rule 22). It runs no prover and reads no source; it reads the records the lanes wrote, each
carrying the fingerprint it was measured at, and refuses on three grounds: no evidence,
evidence measured at a different fingerprint, or a required prerequisite that failed. The
implementation it exists to make unreachable is *"a lane printed PASS earlier, so stamp
whatever the tree contains now"*.

It is **not** part of `scripts/local_gate.sh`, and should not be folded into it. The local
gate asks whether this working tree satisfies its build and test gates. The pipeline asks
whether, given successful evidence over these exact inputs, a freshness record may be
issued. Only the second may write to the attestation store.

Issuance is idempotent: no timestamps, no run ids, no counters. Attesting three times
writes the same bytes three times, because "attested more recently" must never be able to
mean "fresher" — freshness is fingerprints, not clocks.

## Related

- `baseline/phase0-assurance-baseline.md` — what security assurance cost before this
  existed, and the two named pilot candidates.
- ADR-MCPS-048 — generated-first build graph; verification Bazel metadata is generated
  from the manifest rather than hand-maintained across the tree.
- ADR-MCPRE-057 / ADR-MCPRE-058 — the refactor that created the seams being verified.
