# CI Runner Migration Analysis — GitHub-Hosted vs Self-Hosted

**Date:** 2026-09-28  
**Conclusion:** No migration required; ci.yml already on GitHub-hosted runners; four specialist workflows have documented architectural blockers.

## Executive Summary

Standard CI (`ci.yml`) is already fully deployed on GitHub-hosted runners (`ubuntu-latest`). The four remaining self-hosted workflows have non-negotiable specialist requirements rooted in ADR-MCPRE-059 and CLAUDE.md that prevent migration to ephemeral GitHub-hosted infrastructure.

## Current State

### GitHub-Hosted (Already Deployed)

**`ci.yml` — 6 jobs, all on `ubuntu-latest`**
- `cargo`: 30+ structural gates; it builds nothing (the id is what the ruleset requires)
- `rfc9421-cross-verify`: Third-party RFC 9421 cross-verification
- `release-gates`: Feature-gated backend tests (Bazel, async_serve, redis, PKCS#11)
- `bazel`: Semantic-drift gate + test parity
- `sdk-python`: Maturin wheel + clean-env install
- `sdk-typescript`: NAPI package + clean-dir install

All portable work already runs on GitHub-hosted infrastructure. No action needed.

### Self-Hosted (Must Remain)

All four retain `[self-hosted, macOS, ARM64]` with documented architectural reasons:

| Workflow | Job | Reason | Key Constraint |
|---|---|---|---|
| `extraction-image.yml` | `build` | Preserves non-reproducible artifact | `/opt/verification/extraction-artifacts/` (5.6 GiB, cannot rebuild) |
| `verification.yml` | `verification` | **Required status check**; depends on artifact; unified "one ordered job" | Artifact dependency + Verus native + single evidence directory |
| `slo.yml` | `lane` | Performance measurement; exclusive host required | `/opt/verification/slo/` + `/opt/verification/runner-arbiter/` + noisy-box refusal |
| `release-assurance.yml` | `release-assurance` | Manual; couples to slo.yml evidence | `/opt/verification/slo/` (shared store) |

## Why Migration Is Not Possible

### 1. Non-Reproducible Extraction Artifact

**Source:** `verification/policy/toolchains.lock.toml`, `verification/reviews/rulings/extraction-artifact-storage-2026-09-09.md`

The extraction image (`linux/arm64`) is built from a Dockerfile with unpinned inputs:
- `FROM debian:bookworm-slim` (mutable tag)
- `apt-get install …` (12 unpinned packages)
- `opam install …` (~15 unpinned libraries, build Aeneas binary)

**Consequence:** The same pins produce a **different image on different build dates**. Rebuilding after a `docker image prune` yields different bytes.

**Storage Model:**
- Image is preserved at: `/opt/verification/extraction-artifacts/sha256/<artifact_digest>.tar`
- ADR-MCPRE-059 §19 & the ruling reject registry storage (GHCR) and require local preservation
- The ruling explicitly states this is not a distribution problem, it is a durability problem

**For GitHub-hosted runners:**
- Ephemeral runners have no persistent `/opt` directory
- Artifact cannot be reliably rebuilt to same bytes
- Moving to GitHub-hosted makes evidence irreproducible

### 2. Verification Job Depends on Artifact

**Source:** `.github/workflows/verification.yml`, `tools/verification/verify`

The `verification` job:
- Loads the preserved extraction artifact with `tools/verification/extraction-image load`
- Runs Verus natively on macOS ARM64 (binary for `arm64-macos` only)
- Executes extraction lanes inside the preserved container
- **Is a required status check** for the `Protect main` ruleset

**Architecture:** Single unified job with shared evidence directory. Cannot be split into "hosted host phase + self-hosted extraction phase" without redesigning the test architecture and creating new evidence gaps.

### 3. SLO Measurement Requires Exclusive Host

**Source:** `.github/workflows/slo.yml`, `CLAUDE.md` ("Measure on a quiet box"), `tools/slo/host_gate.py`

The SLO lane:
- Measures proxy throughput under controlled conditions
- Requires **host-level exclusive reservation** (dev1 enforces this via pre-job admission hooks)
- Refuses to measure if box load exceeds threshold (see `scripts/local_slo_lane.sh`, `ALLOW_NOISY_BOX` explicitly forbidden)
- Stores evidence at `/opt/verification/slo` (persistent across runs)
- Uses persistent host arbiter at `/opt/verification/runner-arbiter` to coordinate with other runners on the physical host

**For GitHub-hosted runners:**
- Ephemeral, shared across many repositories
- No host-level exclusive reservation mechanism
- Load is uncontrollable and declared as unmeasurable
- No persistent `/opt` directories
- Measurement would violate CLAUDE.md § "Measure on a quiet box"

### 4. Release Assurance Couples to SLO Store

**Source:** `.github/workflows/release-assurance.yml`, `tools/verification/release-assurance`

Release assurance:
- Runs `tools/verification/release-assurance --decide`, which reads from `/opt/verification/slo`
- Fails closed if the evidence store is empty or unresolved
- Is a manual workflow that composes evidence from a verification run

Moving would require either:
- Transporting SLO evidence (new artifact architecture, out of scope)
- Running without freshness checks (violates release semantics)

## What GitHub-Hosted Cannot Provide

GitHub-hosted runners lack:
1. **Persistent local storage outside GITHUB_WORKSPACE** — The extraction artifact, SLO evidence store, and host arbiter all require `/opt` persistence
2. **Host-level exclusive reservation** — Multiple tenants, uncontrollable load
3. **Native Verus binary** — Only available on `arm64-macos`; GitHub-hosted `macos-15` exists but also lacks persistent `/opt`
4. **Unified evidence directory across host+container phases** — GitHub-hosted job-level `container:` is Linux-only; macOS needs explicit Docker invocation

## Measurement Notes

No timing measurements are needed because **no jobs are being migrated**. The ci.yml jobs already run on GitHub-hosted and are performant. The four specialist workflows have architectural constraints that are independent of performance.

## Future Considerations

If GitHub (or another platform) ever offers:
- Persistent `/opt` directories on macOS ARM64 runners
- Host-level exclusive reservation mechanism for performance measurement
- Multi-machine test orchestration with shared state directories

Then `extraction-image.yml` and `slo.yml` could be reconsidered. `verification.yml` would still require the artifact preservation invariant to hold.

---

**Status:** ✅ Analysis complete. No changes required. Current distribution of portable → GitHub-hosted and specialist → self-hosted is correct by design.
