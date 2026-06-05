<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-018: CI Reproducibility Posture and Conformance-Manifest Authority

## Status

Proposed

## Context

PRD (stories 1–3) requires MCP-S to move from local-green to CI-green with proven fresh-clone reproducibility. Findings from the codebase: no `bazel test //components/mcps/...` job exists in CI; the mcps build references no submodule (the granian decoupling holds at the build level); crates are fetched from crates.io at build time (pinned by `Cargo.lock`, not vendored), so builds are network-dependent, not hermetic. The published "9 targets / 21 vectors" prose is already stale (now ~17 targets plus Phase 5/6 vectors). ADR-MCPS-011 established conformance-as-specification and ADR-MCPS-012 the isolated rules_rust workspace; this decision sets the CI and reproducibility posture on top of them.

## Decision

MCP-S CI is a path-filtered job (triggered on `components/mcps` and its build inputs, not the global gate) plus a scheduled cold-clone job that intentionally skips submodule init and runs with no warm cache; the reproducibility claim is *"cold-clone, no-submodule, lockfile-reproducible with network access to crates.io"* (explicitly not offline-hermetic), and a committed, drift-guarded conformance manifest — not prose — is the authoritative source for the target and vector lists.

## Rationale

Path-filtering avoids taxing unrelated PRs with the Rust + rustls build while still gating every relevant change. The cold-clone-no-submodule job proves both fresh-clone reproducibility and the granian decoupling in one shot. Crates are not vendored, so honesty requires claiming network-dependent reproducibility rather than hermeticity; offline / air-gapped builds are a separate supply-chain decision. A drift-guarded manifest prevents documented coverage from rotting again (as the 9/21 prose did) by failing CI on any mismatch between the manifest and the actual fixtures/targets.

## Alternatives Considered

- **Put mcps tests in the global pr-gate** — rejected: punishes unrelated Python/doc PRs with Rust builds.
- **Claim offline-hermetic reproducibility** — rejected: crates are fetched from the network; the claim would be false without vendoring/mirroring.
- **Vendor/mirror crates now for hermeticity** — rejected: a supply-chain hardening sub-project; deferred until air-gapped deployment is actually required.
- **Keep prose target/vector counts** — rejected: already rotted; drift is invisible without a guard.

## Consequences

### Positive
- Continuous, relevant-PR conformance gating; provable fresh-clone reproducibility; verified granian decoupling.
- Documented coverage cannot silently drift.

### Negative
- Builds require network access to crates.io; no air-gapped guarantee until a future vendoring decision.
- A scheduled cold-clone job consumes CI minutes (nightly/weekly plus pre-release dispatch).

### Neutral
- The manifest must be updated alongside any target/vector change, enforced by the guard test.

## Compliance and Enforcement

The path-filtered CI job and the scheduled cold-clone job live in `.github/workflows`. The drift-guard test fails on any manifest/fixture/target mismatch. The pre-release reproducibility dispatch is recorded. Documentation references the manifest and never hardcodes counts.

## Related

- PRD: (author's private monorepo)
- Prior ADRs: ADR-MCPS-011 (conformance-as-specification), ADR-MCPS-012 (build integration / isolated workspace)
- Follow-up: offline-hermetic / vendored builds (future supply-chain issue)
