<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-048: Generated-First Build Graph — Cargo Manifests Are the Source of Truth, Bazel BUILD Files Are Generated and CI Staleness-Gated

## Status

Accepted (targets v0.9 build-infra; mechanical, no product-logic change).

Relates to and supersedes the *practice* critiqued in issue #220 (Bazel/cargo
parity rot). Does not remove Bazel. Builds on ADR-MCPS-011 (workspace structure,
conformance-as-specification) and ADR-MCPS-018 (CI reproducibility posture).

## Context

MCP-S ships **two build systems** for its Rust code: Cargo (`Cargo.toml` per
crate) and Bazel (`BUILD.bazel` per crate, Bzlmod / `MODULE.bazel`). It is also
now **polyglot**: a Rust core plus a Python SDK (`sdk/python`, maturin/PyO3) and a
TypeScript SDK (`sdk/typescript`, napi-rs). The README already states the operating
reality: *"Cargo is the public-facing default; Bazel is the hermetic build path the
maintainer uses internally."*

Issue #220 recorded the failure mode: Bazel accumulated dependency rot — a core
binary did not build under Bazel on a merged-PR tip (`unresolved crate mcps_core`),
cascading to ~25 fail-to-build targets. Cargo, meanwhile, is fully green (the
authoritative CI gate). This is **not** bad luck; it is structural. The root cause,
diagnosed precisely:

Dependency truth lives on **three** surfaces, of which only one is still
hand-maintained:

| Surface | Truth today | Drifts? |
|---|---|---|
| **Versions** | Central already: root `[workspace.dependencies]` (31 deps) inherited by 15 crates via `foo = { workspace = true }` | No — one place |
| **Third-party Bazel deps** | Generated already: `crate_universe` `crate.from_cargo(name = "crates_mcps")` reads `Cargo.toml`/`Cargo.lock` → `@crates_mcps//:<crate>` | No — derived |
| **First-party BUILD targets + edges** | **Hand-written**: each crate's `rust_library`/`rust_binary`/`rust_test` and its `deps = ["//mcps-core", …]` | **Yes — this is #220** |

Two of the three surfaces are already centralized/generated the way the maintainer's
enterprise monorepo does it. The remaining hand-maintained surface — first-party
BUILD targets and their first-party dependency edges — is the entire drift class:
when a `.rs` file grows a new `use mcps_core::…`, the Cargo build just works while
the Bazel target silently breaks, because nothing regenerates the BUILD edge and
nothing gates it.

The maintainer will **not** drop Bazel: it is the enterprise/hermetic build path
(remote cache, one graph across languages) and is the house convention
(`CLAUDE.md`: "Bazel + central config; no hand-maintained parallel truth"). At the
same time, MCP-S is an open specification whose value is adoption: downloaders are
Rust (`cargo add`), Python (`pip install`), and Node (`npm install`) developers who
must never be required to install Bazel.

A decision is needed now because the rot recurs on **every** feature branch that
touches Rust deps (it recurred while implementing the v0.9 hardening epic, blocking
the security-traceability-manifest registration of MCPS-56).

## Decision

**Cargo/`pyproject.toml`/`package.json` manifests are the sole human-authored
source of dependency truth; all Bazel first-party BUILD files are generated
(`gazelle_rust` for first-party targets/edges, `crate_universe` for third-party) and
a CI staleness gate fails the build if any committed BUILD file diverges from what
the generator produces; Bazel remains the internal enterprise/hermetic path and the
ecosystem-native artifacts (`cargo`/`pip`/`npm`) are the supported, CI-verified
path for downloaders who skip Bazel.**

## Rationale

This adapts the maintainer's enterprise "central-config, no hand-edited build files"
default (`CLAUDE.md`) to a Rust-first polyglot public repository, rather than
overriding it. Two of the three dependency surfaces are already generated/central
here; the decision closes the third with the same principle instead of continuing to
hand-maintain a second copy of a fact Cargo already owns.

- **Generation removes the drift class.** `gazelle_rust` derives first-party targets
  and `deps` from the actual `use` graph, exactly as `crate_universe` already derives
  third-party deps from `Cargo.lock`. Cargo manifests stay the one authored surface.
- **A CI staleness gate is load-bearing, not optional.** #220 happened because Bazel
  is not gated. Generation alone rots identically unless CI fails on stale BUILD
  files (`bazel run //:gazelle -- --mode=diff` / a gazelle diff test). Generate **and**
  gate.
- **The enterprise/downloader split is honest and mostly already true.** maturin and
  napi-rs already build the Python/TS bridges via Cargo without Bazel; downloaders
  already consume `cargo`/`pip`/`npm`. Making those artifacts CI-verified makes
  "skip Bazel" a first-class supported path rather than a rotting side-artifact.
- **Keeping Bazel is a first-class goal**, satisfied: Bazel stays the hermetic,
  remote-cacheable, cross-language graph — it simply stops being a hand-maintained
  parallel truth.

## Alternatives Considered

- **Status quo — keep hand-maintaining BUILD files.** Rejected: this *is* #220; the
  rot recurs every feature branch and has already blocked security-evidence work.
- **Drop Bazel from the shipped repo.** Rejected by constraint: Bazel is the
  enterprise/hermetic path and the house convention. (For a pure-Rust library Cargo
  alone would suffice, but that is not the maintainer's target.)
- **Bazel-first, mandatory for everyone (including downloaders).** Rejected: an
  adoption killer for an open specification; contradicts "downloaders can skip
  Bazel." "Authoritative *and* skippable" is self-contradictory unless BUILD files
  are generated from the manifests downloaders already use.
- **Port the monorepo's bespoke central-config TOML (`dependencies-dev.toml`) here.**
  Rejected as unnecessary: Cargo's `[workspace.dependencies]` is the ecosystem-native
  equivalent and is already in place, and it keeps `cargo`/`pip`/`npm` working
  directly for downloaders. Inventing a bespoke central file would re-introduce a
  non-native source of truth.

## Consequences

### Positive
- The #220 drift class is eliminated at the source; `bazel test //...` regains parity
  with the green Cargo suite and stays there.
- Contributors stop hand-editing BUILD files; a new `use` is picked up by
  `bazel run //:gazelle`.
- Security-evidence artifacts (e.g. the traceability manifest) can once again be
  wired to green Bazel targets, because Bazel stops rotting.
- Downloaders get a clean, verified `cargo`/`pip`/`npm` path; enterprise keeps the
  hermetic Bazel graph.

### Negative
- `gazelle_rust` is less battle-tested than gazelle-for-Go; feature-gated deps
  (`#[cfg(feature = "gcp_kms_keysource")]`, `aws_kms_keysource`, `online_ocsp`),
  proc-macros, and build scripts still need occasional gazelle directives/annotations.
  Realistically "~95% generated, a few annotated exceptions," not literally zero.
- One-time setup cost: wire `gazelle_rust`, annotate the feature-gated crates once,
  add the CI staleness gate, and mechanically fix the current #220 backlog first so
  the generator has a buildable baseline.
- A second, generated way to build the FFI SDKs under Bazel may coexist with
  maturin/napi; the published artifacts remain maturin/napi to match the ecosystem.

### Neutral
- Cargo `[dependencies]` are still authored by hand per crate — but that is the
  ecosystem-native manifest downloaders require, and it is the single source of
  truth, so it is not drift.
- No product/source/logic change; this is build-infra only.

## Compliance and Enforcement

- **CI staleness gate (the enforcement):** a required CI job (`bazel` job in
  `.github/workflows/ci.yml`) runs `python3 scripts/bazel_gazelle_gate.py`, which
  drives the generator in read-only diff mode and **fails on unmanaged semantic
  drift** — a target or `deps` edge the Cargo graph has but the committed BUILD
  omits. Per the Implementation notes above it gates the *semantic* managed set,
  not byte-identity, with a categorized allowlist (HITL/live-cloud, platform,
  naming collisions, and tracked known drift). This is what would have caught #220
  at PR time; on first run it caught five real missing-target drifts.
- **Bazel build/test parity job:** the same `bazel` job runs `bazel test //...`,
  which must pass (or each documented gap is explicitly tracked), matching the
  Cargo suite.
- **Downloader-artifact jobs (MCPS-71):** two required CI jobs (`sdk-python`,
  `sdk-typescript` in `.github/workflows/ci.yml`) build the ecosystem-native
  artifacts from the same source — the maturin wheel and the napi package — and
  **install each into a clean environment** (a fresh venv / an empty npm project;
  wheel/tarball only, never an editable install and never the source tree on the
  import path) before running the SDK suites. Neither job installs or invokes
  Bazel; the e2e suites that need the built Rust binaries self-skip cleanly, so the
  clean-env lane exercises the downloader's unit surface. Together with the pure
  `cargo` jobs (the third downloader path), this makes the README's "downloaders
  skip Bazel" claim CI-backed, not assumed.
- Until the gate lands, Cargo remains the authoritative gate (unchanged).

## Implementation notes (MCPS-68 / MCPS-69 — refines the gate design)

Wiring `gazelle_rust` (MCPS-68) and annotating the awkward crates (MCPS-69)
surfaced constraints that **revise the "byte-identical BUILD" gate above**. What
is proven and what must change:

- **Proven:** `gazelle_rust` in `generate_from_cargo` mode, with
  `map_kind rust_* → nt_rust_*`, generates one target per crate root and resolves
  first-party (`//mcps-*`) + third-party (`@crates_mcps//:`) `use`-edges through
  the house macros. It also catches genuine drift (it found `draft02_vectors_test`,
  a cargo test with no Bazel target → MCPS-76).
- **Feature-flavor selection is not inferable and is pinned by hand.** Several
  crates publish >1 target with the same `crate_name` (`mcps_host` +
  `mcps_host_test_fixtures`; `mcps_proxy` + `_fault`/`_dev_env`/`_ext`;
  `mcps_transport` + `_fault`). A `use mcps_proxy::X` cannot say which flavor, so:
  root-BUILD `# gazelle:resolve` pins the DEFAULT (plain) target, and every
  consumer edge that needs a specific flavor carries a trailing **`# keep`**
  (gazelle preserves it). This is the documented pattern for adding a
  feature-gated/flavored dep: point at the flavor target and append `# keep`.
- **Byte-identity is NOT achievable; gate on SEMANTIC drift.** `generate_from_cargo`
  always adds `compile_data = ["Cargo.toml"]` + explicit `visibility` and sorts
  `deps` — none suppressible. So the staleness gate must compare the **managed
  set** (targets exist; `deps`/`srcs` edges match) and normalize/ignore
  formatting (visibility, compile_data-of-Cargo.toml, dep order), NOT require a
  byte-identical file. Write output is **not** auto-adopted wholesale.
- **Cargo-only / HITL test files can't be suppressed by directive.** In cargo
  mode gazelle enumerates tests from Cargo metadata, so `# gazelle:exclude <file>`
  does not stop it proposing targets for the HITL live-cloud KMS tests
  (`*_live_test.rs`, `#![cfg(feature="…kms…")]` + `#[ignore]`). These stay
  cargo-only; the gate must **allowlist** them as expected non-Bazel targets.
- **Platform-conditional + naming mismatch stay hand-authored.** A generated
  crate-level `mcps_proxy_test` pulls `seccompiler` (Linux-only `prctl`/`SECCOMP_*`)
  into the darwin build, and gazelle's `<crate>_test` naming collides with the
  repo's `proxy_unit_test`. These remain hand-authored; the gate allowlists them.

Net: gazelle is adopted as a **generator for ordinary `use`-edges + a drift
detector**, with a hand-annotated exception set (`# keep` + resolve + a gate
allowlist), rather than the sole byte-authority the Decision's first framing
implied. The ~95%/annotated-exceptions expectation in Consequences holds.

## Related

- Issue: #220 (Bazel/cargo parity rehabilitation — the mechanical baseline this ADR
  builds on).
- Prior ADRs: ADR-MCPS-011 (workspace structure, conformance-as-specification),
  ADR-MCPS-018 (CI reproducibility posture and manifest authority).
- Code/config: `MODULE.bazel` (`crate_universe` hub `crates_mcps`), root `Cargo.toml`
  (`[workspace.dependencies]`), `sdk/python` (maturin), `sdk/typescript` (napi-rs),
  `mcps-conformance/tests/security_traceability_guard_test.rs` (Bazel-target-wired
  evidence that depends on Bazel staying green).
