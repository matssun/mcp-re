<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-012: Project Placement & Build Integration — components/mcps as an Isolated rules_rust Workspace

## Status

Accepted

## Context

Derived from PRD; refines ADR-MCPS-001 (clean-room firewall) and ADR-MCPS-011 (workspace & delivery). Decision A established that MCP-S is clean-room and firewalled from the monorepo trust model, but left the **physical location and build integration** open. Investigation of the repo shows it is already a first-class polyglot Bazel build: `rules_rust 0.68.1` + `rules_rust_prost` + `crate_universe`, a pinned Rust `1.94.1`/edition-2021 toolchain, a generated `rust-project.json` (rust-analyzer), and existing Rust under both `components/rust_components/` (`rsm`, `service-registry`) and `applications/door_access/`. `crate_universe` is configured per-subtree (independent hubs `crates` and `crates_rust_components`), and `MODULE.bazel`'s crate blocks plus `rust-project.json` are generated from `infrastructure/config/build/build-manifests.toml` `[rust]`. The repo's placement rule (`CLAUDE.md`) is reusable libraries → `components/`, specific products → `applications/`.

## Decision

MCP-S lives as a single self-contained Cargo workspace at **`components/mcps/`**, built with the monorepo's `rules_rust` toolchain via per-crate `BUILD.bazel` files and (once external dependencies exist) an **isolated `crates_mcps` `crate_universe` hub**; it depends on no other in-repo crate and no Python component, the canonical hermetic build/test is **`bazel test //components/mcps/...`**, and the Cargo manifests remain authoritative for rust-analyzer, local dev, and future standalone extraction to a public repository.

## Rationale

The monorepo already supports Rust first-class, so an external repo would forfeit hermetic Bazel builds, the pinned toolchain, CI, and rust-analyzer for no firewall benefit — the firewall is fully achievable in-tree. Because `crate_universe` hubs are per-subtree, an isolated `crates_mcps` hub shares zero crates by construction, and the language boundary makes Python-component coupling impossible; `mcps-core`'s purity rule becomes a checkable `deps = []` in its BUILD target. `components/` (not `applications/`) matches the reusable-library convention and the `rust_components` precedent, and keeping the whole thing in one workspace directory preserves clean single-unit extraction to a public repo per ADR-MCPS-010. A specific in-repo MCP service later protected by an MCP-S sidecar would be a thin consumer under `applications/` depending on the `mcps-proxy` crate (the generic wrapper is a component; a specific wrapped service is an application).

## Alternatives Considered

- **Separate external repository**: rejected — loses the monorepo toolchain for no firewall gain, and fragments CI.
- **Under `applications/mcps/`**: workable, but `applications/` is for specific products; MCP-S is a reusable, to-be-published library family.
- **Split `mcps-core` → `components/`, `mcps-proxy`/`mcps-host` → `applications/`**: rejected — fractures the Cargo workspace and breaks single-unit extraction (a Cargo workspace is one rooted tree).

## Consequences

### Positive
- Full monorepo tooling (hermetic Bazel, pinned toolchain, CI, rust-analyzer) with zero Python coupling; the firewall is enforced at the build graph.
- Clean extraction to a public repo remains possible (one contiguous workspace, Cargo manifests authoritative).

### Negative
- Two build entry points (Bazel canonical; Cargo for dev/extraction) must be kept in sync — `BUILD.bazel` files live alongside Cargo manifests (the `door_access` / `rust_components` pattern).
- ADR-MCPS-011's exit criterion changes from `cargo test -p mcps-core` to `bazel test //components/mcps/...`.

### Neutral
- rust-analyzer support is added via `build-manifests.toml [rust.projects]`; the `crates_mcps` hub is added via `[[rust.extra_crate_universes]]` + `/deps sync` when the first external dependency lands.

## Compliance and Enforcement

`mcps-core`'s BUILD target carries `deps = []` (no networking/async/fs); no MCP-S `BUILD.bazel` references any `//components/...` or `//applications/...` Python target or any other in-repo crate; the `crates_mcps` hub (when created) is isolated from `crates` and `crates_rust_components`. Enforced by review and the Bazel dependency graph.

## Related

- PRD: (author's private monorepo)
- Refines: ADR-MCPS-001
- Amends: ADR-MCPS-011
