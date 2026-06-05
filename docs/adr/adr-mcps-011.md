<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-011: Workspace Structure, Phased Delivery, and Conformance-as-Specification

## Status

Accepted

## Context

Derived from PRD. The brief proposes a Rust workspace and a phased plan, and leaves open how much specification to write before code (#18.10) and whether the first sidecar supports `stdio` only or both transports (#18.7). The headline claim of the project is transport-agnosticism, so what demonstrates it — and when — is an architectural decision.

## Decision

MCP-S is delivered as a Rust workspace (`mcps-core` kept free of networking, async runtimes, and filesystem access; plus `mcps-conformance`, `mcps-proxy`, `mcps-host`, and a future `mcps-policy`) built core-first, with the conformance suite exercising both `stdio` and Streamable HTTP from its first milestone, the first reference sidecar implemented `stdio`-only (HTTP following immediately after), and the specification authored as a minimal normative draft that serves as the conformance oracle — with the test vectors as the executable specification.

## Rationale

Keeping `mcps-core` dependency-free makes it reusable by sidecars, hosts, conformance runners, and future non-Rust bindings. Transport-agnosticism is proven by the conformance suite running the *same* signed objects over both transports to identical outcomes — not by both sidecars existing — which decouples the headline claim from the proxy schedule. A minimal oracle avoids both a prose RFC that freezes untested assumptions and a code-first spec that enshrines implementation quirks; the grill itself surfaced three gaps (stale vectors, JCS round-trip landmines, the resolver-outage error) that code and vectors catch faster than prose. `stdio` is the harder, more novel sidecar case (no headers, private pipe, in-band `_meta`), so it goes first.

## Alternatives Considered

- **Full RFC-style spec before code**: rejected — encodes untested assumptions and delays `cargo test`.
- **Code-first, spec backfilled**: rejected — risks enshrining implementation quirks as normative and weakens the independent-interoperability goal.
- **`stdio`-only conformance in v1**: rejected — leaves the headline transport-agnostic claim asserted but unproven.
- **Both transports in the first sidecar**: rejected for v1 — heavier Phase 3 before anything ships; HTTP follows immediately.

## Consequences

### Positive
- Fast path to a green `cargo test -p mcps-core`; the headline claim is demonstrated early by conformance.

### Negative
- The HTTP sidecar lags the `stdio` sidecar by one milestone.

### Neutral
- Phase 0 exit is a 10-point normative oracle (identifier/keys, envelope schema, JCS-safe profile, signing rule, freshness/replay, trust resolution, verification order, error taxonomy, context propagation, regenerated vectors).

## Compliance and Enforcement

Workspace dependency boundaries keep `mcps-core` pure (enforced by crate manifests and review). The Phase 0 oracle is the gate for starting Phase 1. Conformance object-tests plus `stdio` and HTTP harnesses assert identical Core outcomes.

## Related

- PRD: (author's private monorepo)
- Siblings: ADR-MCPS-004/005 (signing/canonicalization), ADR-MCPS-006 (replay), ADR-MCPS-010 (incubation)

---

## Amendment (ADR-MCPS-012)

Build integration and placement are refined by [ADR-MCPS-012](adr-mcps-012.md): MCP-S lives at `components/mcps/` as an isolated `rules_rust` Cargo workspace. The **canonical hermetic build/test is `bazel test //components/mcps/...`** (the original "`cargo test -p mcps-core`" exit criterion is superseded); Cargo manifests are retained for rust-analyzer, local dev, and future standalone extraction.
