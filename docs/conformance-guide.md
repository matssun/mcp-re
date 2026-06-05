# MCP-S Conformance Guide

**Audience:** an engineer who wants to RUN the MCP-S conformance suite from a
fresh clone and understand what it proves.

This guide explains **how to build and run** the suite. It does not restate the
protocol rules (those live in the [MCP-S Core Specification](spec/mcps-core-spec.md))
or the rationale (those live in the ADRs the spec cites). Per the project
convention: the spec states the rule, the ADR records why, this guide explains
how to use it, and the tests prove it.

## What the suite is

The conformance corpus is the executable specification (ADR-MCPS-011,
[view](adr/adr-mcps-011.md)). It is a set of
committed JSON vectors plus harnesses that replay them, transport-agnostically,
as in-process objects, over stdio, and over Streamable HTTP — so a vector that
passes proves object/stdio/HTTP parity.

The vectors fall into three categories:

- **Core** — the frozen wire vocabulary, signing rule, JCS-safe value domain,
  freshness/replay, trust resolution, message constraints, and the
  request/response verification pipelines. Fixtures live under
  `mcps-core/tests/vectors/`.
- **Phase-5 authorization** — the delegated-authorization profile
  (`PolicyEvaluator` + Reference Signed Authorization Profile, ADR-MCPS-013,
  [view](adr/adr-mcps-013.md)). Fixtures live in
  `mcps-policy/tests/vectors/phase5_vectors.json`.
- **Phase-6 transport** — mTLS, transport binding, durable replay, and the
  client-cert lifetime posture (ADR-MCPS-014,
  [view](adr/adr-mcps-014.md)). These are exercised
  by the `mcps-proxy` test targets and by re-running the Core corpus over the
  HTTP harness.

### Counts live in the manifest, not here

The authoritative enumeration of every vector and every Bazel test target — and
their counts — is the drift-guarded conformance manifest:

- Manifest: [`mcps-conformance/conformance_manifest.json`](../mcps-conformance/conformance_manifest.json)
- Drift guard: `//mcps-conformance:drift_guard_test`
  (source: [`tests/drift_guard_test.rs`](../mcps-conformance/tests/drift_guard_test.rs))

This guide deliberately quotes **no** vector or target counts. To learn the
current numbers, read the manifest's `counts` block. The guard re-derives every
count from reality (on-disk fixtures + the `nt_rust_test` rules in the
`BUILD.bazel` files) at test time and FAILS if: a vector on disk is missing from
the manifest, a manifest entry names a non-existent vector, a recorded count is
stale, or a test target was added/removed without a manifest update. So the
manifest cannot silently rot — that is exactly why this guide points at it
instead of hardcoding a number.

## Build prerequisites

This repository is a self-contained Bazel module (`MODULE.bazel` is committed at
the repository root). A fresh clone is immediately buildable — no submodules to
initialize, no dependency-sync step to run.

You can also build the workspace with `cargo` directly (see the README for the
Cargo build path); the Bazel path documented below is the canonical hermetic
gate used in CI.

### Run the suite

```bash
bazel test //... --test_output=errors
```

That builds `mcps-core`, `mcps-conformance`, `mcps-host`, `mcps-policy`, and
`mcps-proxy` and runs every `rust_test` target enumerated in the manifest. A
failure fails the check and blocks merge.

## Running a subset

The wildcard target runs everything; during development you often want one
package or one target. The exact target labels are enumerated in the manifest's
`bazel_test_targets` array — use those names rather than guessing. Examples (the
labels are real, but always cross-check against the manifest):

```bash
# Just the Core crate + its vector replay.
bazel test //mcps-core/...

# Just the conformance harnesses (object / stdio / HTTP / acceptance).
bazel test //mcps-conformance/...

# The drift guard alone (fast; proves the manifest matches reality).
bazel test //mcps-conformance:drift_guard_test
```

If you add or remove a vector fixture, or add/remove an `nt_rust_test` target,
the drift guard will fail until you update the manifest to match. That is the
intended workflow: the manifest is edited deliberately, in the same change that
alters the corpus.

## What a green run proves

- Each Core vector reaches its recorded outcome (`verify_ok` or an exact
  `mcps.*` error token) — and reaches the **same** outcome as an object, over
  stdio, and over HTTP (transport parity).
- The Phase-5 authorization vectors exercise the `PolicyEvaluator` + Reference
  Profile to their recorded allow/deny verdicts.
- The Phase-6 proxy targets exercise mTLS termination, transport binding, the
  durable replay cache, and the client-cert lifetime posture.
- The manifest's enumerated corpus and counts match what is physically on disk
  and in the BUILD files.

For what each layer is claimed to prove (and the single-node production ceiling),
see the [Transport Hardening Guide](transport-hardening-guide.md) and
ADR-MCPS-017 ([view](adr/adr-mcps-017.md)).
