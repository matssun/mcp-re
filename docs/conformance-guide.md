# MCP-RE Conformance Guide

**Audience:** an engineer who wants to RUN the MCP-RE conformance suite from a
fresh clone and understand what it proves.

This guide explains **how to build and run** the suite. It does not restate the
protocol rules (those live in the [MCP-RE Core Specification](spec/mcp-re-core-spec.md))
or the rationale (those live in the ADRs the spec cites). Per the project
convention: the spec states the rule, the ADR records why, this guide explains
how to use it, and the tests prove it.

## What the suite is

The conformance corpus is the executable specification (ADR-MCPS-011,
[view](https://github.com/matssun/mcp-re/discussions/360)). It is a set of
committed JSON vectors plus harnesses that replay them, transport-agnostically,
as in-process objects and over Streamable HTTP — so a vector that
passes proves object/HTTP parity (MCP-RE is HTTP-profile only).

The vectors fall into three categories:

- **Core** — the frozen wire vocabulary, signing rule, JCS-safe value domain,
  freshness/replay, trust resolution, message constraints, and the
  request/response verification pipelines. Fixtures live under
  `mcp-re-core/tests/vectors/`.
- **Phase-5 authorization** — the delegated-authorization profile
  (`PolicyEvaluator` + Reference Signed Authorization Profile, ADR-MCPS-013,
  [view](https://github.com/matssun/mcp-re/discussions/362)). Fixtures live in
  `mcp-re-policy/tests/vectors/phase5_vectors.json`.
- **Phase-6 transport** — mTLS, transport binding, durable replay, and the
  client-cert lifetime posture (ADR-MCPS-014,
  [view](https://github.com/matssun/mcp-re/discussions/363)). These are exercised
  by the `mcp-re-proxy` test targets and by re-running the Core corpus over the
  HTTP harness.

### Counts live in the manifest, not here

The authoritative enumeration of every vector and every Bazel test target — and
their counts — is the drift-guarded conformance manifest:

- Manifest: [`mcp-re-conformance/conformance_manifest.json`](../mcp-re-conformance/conformance_manifest.json)
- Drift guard: `//mcp-re-conformance:drift_guard_test`
  (source: [`tests/drift_guard_test.rs`](../mcp-re-conformance/tests/drift_guard_test.rs))

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

That builds `mcp-re-core`, `mcp-re-conformance`, `mcp-re-host`, `mcp-re-policy`, and
`mcp-re-proxy` and runs every `rust_test` target enumerated in the manifest. A
failure fails the check and blocks merge.

## Running a subset

The wildcard target runs everything; during development you often want one
package or one target. The exact target labels are enumerated in the manifest's
`bazel_test_targets` array — use those names rather than guessing. Examples (the
labels are real, but always cross-check against the manifest):

```bash
# Just the Core crate + its vector replay.
bazel test //mcp-re-core/...

# Just the conformance harnesses (object / HTTP / acceptance).
bazel test //mcp-re-conformance/...

# The drift guard alone (fast; proves the manifest matches reality).
bazel test //mcp-re-conformance:drift_guard_test
```

If you add or remove a vector fixture, or add/remove an `nt_rust_test` target,
the drift guard will fail until you update the manifest to match. That is the
intended workflow: the manifest is edited deliberately, in the same change that
alters the corpus.

## What a green run proves

- Each Core vector reaches its recorded outcome (`verify_ok` or an exact
  `mcp-re.*` error token) — and reaches the **same** outcome as an object, over
  and over HTTP (transport parity).
- The Phase-5 authorization vectors exercise the `PolicyEvaluator` + Reference
  Profile to their recorded allow/deny verdicts.
- The Phase-6 proxy targets exercise mTLS termination, transport binding, the
  durable replay cache, and the client-cert lifetime posture.
- The manifest's enumerated corpus and counts match what is physically on disk
  and in the BUILD files.

For what each layer is claimed to prove (and the single-node production ceiling),
see the [Transport Hardening Guide](transport-hardening-guide.md) and
ADR-MCPS-017 ([view](https://github.com/matssun/mcp-re/discussions/366)).

## v0.8.0 draft-02 conformance corpus pinning

The v0.8.0 draft-02 corpus is pinned **by content, not only by Git tag**. A tag
name records *which commit*; these digests record *which bytes*, so an
independent reviewer can confirm they are recomputing against the same corpus
object rather than trusting that `v0.8.0` still points where they expect.

Two pins, both recomputed from the checked-in corpus bytes by
[`scripts/corpus_digest.py`](../scripts/corpus_digest.py):

- **`manifest.json` SHA-256** — SHA-256 over the exact bytes of
  `mcp-re-core/tests/vectors/draft-02/manifest.json`:

  ```
  a1e7812772975f80aa628048081a354a1a52f7cc1bbe3de306ae69b706bfd7db
  ```

- **`draft02_file_hash_list_digest`** — SHA-256 over a deterministic file-hash
  list covering **every** regular file in
  `mcp-re-core/tests/vectors/draft-02` (the manifest included), sorted by
  repository-relative path, one LF-terminated `\<path\>  sha256:\<hex\>` line per
  file:

  ```
  1e9967f046feb2dbb20d40d13259fd991d4b5129fe62e85a01dc21c707d53130
  ```

### Reproduce the pins

The script is the **normative definition** of these values: the pin is whatever
the checked-in script recomputes from the checked-in corpus, not a value copied
from a comment. It has no third-party dependencies — a fresh clone plus
`python3` is enough.

```bash
# Print both pins (add --list to dump the exact per-file preimage).
python3 scripts/corpus_digest.py

# Fail (non-zero exit) if the corpus no longer matches the published pins.
python3 scripts/corpus_digest.py --check \
  a1e7812772975f80aa628048081a354a1a52f7cc1bbe3de306ae69b706bfd7db \
  1e9967f046feb2dbb20d40d13259fd991d4b5129fe62e85a01dc21c707d53130
```

If the corpus changes intentionally, the digests change with it; regenerate them
with the script and update the values here in the same change.

### Scope of the independent recompute

An independent from-fixture recompute reproduced the committed canonical
preimage bytes and SHA-256 values for the oracle-bearing draft-02 vectors within
its stated scope. This check validates the **canonical-preimage / hash oracle
layer only** — the preimage bytes and their SHA-256 values. It does **not** claim
Ed25519 signature validation, SDK interoperability, or live KMS/server behavior.

> An earlier externally reported second digest (`75f06ec2…f06f`) could not be
> reproduced from the checked-in corpus without its construction, so it is **not
> normative** here. The normative corpus-list digest is the one emitted by
> `scripts/corpus_digest.py` above. A conformance pin must be reproducible from
> checked-in code and checked-in corpus bytes; anything that is not, we do not
> publish as a pin.
