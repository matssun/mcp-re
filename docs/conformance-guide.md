# MCP-RE Conformance Guide

**Audience:** an engineer who wants to RUN the MCP-RE conformance suite from a
fresh clone and understand what it proves.

This guide explains **how to build and run** the suite. It does not restate the
protocol rules (those live in the [MCP-RE Core Specification](spec/mcp-re-core-spec.md))
or the rationale (those live in the ADRs the spec cites). Per the project
convention: the spec states the rule, the ADR records why, this guide explains
how to use it, and the tests prove it.

## What the suite is

The conformance corpus is the executable specification: committed JSON vectors
plus harnesses that replay them against the real verifier. MCP-RE is
HTTP-profile only — RFC 9421 message signatures with RFC 9530 content digests
are the single carrier, and the corpora are organised by profile rather than by
transport.

**A conformance category is a claim about executable evidence.** A category is
advertised here only if it has both a corpus that exists and a test target that
reaches it. `scripts/conformance_claims_gate.py` enforces exactly that, in both
directions, so this table cannot drift away from the tree: a row whose corpus or
harness has been deleted fails the gate, and so does a corpus that exists with
no row advertising it.

<!-- conformance-categories:begin -->

| Category | Corpus | Harness targets |
| --- | --- | --- |
| HTTP profile — RFC 9421 signatures, RFC 9530 digests, the frozen `mcp-re.*` rejection vocabulary | `mcp-re-conformance/tests/vectors/http-profile/` | `//mcp-re-conformance:http_profile_vectors_test`, `//mcp-re-conformance:rfc9421_cross_verification_test`, `//mcp-re-conformance:corpus_pinning_test` |
| Delegated-required credentials — the frozen `d01`–`d22` credential-verification corpus (ADR-MCPRE-052) | `mcp-re-conformance/tests/vectors/delegation-profile/` | `//mcp-re-conformance:delegation_vectors_test`, `//mcp-re-conformance:delegation_cross_verification_test`, `//mcp-re-conformance:corpus_pinning_test` |
| SCITT receipts — RFC 9943 transparency receipts, including third-party interop | `mcp-re-conformance/tests/vectors/scitt/` | `//mcp-re-conformance:scitt_vectors_test`, `//mcp-re-conformance:scitt_interop_test`, `//mcp-re-conformance:scitt_cross_verification_test` |

<!-- conformance-categories:end -->

### Proofs that are target-backed rather than vector-backed

Not every security property is expressed as a replayable vector. Transport
hardening (mTLS termination, transport binding, client-certificate lifetime
posture), the serving-path proofs, and the delegated serving/rotation/fail-closed
behaviours are proven by test targets directly, with no fixture corpus to replay.

Those are enumerated, property by property, in the drift-guarded security
traceability manifest — which maps each claimed property to the exact Bazel
target and test function that proves it:

- Manifest: [`mcp-re-conformance/security_traceability_manifest.json`](../mcp-re-conformance/security_traceability_manifest.json)
- Drift guard: `//mcp-re-conformance:security_traceability_guard_test`

The guard fails if a manifest entry names a target no `BUILD.bazel` declares, a
test function that no longer exists in its source, or a source with no runfile
wired up. For the delegated-required profile specifically, the acceptance gate is
the [Delegated-Required Validation Matrix](spec/delegated-required-validation-matrix.md).

### Preserved vector sets that are NOT conformance

`mcp-re-policy/tests/vectors/phase5_vectors.json` is a preserved authorization
vector corpus. **It is not executed by any harness and is not a conformance
category.** It specifies a signed-authorization profile that was bound to the
retired object carrier; `--authz reference` is refused at the configuration
boundary, so there is no implementation for those vectors to run against. The
corpus is retained because its generator no longer exists and it is the only
remaining copy — it is design input for a future authorization profile, not
evidence about this release. See
[`mcp-re-policy/tests/vectors/README.md`](../mcp-re-policy/tests/vectors/README.md).

### Counts live in the manifests, not here

This guide deliberately quotes **no** vector counts. Each corpus's `manifest.json`
enumerates its own fixtures and publishes a `corpus_digest` over them; the
harnesses re-derive both at test time. To learn the current numbers, read the
corpus manifests.

## Build prerequisites

This repository is a self-contained Bazel module (`MODULE.bazel` is committed at
the repository root). A fresh clone is immediately buildable — no submodules to
initialize, no dependency-sync step to run.

You can also build the workspace with `cargo` directly (see the README for the
Cargo build path); the Bazel path documented below is the canonical hermetic
gate used in CI. Note that the two lanes are not interchangeable: `cargo test
--workspace` does not compile the non-default feature backends, and `bazel test
//...` excludes the `manual`-tagged infra lane.

### Run the suite

```bash
bazel test //... --test_output=errors
```

A failure fails the check and blocks merge.

## Running a subset

The wildcard target runs everything; during development you often want one
package or one target. The category table above names the real labels.

```bash
# Every conformance harness.
bazel test //mcp-re-conformance/...

# One corpus.
bazel test //mcp-re-conformance:http_profile_vectors_test

# The claims gate alone (fast; proves this guide matches the tree).
python3 scripts/conformance_claims_gate.py
```

If you add or remove a corpus, or add/remove a harness target, the claims gate
fails until the table above matches. That is the intended workflow: the guide is
edited deliberately, in the same change that alters the corpus.

## What a green run proves

- **Frozen corpora reach their recorded verdicts.** Every committed vector
  verifies (or is refused with the exact `mcp-re.*` token the fixture records),
  and regenerating the fixtures reproduces the committed bytes.
- **Cross-verification against an independent implementation.** Externally
  produced signatures and credentials verify under the MCP-RE verifier, our
  issuer reproduces the external bytes, and externally built negatives are
  refused — so a green corpus is not merely self-consistent.
- **The corpora are pinned by content.** Each fixture's bytes match the SHA-256
  the manifest publishes, the `corpus_digest` commits to the whole set, no vector
  sits in the directory unpinned, and a tampered fixture fails its hash rather
  than being run.
- **The advertised categories exist.** Every category above has a corpus and a
  harness that reaches it, and every corpus in the tree is advertised.

For what each layer is claimed to prove (and the single-node production ceiling),
see the [Transport Hardening Guide](transport-hardening-guide.md).

## Corpus content pinning

A tag or branch name records *which commit*; a digest records *which bytes*, so
an independent reviewer can confirm they are recomputing against the same corpus
object rather than trusting that a tag still points where they expect. A filename
list has the same weakness one level down — it proves which files were MEANT to
be there, not what was in them.

Each corpus therefore carries its pins in its own `manifest.json`:

- `fixtures[].sha256` — the bytes of each committed fixture;
- `corpus_digest` — a digest over the whole fixture set, so adding or removing a
  vector changes it.

Both are recomputed from the checked-in bytes at test time —
`//mcp-re-conformance:corpus_pinning_test` for the HTTP-profile and delegation
corpora, `//mcp-re-conformance:scitt_vectors_test` for the SCITT corpus — and the
pinning tests include the negative control that makes the mechanism worth having:
a tampered fixture must fail its hash rather than run. CI publishes the digests
into the job summary, so a release packet can quote the exact corpus that was
tested.

The pins are whatever the checked-in harness recomputes from the checked-in
corpus, never a value copied into prose. This guide publishes no digest literals
for that reason: a conformance pin must be reproducible from checked-in code and
checked-in corpus bytes, and a number transcribed into a document is neither.
