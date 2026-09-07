# The ownership remainder, and what stays outside — 2026-09-07

Priority 5 of the v0.17 assurance-closure mandate, whose instruction is the shape of this
slice: *register owners and existing evidence first; state a theorem only where the surface
has an independently meaningful security proposition; do not manufacture theorem IDs.*

Ten units and ten theorems, all over evidence that already existed. Then the part the closure
condition also requires: **an explicit reason for every surface that remains outside**.

## What was registered

| unit | lane | existing controls | theorem |
|---|---|---|---|
| `proxy.aws_kms_adapter` | `aws_kms_keysource` | 14 | THM-0116 |
| `proxy.gcp_kms_adapter` | `gcp_kms_keysource` | 39 | THM-0116, THM-0117 |
| `proxy.pkcs11_adapter` | `pkcs11_keysource` | 9 | THM-0116 |
| `proxy.aws_sts_credentials` | `aws_kms_keysource` | 26 | THM-0117 |
| `core.replay_seam` | default | 12 | THM-0118 |
| `core.trust_resolver_seam` | default | 7 | THM-0119 |
| `core.content_address` | default | 7 | — |
| `core.audit_vocabulary` | default | 5 | THM-0122 |
| `client.manifest_floor` | default | 18 | THM-0121 |
| `client.anchor_refresh` | default | 6 + 2 e2e | THM-0120 |
| `client.local_serving_pipeline` | default | 11 + 8 e2e | THM-0123 |
| `client.deployment_config` | default | 16 | THM-0124 |
| `client.request_construction` | default | 12 | THM-0125 |

THM-0108's scope named the adapters as unowned and said exactly what it did *not* establish
about them — that any of them speaks its provider's protocol correctly, selects the right
key, or reaches the endpoint a deployment intended. THM-0116 and THM-0117 are the parts of
that with a meaningful proposition and evidence that already exists.

**Custody is deliberately NOT among them.** That the private key never leaves the KMS is the
provider's property and the trait's shape, and in particular nothing here is a FIPS-140-2
Level 3 claim: a Cloud KMS `EC_SIGN_ED25519` key version may be SOFTWARE- or HSM-protected
and the two REST operations used cannot establish which.

`core.content_address` is registered as an owner **without** a theorem. "A parser accepts
exactly what it emits" is what its seven controls state directly; a theorem would restate it.

## The lane caught two of this slice's own mistakes

Neither would have been visible from a green `cargo test`.

**Ten selectors named a module that does not exist.** `request.rs` puts its controls in
`evidence_precondition_tests` and `notification_tests`, not `tests`. `verify-tests` reported
them as `never ran` — which is the whole reason the battery is declared by exact selector
rather than by module.

**A control of this campaign's own was flaky by construction.** The nonce fill control
compared two draws, and two draws of ONE byte collide once in 256: it would have failed on a
correct implementation roughly every four hundredth run. Rewritten over eight draws with a
distinct initial byte each time — so an untouched buffer yields a distinct value and cannot be
mistaken for a fresh draw — and stress-run forty times.

## What remains outside, and why

329 of 509 source files are now owned. The residue, classified rather than left silent:

### Within this mandate's scope — OWNERSHIP-ONLY, evidence gap named

`mcp-re-client-proxy/src/{route,transport,verified_outcome}.rs` — **0 controls between them**.
`verified_outcome.rs` has the sharpest unowned proposition left on the client side: an
`InputRequiredResult` carrying no usable `requestState` is MALFORMED rather than terminal, and
MCP 2026-07-28 closes the `resultType` set so an unrecognized one is never resolved to
terminal. Its `read_outcome` is `pub(crate)` over a `VerifiedDelegatedResponse`, so a control
needs a full signing round trip; the classification RULE it composes is owned
(`client.execution_contract`), and its composition is not.

**Classified `ACTION_REQUIRED`, not out of scope.** Registering a unit here would have to cite
another unit's controls, which is the "one fact under two owners" this campaign has refused
four times. It needs new controls, and that is a slice of its own.

`mcp-re-client/src/startup.rs` — 159 lines, 0 controls, and its own doc states a live
security fact: the anchor refresher is started UNCONDITIONALLY because it is the only place
anchors are WITHDRAWN once the manifest in force has lapsed, and nothing on the request path
consults that expiry. THM-0120 establishes what the refresher DOES; that the deployable
always starts one is unmeasured. **`ACTION_REQUIRED`.**

### Within scope — genuinely nothing to own

`mcp-re-core/src/lib.rs`, `mcp-re-client-core/src/lib.rs`, `mcp-re-host/src/lib.rs`,
`mcp-re-client-proxy/src/lib.rs`, `mcp-re-demo/src/lib.rs`: module declarations and `pub use`
re-exports. A re-export decides visibility, not behaviour, and every item it names is owned
where it is defined.

`mcp-re-core/src/ids.rs`: three frozen constants with a control pinning all three. Its content
is the constants themselves, and their values are pinned by every conformance vector.

`mcp-re-core/src/wire.rs`: the JSON-RPC error envelope, whose only decision — that the token
in `message`/`data.mcp_re_error` is `McpReError::wire_code()` — is THM-0111's and THM-0122's.

`mcp-re-client/src/{lib,main}.rs`: the composition root and the binary entry point.

### Deliberately dormant, excluded by name

`mcp-re-policy/src/revocation.rs` — `LiveTrustResolver`'s seam is `#[allow(dead_code)]` and
documents itself NOT WIRED; no production path installs a `RevocationSource`.

`mcp-re-host/src/signer.rs` — `HostSigner` has no consumer anywhere in the tree.

Both retained deliberately, both excluded on the `window_policy.rs` / `l1_fast_reject.rs`
precedent: **never state a theorem over code no deployment runs.**

### Not production code

`mcp-re-test-paths/**` (test-only path resolution; three of its files ARE owned by
`conformance.verdict_vocabulary_scope`, because a scanner that mis-reads a literal makes a
guard pass over code it never read), `mcp-re-demo/src/demo_fixtures.rs`, and
`verification/reproducers/verus-ice-closure-return-type/` (a compiler-bug reproducer).

### Outside the Cargo/Bazel workspace

`sdk/python/src/**` and `sdk/typescript/src/**` are separate Cargo workspaces with their own
lockfiles and no Bazel target. `sdk_python.exchange_path` and `sdk_typescript.exchange_path`
own their exchange paths with measured `test://` evidence across the pinned runtimes; the
wrapper sources themselves cannot be delivered as runfiles, and the producer check on the file
they render refusals through covers the one property that matters here (THM-0111).

### Outside this mandate

`mcp-re-proxy` (139 files) and `mcp-re-http-profile` (17). Neither is on priority 5's list,
which names `gcp_kms_keysource.rs`, `aws_sts.rs`, `aws_kms_keysource.rs`, `pkcs11_keysource/**`,
`mcp-re-client`, `mcp-re-core` and `mcp-re-client-proxy`. `scitt/prototype/{mod,tree}.rs` is
among them and the census already read it correctly: two files named "prototype", an
out-of-scope declaration rather than a unit.
