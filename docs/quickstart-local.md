<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quickstart — local demo (no cloud credentials)

The fastest way to see what MCP-RE actually does: run the single-node HTTP-profile
demo and watch the **real `mcp_re_proxy_cli` PEP** — over real mTLS, in front of a
Streamable-HTTP inner MCP backend — **accept a valid signed call** and **fail
closed** on a missing/untrusted client cert, a tampered object signature, and a
wrong transport binding. MCP-RE is HTTP-profile only (a stdio-only server is
fronted by an external plain-MCP adapter such as FastMCP); these are HERMETIC
tests that exit non-zero if any expected rejection does not happen, so a green run
is a security assertion, not a printout.

## Run it

```sh
./scripts/demo-local.sh
```

That runs the hermetic HTTP-profile end-to-end proofs (no cloud, no external
infra). Expected final line:

```text
OK: MCP-RE local demo completed
```

You can also run the underlying suites directly. Each is a MODULE inside a merged
test binary, so it is selected by a name filter rather than by being its own
`--test` target:

```sh
cargo test -p mcp-re-proxy --test integration -- mtls_transport_binding_test::
cargo test -p mcp-re-proxy --test integration_async --features async_serve -- mtls_client_leg_e2e_test::
cargo test -p mcp-re-proxy --test integration_async --features async_serve -- delegated_client_server_e2e_test::
cargo test -p mcp-re-proxy --test integration_async --features async_serve -- verified_context_carrier_test::
```

A name filter that matches nothing exits **0**, so a typo in one of these reports
success having run no test. `demo-local.sh` routes every lane through
`scripts/run_test_lane.sh`, which reads libtest's own count back and fails on zero —
which is why the script, not this list, is the entry point to prefer.

## What it proves

**`mtls_transport_binding_test`** performs a REAL rustls mutual-TLS handshake and
binds the verified request actor to the peer certificate. A mismatched binding —
signer ≠ cert identity — **fails closed**; a valid mTLS channel never downgrades
envelope verification.

**`mtls_client_leg_e2e_test`** drives the client leg over a real network hop: the
client proxy signs RFC 9421/9530, the verifying mTLS transport presents a client
certificate and pins the server, and a **forged response signature fails closed**
on the client side.

**`delegated_client_server_e2e_test`** runs the full delegated-required round trip,
including the **replay refusal** and the **signed rejection** — delegated-required
is MCP-RE's only response-signing mode.

**`verified_context_carrier_test`** covers the reserved-field guard and the injected
verified context: the sidecar-owned context the proxy injects cannot be forged by a
caller supplying the reserved field itself.

The broader per-`mcp-re.*`-token vector matrix (tampered body/id, replay, expiry,
wrong audience, missing envelope, authorization scope, response binding) is the
conformance corpus, drift-guarded and run over both the object and HTTP harnesses
(`bazel test //mcp-re-conformance/...`); see the security-claim matrix below.

## Verifying the demo scripts themselves

To confirm the demo entry points work on a clean checkout (the HTTP-profile
end-to-end proofs pass and the GCP wrapper fails closed without `PROJECT_ID`), run
the offline smoke test — no cloud credentials required:

```sh
./scripts/test-demos.sh
```

It exits non-zero, naming the failing assertion, if any demo regresses.

## Next: optional live GCP Cloud KMS validation

Cloud is **not** a dependency of this demo. When you want to prove the
non-exporting GCP key-custody path (object signing and delegated-TLS server
signing performed inside Cloud KMS), run it separately:

```sh
PROJECT_ID=my-gcp-project ./scripts/demo-gcp-kms.sh
```

See [`docs/quickstart-gcp-kms.md`](quickstart-gcp-kms.md).

## See also

- [`docs/security/google-validation-plan.md`](security/google-validation-plan.md) — the full staged GCP validation plan.
- [`docs/security/gcloud-kms-validation.sh`](security/gcloud-kms-validation.sh) — the live KMS harness.
- [`docs/spec/security-boundary.md`](spec/security-boundary.md) — what MCP-RE protects and what it does not.
- `verification/policy/theorems.toml` — the argument behind every claim: root theorems, their support closure, and the registered premises. (`docs/spec/v0.5-claim-matrix.md` is historical.)
- [`docs/sidecar-deployment-guide.md`](sidecar-deployment-guide.md) — running the PEP in front of a Streamable-HTTP inner backend.
