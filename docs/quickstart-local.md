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

You can also run the underlying tests directly (Bazel or Cargo — no env setup):

```sh
bazel test //mcp-re-proxy:full_stack_test //mcp-re-demo:demo_mtls_client_test
# or:
cargo test -p mcp-re-proxy --test full_stack_test
cargo test -p mcp-re-demo  --test demo_mtls_client_test
```

## What it proves

**`full_stack_test`** spawns the REAL `mcp_re_proxy_cli` process (TLS-terminating
PEP) over real mTLS in front of an in-process Streamable-HTTP inner MCP echo
backend, and drives the security matrix:

- a valid client cert + signed request round-trips: the proxy verifies the
  envelope, checks freshness/replay, strips the external envelope, injects the
  sidecar-owned verified context, forwards over HTTP, signs the response, and the
  response binds to the request hash;
- **no client certificate** → rejected at the mTLS handshake (fail closed);
- **untrusted client certificate** → rejected at the handshake (fail closed);
- valid cert + **tampered object signature** → `mcp-re.invalid_signature` (a valid
  mTLS channel never downgrades object verification);
- valid cert + **wrong transport binding** (signer ≠ cert identity) →
  `mcp-re.transport_binding_failed`.

**`demo_mtls_client_test`** drives the host-side HostSession client + the verifying
mTLS transport against a real proxy server: a signed request round-trips and the
client verifies the response against the **stored** request hash; a wrong response
hash and a forged response signature each fail closed on the client side.

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
- [`docs/spec/v0.5-claim-matrix.md`](spec/v0.5-claim-matrix.md) — every claim, each traceable to a green test.
- [`docs/sidecar-deployment-guide.md`](sidecar-deployment-guide.md) — running the PEP in front of a Streamable-HTTP inner backend.
