<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Fleet Deployment Guide (horizontally-scaled)

**Audience:** an operator running the MCP-RE policy-enforcement proxy as a
**fleet** of replicas behind a load balancer, rather than a single node.

**Status:** NON-NORMATIVE reference, mirroring the
[Mode-C GCP cookbook](mode-c-attested-ingress-gcp-cookbook.md). The design is
[ADR-MCPS-049](adr/adr-mcps-049.md). Live-cluster validation is tracked
separately (MCPS-90, HITL); this guide + the Helm chart under
[`deploy/helm/mcp-re-proxy`](../deploy/helm/mcp-re-proxy) are the reference, and the
coherence properties are proven by the CI-gated e2e tests named below.

For single-node deployment read the
[Sidecar Deployment Guide](sidecar-deployment-guide.md) first — this guide only
adds the horizontal-scale concerns.

## What "fleet" changes

A single verifier owns all of its state locally. A fleet of verifiers behind a
load balancer does not: a replayable request may reach a **different** verifier
than the one that admitted the first nonce, and a revocation applied at one node
must reach the others. MCP-RE closes both with **shared state**, and the proxy
**fails closed** if you ask for a fleet without it.

The two posture flags are orthogonal (ADR-MCPS-049 clause 1):

- `--strict` — the security posture (reject insecure config, not warn).
- `--fleet` — the deployment topology (reject node-local replay caches).

The production fleet guarantee is **`--strict --fleet`**. Under it the proxy
**refuses to start** unless the replay cache is a shared tier at
`REDIS_WAIT_QUORUM` or stronger (a `memory` or `file` cache is node-local and
cannot see a peer's nonces).

## Prerequisites

1. A **shared Redis** reachable by every replica, used for two things:
   - the shared replay store (`--replay-cache shared`, ADR-MCPS-020), and
   - the trust-epoch revocation source (`--trust-epoch-redis-url`, MCPS-84).
   One Redis serves both; there is no second dependency.
2. A Kubernetes **Secret** with the proxy's material: `tls.crt`, `tls.key`,
   `client-ca.pem`, `trust.json`, `signing-seed`.
3. A container image of `mcp-re-proxy` built with the `redis_replay` feature.

## Install

```sh
helm install my-fleet deploy/helm/mcp-re-proxy \
  --set replicaCount=3 \
  --set replay.redisUrl=redis://mcp-re-redis:6379 \
  --set replay.durabilityTier=redis-wait-quorum:2:2000 \
  --set revocation.tier=push:60 \
  --set revocation.trustEpochRedisUrl=redis://mcp-re-redis:6379 \
  --set tls.secretName=mcp-re-proxy-material \
  --set-json 'inner.httpUrls=["http://inner-mcp.default.svc.cluster.local:8080/mcp"]'
```

MCP-RE is HTTP-profile only: the inner plane is one or more Streamable-HTTP MCP
backends (`inner.httpUrls`). A **stdio-only** inner server is out of scope for
MCP-RE — front it with an EXTERNAL plain-MCP adapter (e.g. FastMCP's stdio↔HTTP
proxy) that exposes HTTP, run that adapter as your own sidecar/deployment, and
point `inner.httpUrls` at it.

The chart renders `--strict --fleet` by default and includes a **fail-closed
guardrail**: `helm template`/`install` errors out if `fleet=true` is paired with
a non-shared or sub-quorum replay tier, so an unsafe fleet manifest cannot be
produced.

## Cloud KMS custody on GKE (Workload Identity)

By default the chart mounts a raw `signing-seed` from the Secret
(`keySource=fileSeed`). On GKE you can instead keep the signing key in **GCP
Cloud KMS** so no key material ever enters the pod — the proxy authenticates to
KMS via **Workload Identity** (the metadata-server token path), not a key file.

Build the image with the `gcp_kms_keysource` feature, then:

1. Create a Google Service Account (GSA) and grant it signing on the key:
   ```sh
   gcloud iam service-accounts create mcp-re-signer
   gcloud kms keys add-iam-policy-binding KEY --keyring RING --location LOC \
     --member "serviceAccount:mcp-re-signer@PROJECT.iam.gserviceaccount.com" \
     --role roles/cloudkms.signerVerifier
   ```
2. Bind the GSA to the chart's Kubernetes ServiceAccount (KSA) and annotate it:
   ```sh
   gcloud iam service-accounts add-iam-policy-binding \
     mcp-re-signer@PROJECT.iam.gserviceaccount.com \
     --role roles/iam.workloadIdentityUser \
     --member "serviceAccount:PROJECT.svc.id.goog[NAMESPACE/my-fleet-mcp-re-proxy]"
   ```
3. Install with the KMS key source (the `signing-seed` Secret key is then
   unnecessary):
   ```sh
   helm install my-fleet deploy/helm/mcp-re-proxy \
     ... \
     --set keySource=gcpKms \
     --set gcpKms.keyVersion=projects/PROJECT/locations/LOC/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/N \
     --set gcpKms.useMetadata=true \
     --set 'serviceAccount.annotations.iam\.gke\.io/gcp-service-account=mcp-re-signer@PROJECT.iam.gserviceaccount.com'
   ```

`helm template`/`install` fails closed if `keySource=gcpKms` is set without
`gcpKms.keyVersion`. Setting `gcpKms.tlsKeyVersion` (a second, distinct KMS key)
additionally delegates the TLS server private key to KMS; the chart then omits
`--tls-key` and the Secret need not carry `tls.key`. Live-cluster validation of
this path is MCPS-90 (HITL).

## The four fleet concerns

### 1. Replay coherence (ADR-MCPS-049 W1, proof a)

A nonce admitted on replica A is replay-rejected on replica B, because the
`(signer, audience, nonce)` key lives in the shared Redis store. The `--fleet`
gate enforces the shared tier; the property is proven by
`fleet_replay_e2e_test.rs`.

### 2. Trust/revocation coherence (W1 proof b, MCPS-84/85)

Set `--revocation-tier push` with `--trust-epoch-redis-url`. Each replica polls a
monotonic **trust-epoch** key; when an operator advances it (`INCR`), every
replica flushes its trust cache on the next request and re-resolves live. The
**cross-replica revocation-lag bound is per tier** (ADR-MCPS-049 clause 3):

| Tier | Bound |
|---|---|
| Trust key-status | near-zero when the trust-epoch source is healthy; bounded `T` on a source outage (fail-closed); bounded `T` with no source |
| Client-cert CRL | the CRL `nextUpdate` / reload cadence (MCPS-66) — a fleet's CRL-rollout window |

Zero-window revocation is **not** claimed on either tier. The proxy prints the
bounds from real config at startup (`FLEET cross-replica revocation-lag bounds`).
Proven by `fleet_trust_epoch_e2e_test.rs`, which includes a negative control
(the sibling serves stale trust until the epoch advances).

### 3. Inner-session affinity (clause 2, MCPS-83)

MCP-RE replicates **no** inner-server session state across replicas. Under
ADR-MCPRE-051 the PEP's inner plane is stateless Streamable-HTTP (`--inner-http-url`),
so the norm is no affinity at all. Client→proxy stickiness is now a **Service**
setting, not a proxy flag (`--inner-session` was removed with the in-proxy stdio
mode, MCPRE-118). Set it via the chart's `service.sessionAffinity`:

- `None` (default) — any replica may serve any request; plain round-robin. This is
  correct for a stateless HTTP inner backend.
- `ClientIP` — the Service pins a client to one replica. Use only when the inner
  **HTTP backend** you front is itself session-stateful and has no stickiness of
  its own (e.g. an external stateful MCP server, or the external plain-MCP adapter
  fronting one).

The MCP-RE authenticity checks are identical on every replica either way; affinity
is only about inner-session continuity. MRT continuations are replica-independent
by construction (ADR-MCPS-047) — the continuation rides the signed preimage — so
a mid-continuation replica switch still verifies (proven at the proxy layer).

### 4. Graceful rollout (W3, MCPS-88)

On `SIGTERM` (a rollout / `kubectl delete pod`) the proxy stops accepting on every
per-core listener and joins **all** in-flight requests within a bounded grace
window (each request already bounded by its deadline), then exits 0 with zero
abandoned requests (ADR-MCPRE-051 §6, proven by `async_drain_test.rs`). Set
`drainGracePeriodSeconds` above your request deadline. Health probes are
**tcpSocket** against the bind port — the proxy speaks MCP-RE over TLS, not HTTP,
so "port accepting" is the honest readiness signal (no synthetic `/healthz`).

## Capacity

The concurrent-TLS-client load harness (`tls_load_harness_bench.rs`,
ADR-MCPRE-051 §7) drives the real per-core listener over mTLS and reports p50/p99/p999
added latency and throughput against the declared benchmark envelope
([`docs/bench/adr-051-load-harness-envelope.md`](bench/adr-051-load-harness-envelope.md));
run it against your Redis to size the fleet. The dominant per-request cost at
scale is the shared-store round-trip. (The older single-thread
`fleet_throughput_bench.rs` (MCPS-89) calls `Proxy::handle` directly and cannot
measure the concurrent serving path.)

## What a fleet still does NOT claim

- **zero-window revocation** — the per-tier bounds above are windows, not zero.
- **cross-replica inner-session replication** — stateful inners need sticky
  routing; MCP-RE does not move inner state between replicas.
- **multi-tenant isolation between mutually distrusting operators** — the fleet
  is one trust domain / one operator (see
  [security boundary §8](spec/security-boundary.md)).

Live-cluster validation on real Kubernetes (GKE) is MCPS-90 (HITL).
