<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Fleet Deployment Guide (horizontally-scaled)

**Audience:** an operator running the MCP-S policy-enforcement proxy as a
**fleet** of replicas behind a load balancer, rather than a single node.

**Status:** NON-NORMATIVE reference, mirroring the
[Mode-C GCP cookbook](mode-c-attested-ingress-gcp-cookbook.md). The design is
[ADR-MCPS-049](adr/adr-mcps-049.md). Live-cluster validation is tracked
separately (MCPS-90, HITL); this guide + the Helm chart under
[`deploy/helm/mcps-proxy`](../deploy/helm/mcps-proxy) are the reference, and the
coherence properties are proven by the CI-gated e2e tests named below.

For single-node deployment read the
[Sidecar Deployment Guide](sidecar-deployment-guide.md) first — this guide only
adds the horizontal-scale concerns.

## What "fleet" changes

A single verifier owns all of its state locally. A fleet of verifiers behind a
load balancer does not: a replayable request may reach a **different** verifier
than the one that admitted the first nonce, and a revocation applied at one node
must reach the others. MCP-S closes both with **shared state**, and the proxy
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
3. A container image of `mcps-proxy` built with the `redis_replay` feature.

## Install

```sh
helm install my-fleet deploy/helm/mcps-proxy \
  --set replicaCount=3 \
  --set replay.redisUrl=redis://mcps-redis:6379 \
  --set replay.durabilityTier=redis-wait-quorum:2:2000 \
  --set revocation.tier=push:60 \
  --set revocation.trustEpochRedisUrl=redis://mcps-redis:6379 \
  --set innerSession=stateful \
  --set tls.secretName=mcps-proxy-material \
  --set-json 'inner.command=["/usr/local/bin/your-mcp-server"]'
```

The chart renders `--strict --fleet` by default and includes a **fail-closed
guardrail**: `helm template`/`install` errors out if `fleet=true` is paired with
a non-shared or sub-quorum replay tier, so an unsafe fleet manifest cannot be
produced.

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

MCP-S replicates **no** inner-server session state across replicas. Declare the
wrapped server's statefulness with `--inner-session`:

- `stateful` (default) — a logical session holds state on one replica; the chart
  sets the Service `sessionAffinity: ClientIP` so the load balancer pins it.
  **Sticky routing is required.**
- `stateless` — any replica may serve any request; the chart uses plain
  round-robin.

The MCP-S authenticity checks are identical on every replica either way; affinity
is only about inner-session continuity. MRT continuations are replica-independent
by construction (ADR-MCPS-047) — the continuation rides the signed preimage — so
a mid-continuation replica switch still verifies (proven at the proxy layer).

### 4. Graceful rollout (W3, MCPS-88)

On `SIGTERM` (a rollout / `kubectl delete pod`) the proxy stops accepting, lets
the single in-flight request finish (bounded by the request deadline), and exits
0. Set `drainGracePeriodSeconds` above your request deadline. Health probes are
**tcpSocket** against the bind port — the proxy speaks MCP-S over TLS, not HTTP,
so "port accepting" is the honest readiness signal (no synthetic `/healthz`).

## Capacity

`fleet_throughput_bench.rs` (MCPS-89) reports the per-request PEP added latency
and throughput over the shared store; run it against your Redis to size the
fleet. The dominant per-request cost at scale is the shared-store round-trip.

## What a fleet still does NOT claim

- **zero-window revocation** — the per-tier bounds above are windows, not zero.
- **cross-replica inner-session replication** — stateful inners need sticky
  routing; MCP-S does not move inner state between replicas.
- **multi-tenant isolation between mutually distrusting operators** — the fleet
  is one trust domain / one operator (see
  [security boundary §8](spec/security-boundary.md)).

Live-cluster validation on real Kubernetes (GKE) is MCPS-90 (HITL).
