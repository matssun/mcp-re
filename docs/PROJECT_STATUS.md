<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Project Status

## Current status

MCP-S is an experimental third-party security extension proposal for MCP.

It is not an official MCP extension unless accepted through the official MCP governance and proposal process.

**Current release: v0.10.1** (2026-07-05) — horizontally-scaled fleet posture
(ADR-MCPS-049) over the v0.10.0 Mode C ingress base. The frozen wire envelope is the
`draft-02` runtime-evidence profile (frozen at v0.6.0; served end-to-end since
v0.7.0). Per-release detail is in [`CHANGELOG.md`](../CHANGELOG.md); the design
lines are in [`docs/adr/`](adr/).

## Current implementation claim

The current implementation may claim:

> MCP-S is production-hardened for single-node Rust-native deployments.

This claim is bounded and should not be broadened without additional implementation, tests, and documentation.

## Demonstrated capabilities

The current demonstration and live-validation package proves:

### Single-node Rust-native end-to-end path

- HostSession signs outbound requests; client transport verifies server
  certificate and identity; mTLS to `mcps-proxy`;
- `mcps-proxy` verifies object signatures, freshness/replay, and delegated
  authorization before dispatch;
- caller-supplied verified context is stripped, sidecar-owned context injected;
- a persistent inner MCP server handles multiple requests; denied requests never
  reach it; responses are signed and bound to the request hash; HostSession
  verifies the response signature.

### Four-hop client-to-server path as separate OS processes (v0.7)

- A plain-MCP client → `mcps-client-proxy` (the local adoption bridge, signs
  `draft-02` requests + verifies responses) → mTLS → `mcps-proxy` server PEP →
  unmodified inner MCP server, organized as a runnable persona ladder
  (ADR-MCPS-045), with scoped deny-before-dispatch authorization and
  transport-identity binding on the wire.

### Client SDKs — Python and TypeScript (v0.7 / v0.8)

- Both SDKs bind to the SAME audited `mcps-client-core` (the Python SDK via
  maturin/PyO3, the TypeScript SDK via napi-rs), so the signed preimage is
  byte-identical across languages, and both are exercised through the real
  four-hop matrix. Non-exporting custody (HSM/KMS-style callback signer) is proven
  byte-identical to the direct software path.

### Stateless multi-round-trip continuation (v0.8)

- Request-associated elicitation folded into strict MCP-S as signed
  multi-round-trip continuation evidence (ADR-MCPS-047), fail-closed on arbitrary
  server push.

### Enterprise ingress — two honest postures (v0.9 / v0.10)

- **Mode A (`end_to_end_mtls`, default)** — the node terminates client mTLS and
  binds the verified peer to the request signer, with a v0.9 certificate-revocation
  honesty pass: a strict short-lived-cert lifetime ceiling and static-CRL
  fail-closed-on-stale (ADR-MCPS-023 §A1).
- **Mode C (`attested_ingress`, explicit opt-in, v0.10)** — a controlled ingress
  attestor signs a request-bound `mcps/lb-ingress-assertion/v2` assertion the node
  verifies over a pinned attestor→node channel. This is **attested delegation**,
  NOT end-to-end mTLS (the load balancer witnesses proof-of-possession and stays in
  the trusted computing base); the node binds the assertion (bind-not-interpret)
  and records three trust facts. The forwarded request is byte-identical to Mode A
  (zero `draft-02` preimage change). See the non-normative
  [Google Cloud cookbook](mode-c-attested-ingress-gcp-cookbook.md).

### Horizontally-scaled fleet deployment (v0.10.1)

MCP-S runs as N identical replicas behind a load balancer with no security claim
weakened, behind an explicit `--fleet` flag that is orthogonal to `--strict`
(ADR-MCPS-049). The heavy replay/trust primitives already existed (v0.3 shared
tiers); v0.10.1 composes, *proves*, and documents the fleet and closes the
node-local coherence gaps:

- **Cross-replica replay coherence** — `--fleet` rejects node-local (memory/file)
  replay caches, so a replica must use a shared, cross-replica ReplayCache (Redis).
  A two-replica e2e proves a nonce accepted by one replica is rejected by a sibling
  (MCPS-79/80/81).
- **Cross-replica trust revocation** — a Redis-backed trust-epoch source flushes the
  ADR-021 Push-tier trust cache across replicas on an epoch advance, reverting to the
  bounded-staleness guarantee on a read outage, with explicit per-tier
  revocation-lag bounds. An e2e proves a revocation reaches a sibling, with a
  negative control (MCPS-84/85/86).
- **Fleet operations** — self-declared inner-session statefulness (`--inner-session`)
  driving Service session affinity (MCPS-83); graceful `SIGTERM`/`SIGINT` drain for
  rolling deploys (MCPS-88); a fleet PEP throughput / added-latency benchmark
  (MCPS-89).
- **Kubernetes/Helm reference** + deployment guide (MCPS-87), with a fail-closed
  guardrail that refuses a `--fleet` deployment wired to a weak (node-local) tier.

### Live Google Cloud KMS validation (v0.5.1)

- **Object signing against real Cloud KMS** (`EC_SIGN_ED25519`): signatures
  produced by a live `asymmetricSign` and verified by `mcps-core`; the private
  key never leaves KMS (`getPublicKey`/`asymmetricSign` only).
- **Delegated TLS server-signing against real Cloud KMS**: a fully-validating
  rustls mTLS handshake completes only because a live KMS `asymmetricSign`
  produced the `CertificateVerify`; the TLS private key lives entirely in KMS
  (leaf minted over the KMS public key).
- **Fail-closed negative lanes**: wrong-identity, bad-token, non-Ed25519 key,
  leaf-not-bound-to-KMS-key, and untrusted-client cases all reject with the
  correct frozen wire codes.
- One-command reproduction harness (`docs/security/gcloud-kms-validation.sh`).

## Not yet claimed

MCP-S does not currently claim:

- official MCP extension status;
- universal enterprise authorization (MCP-S binds authorization decisions; it
  does not interpret or replace an enterprise authz system);
- an EMA (enterprise-managed authorization) implementation;
- portable audit receipts;
- full SIEM / Security Command Center integration (the audit taxonomy is frozen
  and SCC-mappable, but the integration itself is unbuilt — Stages 2–3 of the
  Google validation plan);
- broad multi-cloud live validation: GCP Cloud KMS is live-proven; the AWS KMS
  adapter is shipped but **not** yet live-proven, so multi-cloud custody is not
  claimed until AWS is also live-proven;
- **zero-window certificate revocation.** Mode A enforces short-lived certs plus a
  static CRL that fails closed on staleness, and Mode C delivers dynamic mid-life
  revocation via the attestor's CRL (keyed on the client cert serial) — but online
  OCSP stays non-default, and revocation latency is bounded by the CRL cadence, not
  zero;
- OS-level sandboxing of wrapped servers, and signed tool-manifest enforcement
  (gated on the high-assurance cargo features — see the README deployment
  profiles);
- a **fully retired single-node ceiling.** The v0.10.1 fleet posture
  (ADR-MCPS-049) proves cross-replica replay and trust-revocation coherence, but
  the dedicated proof that a multi-round-trip continuation survives a replica switch
  (MCPS-82) and live multi-node (GKE) validation are still pending, so the
  single-node non-claim is lifted only conditionally, not fully retired.

## Proposal readiness

Before submitting MCP-S as an MCP extension proposal, ensure that the repository contains a clear specification, security boundary, test traceability document or manifest, runnable reference implementation, conformance vectors, demo evidence, explicit non-claims, and license/contribution files.
