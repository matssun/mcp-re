<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Project Status

## Current status

MCP-RE is an experimental third-party security extension proposal for MCP.

It is not an official MCP extension unless accepted through the official MCP governance and proposal process.

**Current release: v0.12.1** (2026-07-14) — the first live
KMS-via-Workload-Identity GKE run, over the HTTP-profile serving stack landed in
v0.11–v0.12. The sole over-the-wire carrier is the **RFC 9421 HTTP Message
Signatures + RFC 9530 Content-Digest** profile (`mcp-re-http-v1`, ADR-MCPRE-050);
the earlier native/object envelope (Ed25519-over-JCS `_meta`, draft-01/draft-02)
and the stdio transport were **removed**, not kept as fallbacks. Response signing
is **delegated-required only** (ADR-MCPRE-052): a root key in HSM/KMS issues
short-TTL delegated signing keys, and direct-root response signing was deleted
from the runtime surface. Per-release detail is in [`CHANGELOG.md`](../CHANGELOG.md);
the design lines are in the [ADR discussions](https://github.com/matssun/mcp-re/discussions?discussions_q=label%3Aadr).

## Current implementation claim

The current implementation may claim:

> MCP-RE is production-hardened for single-node Rust-native deployments over the
> RFC 9421 + RFC 9530 HTTP profile with delegated-required response signing, and —
> for a deployment that declares the shared, quorum-durable replay tier and the
> four deployment modes — for horizontally-scaled multi-node fleets within one
> trust domain / one operator, at the security tier composed from those modes
> (proven live on a 2-node GKE cluster, v0.11, with KMS custody via Workload
> Identity added in v0.12.1).

This claim is tiered: single-node is the unconditional floor; the multi-node
extension holds only at the declared shared-tier profile (`--fleet` fails closed on a
node-local cache). It should not be broadened — in particular to unconditional
multi-node replay safety — without additional implementation, tests, and documentation.

## Demonstrated capabilities

The current demonstration and live-validation package proves:

### HTTP-profile end-to-end path (v0.11)

- A plain-MCP client speaks ordinary MCP over one signed mTLS POST to a local
  client-side proxy / SDK transport; the request is signed under the RFC 9421 HTTP
  profile (RFC 9530 `Content-Digest` over the body `_meta`);
- `mcp-re-proxy` runs the RFC 9421 `HttpProfileProxy` serving path
  (ADR-MCPRE-051): it verifies the request signature, freshness/replay, transport
  binding, and delegated authorization before dispatch;
- caller-supplied verified context is stripped, sidecar-owned context injected;
- the inner MCP server is reached over HTTP; denied requests never reach it;
  the response is **delegated-signed** and bound to the request evidence, and the
  client verifies both the response signature and the delegation credential.
- A stdio-only MCP server is fronted by an external plain-MCP adapter (e.g. FastMCP)
  that speaks HTTP to the proxy — stdio is out of scope for MCP-RE itself.

### Delegated signing custody (v0.11 / v0.12)

- **Delegated-required is the only response-signing mode.** A root key
  (HSM/KMS-held, non-exporting) issues a short-TTL JOSE/JWS delegation credential
  for an in-memory delegated key that signs each response; rotation overlap and a
  fail-closed issuance path are wired, and direct-root response signing is gone from
  the runtime surface (ADR-MCPRE-052).
- 22 golden delegation vectors (d01–d22) plus an independent python-cryptography
  JOSE cross-verify gate (both directions) are CI-wired.
- **mTLS transport binding (RFC 8705 `x5t#S256`)** is proven over a real mutual-TLS
  handshake against the production stack: the request's own channel accepts; a
  relayed request over another valid channel fails closed.

### Client SDKs — Python and TypeScript, HTTP-profile (v0.11)

- Both SDKs bind the SAME audited `mcp-re-client-core` (Python via maturin/PyO3,
  TypeScript via napi-rs) and are retargeted to the HTTP profile, so the signed
  RFC 9421 signature base is byte-identical across languages. Live cross-process
  e2es run against the real `mcp-re-proxy` fronting an in-process HTTP MCP backend.
  Non-exporting custody (HSM/KMS-style callback signer) is proven byte-identical to
  the direct software path.

### Stateless multi-round-trip continuation (v0.8)

- Request-associated elicitation folded into strict MCP-RE as signed
  multi-round-trip continuation evidence (ADR-MCPS-047), fail-closed on arbitrary
  server push.

### Enterprise ingress — two honest postures (v0.9 / v0.10)

- **Mode A (`end_to_end_mtls`, default)** — the node terminates client mTLS and
  binds the verified peer to the request signer, with a certificate-revocation
  honesty pass: a strict short-lived-cert lifetime ceiling and static-CRL
  fail-closed-on-stale (ADR-MCPS-023 §A1). OCSP, when enabled, is always fail-closed
  as of v0.12.0 (the fail-open relaxation was removed).
- **Mode C (`attested_ingress`, explicit opt-in)** — a controlled ingress attestor
  signs a request-bound `mcp-re/lb-ingress-assertion/v2` assertion the node verifies
  over a pinned attestor→node channel. This is **attested delegation**, NOT
  end-to-end mTLS (the load balancer witnesses proof-of-possession and stays in the
  trusted computing base); the node binds the assertion (bind-not-interpret) and
  records three trust facts. The forwarded request is byte-identical to Mode A. See
  the non-normative [Google Cloud cookbook](mode-c-attested-ingress-gcp-cookbook.md).

### Horizontally-scaled fleet deployment (v0.10.1) + live GKE validation (v0.11 / v0.12.1)

MCP-RE runs as N identical replicas behind a load balancer with no security claim
weakened, behind an explicit `--fleet` flag orthogonal to `--strict`
(ADR-MCPS-049). The fleet composes, *proves*, and documents the node-local
coherence guarantees:

- **Cross-replica replay coherence** — `--fleet` rejects node-local (memory/file)
  replay caches; a replica must use a shared, cross-replica ReplayCache (Redis). A
  two-replica e2e proves a nonce accepted by one replica is rejected by a sibling
  (MCPS-79/80/81).
- **Cross-replica trust revocation** — a Redis-backed trust-epoch source flushes the
  ADR-021 Push-tier trust cache across replicas on an epoch advance, reverting to the
  bounded-staleness guarantee on a read outage, with explicit per-tier
  revocation-lag bounds. An e2e proves a revocation reaches a sibling, with a
  negative control (MCPS-84/85/86).
- **Fleet operations** — session affinity for stateful inner backends; a bounded
  graceful `SIGTERM`/`SIGINT` drain of in-flight requests for rolling deploys
  (ADR-MCPRE-051 §6); a concurrent-TLS-client load harness reporting p50/p99/p999
  against the declared envelope (ADR-MCPRE-051 §7).
- **Kubernetes / Helm reference** — an HTTP-profile-only chart (`strict` + `fleet`,
  fail-safe defaults, gcpKms Workload-Identity custody), with a fail-closed guardrail
  that refuses a `--fleet` deployment wired to a weak (node-local) tier.
- **Live GKE validation** — the fleet was stood up on a real GKE cluster: a
  cross-replica replay-coherence proof (nonce admitted on replica A → rejected on B
  via the shared tier), and in v0.12.1 the **first live KMS-via-Workload-Identity
  run**, which surfaced and fixed a real on-GKE custody bug (the WI metadata token
  URL). The ADR-MCPRE-051 §7 SLO baseline is **measured, declared, and gated** on
  the delegated-required serving path — **395.6 rps (e2-standard-8) / 492.9 rps
  (c3-standard-8) at 8 cores**, both PASS. Runbook:
  [`docs/security/gke-slo-baseline-runbook.md`](security/gke-slo-baseline-runbook.md).

### Live Google Cloud KMS validation

- **Object/response signing against real Cloud KMS** (`EC_SIGN_ED25519`): signatures
  produced by a live `asymmetricSign` and verified by `mcp-re-core`; the private key
  never leaves KMS (`getPublicKey`/`asymmetricSign` only), and on GKE the proxy
  resolves the key through Workload Identity (v0.12.1).
- **Delegated TLS server-signing against real Cloud KMS**: a fully-validating rustls
  mTLS handshake completes only because a live KMS `asymmetricSign` produced the
  `CertificateVerify`; the TLS private key lives entirely in KMS.
- **Fail-closed negative lanes**: wrong-identity, bad-token, non-Ed25519 key,
  leaf-not-bound-to-KMS-key, and untrusted-client cases all reject with the correct
  frozen wire codes.
- One-command reproduction harness (`docs/security/gcloud-kms-validation.sh`).

## Not yet claimed

MCP-RE does not currently claim:

- official MCP extension status;
- universal enterprise authorization (MCP-RE binds authorization decisions; it
  does not interpret or replace an enterprise authz system);
- an EMA (enterprise-managed authorization) implementation;
- portable audit receipts;
- full SIEM / Security Command Center integration (the audit taxonomy is frozen
  and SCC-mappable, but the integration itself is unbuilt);
- broad multi-cloud live validation: GCP Cloud KMS is live-proven (including on GKE
  via Workload Identity); the AWS KMS adapter is shipped with its live lane written
  but **not** yet run against real AWS KMS, so multi-cloud custody is not claimed
  until AWS is also live-proven;
- **topology-independent zero-drop rolling updates.** The graceful-drain path is
  clean in-process and on kind, but the live GKE rolling-update proof has a known
  residual — a rollout dropped **2 of 590** in-flight requests through a real L4
  `LoadBalancer` (a GKE kube-proxy endpoint-propagation timing gap), tracked as a
  follow-up (likely a longer `drainPreStopSeconds`). Zero-drop under an arbitrary L4
  load balancer is therefore **not** claimed; any zero-drop statement is bounded to
  a declared, validated topology and drain configuration;
- **zero-window certificate revocation.** Mode A enforces short-lived certs plus a
  static CRL that fails closed on staleness, and Mode C delivers dynamic mid-life
  revocation via the attestor's CRL — but revocation latency is bounded by the CRL
  cadence, not zero;
- OS-level sandboxing of wrapped servers, and signed tool-manifest enforcement
  (gated on the high-assurance cargo features — see the README deployment profiles);
- **unconditional (zero-configuration) multi-node replay safety.** The
  horizontally-scaled claim (ADR-MCPS-049) holds only for a deployment that declares
  the shared, quorum-durable replay tier — `--fleet` fails closed on a node-local
  cache. Within that declared tier the single-node ceiling is retired (the
  MRT-survives-replica-switch proof, MCPS-82, and live 2-node GKE validation,
  MCPS-90). Zero-window revocation and cross-replica inner-session replication remain
  non-claims.

## Proposal readiness

Before submitting MCP-RE as an MCP extension proposal, ensure that the repository contains a clear specification, security boundary, test traceability document or manifest, runnable reference implementation, conformance vectors, demo evidence, explicit non-claims, and license/contribution files.
