# MCP-RE Transport Hardening Guide

**Audience:** an operator or security reviewer who wants to understand and
configure the Phase-6 transport hardening of the `mcp-re-proxy` sidecar — mTLS,
transport binding, key sourcing, and durable replay protection — and what each
check does and does not prove.

This guide explains **how to use** the transport-hardening features. The rules
are in the [MCP-RE Core Specification](spec/mcp-re-core-spec.md);
the rationale is in ADR-MCPS-014
([view](https://github.com/matssun/mcp-re/discussions/363), Rust-native transport
hardening) and ADR-MCPS-017
([view](https://github.com/matssun/mcp-re/discussions/366), single-node
production claim ceiling). The proofs are the `//mcp-re-proxy:*`
test targets in the [conformance manifest](../mcp-re-conformance/conformance_manifest.json).
For the full CLI flag reference, see the
[Sidecar Deployment Guide](sidecar-deployment-guide.md).

## Three independent checks — none replaces another

This is the most important idea in this guide. The proxy performs three separate
verifications, each answering a different question:

| Check | Mechanism | What it proves |
| --- | --- | --- |
| **mTLS** | rustls client-cert verification | the **transport peer** — which channel the request arrived on |
| **Message signature** | RFC 9421 HTTP Message Signature + RFC 9530 Content-Digest (`mcp-re-http-profile`) | the **request signer** — who produced this exact message |
| **Authorization** | none active — `--authz reference` is refused at configuration | **may-act** — whether the actor is permitted to do this. MCP-RE does not answer this today; the reference profile was bound to the retired object carrier and must be rebuilt on HTTP-profile request evidence. Authorize upstream of the proxy. |

These are orthogonal. mTLS does not prove who signed the message; a valid message
signature does not prove which channel it came over; neither proves the actor is
authorized. **Transport binding** (below) is what ties the first two together by
asserting the signer and the transport peer are consistent. Do not treat any one
as a substitute for another.

## mTLS via `RustlsDirectProvider`

Source: [`tls.rs`](../mcp-re-proxy/src/tls.rs).

The proxy terminates TLS **itself** with `rustls` (the `ring` crypto provider,
installed explicitly — no process-global default). It REQUIRES and verifies a
client certificate against the configured client-CA trust anchors
(`WebPkiClientVerifier`); a missing or untrusted client certificate fails at the
handshake (fail closed). Streamable HTTP here is single-request-per-connection
JSON (one POST in, one JSON response out) — SSE streaming is intentionally not
implemented.

Configure it with the key-material flags and the client-CA:

```text
--tls-cert <chain.pem>     # server certificate chain (leaf first)
--tls-key  <server.pem>    # server private key
--client-ca <ca.pem>       # client-CA trust anchors for mTLS verification
```

The verified client identity is extracted from the leaf certificate using the
**authoritative** field you select — with **no fallback**:

```text
--transport-identity-source uri_san   # URI SAN (SPIFFE-style), recommended default
--transport-identity-source dns_san   # DNS SAN
--transport-identity-source cn_legacy # Common Name — LEGACY, deprecated, warns
```

If the selected field is absent from the certificate, identity extraction returns
nothing and the (required) binding fails closed — a missing URI SAN is **never**
silently downgraded to a DNS SAN or CN.

## Transport binding

Source: [`transport.rs`](../mcp-re-proxy/src/transport.rs).

The binding policy asserts the request's verified `signer` is consistent with the
verified transport identity.

**`--transport-binding exact` is the default and the only deployable value.** The
request `signer` must equal the verified transport identity (the key-holder is the
cert-holder), and a required-but-absent identity fails closed. The parser accepts two
other values — `lb-assertion` (Mode B) and `attested-ingress` (Mode C) — and the
validation boundary refuses both; they are retained and tested, not deployable.

**There is no value that turns binding off.** `--transport-binding none` is not
accepted by the parser, and `BindingKind::None` is refused at validation, so a
programmatically built configuration cannot reach the serving path with the mTLS
identity ignored either.

**The binding is not caller-supplied.** `HttpProfileProxy` takes a `TransportBinding`
— a value only this crate constructs, from a channel-binding state the configuration
owner recognised — and the one public way to install it is
`with_exact_match_transport_binding()`. A `Box<dyn TransportBindingPolicy>` parameter
would have stated only that *some* rule runs, which is satisfied equally by a rule that
admits every request; possession of a `TransportBinding` states *which* rule.

`MappedBinding` maps each `signer` to a set of allowed transport identities (e.g. a DID
signer permitted over one or more SPIFFE IDs). It is a **strict, explicit allowlist**:
matches are exact, byte-for-byte, case-sensitive string equality — no wildcards, no
globs, no regex (a literal `"*"` is just an ordinary string). No configuration selects
it and the serving path never constructs it, so it is a library type with no deployment
route.

A failure of any binding is always `mcp-re.transport_binding_failed`, emitted at the
proxy (the only component holding the connection).

## KeySource

Source: [`key_source.rs`](../mcp-re-proxy/src/key_source.rs).

A sidecar needs three pieces of material: the Ed25519 **signing key** (a 32-byte
seed, Base64URL-no-pad), the **TLS server certificate chain + key** (PEM), and
the **client-CA trust anchors** (PEM). Two sources implement the `KeySource`
trait:

- **`FileKeySource`** (`--key-source file`, default) — reads from disk. Use this
  in production with `0600` permissions; the CLI warns about group/world-readable
  key files.
- **`EnvKeySource`** (`--key-source env`) — reads from environment variables.
  **Dev/CI only**, and compiled in only under the non-default `dev_env_key_source`
  cargo feature: a production build has no `env` option at all and rejects the value
  as unknown. Env vars are visible to the process tree and leak via crash dumps,
  `ps e`, and `/proc/<pid>/environ`, so this is a build-time decision rather than a
  runtime one. `KeyError` values carry only the var NAME and the parse
  failure, never the secret bytes, so they are safe to log.

**HSM/KMS-backed sources** now implement the `KeySource` trait — PKCS#11, AWS
KMS, and GCP KMS adapters selected with `--key-source` — each behind its own
build feature, so a default build parses the flag but fails closed at
construction. GCP-KMS custody has been exercised on live GKE via Workload
Identity (v0.12.1). A non-exporting device never surrenders the private key; the
proxy drives it through the `ResponseSigner` seam.

## Replay protection

Source: [`shared_replay.rs`](../mcp-re-proxy/src/shared_replay.rs),
[`replay_tier.rs`](../mcp-re-proxy/src/replay_tier.rs).

Replay protection is keyed by the `(signer, audience, nonce)` triple (per ADR-MCPS-006)
and is invoked only after signature verification succeeds, so invalid-signature garbage
can never burn a legitimate nonce. A nonce need only be remembered until its request can
no longer pass the freshness window, which is what bounds the store.

Every replay store is shared. There is no backend-kind flag: `--replay-durability-tier`
names the guarantee, and its locator (`--replay-redis-url` or `--cpstore-etcd-endpoint`)
names the store that must deliver it. A deployment declaring no tier does not start —
there is no node-local cache to fall back to, because a node-local cache cannot see a
request replayed to a peer verifier within the acceptance window.

The tier is a **deployment assertion**: the proxy enforces what it controls (issuing
`WAIT` and failing closed on insufficient acks) and surfaces the tier, but it cannot
prove every external store-topology property. Two tiers meet the strict-production
minimum — `redis-wait-quorum:<quorum>:<timeout_ms>` and `linearizable`. The weaker two
parse but are refused as deployment states.

## Certificate revocation — three planes, and the short-lived-cert baseline

Source: `ServerOptions::max_client_cert_lifetime` in [`tls.rs`](../mcp-re-proxy/src/tls.rs).

Revocation lives on three separate planes; do not conflate them:

1. **TLS/mTLS certificate revocation** — a transport-hardening concern. For
   deployments that use mTLS identity, the proxy enforces **static CRLs**, which
   fail closed on staleness, alongside the short-lived-cert ceiling below. Online
   OCSP is refused in every v0.16 build: it is implemented only against the blocking
   serve loop, and the production data plane is the per-core async fleet, which
   performs no responder round trip.
2. **MCP-RE signer/key revocation** — the runtime-evidence plane. MCP-RE Core / the
   HTTP profile does **not** use OCSP; it verifies RFC 9421 signatures, the RFC 9530
   `Content-Digest`, actor trust resolution, artifact bindings, replay, response
   binding, and continuation binding. A compromised or rotated *actor signing key* is
   revoked through the **trust resolver / key policy** (per the spec's
   trust-resolution section and ADR-MCPS-007), never a certificate mechanism.
3. **OAuth/token revocation** — a separate authorization-server / introspection /
   token-policy concern, outside MCP-RE. MCP-RE **binds** an authorization artifact;
   it does not interpret or revoke it.

Where an ingress or attestor performs mTLS revocation checking, that result may be
recorded or bound as ingress/attestor evidence (Mode C) — but it is transport
evidence, not part of the MCP-RE object-evidence protocol.

### Revocation on a connection the peer already holds

rustls consults the CRLs during client authentication, and client authentication runs
on a **full handshake only**. A keep-alive or HTTP/2 connection then serves every
later request without the verifier being consulted again — so a peer added to a
reloaded CRL kept full authenticated access for as long as it did not reconnect, and
`--client-crl-reload-secs` reached new connections alone.

The serving path therefore re-checks the peer certificate on **every request**, not
only at the handshake:

* its **validity window** (`notBefore`/`notAfter`) against the clock; and
* its **serial** against the CRLs in force right now, when CRLs are configured —
  `client_revocation.rs`, an index rebuilt from the same bytes as the verifier on each
  reload and swapped atomically, so a refreshed CRL reaches requests being served on
  open connections.

The per-request verdict rules mirror the handshake's deliberately, including
deny-on-unknown-status and treating a CRL past its `nextUpdate` as covering nothing.
With no CRLs configured rustls performs no revocation checking, and neither does this
— the request path is unchanged.

Two bounds remain, and they are narrower than before:

* `--max-connection-age-secs` (default 300s) bounds **chain re-validation**. Chain
  building happens at the handshake, so a withdrawn or expired client CA reaches an
  established connection only when the peer re-handshakes.
* TLS session resumption is **bound to the trust epoch** (ADR-MCPRE-055). A resumed
  session restores the stored peer chain and skips client auth entirely, and the
  per-request checks cover validity and revocation but not the chain — so resumption is
  gated on a digest of the trusted client-CA set and the client-auth policy, the inputs
  chain building depends on. While that digest holds, a stored chain is one the current
  trust would still build; when a CA is withdrawn it changes and every stored session
  stops being a shortcut. CRL contents are deliberately NOT in the digest: revocation is
  already enforced per request, and a re-signed CRL would otherwise tear down every
  connection on each reload.

**This is what makes warm connections safe to keep.** A deployment holding connections
open pays the full handshake once per connection rather than once per request, and an
expired or revoked credential is still caught on the next request rather than at the
next handshake.

**The short-lived-cert baseline (plane 1).** Independent of OCSP/CRL, the proxy
enforces **short-lived** client certs: it rejects a certificate whose validity span
(`not_after - not_before`) exceeds the limit, or whose validity cannot be parsed,
with `mcp-re.transport_binding_failed`.

```text
--max-client-cert-lifetime 1h    # default; also accepts 30m, 3600, none
```

`none`/`0` disables the check (strongly discouraged — the CLI warns). The exposure
window of a compromised transport credential is bounded by this value; the
end-to-end request-authority exposure window is
`cert_lifetime + resolver_cache_ttl + request_lifetime + max_clock_skew`. HSM/KMS-backed
key sources are shipped behind their build features — see the deployment profiles in
the README.

## Production claim

The single-node-only ceiling of ADR-MCPS-017 is **superseded by ADR-MCPS-049**
([view](https://github.com/matssun/mcp-re/discussions/397)): MCP-RE's production
claim is **tiered** — a single-node floor, plus, at the declared shared,
quorum-durable replay tier, horizontally-scaled multi-node fleets within one trust
domain / one operator (`--fleet` fails closed on a node-local cache), proven live on
GKE. The serve loop is the **async per-core fleet** of ADR-MCPRE-051 (no longer
single-threaded). The former "deferred future seams" have shipped: distributed
replay (Redis), HSM/KMS-backed key sources (GCP live-proven, including on GKE via
Workload Identity), multi-node trust distribution, and online revocation (CRL/OCSP).
For the exact current claim and its bounds see
[`docs/PROJECT_STATUS.md`](PROJECT_STATUS.md).
