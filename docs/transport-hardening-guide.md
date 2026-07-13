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
| **Authorization** | Phase-5 `PolicyEvaluator` | **may-act** — whether the actor is permitted to do this |

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
verified transport identity. Configure it with `--transport-binding`:

- **`exact`** (`ExactMatchBinding`, default) — the request `signer` must equal
  the verified transport identity (the key-holder is the cert-holder). A
  required-but-absent identity fails closed.
- **`none`** — no binding; the mTLS identity is ignored. Only for deployments
  where the channel identity is genuinely not the signer.

A third policy, `MappedBinding`, maps each `signer` to a set of allowed transport
identities (e.g. a DID signer permitted over one or more SPIFFE IDs). It is a
**strict, explicit allowlist**: matches are exact, byte-for-byte, case-sensitive
string equality — no wildcards, no globs, no regex (a literal `"*"` is just an
ordinary string). It is available in the library; the production CLI currently
wires `exact` or `none`. A failure of any policy is always
`mcp-re.transport_binding_failed`, emitted at the proxy (the only component holding
the connection).

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
  **Dev/CI only**, and refused unless `--allow-env-keysource` is passed, because
  env vars are visible to the process tree and leak via crash dumps, `ps e`, and
  `/proc/<pid>/environ`. `KeyError` values carry only the var NAME and the parse
  failure, never the secret bytes, so they are safe to log.

An **HSM/KMS-backed source is a documented future implementation** of the
`KeySource` trait — it does not exist today. This guide does not claim otherwise.

## Durable replay cache

Source: [`durable_replay.rs`](../mcp-re-proxy/src/durable_replay.rs).

Replay protection is keyed by the `(signer, audience, nonce)` triple (per
ADR-MCPS-006) and is invoked only after signature verification succeeds.
`--replay-cache`:

- **`memory`** (default) — fast, but lost on restart.
- **`file`** (requires `--replay-path`) — `DurableReplayCache`: survives process
  restarts on one host with no external service. State is persisted on every
  insert via temp-file + atomic rename, so a concurrent reader never sees a
  half-written file. A persistence failure surfaces as
  `mcp-re.replay_cache_unavailable` (fail closed) and the in-memory insert is rolled
  back so a transient failure can be retried.

Honest limits of the durable cache:

- It is **single-node**, not distributed. Two processes sharing one file is
  unsupported (last-writer-wins on rename can drop entries); pointing several
  nodes at one file does NOT protect against cross-node replay (each sees only
  its own file). A shared atomic backend (e.g. Redis) behind the same
  `mcp_re_core::ReplayCache` trait is a documented **future** backend.
- **External** rollback of the state file (snapshot restore, or a filesystem that
  loses the latest write) is NOT detected — there is no monotonic counter — and
  can reopen a replay window. Mitigate by keeping freshness windows short and not
  restoring the file from stale snapshots.

## Max client-certificate lifetime — the v1 revocation posture

Source: `ServerOptions::max_client_cert_lifetime` in [`tls.rs`](../mcp-re-proxy/src/tls.rs).

MCP-RE Core defines **no online revocation** — no CRL, no OCSP, no transparency
log (per the spec's trust-resolution section and ADR-MCPS-007). With no online
revocation, a compromised client certificate is usable until it expires. The v1
posture is therefore to ENFORCE **short-lived** client certs: the proxy rejects a
certificate whose validity span (`not_after - not_before`) exceeds the limit, or
whose validity cannot be parsed, with `mcp-re.transport_binding_failed`.

```text
--max-client-cert-lifetime 1h    # default; also accepts 30m, 3600, none
```

`none`/`0` disables the check (strongly discouraged — the CLI warns). The
exposure window of a compromised transport credential is bounded by this value;
the end-to-end request-authority exposure window is
`cert_lifetime + resolver_cache_ttl + request_lifetime + max_clock_skew`. CRL/OCSP
and an HSM-backed source are deferred enterprise capabilities, not part of the v1
claim.

## Production claim ceiling

Per ADR-MCPS-017 ([view](https://github.com/matssun/mcp-re/discussions/366)),
MCP-RE's production claim is bounded to a **single node**. Explicitly deferred
future seams — not part of the v1 claim — include: distributed/durable replay
backends (e.g. Redis), HSM/KMS-backed key sources, multi-node trust distribution,
online revocation (CRL/OCSP), horizontal scale, and a `ReverseProxyMtlsProvider`
(reverse-proxy header-injected identity). The serve loop is single-threaded and
the durable cache is single-node by design. Configure within this ceiling, and
treat anything beyond it as future work.
