# MCP-RE Host Integration Guide

**Audience:** an engineer integrating an MCP **host / client** (the agent's local
ambassador) so it signs MCP-RE requests and verifies the bound responses.

This guide explains **how to use** the `mcp-re-host` crate. The rules it enforces
are in the [MCP-RE Core Specification](spec/mcp-re-core-spec.md);
the rationale is in ADR-MCPS-003
([view](https://github.com/matssun/mcp-re/discussions/352), signing locus) and
ADR-MCPS-015 ([view](https://github.com/matssun/mcp-re/discussions/364),
client host-session architecture). The proofs are the
`//mcp-re-host:*` test targets (see the
[conformance manifest](../mcp-re-conformance/conformance_manifest.json)).

## What the crate contains

Source: [`mcp-re-host/src/`](../mcp-re-host/src/).

- **`HostSigner`** (`signer.rs`) — the local key/actor context. It owns the
  agent's Ed25519 signing key privately and turns a request into a
  [`SignedRequest`] over the RFC 9421 carrier.
- **`Clock` / `NonceSource`** (`clock.rs`, `nonce.rs`) — the two injected
  freshness inputs, with the production providers `SystemClock` and
  `SystemNonceSource` and the deterministic `FixedClock` / `SeededNonceSource`
  behind the `test-fixtures` feature.
- The response side is **re-exported**, not reimplemented: `verify_delegated_response`,
  `ResponseExpectation`, `DelegationPolicy`, `RevocationSource` and friends come
  from `mcp-re-client-core`.

There is **no session type.** A stateful `HostSession` with a pending-request map
existed on the deleted draft-01/object model and was not rebuilt on RFC 9421; the
correlation it provided is now carried by the protocol itself (see *How a response
is correlated*, below). Do not look for `session.rs`, `pending.rs` or
`verified_result.rs` — they are gone, not deferred.

`HostSigner` is **transport-free**: it produces bytes and adds no networking or
async dependency. Sending them is the caller's concern.

### The key never leaves the host

`HostSigner` exposes `signer()` and `key_id()` (public identities, not secrets)
but has **no accessor for the signing key** and never returns a detached
signature — only a finished `SignedRequest`. Model logic that holds a
`HostSigner` can request a signed request but can neither read the key nor forge
a signature (ADR-MCPS-003: the model never holds keys). Do not add such an
accessor; the absence is a guaranteed invariant the tests rely on.

## Signing a request

The caller supplies the nonce and the freshness window explicitly. That is the
whole contract — there is no layer that fills them in for you, and injecting them
is what lets a deployment choose its own entropy and clock sources.

```rust
use mcp_re_host::HostSigner;
use mcp_re_host::SystemClock;
use mcp_re_host::Clock;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::AudienceTuple;
use mcp_re_core::SigningKey;
use serde_json::json;
use serde_json::Value;

// The host owns the agent's signing key (a 32-byte Ed25519 seed) privately.
let signing_key = SigningKey::from_seed_bytes(&seed_bytes);
let signer = HostSigner::new(signing_key, "did:example:agent-1", "key-1");

let created = SystemClock::new().now_unix();
let expires = created + 300;            // <= 5 min (ADR-MCPS-015)
let nonce = mcp_re_client::next_nonce(); // 128-bit floor, Base64URL-no-pad

let id: Value = json!("req-1");
let signed = signer.sign_tool_call(
    &id,
    "search",                                  // tool name
    json!({ "query": "rust" }),                // arguments
    "https://mcp.example.com/mcp",             // canonical @target-uri
    audience,                                  // AudienceTuple
    artifact_bindings,                         // Vec<ArtifactBinding>, non-empty
    &nonce,
    created,
    expires,
)?;
// `signed.request()` is the signed HTTP request to send; `signed.body()` its bytes.
```

`sign_request` is the general form when you are not making a `tools/call`.

`HostSigner` is the **sole author** of the request's `Content-Digest`,
`Signature-Input` and `Signature`; a caller-supplied value for any of them is
overwritten, so the emitted evidence always matches the bytes actually carried.

The working in-tree example of exactly this wiring is `mcp-re-client`:
`next_nonce` draws over `SystemNonceSource`, and `ServeContext::for_local_config`
reads `SystemClock`'s `now_unix` when it builds the serving context.

## Verifying a response

Verification is **delegated-required**: a response signed directly by a root key
fails closed, and there is no second entry point that would accept one.

```rust
use mcp_re_host::verify_delegated_response;
use mcp_re_host::DelegationPolicy;
use mcp_re_host::ResponseExpectation;

let expectation = ResponseExpectation::for_signed(&signed);
let verified = verify_delegated_response(
    &response,          // the HttpResponse received
    &trust,             // your DelegatedResponseTrust
    &expectation,
    &DelegationPolicy::default(),
    now_unix,
)?;
```

### How a response is correlated

`ResponseExpectation::for_signed(&signed)` carries **the request you signed**, and
the response's `;req` covered components resolve against it. Correlation is
therefore cryptographic rather than bookkeeping: the client does not look a hash
up in a map keyed by JSON-RPC `id`, it re-derives the request's signature base and
the response either verifies against that base or it does not.

The consequence worth internalising: a valid response for exchange A **cannot**
verify as the answer to a different exchange A′, because A′ carries a different
nonce and therefore a different signature base. Splicing fails at the floor, not
at an application-level check that could be forgotten.

Pin the credential **issuer** with `ResponseExpectation`'s expected-issuer field
when policy requires it. Do not pin the delegated response-signing kid: it is an
RFC 7638 thumbprint that rotates every TTL by design, so pinning it would fail on
the first rotation and would say nothing about server identity.

## What this proves — and what it does not

A verified response proves the delegated **signer** produced this exact object,
under a credential chaining to a trusted anchor, and that it is bound to your
request. It says nothing about transport peer identity or authorization — those
are separate, independent checks performed at the proxy (see the
[Transport Hardening Guide](transport-hardening-guide.md)). None of the three
replaces another.
