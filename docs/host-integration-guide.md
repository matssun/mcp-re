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

## The two types

Source: [`mcp-re-host/src/`](../mcp-re-host/src/).

- **`HostSigner`** (`signer.rs`) — the local key/actor context. It owns the
  agent's Ed25519 signing key privately and turns a request into signed wire
  bytes.
- **`HostSession`** (`session.rs`, with `pending.rs`, `clock.rs`, `nonce.rs`) —
  a thin **stateful** layer over the unchanged signer. It stamps freshness,
  draws nonces, and correlates each response to the request it answers.

Both are **transport-free**: they produce and consume raw JSON-RPC bytes and add
no networking or async dependency. Sending the bytes is the caller's concern.

### The key never leaves the host

`HostSigner` exposes `signer()` and `key_id()` (public identities, not secrets)
but has **no accessor for the signing key** and never returns a detached
signature — only finished, signed wire bytes. Model logic that holds a
`HostSigner` can request a signed request but can neither read the key nor forge
a signature (ADR-MCPS-003: the model never holds keys). Do not add such an
accessor; the absence is a guaranteed invariant the tests rely on.

## Signing a request with `HostSession` (recommended)

`HostSession` is generic over an injected `Clock` and `NonceSource`. Use the
production providers (`SystemClock`, `SystemNonceSource`) in real deployments and
the deterministic providers (`FixedClock`, `SeededNonceSource`) in tests so
signed output is reproducible.

```rust
use mcp_re_host::HostSession;
use mcp_re_host::HostSigner;
use mcp_re_host::SystemClock;
use mcp_re_host::SystemNonceSource;
use mcp_re_core::SigningKey;
use serde_json::json;
use serde_json::Value;

// The host owns the agent's signing key (a 32-byte Ed25519 seed) privately.
let signing_key = SigningKey::from_seed_bytes(&seed_bytes);
let signer = HostSigner::new(signing_key, "did:example:agent-1", "key-1");

// Conservative default request lifetime (<= 5 min, ADR-MCPS-015). Use
// `HostSession::new(.., lifetime_secs)` to set an explicit lifetime.
let mut session = HostSession::with_defaults(signer, SystemClock::new(), SystemNonceSource::new());

let id: Value = json!("req-1");
let wire_bytes = session.sign_tool_call(
    &id,
    "search",                              // tool name
    json!({ "query": "rust" }),            // arguments
    "did:example:user-7",                  // on_behalf_of
    "did:example:server-1",                // audience (the intended verifier)
    "sha256:...",                          // authorization_hash (opaque binding)
)?;
// `wire_bytes` is a complete signed JSON-RPC request. Send it over your transport.
```

The session is the **sole author** of the envelope's `nonce`, `issued_at`, and
`expires_at` (drawn from the injected clock + RNG); any caller-supplied `_meta`
request block is overwritten by `HostSigner`. `sign_request` is the general form
when you are not making a `tools/call`.

### What the session stores

On a successful `sign_*`, the session computes the Core `request_hash` and stores
it keyed by the JSON-RPC `id`. Response verification later binds against this
**stored** hash — never a caller-supplied expected hash. This is the
request/response correlation mechanism.

## Verifying a response

```rust
use mcp_re_core::TrustResolver; // your resolver (e.g. InMemoryTrustResolver)

let verified = session.verify_response(&response_bytes, &resolver)?;
// `verified` is a VerifiedResponse; the pending entry for its id is now evicted.
```

`verify_response` extracts the response's JSON-RPC `id`, looks up the stored
`request_hash` for that id, and verifies the server signature **and** that the
response's `request_hash` equals the stored one. The `TrustResolver` is passed as
data per call (transport-free; the session holds no resolver).

## Rejection and cleanup behavior

The session fails closed in each of these cases — know them, because they are the
correlation contract:

| Situation | Result |
| --- | --- |
| Response signed over the **wrong** `request_hash` | rejected (`mcp-re.response_hash_mismatch`) even if the signature itself is valid |
| Response whose `id` was **never signed** (unknown id) | `mcp-re.missing_envelope` — no stored hash to bind against, so it refuses to trust the response |
| A second `sign_*` reusing an **in-flight** id | `mcp-re.replay_detected` — refuses to clobber the stored hash (which would let a response bind to the wrong request); the id is signable again only after eviction |

Eviction and introspection:

- A **fully verified** response evicts the pending entry; the id is then free to
  be reused. A **failed** verification leaves the entry in place, so a later,
  correctly-bound response can still verify.
- `cancel_request(&id)` drops one pending entry by id (`true` if present, else a
  no-op `false`).
- `expire_pending(now_unix)` drops every entry expired at `now_unix` and returns
  the count removed. Long-lived hosts call this periodically with the injected
  clock's `now` so abandoned requests do not accumulate. Expiry is inclusive of
  the request's `expires_at` instant.
- `pending_count()` returns the number of outstanding requests; `stored_request_hash(&id)`
  returns the stored hash for an id (for correlation tests / introspection).

## Using the bare `HostSigner`

If you manage freshness, nonces, and correlation yourself, call `HostSigner`
directly. You then supply `nonce`, `issued_at`, and `expires_at` explicitly and
must store the `request_hash` yourself for response verification (which you do
with the re-exported `mcp_re_core::verify_response`). Prefer `HostSession` unless
you have a specific reason not to — it exists precisely so callers do not
hand-roll these three responsibilities.

## What this proves — and what it does not

A verified response proves the JSON-RPC **signer** produced this exact object and
that it is bound to your request. It says nothing about transport peer identity
or authorization — those are separate, independent checks performed at the proxy
(see the [Transport Hardening Guide](transport-hardening-guide.md)). None of the
three replaces another.
