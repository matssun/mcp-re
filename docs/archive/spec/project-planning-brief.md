# MCP-RE Project Planning Brief

## A Zero Trust Security Profile for the Model Context Protocol

**Status:** Planning Draft
**Working name:** MCP Runtime Evidence (MCP-RE)
**Initial implementation language:** Rust
**Initial crate family:** `mcp-re-core`, `mcp-re-proxy`, `mcp-re-host`, `mcp-re-conformance`
**Current objective:** Prepare the project for engineering planning, implementation scoping, and open-source discussion.

> **Profile status (ADR-MCPRE-050).** This document describes the MCP-RE **native /
> object profile** (JCS canonicalization, `_meta` envelope). That profile is
> **DEPRECATED** — not a security mechanism, not an alternative carrier, not a
> fallback. The one live security carrier is the RFC 9421 + RFC 9530 HTTP profile
> (`mcp-re-http-profile`). This brief is retained as historical background; see
> [../../CURRENT_ARCHITECTURE.md](../../CURRENT_ARCHITECTURE.md) and the
> [Active Profile Boundary and Legacy Quarantine](../../design/active-profile-and-legacy-quarantine.md)
> note. Do not treat any JCS/object material here as current design.

---

## 1. Executive Summary

MCP-RE is proposed as a hardened, transport-agnostic security profile for the Model Context Protocol.

The goal is not to replace MCP. The goal is to make MCP usable in production-grade agent systems where tool calls must be attributable, tamper-evident, replay-protected, auditable, and eventually bound to delegated authority.

The core design decision is:

> MCP-RE secures the MCP JSON-RPC object itself, not only the transport.

This is necessary because MCP supports both local `stdio` and remote Streamable HTTP transports. HTTP headers alone cannot secure stdio-based MCP. MCP-RE therefore places a signed security envelope inside MCP request and response metadata, making the invocation self-protecting across transports.

The first implementation should focus narrowly on **MCP-RE Core**:

* signed MCP requests;
* signed MCP responses;
* deterministic JSON canonicalization;
* Ed25519 signature verification;
* actor/key binding through a trust resolver;
* audience binding;
* nonce and expiry checks;
* batch rejection;
* fail-closed behavior;
* conformance test vectors.

Delegated authorization, Biscuit/UCAN token evaluation, mTLS binding, sandboxing, audit ledgers, and human approval flows are important follow-on work, but they should not be included in the first implementation milestone.

---

## 2. Problem Statement

MCP gives agents and LLM hosts a standard way to discover and invoke tools, resources, and prompts. However, ordinary MCP does not yet provide a complete protocol-level Zero Trust security model for high-assurance, multi-agent, cross-domain, or enterprise deployments.

The main risks are:

1. **Unattributed tool calls**
   A tool invocation may not be cryptographically bound to a specific actor identity.

2. **Transport-specific security gaps**
   HTTP-layer controls do not apply to stdio. A secure MCP profile must work across both local and remote transports.

3. **Request tampering**
   An intermediary or compromised local component could alter a tool name, resource identifier, argument, or correlation ID unless the whole JSON-RPC object is signed.

4. **Response tampering and context poisoning**
   Tool outputs become model context. They should be attributable and tamper-evident before being given to an agent or LLM.

5. **Replay attacks**
   A previously valid invocation could be replayed unless nonces, expiry, and optional sequence checks are enforced.

6. **Confused deputy risks**
   Sidecars can protect the MCP boundary, but downstream systems also need verified identity and authorization context.

7. **Lack of conformance tests**
   Without canonical test vectors, multiple implementations can each appear correct while failing interoperability.

---

## 3. Project Goal

The project goal is to define and implement an MCP-RE Core profile that can be proposed to the open-source MCP community.

The first project outcome should be:

> A Rust implementation and conformance suite proving that MCP JSON-RPC requests and responses can be signed, verified, replay-protected, and rejected fail-closed across stdio and Streamable HTTP.

---

## 4. Scope

### 4.1 In Scope for MCP-RE Core

MCP-RE Core includes:

* transport-agnostic request security envelope;
* transport-agnostic response security envelope;
* deterministic RFC 8785/JCS canonicalization;
* `Ed25519` request and response signatures;
* Base64URL without padding for signatures and hashes;
* SHA-256 hash identifiers using `sha256:<base64url-no-padding>`;
* actor/key resolution through a local trust resolver;
* `on_behalf_of` as a signed structural binding;
* `capability_hash` as a signed opaque structural binding;
* audience binding;
* nonce and expiry checks;
* JSON-RPC `id` included in the signature preimage;
* signed responses for verified requests;
* rejection of JSON-RPC batch messages;
* prohibition of security-relevant JSON-RPC notifications;
* standardized JSON-RPC error objects;
* conformance vectors and black-box tests.

### 4.2 Explicit Non-Goals for MCP-RE Core

MCP-RE Core does not define:

* full delegated authorization semantics;
* Biscuit, UCAN, macaroon, or OAuth token validation;
* mTLS requirements;
* MLS group messaging;
* VAEP-style event ledgers;
* Merkle transparency logs;
* human approval UX;
* agent memory;
* sandboxing or kernel enforcement;
* prompt-injection elimination.

These belong in later profiles or adjacent systems.

---

## 5. Relationship to VAEP

The earlier VAEP discussion was useful because it identified the broader trust model: signed events, provenance, delegated authority, auditable actions, and human-agent collaboration.

However, MCP-RE should not try to implement VAEP.

The correct relationship is:

* **VAEP**: broader agent communication, memory, audit, and human-decision substrate.
* **MCP-RE**: narrower hardened profile for MCP tool/resource/prompt invocation.

MCP-RE events may later be recorded into a VAEP-style ledger, but that is not part of MCP-RE Core.

---

## 6. Core Design Decisions

### 6.1 Extension Identifier

During incubation, examples use:

```text
com.example/mcp-re-security
```

This identifier is only valid for examples and non-public conformance fixtures.

Before public release, it must be replaced by a controlled reversed-domain identifier, for example:

```text
org.<controlled-domain>/mcp-re-security
se.<controlled-domain>/mcp-re-security
com.<controlled-domain>/mcp-re-security
```

The Rust crate should remain named separately:

```text
mcp-re-core
```

The protocol extension should not be named after the implementation crate.

---

### 6.2 Metadata Keys

Request metadata key:

```text
com.example/mcp-re-security.request
```

Response metadata key:

```text
com.example/mcp-re-security.response
```

These keys are placeholders until a controlled public extension identifier is chosen.

---

### 6.3 Signature Algorithm

MCP-RE Core defines only:

```text
alg = "Ed25519"
```

The Ed25519 signature is computed over the RFC 8785/JCS canonical UTF-8 byte sequence directly.

Pre-hashing is forbidden for `alg = "Ed25519"`.

Unknown algorithms must be rejected unless explicitly negotiated by a future profile.

---

### 6.4 Canonicalization Rule

For request signing:

1. Start with the complete MCP JSON-RPC request object.
2. Ensure the MCP-RE request envelope is present.
3. Ensure `signature.alg` and `signature.key_id` are present.
4. Ensure `signature.value` is absent.
5. Canonicalize the complete JSON-RPC object using RFC 8785/JCS.
6. Sign the resulting UTF-8 byte sequence directly with Ed25519.
7. Insert the resulting Base64URL-without-padding signature into `signature.value`.

For request verification:

1. Parse the complete MCP JSON-RPC request object.
2. Extract and retain `signature.value`.
3. Remove `signature.value`.
4. Canonicalize the transformed object using RFC 8785/JCS.
5. Resolve `(actor, key_id)` to a public key.
6. Verify the signature over the canonical byte sequence.

The same transformation applies symmetrically to signed responses.

The complete JSON-RPC object is signed, not merely the MCP-RE envelope. This means the tool name, arguments, ordinary MCP metadata, JSON-RPC `id`, and MCP-RE metadata are all integrity-protected.

---

### 6.5 Hash Format

All hashes use:

```text
sha256:<base64url-no-padding>
```

Example:

```text
sha256:4YRTQPdgAvwKnmzU67RAKWhs8frL7MKL8C7C3pvlHIY
```

---

### 6.6 Request Hash

A signed response includes `request_hash`.

`request_hash` is defined as:

> The SHA-256 hash of the verified request signing preimage, meaning the JCS canonical byte sequence of the request after `signature.value` has been removed.

It is not the hash of the transmitted signed JSON object.

---

### 6.7 Response Integrity

Signed responses are required for all verified request/response methods covered by MCP-RE Core.

Response verification order:

1. Verify the response signature over the received response object after removing `signature.value`.
2. Verify that the response `request_hash` exactly matches the locally verified request preimage hash.

Application-level error responses for verified requests must also be signed where possible.

Errors generated before request verification may be unsigned but should include a diagnostic JSON-RPC error object.

---

### 6.8 Notifications

MCP-RE Core may allow non-mutating notifications if local policy permits.

However, notifications must not cause:

* tool execution;
* resource access;
* prompt access;
* state mutation;
* security-relevant context expansion.

Operations with security consequences must use JSON-RPC requests with IDs so that verification failures can be returned deterministically.

---

### 6.9 Batch Messages

MCP-RE Core rejects all JSON-RPC batch messages.

Batch signing is deferred to a future profile.

---

### 6.10 Unknown Fields

MCP-RE Core should fail closed on unknown fields inside the MCP-RE security envelope unless a negotiated extension explicitly permits them.

Recommended rule:

> Unknown fields inside `com.example/mcp-re-security.request` or `com.example/mcp-re-security.response` must be rejected by Core implementations.

If extension data is needed later, reserve an explicit field such as:

```json
"extensions": {}
```

---

## 7. Request Envelope Example

```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "echo",
    "arguments": {
      "text": "hello"
    },
    "_meta": {
      "com.example/mcp-re-security.request": {
        "version": "draft-01",
        "actor": "did:example:agent-1",
        "audience": "did:example:server-1",
        "on_behalf_of": "did:example:user-1",
        "capability_hash": "sha256:eWHAEIVquB751_5ee85fezp0txichxG3YIsH5z-soEQ",
        "nonce": "test-nonce-123",
        "issued_at": "2026-05-28T20:00:00Z",
        "expires_at": "2026-05-28T20:05:00Z",
        "signature": {
          "alg": "Ed25519",
          "key_id": "key-1",
          "value": "8yeeiH7ED74qD6nVlcZfGB5sXnwDHT3t70lylJTWoUMdhGOs7tIo_JO9l_6fk3j4xY5_u5Zs9J-ThNvze3GIBw"
        }
      }
    }
  }
}
```

---

## 8. Response Envelope Example

```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "hello"
      }
    ],
    "_meta": {
      "com.example/mcp-re-security.response": {
        "request_hash": "sha256:4YRTQPdgAvwKnmzU67RAKWhs8frL7MKL8C7C3pvlHIY",
        "server_actor": "did:example:server-1",
        "trust_label": "internal-verified",
        "issued_at": "2026-05-28T20:00:02Z",
        "signature": {
          "alg": "Ed25519",
          "key_id": "server-key-1",
          "value": "5gWwYD3iWYgDV_9Prjliy7sH4eJyjnYjiEAaDK_DN6YPcGVxz9Y0SeEG9U7yCGH-aDM6cCTkpjPYMZgQ0kmPBg"
        }
      }
    }
  }
}
```

---

## 9. Trust Resolution

MCP-RE Core does not mandate a specific identity system.

The verifier resolves:

```text
(actor, key_id) -> public verification key
```

through a configured trust resolver.

Example resolver entry:

```json
{
  "did:example:agent-1#key-1": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
}
```

`mcp-re.actor_binding_failed` means either:

* the actor/key pair could not be resolved; or
* the resolved key did not verify the signature.

Enterprise identity, DID resolution, SPIFFE/SPIRE, X.509, and key transparency can be considered later. MCP-RE Core only needs the abstract resolver interface.

---

## 10. Structural Authority Bindings

MCP-RE Core includes:

```text
on_behalf_of
capability_hash
```

Core verifies that these fields are present, correctly formatted, and signed.

Core does not interpret the authorization artifact behind `capability_hash`.

Delegation profiles will later define:

* Biscuit profile;
* UCAN profile;
* OAuth-bound profile;
* revocation behavior;
* attenuation rules;
* scope evaluation;
* principal/actor authorization.

---

## 11. Context Propagation to Inner MCP Servers

A sidecar can verify MCP-RE at the boundary, but it cannot fully prevent confused-deputy problems if the inner MCP server uses broad downstream credentials.

Therefore, when a sidecar forwards a verified request to an inner MCP server, it should provide verified context:

* actor;
* key ID;
* principal / `on_behalf_of`;
* audience;
* capability hash;
* request hash;
* policy decision.

For stdio-wrapped inner servers, this should use a sidecar-controlled local metadata channel, environment handle, or verified context object.

For Streamable HTTP inner hops, headers may be used only on private loopback or Unix-socket connections and must be overwritten by the sidecar. They must never be accepted directly from external callers.

---

## 12. Standard Error Object

MCP-RE errors are returned as JSON-RPC error objects.

Example:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32003,
    "message": "mcp-re.invalid_signature",
    "data": {
      "mcp_re_error": "mcp-re.invalid_signature",
      "policy": "core",
      "retryable": false,
      "details": "Ed25519 signature verification failed against the JCS preimage."
    }
  },
  "id": 1
}
```

If the ID cannot be determined, `id` should be `null`.

---

## 13. Initial Error Taxonomy

Core error constants:

```text
mcp-re.missing_envelope
mcp-re.unsupported_version
mcp-re.invalid_signature
mcp-re.canonicalization_failed
mcp-re.expired_request
mcp-re.replay_detected
mcp-re.invalid_audience
mcp-re.actor_binding_failed
mcp-re.transport_binding_failed
mcp-re.capability_hash_missing
mcp-re.missing_principal
mcp-re.invalid_principal_format
mcp-re.response_sig_invalid
mcp-re.response_hash_mismatch
mcp-re.downgrade_forbidden
mcp-re.batch_forbidden
mcp-re.notification_forbidden
mcp-re.unknown_envelope_field
```

Delegation-specific errors should not be part of Core. They belong in later profiles:

```text
mcp-re.capability_malformed
mcp-re.capability_expired
mcp-re.capability_revoked
mcp-re.capability_scope_denied
mcp-re.principal_binding_failed
```

---

## 14. Rust Workspace Proposal

Recommended repository:

```text
mcp-re/
  Cargo.toml

  crates/
    mcp-re-core/
      envelope structs
      JCS canonicalization
      Ed25519 signing and verification
      hash utilities
      trust resolver trait
      error enum
      request/response verification
      test vectors

    mcp-re-proxy/
      server-side sidecar
      stdio wrapper
      Streamable HTTP wrapper
      fail-closed dispatch
      verified context propagation

    mcp-re-host/
      client-side ambassador
      request signing
      response verification
      tool filtering
      local token/authority context interface

    mcp-re-conformance/
      black-box conformance runner
      valid vector tests
      tamper tests
      replay tests
      response binding tests
      stdio and HTTP harnesses

    mcp-re-policy/
      future delegation layer
      Biscuit profile
      UCAN profile
      policy evaluation
```

`mcp-re-core` should not depend on networking, async runtimes, filesystem access, or MCP server implementations.

It should be usable by:

* sidecars;
* hosts;
* proxies;
* conformance runners;
* future non-Rust bindings.

---

## 15. Implementation Phases

### Phase 0 — Planning and Freeze Confirmation

Goal: approve the initial project scope and pre-implementation rules.

Deliverables:

* controlled extension identifier decision;
* agreement on request/response metadata keys;
* accepted Core signing rules;
* accepted error taxonomy;
* accepted test vectors;
* repository ownership decision.

Exit criteria:

* team agrees that MCP-RE Core is narrow and implementable;
* no further architecture expansion before `mcp-re-core`.

---

### Phase 1 — `mcp-re-core`

Goal: implement the pure cryptographic verification crate.

Deliverables:

* Rust data structures for request/response envelopes;
* JCS canonicalization support;
* Ed25519 signing and verification;
* SHA-256/Base64URL helpers;
* trust resolver trait;
* request verification;
* response verification;
* error enum;
* test vector suite.

Exit criteria:

* all published vectors pass;
* tampered request fails;
* signed response verifies;
* response bound to wrong request fails;
* malformed/JCS-invalid inputs fail deterministically.

---

### Phase 2 — `mcp-re-conformance`

Goal: create a black-box conformance runner.

Deliverables:

* CLI runner;
* stdio target harness;
* Streamable HTTP target harness;
* valid request/response tests;
* tamper tests;
* replay tests;
* wrong-audience tests;
* missing-envelope tests;
* batch rejection tests;
* notification rejection tests.

Example intended command:

```text
mcp-re-conformance --server-exec ./target/release/example-mcp-server --profile core
```

Exit criteria:

* runner can test a native MCP-RE server;
* runner can test a sidecar-wrapped ordinary MCP server;
* results are deterministic and machine-readable.

---

### Phase 3 — `mcp-re-proxy`

Goal: implement a server-side sidecar.

Deliverables:

* stdio interception;
* Streamable HTTP interception;
* request verification before dispatch;
* response signing;
* fail-closed behavior;
* verified context propagation to inner MCP server.

Exit criteria:

* unsigned requests never reach the inner MCP server;
* tampered requests never reach the inner MCP server;
* verified requests are forwarded correctly;
* responses are signed before returning to the host.

---

### Phase 4 — `mcp-re-host`

Goal: implement client-side ambassador behavior.

Deliverables:

* request envelope injection;
* request signing;
* response verification;
* tool filtering based on local policy;
* local key and actor context interface;
* clear separation from LLM/model logic.

Exit criteria:

* LLM never manages private keys;
* LLM never constructs MCP-RE signatures;
* ordinary MCP tool intent is converted into signed MCP-RE requests by the host layer.

---

### Phase 5 — Delegation Profile

Goal: add real delegated authorization.

Candidate profiles:

* Biscuit;
* UCAN;
* OAuth-bound capabilities.

Deliverables:

* capability token profile;
* attenuation semantics;
* scope evaluation;
* revocation strategy;
* principal binding;
* delegation conformance vectors.

Exit criteria:

* `capability_hash` becomes bound to a verified authorization artifact;
* server-side policy can deny requests based on token scope.

---

### Phase 6 — Transport Binding and Runtime Hardening

Goal: add higher-assurance production features.

Candidate work:

* mTLS binding for Streamable HTTP;
* SPIFFE/SPIRE identity integration;
* local process sandboxing;
* filesystem and network restrictions;
* signed tool manifests;
* audit event export;
* private registry integration.

These should remain outside Core.

---

## 16. Conformance Vector Status

The current vector set contains:

1. valid signed request;
2. modified request argument producing `mcp-re.invalid_signature`;
3. valid signed response;
4. response bound to wrong request hash.

The existing request and response signatures have been checked and are reproducible.

One additional vector should be added before coding starts:

### Vector 4B — Signed Wrong-Request Response

Purpose:

* produce a response with a wrong `request_hash`;
* sign it correctly with the server key;
* expect signature verification to pass;
* expect `request_hash` comparison to fail with `mcp-re.response_hash_mismatch`.

Suggested wrong request hash:

```text
sha256:y3G62cwbgVaTteUzP7Ax8cRUbTvBPZOQ9psEgeS-6xA
```

JCS response preimage:

```text
{"id":1,"jsonrpc":"2.0","result":{"_meta":{"com.example/mcp-re-security.response":{"issued_at":"2026-05-28T20:00:02Z","request_hash":"sha256:y3G62cwbgVaTteUzP7Ax8cRUbTvBPZOQ9psEgeS-6xA","server_actor":"did:example:server-1","signature":{"alg":"Ed25519","key_id":"server-key-1"},"trust_label":"internal-verified"}},"content":[{"text":"hello","type":"text"}]}}
```

SHA-256 hash of this response preimage:

```text
sha256:ZvQDUoRyGA4vQ4ap4_daO957_vW-HAtRlfympHL5Db8
```

Valid Ed25519 signature over this wrong-hash response preimage:

```text
PPpXbTooOOJzbuqvdoSNjJSkbYj9uon-Kpa9UdeVjNM7jzNa3N39Ncy_MhavcEf0esIE4lY0sHJXlJ16ruvBAA
```

Expected result:

```text
mcp-re.response_hash_mismatch
```

This vector is important because merely modifying `request_hash` without re-signing would usually fail earlier as `mcp-re.response_sig_invalid`.

---

## 17. Planning Meeting Agenda

Recommended agenda for the first project planning session:

1. Confirm project goal: MCP-RE Core, not VAEP, not full delegation.
2. Choose project repository structure.
3. Choose controlled extension identifier.
4. Approve request and response metadata keys.
5. Approve signing/canonicalization rules.
6. Approve signed-response requirement.
7. Approve no batch messages in Core.
8. Approve notification restrictions.
9. Approve unknown-field fail-closed behavior.
10. Approve error taxonomy.
11. Approve test vector set, including Vector 4B.
12. Assign owners for:

    * `mcp-re-core`;
    * `mcp-re-conformance`;
    * `mcp-re-proxy`;
    * `mcp-re-host`;
    * draft specification.
13. Decide first target MCP server for sidecar wrapping.
14. Decide whether the first public artifact is:

    * Rust crate;
    * draft spec;
    * conformance runner;
    * all three together.

---

## 18. Key Open Decisions

The team must decide:

1. What controlled domain/vendor prefix will replace `com.example`.
2. Whether unknown fields are rejected or allowed under an explicit `extensions` object.
3. Whether `sequence` remains out of Core initially.
4. How nonce replay caches are scoped and persisted.
5. Whether `issued_at` future skew is checked in Core.
6. Which MCP server is used as the first test target.
7. Whether the first sidecar supports stdio only or both stdio and Streamable HTTP.
8. Whether the initial project is proposed upstream immediately or incubated independently first.
9. How verified context is passed to stdio inner servers.
10. How much of the spec should be written before code starts.

---

## 19. Recommended First Engineering Task

Do not start with the proxy.

Start with `mcp-re-core`.

First concrete task:

> Implement the JCS transformation, Ed25519 verification, hash helpers, and the published request/response vectors.

The first pull request should contain:

* `EnvelopeRequest`;
* `EnvelopeResponse`;
* `SignatureBlock`;
* `TrustResolver` trait;
* `verify_request`;
* `verify_response`;
* `canonicalize_for_request_signature`;
* `canonicalize_for_response_signature`;
* conformance vectors as tests.

Success condition:

```text
cargo test -p mcp-re-core
```

passes all valid and invalid vectors.

---

## 20. Success Criteria for the Project

MCP-RE Core succeeds if:

1. A normal MCP request can be signed without changing MCP’s JSON-RPC structure.
2. The same signed request works over stdio and Streamable HTTP.
3. A tampered tool argument invalidates the signature.
4. A tampered JSON-RPC `id` invalidates the signature.
5. A replayed request is rejected.
6. An expired request is rejected.
7. A wrong audience is rejected.
8. A response from the server is signed and bound to the verified request.
9. A response bound to the wrong request is rejected.
10. Ordinary MCP servers can be protected by a sidecar without rewriting their internals.
11. Native MCP-RE servers can pass the same conformance suite.
12. The LLM never sees or manages private keys.
13. The design can be presented upstream as a narrow MCP security profile rather than a competing protocol.

---

## 21. Recommended Positioning for Open Source Discussion

The public framing should be modest and precise:

> MCP-RE is a proposed Zero Trust security profile for MCP. It signs MCP JSON-RPC requests and responses in-band using transport-agnostic metadata, making MCP tool calls attributable, tamper-evident, replay-protected, and auditable across stdio and Streamable HTTP.

Avoid claiming that MCP-RE:

* solves all MCP security problems;
* prevents prompt injection;
* replaces OAuth;
* replaces mTLS;
* replaces sandboxing;
* implements full delegated authorization in Core;
* requires a ledger;
* requires new cryptography.

The strongest argument for adoption is compatibility:

> MCP-RE can protect existing MCP servers through a sidecar while allowing future MCP servers to implement the profile natively.

---

## 22. Final Recommendation

The project is ready to enter planning.

Implementation should begin only after the planning group approves:

1. controlled extension identifier;
2. metadata keys;
3. canonicalization/signing rule;
4. signed response requirement;
5. error taxonomy;
6. initial vector suite including Vector 4B;
7. Rust workspace structure.

After those are approved, start with `mcp-re-core` and the conformance vectors before building any proxy or host behavior.
