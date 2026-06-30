<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-046: Signed Rejection Receipts

## Status

Proposed — v0.7+/post-walkthrough. Arises from the **wire-honesty discovery** in
[045](adr-mcps-045.md) §3d (Tier T3): a server/proxy that fails a request closed
returns an UNSIGNED error whose reason the client rightly distrusts, so the
specific cause never reaches the caller. Depends on the existing response-signing
machinery ([026](adr-mcps-026.md) signing scope vs stateless `_meta`,
[038](adr-mcps-038.md) draft-02 envelope), the server PEP response path
(`mcps-proxy` `build_response_envelope`), the client verification pipeline
([044](adr-mcps-044.md) client integration model), and the frozen `mcps-core`
error taxonomy (the `mcps.*` wire codes).

## Context

MCP-S clients only believe SIGNED evidence — a response is trusted only after its
signature, server signer, version, canonicalization id, and request-hash binding
all verify. This is the protocol's core safety rule and it is correct.

The consequence surfaced concretely while building T3. When the server PEP refuses
a request before dispatch (e.g. `mcps.transport_binding_failed`), it replies with
a plain JSON-RPC error object that is NOT a signed MCP-S envelope. The client's
response verifier finds no trustworthy envelope and fails closed with a GENERIC
verdict (it surfaces e.g. `mcps.missing_envelope` or `mcps.downgrade_forbidden`
depending on what bytes came back, never the server's actual reason). The server
knows exactly why it said no; the client architecturally cannot learn it over an
untrusted channel.

This is not a bug — a client that trusted unsigned rejection reasons would be
trivially exploitable (any on-path party could forge or rewrite the cause). But it
IS a capability gap: legitimate callers get "rejected, reason unknown," which is
poor for diagnostics, support, and client-side policy that wants to branch on a
trusted cause (e.g. "re-mint the grant on `authorization_scope_denied`, but do NOT
retry on `replay_detected`").

The fix is NOT to relax the trust rule. It is to give the server a way to tell the
client the reason *in a form the client can verify*.

## Decision

### D1 — Clients MUST NOT trust unsigned rejection reasons

The current posture is retained and made explicit: an unsigned error body's
reason is untrusted. A client that receives no verifiable signed response reports
only a generic fail-closed verdict. It MUST NOT echo an unsigned `wire_code` as if
it were established fact.

### D2 — Servers/proxies SHOULD return a signed rejection receipt for classifiable security failures

A **signed rejection receipt** is a signed, request-bound MCP-S response whose
outcome is `rejected` and which carries a stable `wire_code`. It reuses the
existing response-signing capability; it is NOT a new cryptographic mechanism.

Conceptually (final wire location is D4):

```json
{
  "jsonrpc": "2.0",
  "id": "...",
  "error": {
    "code": -32000,
    "message": "MCP-S request rejected",
    "data": { "wire_code": "mcps.transport_binding_failed" }
  },
  "_meta": {
    "se.syncom/mcps.response": {
      "version": "draft-02",
      "canonicalization_id": "mcps-jcs-int53-json-v1",
      "outcome": "rejected",
      "wire_code": "mcps.transport_binding_failed",
      "request_hash": "...",
      "server_signer": "...",
      "issued_at": "...",
      "signature": { "alg": "...", "key_id": "...", "value": "..." }
    }
  }
}
```

The client may expose the specific reason ONLY after verifying, over the signed
preimage: the response signature, `server_signer`, `version`,
`canonicalization_id`, the `request_hash` binding to THIS request, `outcome ==
rejected`, and that `wire_code` is itself inside the signed preimage. Absent a
valid receipt, D1 applies: generic fail-closed only.

### D3 — Sign only the stable wire-code vocabulary, never internal diagnostics

A receipt carries a stable `mcps.*` code from the frozen taxonomy, e.g.:

```text
mcps.transport_binding_failed
mcps.authorization_scope_denied
mcps.replay_detected
mcps.freshness_failed
mcps.unexpected_server_signer
mcps.authorization_binding_missing
mcps.authorization_binding_mismatch
```

Detailed diagnostics — stack traces, certificate internals, policy internals,
matched-rule ids — stay in server logs/audit and are NEVER placed in a
client-facing receipt. The receipt is a *classification*, not a debugging dump,
so it cannot become an oracle or a leakage channel.

### D4 — The receipt needs an error-path home and verifier support (open design)

Today the response verifier locates the envelope at `result._meta[RESPONSE_META_KEY]`
(`mcps-core` `locate_envelope(msg, "result", …)`). A rejection is a JSON-RPC
*error* with NO `result`, so the receipt cannot live there. This ADR defers the
exact structural choice but fixes the requirement: the receipt is located on the
error path (candidate: `error._meta[RESPONSE_META_KEY]` with `outcome=rejected`),
and the client verifier gains an explicit rejection-receipt path distinct from the
success path. The signed preimage MUST cover `outcome` and `wire_code` so neither
can be stripped or flipped to a success. This is precisely why this is a separate
protocol feature, not a patch to the T3 test.

### D5 — Not every failure can produce a receipt; that is acceptable

A signed receipt is possible only when the server can safely classify the failure
AND sign. It is impossible — and the client still gets only a generic fail-closed
verdict — when:

- the connection never established (no server reached);
- the server's response-signing key is unavailable;
- the request is so malformed that no request id/hash can be computed to bind to;
- response signing itself fails.

These remain "fail closed, no trusted reason," which is correct.

## Testing split

- **T3 (now):** assert the externally valid OUTCOME — the client fails closed and
  the inner fileserver's received-log stays empty (denied before dispatch), proven
  cross-process. Do NOT assert the client sees a trusted reason; it cannot yet.
- **Server-side / in-process (now):** the exact `wire_code` for each rejection is
  pinned where the server internals are directly visible (e.g. `mcps-proxy`'s
  `transport_binding_failed` test).
- **Follow-up (once receipts exist):** a second test class —
  - *without* receipt: client fails closed generically; received-log proves the
    inner was not reached;
  - *with* receipt: client verifies the signed rejection and MAY expose
    `wire_code = mcps.transport_binding_failed`; received-log STILL proves the
    inner was not reached.

## Consequences

- The trust rule is preserved: clients never believe unsigned reasons.
- Legitimate callers gain a *verifiable* cause for security rejections, enabling
  trustworthy client-side branching and far better diagnostics/support.
- New surface to build, in this order: an error-path receipt location + signing in
  the server PEP rejection paths; a client verifier branch for rejection receipts;
  the follow-up test class. Each is its own change.
- Bounded scope by construction: only stable taxonomy codes are signed; internal
  diagnostics never enter the protocol, so the receipt cannot become an oracle.
- Until implemented, [045](adr-mcps-045.md) §3d stands: T3 proves the outcome, the
  in-process suite proves the reason.
