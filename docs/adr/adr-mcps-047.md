<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-047: Bidirectional Runtime Evidence — Verifying Server-Initiated MCP Messages

## Status

Proposed — v0.8+/post-walkthrough. Arises from the **server-initiated
verification gap** discovered while building the Python SDK ([044](adr-mcps-044.md)
client integration, issue #199): MCP-S draft-02 secures the client-initiated
request/response path and nothing else. Depends on the draft-02 envelope
([038](adr-mcps-038.md)), the signing scope vs stateless `_meta` rule
([026](adr-mcps-026.md)), the authorization-binding forms ([039](adr-mcps-039.md)),
the discovery/route-policy model ([043](adr-mcps-043.md)), the client
correlation/verification pipeline ([044](adr-mcps-044.md)), the frozen `mcps-core`
error taxonomy, and the transport identity the server PEP already extracts
([014](adr-mcps-014.md) transport binding). Sibling of [046](adr-mcps-046.md)
(signed rejection receipts): both add a *new signed direction* over the existing
machinery without relaxing the trust rule.

## Context

MCP-S's return-leg security rests on ONE binding: `request_hash`. The client signs
a request whose preimage covers method/params/id, `audience`, `on_behalf_of`, the
`authorization_binding`, and client-chosen freshness (`nonce`/`issued_at`/
`expires_at`); `request_hash = sha256(preimage)`. The server signs a **response
whose preimage includes that same `request_hash`**, and the client accepts it only
when the signature verifies under a trusted server key AND
`response.request_hash == the request_hash it holds`. That equality is what defeats
response substitution, cross-request splicing, stale-response replay, and
wrong-server responses. In `mcps-client-core` it is not optional:
`verify_signed_response` requires a `ResponseExpectation { expected_request_hash }`.
There is deliberately no "verify a standalone server message" entrypoint.

But MCP is **bidirectional**. A server also initiates:

- **request-associated events** — e.g. `notifications/progress`,
  `notifications/cancelled`, partial results tied to an in-flight client call;
- **unsolicited notifications** — `notifications/message` (logging),
  `notifications/resources/updated`, `notifications/tools/list_changed`, … with no
  `id` and no client call behind them;
- **server-to-client requests** — `sampling/createMessage` (drive the client's
  LLM), `roots/list`, `elicitation/create`: id-bearing, expecting a client reply.

None of the latter two is a reply to a client request, so there is **no
`request_hash`** to bind them to — the mechanism that makes inbound traffic
trustworthy has nothing to attach to. A bare server signature is far weaker than
the request/response binding and leaves concrete holes: no freshness bound to a
client-chosen value (⇒ replay of a captured, validly-signed server message); no
recipient/session binding (⇒ cross-channel/cross-session injection of a valid
message); and, for server→client requests, no defined preimage for the client's
reply and nothing for the server to bind that reply to.

Verifying server-initiated traffic is therefore not an SDK feature — it is a
**second evidence direction** that must be designed as protocol, with its own
threat model and conformance vectors. Improvising it in the SDK would manufacture
exactly the unverified inbound channel the current fail-closed default protects
(an unverified `sampling/createMessage` steering the client's model with
attacker-controlled prompts is the worst case).

## Decision

### D1 — Strict MCP-S is the client-initiated request/response subset, until this ADR ships

Under `require_mcps`, a server-initiated message carries no bindable evidence and
**fails closed**: `mcps.notification_forbidden` for a notification (no `id`),
`mcps.missing_envelope` for an id-bearing server request. This is the correct
posture and is retained.

`allow_unverified_server_initiated` is a **degraded / migration policy ONLY**. When
enabled, a server-initiated message is delivered to the application and MUST be
audited as **no-evidence** (`AbsenceReason::plain-unsigned`, no signer, no binding).
It MUST NOT be described, defaulted, or certified as strict enterprise MCP-S — it is
an explicit operator opt-out of the security guarantee for the server-initiated
channel, chosen to run legacy servers during migration. Strict deployments leave it
off; server-initiated MCP features (sampling/roots/elicitation and non-associated
notifications) are simply refused until D2–D5 are implemented.

### D2 — Three categories of server-initiated evidence, designed and shipped independently

The problem splits into three tiers of increasing cost. Each is a separate wire
feature with its own vectors; a deployment gains each capability only when its tier
is implemented.

- **Category A — request-associated server events.** An event emitted by the server
  *while handling an in-flight client request* MAY bind to that request's existing
  `request_hash` (e.g. `notifications/progress` for a running `tools/call`). This is
  the cheapest tier: it reuses the client's `request_hash` as the anchor, so no new
  freshness/recipient scheme is required — the event's signed preimage includes the
  `request_hash` and the client verifies it against a still-outstanding correlation
  entry. It requires the correlation store to **associate without consuming**: a
  request may emit several events before its terminal response, so associated events
  peek the entry and only the terminal response consumes it (contrast the current
  `take_for_response`, which consumes on first match).

- **Category B — unsolicited server notifications.** A notification with no client
  request behind it (logging, resource-updated, list-changed) has no `request_hash`.
  It requires a full server→client evidence unit: **server signer + key_id**, a
  **server-chosen `nonce`**, **`issued_at`/`expires_at`**, a **recipient/route
  binding** (D3), and a **client-side replay cache** (D4). The client verifies
  signature + trusted signer + freshness + recipient match + non-replay, then
  delivers it as verified.

- **Category C — server-to-client requests.** `sampling/createMessage`, `roots/list`,
  `elicitation/create` need BOTH directions signed:
  1. a **signed server request** carrying the same evidence as Category B plus its
     method/params, from which the client computes a **`server_request_hash`**;
  2. a **client-signed response bound to `server_request_hash`** — the mirror image
     of the existing client-request/server-response model, with the client as signer
     and the server as verifier.

  Only Category C closes the loop for the server-initiated features MCP users most
  want; it is the largest and lands last.

### D3 — The anchor is a transport-appropriate channel/route binding, NOT `initialize`

Our posture is **stateless-primary**: the server PEP verifies each request
independently (freshness + replay cache, no per-session server state). Server→client
evidence MUST preserve that — it must be verifiable per-message without a handshake
having established shared session state. Therefore the recipient/session binding
MUST NOT be anchored on `initialize` (an `initialize`-established session id would
force server-held session state and break stateless operation, and is unavailable to
a stateless reconnect).

Instead bind to something both sides know per-message without shared mutable state.
In order of strength:

1. **Channel binding** — where the transport provides it, bind the message to the
   established secure channel (e.g. mTLS exported keying material / a channel id).
   Strongest; ties the message to the exact connection.
2. **Recipient identity** — bind the **recipient** = the client's verified identity,
   the mirror of the client request's `audience`. The server PEP already extracts the
   peer client identity (URI-SAN, [014](adr-mcps-014.md)); the reverse-direction
   preimage binds "for recipient = `<client-id>`", and the client checks it equals
   its own identity. Stateless and transport-appropriate.
3. **Route binding** — bind the operator-configured `route_id` from discovery
   ([043](adr-mcps-043.md)). Coarser but works where no per-connection identity
   exists (e.g. behind a terminating proxy that re-binds identity by header).

A deployment binds the strongest anchor its transport affords; the recipient
binding (2) is the baseline REQUIRED floor, so a validly-signed server message for
recipient A cannot be replayed into recipient B's channel.

### D4 — Freshness and replay for the server→client direction

Categories B and C need their own freshness model (Category A inherits the client
request's). The server signs `nonce` + `issued_at` + `expires_at` into the preimage;
the client verifies `issued_at ≤ now ≤ expires_at` within a bounded skew and keeps a
**replay cache keyed by `(server_signer, nonce)`** over the acceptance window,
rejecting duplicates (`mcps.replay_detected`). The cache is client-side and bounded
exactly like the server's request replay cache ([006 posture: cache failure fails
closed]); a cache-unavailable condition fails closed
(`mcps.replay_cache_unavailable`). Because the preimage also carries the recipient
binding (D3), a replay into a different channel fails the recipient check even before
the nonce check.

### D5 — Envelope location and preimage coverage (open structural choice)

Server-initiated messages are JSON-RPC **requests/notifications**, not responses, so
the evidence cannot live at `result._meta[RESPONSE_META_KEY]`. A new request-side
home is needed — candidate `params._meta["se.syncom/mcps.server_event"]` (mirroring
the client request envelope at `params._meta["se.syncom/mcps.request"]`), with the
client's Category-C reply carrying a normal client-signed response envelope bound to
`server_request_hash`. This ADR fixes the REQUIREMENTS and defers the exact key/shape:

- The signed preimage MUST cover, per category: `server_signer`, `key_id`, the
  method/params, the recipient/route binding (D3), and — for B/C — `nonce`/
  `issued_at`/`expires_at`; for A the bound `request_hash`; for C the client reply's
  bound `server_request_hash` and its `outcome`.
- `nonce`/`issued_at`/`expires_at`/recipient MUST be INSIDE the signed preimage so
  none can be stripped or rewritten on-path.
- Verification is a distinct inbound path in the client core, separate from the
  success-response path, returning a typed verified/rejected verdict with a frozen
  `mcps.*` reason — never a placeholder.

### D6 — Phasing

Ship in cost order, each with conformance vectors and a fail-closed default until
present: **A** (reuse `request_hash`; correlation associate-without-consume) →
**B** (server nonce/expiry/recipient + client replay cache) → **C** (symmetric
signed server request + client-signed `server_request_hash` reply). A deployment
advertises which categories it supports via discovery ([043](adr-mcps-043.md)); a
client offered a server-initiated message of an unsupported category fails closed
per D1.

## Non-goals

- No new cryptography — reuse Ed25519 signing, JCS int53 canonicalization, and the
  existing key custody/trust resolution in both directions.
- MCP-S still does not interpret message *content* (bind-not-interpret): verifying a
  `sampling/createMessage` proves origin/freshness/recipient, NOT that its prompt is
  safe. Content policy stays with the application.
- No `initialize`-anchored session state (D3).

## Consequences

- The trust rule is preserved: clients never believe an unverifiable server message;
  strict mode refuses server-initiated features rather than weakening.
- MCP-S gains a principled path to full bidirectional MCP (sampling/roots/
  elicitation/notifications) without abandoning stateless-primary operation.
- New surface, in this order: correlation associate-without-consume + a Category-A
  verify path; a server→client evidence envelope + client replay cache (B); a
  symmetric client-signed reply bound to `server_request_hash` (C); discovery
  advertisement of supported categories; conformance vectors per category.
- Until each category ships, the SDK's current behavior stands
  (`mcps_sdk.transport.verify_inbound`): fail closed under `require_mcps`,
  no-evidence pass-through only under the explicitly degraded
  `allow_unverified_server_initiated`.
- Interaction with [046](adr-mcps-046.md): a Category-C server request that the
  client refuses could itself warrant a signed rejection receipt in the reverse
  direction — the two ADRs share the "signed evidence in the non-primary direction"
  shape and should reuse one envelope-location decision.
