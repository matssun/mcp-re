<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE × EMA composition

> **Status: design note. MCP-RE implements no EMA-specific code and makes no EMA
> claim.** EMA (Enterprise-Managed Authorization) is an MCP Authorization
> Extension in `modelcontextprotocol/ext-auth`. This document records how MCP-RE
> composes with it so the two are not conflated, and shows that composition needs
> no wire-envelope change: an EMA-derived authorization artifact binds through the
> existing `artifact_bindings` machinery of ADR-MCPRE-050.

## The one-line distinction

> **EMA decides whether the enterprise user/client may *obtain* authorization.
> MCP-RE proves that a *concrete MCP call* was signed, fresh, non-replayed,
> response-bound, and bound to that EMA-derived authorization artifact.**

EMA is an *authorization-issuance* concern: identity, policy, consent, scope. It
answers "may this principal be granted this capability?" MCP-RE is a *per-message
authenticity* concern: it answers "is *this exact call*, on the wire, genuinely
the authorized one — unforged, unreplayed, and is its response genuinely bound
back to it?" They sit at different layers and compose; neither replaces the
other.

MCP-RE **binds EMA artifacts, it does not interpret them.** It treats an EMA-derived
authorization artifact as an opaque, hashed input bound into the signed request
evidence. It does not parse EMA policy, re-decide scope, or re-run the enterprise's
authorization logic. In particular it does not parse ID-JAG.

That rule is about EMA-NATIVE artifacts. It is not a claim that MCP-RE never
interprets any authorization evidence: under ADR-MCPRE-065 a deployment may configure
an authorization authority whose decisions MCP-RE authenticates and enforces itself
(Mode 2). Those decisions are issued in MCP-RE's own claim vocabulary by an authority
MCP-RE is configured to trust — not EMA artifacts read by a proxy that was told not
to read them.

## Diagram A — the MCP-RE enforcement path, without EMA

The client signs each call under the HTTP profile; the proxy verifies and
enforces before the inner MCP server is ever reached.

```text
┌────────────────┐  signed MCP-RE request  ┌───────────────────────────┐   HTTP    ┌──────────────────┐
│ MCP client     │ ─────────────────────►  │ mcp-re-proxy (PEP)        │ ────────► │ inner MCP server │
│  • signs req   │      (mTLS)             │  • verify RFC 9421 + 9530 │           │ (unmodified)     │
│  • verifies    │                         │  • freshness / replay     │           │                  │
│    response    │ ◄─────────────────────  │  • artifact bindings      │ ◄──────── │  runs the tool   │
└────────────────┘  delegated-signed,      │  • strip caller-seeded    │           └──────────────────┘
                    request-bound response │    verified context       │
                                           │  • sign response          │
                                           └───────────────────────────┘
                                             denied requests never reach the inner server
```

MCP-RE is HTTP-profile only. A stdio-only inner server is fronted by an external
plain-MCP adapter that speaks HTTP to the proxy; MCP-RE itself has no stdio leg.

## Two composition modes

When EMA is present, MCP-RE composes in one of two distinct modes. **Pick one per
deployment and state which** — see the *"EMA twice"* warning below.

### Mode 1 — EMA *binding* mode (for EMA-native MCP servers)

The MCP server (or its platform) is itself EMA-aware and performs the
authorization decision. MCP-RE does **not** re-decide authorization; it **binds**
the EMA authorization artifact into the signed call so the artifact cannot be
swapped, forged, replayed, or detached from the specific request — and binds the
response back to that request.

Use this when the backend already enforces EMA. MCP-RE adds message authenticity,
freshness, replay protection, and response binding *around* the EMA decision.

```text
┌────────────┐  signed req + bound      ┌──────────────────────┐         ┌──────────────────────────┐
│ MCP client │  EMA-artifact digest     │ mcp-re-proxy         │  HTTP   │ EMA-native MCP server     │
│            │ ───────────────────────► │  • verify signature  │ ──────► │  • reads EMA artifact     │
│            │       (mTLS)             │  • freshness/replay  │         │  • MAKES the authz        │
│            │                          │  • BIND EMA artifact │         │    DECISION (EMA enforce) │
│            │ ◄─────────────────────── │    (does NOT decide) │ ◄────── │  • runs tool              │
└────────────┘  request-bound response  │  • bind response     │         └──────────────────────────┘
                                        └──────────────────────┘
                                  MCP-RE guarantees authenticity; the SERVER enforces EMA.
```

Claim: *MCP-RE binds runtime call evidence to an EMA-derived authorization
artifact.* Non-claim: *MCP-RE enforces EMA for an EMA-native server.*

### Mode 2 — EMA *enforcement* mode (only for private backends behind MCP-RE)

The backend is **not** EMA-aware — it is a private server fully behind the
enforcement point. Here MCP-RE enforces the EMA-derived grant *before dispatch*
(deny-before-dispatch), because nothing downstream will.

Use this **only** when the backend is private and the proxy is the sole
enforcement point, with network policy, mTLS, or loopback binding preventing
bypass. Do **not** use it in front of a server that itself enforces EMA.

```text
┌────────────┐  signed req + EMA-       ┌────────────────────────────┐   HTTP    ┌────────────────────┐
│ MCP client │  derived grant           │ mcp-re-proxy               │ ────────► │ PRIVATE backend    │
│            │ ───────────────────────► │  • verify signature        │           │ (not EMA-aware,    │
│            │       (mTLS)             │  • freshness/replay        │           │  fully behind the  │
│            │                          │  • ENFORCE the grant       │           │  enforcement point)│
│            │ ◄─────────────────────── │    (deny-before-dispatch)  │ ◄──────── │  runs tool only if │
└────────────┘  request-bound response  │  • bind response           │           │  the proxy allowed │
                                        └────────────────────────────┘
                                  MCP-RE is the SOLE enforcement point.
```

Claim: *MCP-RE can act as the Layer 4 enforcement point for EMA-derived decisions
when the inner server is explicitly deployed as a private backend.* Non-claim:
*MCP-RE can transparently disable EMA in arbitrary third-party EMA-native
servers.*

## The "EMA twice" warning

Do **not** run EMA enforcement in both the proxy (Mode 2) **and** an EMA-native
backend (Mode 1) for the same call. Enforcing the same authorization twice in two
places is an ambiguity, not extra safety:

- the two evaluators can **disagree** (different policy versions, clock skew,
  partial revocation visibility), producing inconsistent allow/deny;
- it is unclear **which** decision is authoritative for audit;
- a permissive proxy policy can silently **widen** a stricter backend decision,
  or a stricter proxy can **shadow-deny** calls the backend would have allowed,
  hiding the real policy surface.

**Rule:** exactly one component enforces EMA per call. If the backend is
EMA-native, use Mode 1 and let the backend decide (MCP-RE binds, does not decide).
If the backend is private, use Mode 2 and let the proxy enforce. State the mode
explicitly in the deployment's security posture.

A double-check / defence-in-depth deployment is permitted only as an explicit,
documented choice, carrying all four consequences above.

## How an EMA artifact binds

The request evidence block's `artifact_bindings[]` (ADR-MCPRE-050) is the binding
surface. It is required and non-empty on every signed request, and each entry
carries a digest — never artifact bytes, never a raw credential.

| EMA-derived artifact | `artifact_type` | `binding_type` |
|---|---|---|
| The final MCP access token, proof-of-possession bound | `oauth-dpop` / `oauth-mtls` | `opaque-digest` |
| A rich-authorization-request grant | `oauth-rar` | `opaque-digest` |
| A normalized authorization **decision** from the enterprise IdP / PDP — LINKED | `pdp-decision` | `reference-digest` |
| An authorization **decision** MCP-RE itself enforces — CARRIED | `pdp-decision` | `opaque-digest` |

The two decision rows are different claims, and the `artifact_type` × `binding_type`
product is what expresses the difference.

**`reference-digest` is LINKAGE.** It carries `authorization_system_id` (which
authorization system decided), `reference_scheme_id` (what the reference means and
how the digest was produced), and `reference_value` — **the stable `decision_id`**.
What MCP-RE establishes is that this reference and digest were integrity-bound into
the signed call. It does **not** establish that the referenced decision is genuine,
authoritative, or about this request: MCP-RE holds no decision artifact and no
authority signature, so there is nothing for it to authenticate. The EMA-native
backend remains responsible for establishing that. The digest keeps the record
verifiable independently of that system's live state, so an audit years later does
not depend on the IdP still being able to replay the decision.

**`opaque-digest` is CARRIED EVIDENCE**, and it is the Mode-2 enforcement profile
(ADR-MCPRE-065 Slice 2). The decision document itself travels in the body beside its
binding, and MCP-RE authenticates it under a configured authorization-authority trust
seam, matches it against the verified actor and the signed-body action, and refuses
before dispatch unless it says permit. That is the form a private-backend deployment
uses, and it is what makes MCP-RE an enforcement point rather than a binder.

Consequences worth stating plainly:

- MCP-RE never parses ID-JAG, introspection responses, or EMA policy. It hashes
  bytes it is handed, or records a digest an external system produced.
- Binding a token digest and binding a decision reference are different claims.
  The first proves *this call presented that credential*; the second proves *this
  call was made under that decision id*. A deployment may bind both.
- EMA composition needs no new field: the linkage row above binds through the
  existing machinery. The **carried** row does add one — `authorization_decision`,
  the inline compact JWS beside its binding — and that is exactly the "separate ADR"
  this note pointed at: ADR-MCPRE-065, which owns authorization semantics. It is an
  extension of the ADR-MCPRE-050 request evidence block, not a new envelope, and it
  follows the `admission` / `admission_assertion` precedent.

## Verified-context linkage

The EMA linkage reaches the inner server through the verified-context carrier
(profile §10), which is off by default and delivered only under an explicit trust
configuration. The carrier hands the inner server the PEP's verified conclusion —
profile, resolved actor, key id, audience, verification instant, and the verified
request evidence, `artifact_bindings` included. The `decision_id` an EMA
deployment cares about is therefore readable from the bound `reference_value`
without a bespoke field.

Caller-seeded verified context is stripped at the boundary and never forwarded: a
caller that could seed it would be asserting its own authorization conclusion.

## Statelessness

MCP 2026-07-28 is stateless — every request carries what is needed to process it.
That matches this composition: an authorization artifact is bound **per call**, so
MCP-RE's freshness and replay guarantees stay independent of OAuth token lifetime.
A token that is still valid does not make a replayed call fresh.

## What this means for claims

- MCP-RE does **not** implement EMA and makes **no** EMA claim.
- MCP-RE's contribution in either mode is the same: per-message signature,
  freshness, replay protection, transport binding, response-to-request binding,
  and *binding* the authorization artifact — not authorization issuance.
- See [`docs/PROJECT_STATUS.md`](../PROJECT_STATUS.md) for the current claims and
  non-claims, and [`docs/spec/security-boundary.md`](security-boundary.md) for the
  protected/unprotected surface.
