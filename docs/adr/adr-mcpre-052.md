<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-052: Delegated Signing-Key Attestation — a JOSE/JWS Delegation Credential Carried in the RFC 9421 HTTP Evidence

## Status

Accepted — ratified 2026-07-09 after a targeted four-point clarification pass
(no broad re-grill; owner rulings folded in):

1. **`aud` semantics** — `aud` identifies the verifier/service audience (RFC 7519),
   NOT the profile; profile/scope/signer move to `mcp_re_profile` /
   `mcp_re_audience_hash` / `mcp_re_server_signer` (§1, §3 step 5).
2. **`trust_epoch`** — a HARD verifier gate: accept only credentials whose epoch is
   in the active accepted set (§3 step 6, §5; token `delegation_trust_epoch_stale`).
3. **Delegation mode** — REQUIRED by default; a directly root-signed response is
   rejected. Mixed direct/delegated is an explicit, audited `mixed-migration` mode,
   excluded from the production SLO profile (§3).
4. **Credential replay** — no independent per-use anti-replay; possession of the
   delegated private key is the control, and the credential is covered by the
   RFC 9421 response signature; `jti` is audit/revocation only (§5a).

Companion to ADR-MCPRE-051 §5 (High-Throughput Serving Architecture — delegated
signing custody). **This ADR is BLOCKING for any production delegated-signing
release (ADR-MCPRE-051 §5): no release signs responses with a delegated key before
its conformance vectors (§9) are green.**
The *decision to adopt* delegated signing is already made in ADR-MCPRE-051; this
ADR ratifies only the **credential format**, the verifier trust chain, and the
lifecycle taxonomy.

## Context

ADR-MCPRE-051 §5 removes the remote HSM/KMS round-trip from the per-request
signing path: the root/identity key stays in the HSM/KMS (ADR-MCPS-028 posture,
unchanged) and issues a **short-lived, in-memory Ed25519 delegated signing key**;
per-request response signing uses the delegated key in process (microseconds),
with KMS/PKCS#11 operations confined to a bounded `spawn_blocking` pool at
issuance/rotation only. ADR-MCPRE-051 fixes the *custody model* — bounded
lifetime, rotation overlap, per-key `key_id`, root-signed delegation, audit,
revocation, fail-closed issuance — and explicitly defers the **wire-level
delegation evidence format** to this companion ADR.

**The controlling constraint is ADR-MCPRE-050.** ADR-MCPRE-050 makes the standards
HTTP profile — **RFC 9421 (HTTP Message Signatures) + RFC 9530 (Digest Fields)** —
the cryptographic carrier for HTTP transports. That is the single target profile.
The native JCS/object envelope (ADR-MCPS-004) is legacy: it MUST NOT be the
foundation for **new** evidence. A delegation credential is new evidence, so the
open question is narrow and standards-shaped:

> **Which standards-shaped delegation credential best binds a short-lived delegated
> signing key to the root identity — carried in the RFC 9421 HTTP evidence, without
> inventing a custom crypto island?**

Today the HTTP-profile response already carries a resolved signer identity
inline: `HttpResponseEvidenceBlock { profile, server_signer, request_evidence }`
lives in the JSON-RPC body `_meta` under the block key
`se.syncom/mcp-re.http.response` and is protected because `content-digest` is a
covered component of the RFC 9421 response signature (`mcp-re-http-profile`,
MCPRE-92…103). `server_signer.keyid` is exactly the RFC 9421 keyid the response
signature verified under. The trust-epoch / revocation subsystem
(`trust_epoch.rs`, `revocation_tier.rs`, `push_trust.rs`) propagates invalidations
fleet-wide with bounded lag. The audit vocabulary (`mcp-re-core/src/audit.rs`) is a
frozen, drift-guarded allowlist; its module note states no third
success/lifecycle event may be minted **without an ADR**. This ADR is that
authorizing ADR for the key-lifecycle audit category.

Two constraints shape the design:

- **No custom crypto island; reuse standards where each is strongest.** A
  delegation credential is a signed *credential*, not an HTTP transaction. RFC 9421
  is a mechanism for signing components of an HTTP *message* — the right tool for
  the response, the wrong tool to press-gang into a bespoke signed credential
  object. JOSE/JWS (RFC 7515) with a JWT claim set (RFC 7519), Ed25519 per RFC 8037,
  and the `cnf` proof-of-possession confirmation claim (RFC 7800) is a
  standards-track format built precisely to carry a signed, key-bound credential.
- **The pure verification core is not extended (ADR-MCPS-018).** JOSE/JWS
  verification is admitted into the **HTTP-profile standards layer**
  (`mcp-re-http-profile`, already a pure — no networking/async/fs — crate that
  parses RFC 9421), **not** into `mcp-re-core`. Admitting a standards-track
  compact-JWS format alongside RFC 9421 is not a custom crypto island; it is one
  more IETF format in the layer whose whole job is IETF HTTP-signature formats.
  `mcp-re-core` stays the lean object verifier and gains nothing.
- **Evidence never impersonates the root (ADR-MCPS-003 signing-locus rule).** The
  delegated key has its own identity; a verifier always distinguishes a delegated
  signature from a root signature, and a compromised delegated key can never be
  mistaken for the root.

## Decision

The delegation evidence is a **compact JOSE/JWS delegation credential** — a
short-lived JWT, **signed by the root key in the HSM/KMS**, that binds a delegated
Ed25519 public key to the root via the `cnf` (proof-of-possession) claim. It is
carried **inline** in the RFC 9421 response evidence and is protected by the
response signature. The delegated key then signs the actual HTTP response under
**RFC 9421**. Three standards, three jobs:

```
JOSE/JWS (JWT)      : the delegation credential  — root delegates to a key
RFC 9421            : HTTP request/response evidence — the delegated key signs the message
RFC 9530            : content-digest — body integrity, a covered RFC 9421 component
```

This is the object profile's **replacement** on the delegation path, not a second
profile: there is exactly one carrier (the HTTP profile), consistent with
ADR-MCPRE-050.

### 1. The delegation credential (compact JWS / JWT)

A **delegation credential** is a compact JWS (RFC 7515) over a JWT claim set
(RFC 7519), signed by the root/identity key with `EdDSA` (Ed25519, RFC 8037):

```
Protected header:
  {
    "typ": "mcp-re-delegation+jwt",   # frozen media type (vocabulary firewall)
    "alg": "EdDSA",                    # Ed25519 (RFC 8037); the ONLY accepted alg
    "kid": "<issuer_kid>"              # the ROOT/identity key_id that signed this credential
  }

Claims:
  {
    "iss":            "<root identity>",         # issuer identity (e.g. did:web / service id)
    "iat":            <unix seconds>,
    "nbf":            <unix seconds>,            # not-before
    "exp":            <unix seconds>,            # bounded lifetime; short TTL
    "jti":            "<delegation event id>",   # ties to the audit issuance event; NOT a replay-cache key (§5a)
    "aud":                   "<verifier/service audience>",  # RFC 7519 aud: WHO may process this credential; a verifier not named here MUST reject
    "mcp_re_profile":        "<http profile id>",  # the MCP-RE evidence profile this credential is valid for (e.g. mcp-re-http-v1)
    "mcp_re_audience_hash":  "<service/audience scope hash>",  # the service/audience scope the delegated key may sign for (matches the request audience tuple, ADR-MCPRE-050)
    "mcp_re_server_signer":  "<expected server signer>",  # the resolved server-signer identity this delegation is bound to
    "mcp_re_key_use": "response-signing",        # the ONLY use this credential authorizes
    "delegated_kid":  "<delegated key_id>",      # the delegated key's own id — never the root's
    "issuer_kid":     "<root key_id>",           # equals the protected-header kid
    "trust_epoch":    "<epoch at issuance>",     # HARD verifier gate (§3 step 6) — accepted only if in the verifier's active epoch set
    "cnf": {                                     # RFC 7800 proof-of-possession
      "jwk": {
        "kty": "OKP", "crv": "Ed25519",
        "kid": "<delegated_kid>",
        "x":   "<delegated Ed25519 public key, base64url-no-pad>"
      }
    }
  }
```

- The credential is **root-signed**: its JWS `kid` is the **root** `issuer_kid`
  (the identity anchor the verifier already trusts). This is the only place the
  root key signs on the delegated path, produced off the hot path at
  issuance/rotation.
- `cnf.jwk` (RFC 7800) carries the **delegated** public key. The root asserts
  proof-of-possession: "the key in `cnf` is authorized to sign, for
  `mcp_re_key_use`, until `exp`." `delegated_kid` is a distinct,
  delegated-namespace identifier (RECOMMENDED shape
  `<issuer_kid>/delegated/<monotonic-counter>`) so a delegated `key_id` is never
  confused for the root's.
- `alg` is **pinned to `EdDSA`**; any other `alg` (including `none`) is rejected —
  no algorithm agility, no downgrade surface.
- **`aud` is not the profile.** Per RFC 7519, `aud` identifies the parties that
  may **process** the credential; a verifier that does not identify itself in
  `aud` MUST reject. The evidence **profile** is a separate claim
  (`mcp_re_profile`), and the **service/audience scope** the delegated key may
  sign for is `mcp_re_audience_hash` (the same audience the request evidence
  binds, ADR-MCPRE-050), with `mcp_re_server_signer` naming the bound signer
  identity. This scoping is what stops a valid-but-lifted credential from being
  accepted anywhere else that merely speaks the same MCP-RE profile — a leaked
  credential is inert outside its `aud` / audience / signer / key-use scope.

### 2. Wire carriage — inline in the response evidence, covered by the RFC 9421 signature

The credential rides **inline** in the response-side evidence block
`se.syncom/mcp-re.http.response`, as a new sibling of `server_signer`:

```
HttpResponseEvidenceBlock {
    profile,
    server_signer,                 # ActorIdentity; server_signer.keyid == delegated_kid
    server_delegation: "<compact JWS>",   # NEW — the delegation credential
    request_evidence,
}
```

Because the evidence block lives in the JSON-RPC body `_meta` and **`content-digest`
is a covered component of the RFC 9421 response signature**, the credential is
protected by the response signature exactly as `server_signer` already is — a
stripped or substituted credential breaks `content-digest` verification. No new
covered HTTP component and no new signature base are introduced; the existing
`@status` / `content-digest` / `content-type` covered set is unchanged. The RFC
9421 response signature verifies under the **delegated** key
(`server_signer.keyid == delegated_kid == cnf.jwk.kid`).

Inline carriage is self-contained: a verifier needs no out-of-band round-trip for
the delegated key — only the pre-existing trust anchor for the **root**
`issuer_kid`. An OPTIONAL resolver-distribution mode (publishing credentials by
`delegated_kid`) is permitted purely as a bandwidth optimization, but is **never
REQUIRED and never the trust source** — the trust source is always the root-signed
credential.

### 3. Verifier trust chain — credential → root, no ephemeral enrollment

**Delegation mode is REQUIRED by default.** In a delegated-signing deployment,
every accepted response MUST carry a valid delegation credential and verify under
the delegated key. A directly **root-signed** response (or any response with no
delegation credential) is **rejected** — the direct-root path is not a silent
fallback, because it would bypass the delegated-key lifecycle (short TTL,
rotation, audit, revocation) and open a downgrade seam. A mixed direct/delegated
deployment is permitted ONLY as an explicit `delegation_mode = "mixed-migration"`:
it MUST audit every direct-root acceptance, is **excluded from the high-throughput
production SLO profile**, and a conformance vector MUST prove that the default
(required) mode rejects a direct-root response.

A verifier presented with a response under a delegated-signing policy:

1. Reads `server_delegation` from the response evidence block. In required mode, a
   response with no valid inline credential — including a directly root-signed one
   — ⇒ `mcp-re.delegation_credential_missing`.
2. Resolves `issuer_kid` to a trusted **root** anchor via the existing trust
   resolver / by-`key_id` trust map. Unknown issuer ⇒
   `mcp-re.delegation_issuer_untrusted`.
3. Verifies the JWS with the root anchor, requiring `alg == EdDSA` and JWS
   `kid == issuer_kid`. Malformed, wrong-alg, or bad root signature ⇒
   `mcp-re.delegation_credential_invalid`.
4. Enforces freshness: `nbf ≤ now ≤ exp` (+ `max_clock_skew`). Outside the window ⇒
   `mcp-re.delegation_credential_expired`.
5. Cross-checks **scope** (all four, fail-closed):
   - **Audience:** the verifier identifies itself in `aud`; else
     `mcp-re.delegation_audience_mismatch`.
   - **Profile:** `mcp_re_profile` == the active HTTP profile id; else
     `mcp-re.delegation_profile_mismatch`.
   - **Service/audience scope:** `mcp_re_audience_hash` == the expected
     request/service audience hash **and** `mcp_re_server_signer` == the expected
     server signer; else `mcp-re.delegation_audience_mismatch`.
   - **Key use:** `mcp_re_key_use` permits this signature use
     (`"response-signing"`); else `mcp-re.delegation_key_use_invalid`.
6. Enforces the **trust epoch as a hard gate**: `trust_epoch` MUST be in the
   verifier's **active accepted epoch set** — default `{ current_trust_epoch }`,
   optionally `{ current, immediately_previous }` only when an explicit, bounded
   rollout window is configured. A credential minted under a superseded epoch not
   in that set ⇒ `mcp-re.delegation_trust_epoch_stale`, **even without a targeted
   `delegated_kid` revocation** — epoch advancement is itself a coarse, coherent
   invalidation (ADR-MCPS-021; the epoch is explicit coherent state per
   ADR-MCPRE-051 §4).
7. Checks revocation: neither `delegated_kid` nor `issuer_kid` is revoked at the
   current trust epoch (§5). Revoked ⇒ `mcp-re.delegation_revoked`.
8. Verifies the **RFC 9421 response signature** with `cnf.jwk`, requiring the
   response signature `keyid == delegated_kid`. A response signed by any other key,
   or a `keyid`/`cnf` mismatch ⇒ `mcp-re.delegation_key_mismatch`; a body/digest
   tamper is caught by the existing HTTP-profile response-signature-invalid token.

Trust flows **only** through the credential to the root — a delegated key is
**never** enrolled out of band, and a verifier that has never seen a given
`delegated_kid` verifies it the first time from the credential alone.

### 4. Lifetime and rotation overlap — no signing gap, no verification gap

- **Bounded lifetime.** Each delegated key has a short TTL `T` (RECOMMENDED
  minutes-to-hours; the concrete value is a deployment-profile parameter, pinned by
  the release profile, not fixed here).
- **Rotation overlap window `O` (`0 < O < T`).** The issuer mints a **successor**
  delegated key + credential at `exp − O` and begins signing with it **before** the
  predecessor lapses. The predecessor's credential stays valid (verifiers accept it)
  until its own `exp`. At any instant at most two delegated keys are simultaneously
  valid; there is **no signing gap** (successor ready before predecessor expiry) and
  **no verification gap** (predecessor accepted until expiry). This is exactly the
  overlap the rotation-tolerant by-`key_id` trust map already supports.

### 5. Revocation via the trust-epoch channel; compromise blast radius

- **Revocation** reuses the existing channels (ADR-MCPS-021, `trust_epoch.rs`,
  `revocation_tier.rs`): revoking a `delegated_kid` publishes it to the revocation
  tier and advances the monotonic **trust epoch**, flushing caches fleet-wide with
  the per-tier bounded lag the fleet already declares. The credential's
  `trust_epoch` claim is a **hard verifier gate** (§3 step 6), not merely a
  detection hint: a credential whose `trust_epoch` is not in the verifier's active
  accepted epoch set is rejected, so an epoch advance invalidates all prior-epoch
  credentials unless the previous epoch is explicitly retained for a bounded
  rollout window. Revoking the `issuer_kid` (root) invalidates **every** credential
  it signed.
- **Blast radius.**
  - *Delegated key compromised:* an attacker can forge signatures only until
    `min(exp, revocation-takes-effect)` — bounded by `T` and cut shorter by
    trust-epoch revocation. The **root is untouched**; all other delegated keys are
    unaffected.
  - *Root compromised:* full identity compromise, exactly as today (ADR-MCPS-028
    governs root custody). Delegation does not enlarge this; it **shrinks** the
    root's exposure by removing it from the hot path — the root signs only
    credentials at issuance/rotation, orders of magnitude less often than
    per-request signing would touch it.

### 5a. Credential replay — no independent anti-replay; possession is the control

The delegation credential is a **public, reusable, short-lived authorization for a
delegated public key**; it does **not** authorize a response by itself. A response
is accepted only if the **delegated private key** signs the RFC 9421 response
evidence (RFC 7800 proof-of-possession: the credential carries the PoP public key
in `cnf.jwk`; the presenter must prove possession of the matching private key).
Two rules make this safe without a per-use replay cache:

1. The credential **MUST be covered by the RFC 9421 response signature** — it rides
   in the `content-digest`-covered evidence block (§2), so it cannot be stripped or
   swapped without breaking verification.
2. `jti` is for **audit / revocation / correlation only** — it is **not** a
   request-replay admission key. Response replay is handled by the existing
   HTTP-profile replay tier (ADR-MCPRE-050/051 §4), unchanged.

Lift-and-reuse of a credential is therefore inert except **within its own scope**:
same `delegated_kid`, `mcp_re_profile`, `mcp_re_key_use`, `mcp_re_server_signer`,
`mcp_re_audience_hash`/`aud`, a valid `nbf`/`exp` window, an accepted `trust_epoch`,
and not revoked. Any difference ⇒ reject (§3 steps 5–7). An attacker without the
delegated private key gains nothing from a copied credential.

### 6. Fail-closed issuance

If the HSM/KMS cannot issue or rotate a successor, the proxy continues signing with
the current delegated key **only until its `exp`**, then **STOPS signing** (serves
fail-closed `mcp-re.*` errors) rather than extend a stale key past its credential's
window. A verifier independently enforces the same bound: a credential with
`exp < now` is rejected (`mcp-re.delegation_credential_expired`). TTL is never
extended in place; expiry is authoritative on both sides.

### 7. Audit events — a new, ADR-authorized key-lifecycle category

This ADR authorizes a **third audit category**, `KEY_LIFECYCLE_EVENT_TYPES`, added
to the frozen, drift-guarded vocabulary in `mcp-re-core/src/audit.rs` (extending the
CI `audit_vocabulary_guard_test` allowlist in the same change that lands the
implementation):

- `mcp-re.delegated_key.issued`
- `mcp-re.delegated_key.rotated`
- `mcp-re.delegated_key.retired`

Each event records `event_type`, `delegated_kid`, `issuer_kid`, `nbf`, `exp`, the
`jti`, and the event timestamp. Events carry **no private key material and no
nonce/correlation data** (ADR-MCPS-020 startup-line discipline). Issuance failure
and fail-closed stop-signing (§6) are audited on the same channel.

### 8. Error taxonomy (frozen `mcp-re.*` tokens)

The delegation path adds these to the frozen wire-token taxonomy (pinned by
conformance vectors, §9; subject to the ADR-MCPS-002 vocabulary firewall):

| Token | Meaning |
|---|---|
| `mcp-re.delegation_credential_missing` | A delegated-key-signed response carried no inline credential. |
| `mcp-re.delegation_credential_invalid` | JWS malformed, `alg` ≠ `EdDSA`, JWS `kid` ≠ `issuer_kid`, or the root signature does not verify. |
| `mcp-re.delegation_credential_expired` | `now` outside `[nbf, exp]` (+ skew). |
| `mcp-re.delegation_issuer_untrusted` | `issuer_kid` is not a trusted root anchor. |
| `mcp-re.delegation_profile_mismatch` | `mcp_re_profile` ≠ the active HTTP profile id. |
| `mcp-re.delegation_audience_mismatch` | verifier not named in `aud`, or `mcp_re_audience_hash`/`mcp_re_server_signer` ≠ the expected service/audience scope. |
| `mcp-re.delegation_key_use_invalid` | `mcp_re_key_use` does not permit this signature use. |
| `mcp-re.delegation_trust_epoch_stale` | `trust_epoch` not in the verifier's active accepted epoch set (§3 step 6), independent of targeted revocation. |
| `mcp-re.delegation_key_mismatch` | RFC 9421 response `keyid` ≠ `delegated_kid`, or the response signature does not verify under `cnf.jwk`. |
| `mcp-re.delegation_revoked` | `delegated_kid` or `issuer_kid` revoked at the current trust epoch. |

All are fail-closed: any uncertainty on the delegation chain rejects the response;
a delegated signature is never accepted on a partial or unverifiable chain.

## Rationale

Using JOSE/JWS for the credential and RFC 9421 for the message keeps each standard
in the role it was designed for, which is the whole point of ADR-MCPRE-050's
"standards, not bespoke evidence" posture. JWS/JWT is a standards-track format for
exactly this — a signed, self-describing credential — and RFC 7800's `cnf`
confirmation claim is the standard pattern for binding a token to a
proof-of-possession key, which maps directly onto "the root asserts this delegated
key may sign." Pressing RFC 9421 into signing a bespoke "delegation object" would
reintroduce the very thing ADR-MCPRE-050 removes: a custom evidence object dressed
in standards syntax (what *is* the object, which HTTP fields represent it, may it be
cached, may it travel outside its response, how is its signature base
reconstructed later). RFC 9421 signs the HTTP message; JWS carries the credential;
RFC 9530 gives body integrity — no invented object.

The pure verification core gains nothing: JOSE/JWS verification lives in the
HTTP-profile standards layer that already parses RFC 9421, so `mcp-re-core` stays
lean (ADR-MCPS-018). Inline carriage in the covered evidence block makes a delegated
response **self-verifying** from a single pre-existing anchor (the root), honoring
ADR-MCPRE-051 §5's "trust through the credential to the root, not out-of-band
enrollment of ephemeral keys." The distinct delegated `key_id` namespace and the
`cnf`-bound public key keep the signing-locus rule (ADR-MCPS-003) intact so evidence
never impersonates the root. Rotation overlap and fail-closed expiry give continuity
without a stale-key escape hatch, and revocation rides the coherence channels the
fleet already proves (ADR-MCPS-021), so delegation adds no new distributed-state
machinery.

## Alternatives Considered

- **(a) RFC 9421 signing a custom "delegation evidence object."** Rejected — the
  wrong reuse. A delegation credential is not an HTTP transaction; making RFC 9421
  sign a bespoke object recreates a custom credential-carriage convention (object
  identity, field mapping, cacheability, out-of-response transport, signature-base
  reconstruction) — a bespoke evidence object disguised as standards reuse, exactly
  what ADR-MCPRE-050 avoids. RFC 9421 is used where it is strongest: signing the
  actual response.
- **The legacy JCS/object attestation (the prior draft of this ADR).** Rejected:
  ADR-MCPRE-050 makes native JCS/object signing legacy and forbids it as the
  foundation for new evidence; a two-profile (object + HTTP) delegation design is
  off-target. Superseded by the single HTTP-profile carrier here.
- **(c) X.509 / SPIFFE X509-SVID as the base credential.** Rejected as the base:
  legitimate but heavy — PKIX path validation, ASN.1, name constraints, chain
  handling, and deployment baggage, contradicting the lean-core posture
  (ADR-MCPS-018). Recorded as a **future OPTIONAL enterprise profile** (e.g. for
  SPIFFE/SPIRE shops), never the base ADR-052 format.
- **Out-of-band enrollment of delegated keys (resolver push as the trust source).**
  Rejected as the *authority*: recreates the ephemeral-key-enrollment problem
  ADR-MCPRE-051 §5 forbids and adds a first-use liveness dependency. Kept only as an
  OPTIONAL bandwidth optimization, never the trust source.
- **No credential — enroll each delegated public key directly in every verifier's
  trust map.** Rejected: unbounded trust-map write fan-out on every rotation, no
  cryptographic binding to the root, and a rotation-frequency / propagation race the
  credential chain avoids.
- **Per-request HSM/KMS signing (no delegation).** Rejected upstream by
  ADR-MCPRE-051 §5 (a remote round-trip on the hot path is disqualifying at this
  throughput class); this ADR removes it safely.
- **Long-lived delegated keys, or `alg` agility.** Rejected: long TTLs defeat the
  bounded-blast-radius property (TTL is the primary containment); `alg` agility adds
  a downgrade surface. `alg` is pinned to `EdDSA`, TTL is short.

## Consequences

### Positive
- No remote KMS/HSM operation on the per-request signing path; the root is off the
  hot path and far less exposed.
- One carrier, three standards each in its designed role (JWS credential / RFC 9421
  message / RFC 9530 digest) — a clean standards story, no custom crypto island.
- A delegated-key compromise is bounded by TTL and cut shorter by trust-epoch
  revocation; the root and other delegated keys are unaffected.
- The pure core gains no parsing surface; JOSE/JWS lives in the HTTP-profile layer.
- Delegated responses are self-verifying from the pre-existing root anchor.

### Negative
- A new, ADR-frozen vocabulary (ten `mcp-re.delegation_*` tokens — including
  `delegation_audience_mismatch` and `delegation_trust_epoch_stale` — plus three
  audit event types), four MCP-RE JWT claims (`mcp_re_profile`,
  `mcp_re_audience_hash`, `mcp_re_server_signer`, `mcp_re_key_use`), a new `typ`
  media type (`mcp-re-delegation+jwt`), and a new `server_delegation`
  evidence-block field — additive, but frozen surface.
- The HTTP-profile layer gains a compact-JWS/JOSE verifier (Ed25519/EdDSA only,
  `cnf.jwk` extraction) — a standards-track parser, but net-new code with its own
  hardening obligations (strict `alg`, no `none`, no header injection).
- Verifiers MUST implement the credential chain to accept any delegated signature; a
  verifier predating this ADR rejects delegated responses fail-closed (the correct,
  safe behavior).
- Rotation adds an issuer state machine (overlap window, fail-closed-at-expiry) on
  the signer side.

### Neutral
- Reuses the trust-epoch / revocation coherence (ADR-MCPS-021) and the
  rotation-tolerant by-`key_id` trust map already in the tree.
- Root custody is unchanged (ADR-MCPS-028); this ADR governs only what the root
  delegates and how that delegation is proven.
- The object profile is untouched — it simply is not extended for delegation
  (ADR-MCPRE-050: HTTP profile is the one carrier for new evidence).

## Compliance and Enforcement — Conformance-Vector Plan

Credential verification is pinned by committed golden vectors (conformance-as-
specification, ADR-MCPS-011), runnable by the `mcp-re-conformance` HTTP-profile
runner and gated in CI. Vectors are compact-JWS credentials + RFC 9421 responses:

1. **valid** — valid credential + valid delegated-signed response ⇒ **accept**;
   the verified `server_signer` resolves to the delegated identity.
2. **credential_expired** — `exp < now` ⇒ reject `mcp-re.delegation_credential_expired`.
3. **not_yet_valid** — `now < nbf` ⇒ reject (same token).
4. **key_use_invalid** — `mcp_re_key_use` ≠ `response-signing` ⇒ reject
   `mcp-re.delegation_key_use_invalid`.
5. **profile_mismatch** — `mcp_re_profile` ≠ the active HTTP profile id ⇒ reject
   `mcp-re.delegation_profile_mismatch`.
5a. **audience_mismatch** — verifier not named in `aud`, OR `mcp_re_audience_hash` /
    `mcp_re_server_signer` ≠ the expected service/audience scope ⇒ reject
    `mcp-re.delegation_audience_mismatch` (proves a valid credential for one
    service/scope is not accepted by a different verifier of the same profile).
5b. **trust_epoch_stale** — a valid, unrevoked credential whose `trust_epoch` is
    not in the verifier's active accepted epoch set ⇒ reject
    `mcp-re.delegation_trust_epoch_stale`; a companion vector proves the bounded
    rollout window `{ current, previous }` accepts a previous-epoch credential
    only when explicitly configured.
5c. **delegation_required_rejects_direct_root** — in the default (required) mode, a
    directly root-signed response with no delegation credential ⇒ reject
    `mcp-re.delegation_credential_missing`; the `mixed-migration` mode accepts it
    only with an audit event emitted.
6. **revoked** — `delegated_kid` revoked at the current trust epoch ⇒ reject
   `mcp-re.delegation_revoked`; and root-revocation invalidates its credentials.
7. **substituted_delegated_key** — response signed by a key other than `cnf.jwk` /
   `keyid` ≠ `delegated_kid` ⇒ reject `mcp-re.delegation_key_mismatch`.
8. **credential_stripped** — delegated-key response with the credential removed ⇒
   reject `mcp-re.delegation_credential_missing`; **credential_replaced** — a
   different/foreign credential swapped in ⇒ reject
   `mcp-re.delegation_credential_invalid` (or `_key_mismatch` if it fails the
   `keyid`/`cnf` cross-check) and/or the covered-`content-digest` check.
9. **issuer_untrusted** — `issuer_kid` not a trusted anchor ⇒ reject
   `mcp-re.delegation_issuer_untrusted`.
10. **wrong_alg** — credential header `alg` ≠ `EdDSA` (incl. `none`) ⇒ reject
    `mcp-re.delegation_credential_invalid`.
11. **rotation_overlap** — two valid credentials for successor keys; a response
    under **either** ⇒ **accept** (no verification gap across rotation).
12. **response_signature_mismatch** — valid credential but a body/digest tamper ⇒
    reject via the existing HTTP-profile response-signature-invalid token.

Release gates (with ADR-MCPRE-051): the delegated-signing implementation (MCPRE-122
/ #328) MUST hold these vectors green, MUST prove continuous signing + verification
across a rotation (no gap), and MUST prove fail-closed stop-signing at current-key
expiry when issuance fails — before any release signs with a delegated key.
Cross-verification against an independent JOSE/JWS implementation (mirroring the
RFC 9421 external cross-verify gate, MCPRE-99) SHOULD confirm the credential is
standards-conformant, not merely self-consistent.

## Related

- Companion to: ADR-MCPRE-051 §5 (delegated signing custody — the decision this ADR
  gives a wire format).
- Controlled by: ADR-MCPRE-050 (Standards-Aligned HTTP Profile — RFC 9421 + RFC 9530
  as the one carrier; native JCS/object signing is deprecated and not the foundation
  for new evidence), reinforced by the control note
  [`docs/design/active-profile-and-legacy-quarantine.md`](../design/active-profile-and-legacy-quarantine.md)
  (D6: this ADR must not use a JCS-signed delegation object — satisfied here).
- Builds on: ADR-MCPS-028 (KMS/HSM custody — root retained, unchanged),
  ADR-MCPS-003 (signing-locus rule — evidence never impersonates the root),
  ADR-MCPRE-050 (HTTP profile / RFC 9421 carrier), ADR-MCPS-020 (durability /
  startup-line discipline), ADR-MCPS-021 (revocation / rotation propagation across a
  fleet), ADR-MCPS-002 (frozen wire vocabulary), ADR-MCPS-018 (lean verification
  core).
- Standards: RFC 7515 (JWS), RFC 7517 (JWK), RFC 7519 (JWT), RFC 7800 (`cnf`
  proof-of-possession), RFC 8037 (EdDSA/Ed25519 in JOSE), RFC 9421 (HTTP Message
  Signatures), RFC 9530 (Digest Fields).
- Implemented by: MCPRE-122 (#328) — delegated signing keys (BLOCKED on this ADR's
  ratification).
