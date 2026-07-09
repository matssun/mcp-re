<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-052: Delegated Signing-Key Attestation — Wire Evidence Format, Verifier Trust Chain, Rotation, Revocation, and Audit

## Status

Proposed

Companion to ADR-MCPRE-051 §5 (High-Throughput Serving Architecture — delegated
signing custody). **This ADR is BLOCKING for any production delegated-signing
release (ADR-MCPRE-051 §5): no release signs responses with a delegated key before
this ADR is ratified (Status → Accepted) and its conformance vectors are green.**
The *decision to adopt* delegated signing is already made in ADR-MCPRE-051; this
ADR ratifies only its wire format, verifier trust chain, and lifecycle taxonomy.

## Context

ADR-MCPRE-051 §5 removes the remote HSM/KMS round-trip from the per-request
signing path: the root/identity key stays in the HSM/KMS (ADR-MCPS-028 posture,
unchanged) and issues a **short-lived, in-memory Ed25519 delegated signing key**;
per-request response signing uses the delegated key in process (microseconds),
with KMS/PKCS#11 operations confined to a bounded `spawn_blocking` pool at
issuance/rotation only. ADR-MCPRE-051 fixes the *custody model* — bounded
lifetime, rotation overlap, per-key `key_id`, root-signed attestation, audit,
revocation, fail-closed issuance — and explicitly defers the **wire-level
delegation evidence format** (how the attestation is carried and verified) to this
companion ADR.

Today the response envelope's signature block carries a static `key_id`
(`proxy.rs:774`) resolved against a trust anchor the verifier already holds; the
by-`key_id` trust map is rotation-tolerant (`transport.rs`), and the trust-epoch /
revocation subsystem (`trust_epoch.rs`, `revocation_tier.rs`, `push_trust.rs`)
propagates invalidations across a fleet with bounded lag. The audit vocabulary
(`mcp-re-core/src/audit.rs`) is a frozen, drift-guarded allowlist of exactly two
success event types; its module note states no third success/lifecycle event may
be minted **without an ADR**. This ADR is that authorizing ADR for the
key-lifecycle audit category.

The open question this ADR answers: **by what verifiable, standards-shaped
evidence does a verifier trust a signature made by a delegated key it was never
enrolled with — binding that key, through a root-signed attestation, back to the
identity anchor it already trusts — and how is that key rotated, revoked, audited,
and failed closed?**

Two constraints shape the design:

- **The verification core stays pure and lean (ADR-MCPRE-051 §2, ADR-MCPS-018).**
  The attestation MUST verify with the primitives `mcp-re-core` already has
  (Ed25519 + JCS canonicalization + freshness), with no new parsing surface (no
  X.509/ASN.1 PKI) admitted into the core.
- **Evidence never impersonates the root (ADR-MCPS-003 signing-locus rule).** The
  delegated key has its own identity; a verifier can always tell a delegated
  signature from a root signature, and a compromised delegated key can never be
  mistaken for the root.

## Decision

The delegation evidence is a **signed-object-shaped, root-signed attestation**
carried **inline** alongside each delegated-key signature, verified by the same
Ed25519-over-JCS primitives as every other MCP-RE object. It is **not**
certificate-shaped (X.509) — see Alternatives.

### 1. The delegation attestation object

A **delegation attestation** is a JCS-canonicalizable JSON object binding one
delegated public key to the root, signed by the **root key in the HSM/KMS**:

```
DelegationAttestation:
    profile        : "mcp-re.delegation/v1"     # frozen tag (vocabulary firewall)
    delegated_key  : <Ed25519 public key, base64url-no-pad>
    delegated_kid  : <the delegated key's own key_id>          # never the root kid
    issuer_kid     : <the root/identity key_id that signed this attestation>
    not_before     : <unix seconds>
    expires_at     : <unix seconds>            # bounded lifetime; short TTL
    # signed by the ROOT key over the JCS canonicalization of the above fields.
    signature      : { alg: "ed25519", kid: <issuer_kid>, value: <base64url> }
```

- The attestation's own `signature.kid` is the **root** `key_id` (the identity
  anchor the verifier already trusts); its covered payload names the **delegated**
  key. This is the only place the root key signs on the delegated path, and it is
  produced off the hot path at issuance/rotation.
- `delegated_kid` is a distinct, delegated-namespace identifier
  (RECOMMENDED shape `<issuer_kid>/delegated/<monotonic-counter>`), so a reader —
  human or machine — can never confuse a delegated `key_id` for the root's. The
  response signature block names `delegated_kid`, **never** `issuer_kid`
  (ADR-MCPS-003: evidence names the key that actually signed).

### 2. Wire carriage — inline, root-self-protected, excluded from the delegated preimage

The attestation is carried **inline with the response**, as a sibling of the
response signature, in both profiles:

- **Object profile (ADR-MCPS-004 envelope):** a `delegation` field in the
  envelope's signature block carries the full attestation object. Because the
  attestation is **root-signed and self-protecting**, it is **excluded from the
  delegated-key preimage** (as trace context is excluded, ADR-MCPS-026) — the
  delegated signature covers the response body; the attestation carries its own
  independent root signature. A verifier reconstructs both preimages
  deterministically.
- **HTTP profile (ADR-MCPRE-050, RFC 9421):** the attestation rides in the
  response evidence block (`se.syncom/mcp-re.http.response`), protected by the
  covered `content-digest`, alongside `server_signer`.

Inline carriage is self-contained: a verifier needs no out-of-band resolver
round-trip for the delegated key — only the pre-existing trust anchor for the
**root** `issuer_kid`. (An OPTIONAL resolver-distribution mode, publishing
attestations by `delegated_kid`, is permitted as a bandwidth optimization but is
never REQUIRED and never the trust source — the trust source is always the
root-signed attestation chain.)

### 3. Verifier trust chain — attestation → root, no ephemeral enrollment

A verifier presented with a delegated-key-signed response:

1. Resolves `issuer_kid` to a trusted **root** anchor via the existing trust
   resolver / by-`key_id` trust map. An unknown issuer ⇒
   `mcp-re.delegation_issuer_untrusted`.
2. Verifies the attestation's root signature over its JCS payload. Invalid or
   malformed ⇒ `mcp-re.delegation_attestation_invalid`.
3. Enforces freshness: `not_before ≤ now ≤ expires_at` (+ `max_clock_skew`).
   Outside the window ⇒ `mcp-re.delegation_attestation_expired`.
4. Checks revocation: neither `delegated_kid` nor `issuer_kid` is revoked at the
   current trust epoch (§5). Revoked ⇒ `mcp-re.delegation_revoked`.
5. Verifies the **response** signature with `delegated_key`, requiring the response
   signature block's `kid == delegated_kid`. Mismatch ⇒
   `mcp-re.delegation_key_mismatch`; bad signature ⇒ the existing
   `mcp-re.*` response-signature-invalid token.

Trust flows **only** through the attestation chain to the root — a delegated key
is **never** enrolled out of band, and a verifier that has never seen a given
`delegated_kid` still verifies it the first time from the attestation alone.

### 4. Lifetime and rotation overlap — no signing gap, no verification gap

- **Bounded lifetime.** Each delegated key has a short TTL `T` (RECOMMENDED
  minutes-to-hours; the concrete value is a deployment profile parameter, pinned
  by the benchmark/release profile, not fixed here).
- **Rotation overlap window `O` (`0 < O < T`).** The issuer mints a **successor**
  delegated key at `expires_at − O` and begins signing with it **before** the
  predecessor lapses. The predecessor's attestation stays valid (verifiers accept
  it) until its own `expires_at`. Thus at any instant at most two delegated keys
  are simultaneously valid; there is **no signing gap** (successor ready before
  predecessor expiry) and **no verification gap** (predecessor accepted until
  expiry). This is exactly the overlap the rotation-tolerant by-`key_id` trust map
  already supports on the verify side.

### 5. Revocation via the trust-epoch channel; compromise blast radius

- **Revocation** reuses the existing channels (ADR-MCPS-021, `trust_epoch.rs`,
  `revocation_tier.rs`): revoking a `delegated_kid` publishes it to the revocation
  tier and advances the monotonic **trust epoch**, flushing caches fleet-wide with
  the per-tier bounded lag the fleet already declares. Revoking the `issuer_kid`
  (root) invalidates **every** attestation it signed.
- **Blast radius.**
  - *Delegated key compromised:* an attacker can forge signatures only until
    `min(expires_at, revocation-takes-effect)` — bounded by `T` and cut shorter by
    trust-epoch revocation. The **root is untouched**; all other delegated keys are
    unaffected.
  - *Root compromised:* full identity compromise, exactly as today (ADR-MCPS-028
    governs root custody). Delegation does not enlarge this; it **shrinks** the
    root's exposure by removing it from the hot path — the root signs only
    attestations at issuance/rotation, so it is touched orders of magnitude less
    often than per-request signing would touch it.

### 6. Fail-closed issuance

If the HSM/KMS cannot issue or rotate a successor, the proxy continues signing with
the current delegated key **only until its `expires_at`**, then **STOPS signing**
(serves fail-closed `mcp-re.*` errors) rather than extend a stale key past its
attested window. A verifier independently enforces the same bound: an attestation
with `expires_at < now` is rejected (`mcp-re.delegation_attestation_expired`). TTL
is never extended in place; expiry is authoritative on both sides.

### 7. Audit events — a new, ADR-authorized key-lifecycle category

This ADR authorizes a **third audit category**, `KEY_LIFECYCLE_EVENT_TYPES`, added
to the frozen, drift-guarded vocabulary in `mcp-re-core/src/audit.rs` (extending
the CI `audit_vocabulary_guard_test` allowlist in the same change that lands the
implementation):

- `mcp-re.delegated_key.issued`
- `mcp-re.delegated_key.rotated`
- `mcp-re.delegated_key.retired`

Each event records `event_type`, `delegated_kid`, `issuer_kid`, `not_before`,
`expires_at`, and the event timestamp. Events carry **no private key material and
no nonce/correlation data** (the ADR-MCPS-020 startup-line discipline). Issuance
failure and fail-closed stop-signing (§6) are audited on the same channel.

### 8. Error taxonomy (frozen `mcp-re.*` tokens)

The delegation path adds these to the frozen wire-token taxonomy (pinned by
conformance vectors, §9, subject to the ADR-MCPS-002 vocabulary firewall):

| Token | Meaning |
|---|---|
| `mcp-re.delegation_attestation_invalid` | Attestation malformed or its root signature does not verify. |
| `mcp-re.delegation_attestation_expired` | `now` outside `[not_before, expires_at]` (+ skew). |
| `mcp-re.delegation_issuer_untrusted` | `issuer_kid` is not a trusted root anchor. |
| `mcp-re.delegation_key_mismatch` | Response signature `kid` ≠ `delegated_kid`, or the signature does not verify under `delegated_key`. |
| `mcp-re.delegation_revoked` | `delegated_kid` or `issuer_kid` revoked at the current trust epoch. |

All are fail-closed: any uncertainty on the delegation chain rejects the response;
a delegated signature is never accepted on a partial or unverifiable chain.

## Rationale

A signed-object attestation reuses MCP-RE's existing cryptographic carrier
(Ed25519-over-JCS; RFC 9421 in the HTTP profile) so the **verification core gains
no new parsing surface** — the pure, lean core (ADR-MCPS-018) verifies a delegation
attestation with the same primitives it already ships, unlike an X.509 chain which
would drag ASN.1/PKIX into the trust boundary. Inline carriage makes a delegated
response **self-verifying** from a single pre-existing anchor (the root), honoring
ADR-MCPRE-051 §5's "trust through the attestation chain to the root, not by
out-of-band enrollment of ephemeral keys." Binding `(delegated_key, delegated_kid,
issuer_kid, not_before, expires_at)` under the root signature makes the delegation
**non-repudiable and time-boxed**; the distinct delegated `key_id` namespace keeps
the signing-locus rule (ADR-MCPS-003) intact so evidence never impersonates the
root. Rotation overlap and fail-closed expiry give continuity without a stale-key
escape hatch, and revocation rides the coherence channels the fleet already proves
(ADR-MCPS-021), so delegation adds no new distributed-state machinery.

## Alternatives Considered

- **X.509 / certificate-shaped delegation.** Rejected: admits an ASN.1/PKIX
  parsing surface into the verification core, contradicting the lean-core posture
  (ADR-MCPS-018); MCP-RE's carrier is signed JSON objects / RFC 9421, not PKI.
- **Out-of-band enrollment of delegated keys (resolver push as the trust source).**
  Rejected as the *authority*: it recreates the ephemeral-key-enrollment problem
  ADR-MCPRE-051 §5 explicitly forbids and adds a liveness dependency to first-use.
  Kept only as an OPTIONAL bandwidth optimization, never the trust source.
- **No attestation — enroll each delegated public key directly in every verifier's
  trust map.** Rejected: unbounded fan-out of trust-map writes on every rotation,
  no cryptographic binding to the root, and a rotation-frequency / trust-propagation
  race the attestation chain avoids entirely.
- **Per-request HSM/KMS signing (no delegation).** Rejected upstream by
  ADR-MCPRE-051 §5 (a remote round-trip on the hot path is disqualifying at this
  throughput class); this ADR exists precisely to remove it safely.
- **Long-lived delegated keys.** Rejected: defeats the bounded-blast-radius
  property; TTL is the primary containment for a delegated-key compromise.

## Consequences

### Positive
- No remote KMS/HSM operation on the per-request signing path; the root is off the
  hot path and far less exposed.
- A delegated-key compromise is bounded by TTL and cut shorter by trust-epoch
  revocation; the root and other delegated keys are unaffected.
- Verifiers gain no new parsing surface; the pure core is preserved.
- Delegated signatures are self-verifying from the pre-existing root anchor.

### Negative
- A new, ADR-frozen vocabulary (five error tokens + three audit event types) and a
  new envelope field / response-block member — additive, but frozen surface.
- Verifiers MUST implement the attestation chain to accept any delegated signature;
  a verifier that predates this ADR rejects delegated responses fail-closed (which
  is the correct, safe behavior).
- Rotation adds an issuer state machine (overlap window, fail-closed-at-expiry) on
  the signer side.

### Neutral
- Reuses the trust-epoch / revocation coherence (ADR-MCPS-021) and the
  rotation-tolerant by-`key_id` trust map already in the tree.
- Root custody is unchanged (ADR-MCPS-028); this ADR governs only what the root
  delegates and how that delegation is proven.

## Compliance and Enforcement — Conformance-Vector Plan

Attestation verification is pinned by committed golden vectors (the
conformance-as-specification discipline, ADR-MCPS-011), runnable by the
`mcp-re-conformance` object runner and gated in CI:

1. **valid** — valid attestation + valid delegated-signed response ⇒ **accept**;
   verified `server_signer`/actor resolves to the delegated identity.
2. **attestation_expired** — `expires_at < now` ⇒ reject
   `mcp-re.delegation_attestation_expired`.
3. **not_yet_valid** — `now < not_before` ⇒ reject (same token).
4. **issuer_untrusted** — `issuer_kid` not a trusted anchor ⇒ reject
   `mcp-re.delegation_issuer_untrusted`.
5. **attestation_tampered** — mutated payload / bad root signature ⇒ reject
   `mcp-re.delegation_attestation_invalid`.
6. **key_mismatch** — response `kid` ≠ `delegated_kid`, or response signed by a key
   other than `delegated_key` ⇒ reject `mcp-re.delegation_key_mismatch`.
7. **rotation_overlap** — two valid attestations for successor keys; a response
   under **either** ⇒ **accept** (no verification gap across rotation).
8. **revoked** — `delegated_kid` revoked at the current trust epoch ⇒ reject
   `mcp-re.delegation_revoked`; and root-revocation invalidates its attestations.

Release gates (with ADR-MCPRE-051): the delegated-signing implementation (MCPRE-122
/ #328) MUST hold these vectors green, MUST prove continuous signing + verification
across a rotation (no gap), and MUST prove fail-closed stop-signing at current-key
expiry when issuance fails — before any release signs with a delegated key.

## Related

- Companion to: ADR-MCPRE-051 §5 (delegated signing custody — the decision this ADR
  gives a wire format).
- Builds on: ADR-MCPS-028 (KMS/HSM custody — root retained, unchanged),
  ADR-MCPS-003 (signing-locus rule — evidence never impersonates the root),
  ADR-MCPS-004 (Ed25519-over-JCS carrier), ADR-MCPRE-050 (HTTP profile / RFC 9421
  carrier), ADR-MCPS-020 (trust-epoch-adjacent durability discipline),
  ADR-MCPS-021 (revocation / rotation propagation across a fleet),
  ADR-MCPS-002 (frozen wire vocabulary), ADR-MCPS-018 (lean verification core).
- Implemented by: MCPRE-122 (#328) — delegated signing keys (BLOCKED on this ADR's
  ratification).
