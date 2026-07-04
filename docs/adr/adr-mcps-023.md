<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-023: Ingress and Reverse-Proxy mTLS — End-to-End Binding vs. Trusted-Ingress Re-Assertion

## Status

Accepted (v0.3 — 2026-06-15). Both ingress modes are implemented in `mcps-proxy`:
`end_to_end_mtls` via the pluggable `TransportBindingPolicy` (`ExactMatchBinding`
/ `MappedBinding`, binding the verified mTLS peer to the request signer), and
`trusted_ingress_asserted` via the hardened XFCC asserted-identity path
(RFC2253-aware, cross-element-consistency and unterminated-quote fail-closed;
issue #21). SEP-2243 routing headers remain untrusted in both modes (ADR-MCPS-025).

**v0.9/v0.10 hardening amendment (2026-07-03):** the enterprise-ingress and
mTLS-certificate-revocation deltas are recorded in the
[**v0.9/v0.10 Enterprise-Ingress Amendment**](#v09v010-enterprise-ingress-amendment-2026-07-03)
below. In short: strict admits exactly two postures — `end_to_end_mtls` (Mode A,
default) and a new, explicit-opt-in **Attested Ingress** (Mode C, *attested
delegation*, v0.10); the legacy header / plain-`lb-assertion` paths (Mode B) stay
strict-rejected and out of the recommended cookbook. Mode A gains a v0.9
cert-revocation honesty pass (short-lived-cert default, a strict cert-lifetime
ceiling, static-CRL fail-closed-on-stale). No draft-02 wire change.

## Context

ADR-MCPS-014 binds the verified request to the mTLS client-cert identity via the
opt-in, pluggable `TransportBindingPolicy` (`Box<dyn TransportBindingPolicy>`),
applied after verification, failing with `mcps.transport_binding_failed`. Client
certs are verified against client-CA anchors with short-lived-cert enforcement +
OCSP, no implicit fallback. The binding ties the application-layer signature to
the transport-layer client identity.

A TLS-terminating reverse proxy (Envoy, NGINX, HAProxy, a cloud LB, a service
mesh) breaks that binding: the proxy node's mTLS peer becomes the load balancer,
not the client. ADR-MCPS-017 deferred "reverse-proxy mTLS." This ADR decides the
ingress model. The pluggable `TransportBindingPolicy` is the seam.

## Definitions

- **`authenticated LB↔node channel`** — mTLS, or an equivalent mutually
  authenticated private channel, in which the **node authenticates the ingress
  identity against a configured trusted-ingress allowlist**. Network location, a
  private IP range, a Kubernetes namespace, or the mere presence of a header is
  **not** sufficient.
- **`transport_binding_mode`** — the declared ingress posture: `end_to_end_mtls`
  or `trusted_ingress_asserted`. The bare label `mtls` is forbidden.

## Decision

Support two ingress modes; **Tier 2 is supported but explicitly downgraded** and
MUST NOT be presented as equivalent to end-to-end mTLS.

| Tier | Ingress | Channel binding | LB in identity path? |
|---|---|---|---|
| **1 — `end_to_end_mtls`** *(default, strongest)* | L4 / TLS pass-through; client↔node mTLS end-to-end | Cryptographically bound to the client↔node TLS session | **No** |
| **2 — `trusted_ingress_asserted`** *(optional, weakened)* | L7 ingress terminates client mTLS, re-asserts verified client identity to the node over an authenticated LB↔node channel | Bound to the **LB↔node** hop; client identity is *asserted by trusted ingress*, not end-to-end | **Yes — ingress is in the TCB** |

### Tier 2 is explicit opt-in

Tier 2 MUST be explicitly configured (`transport_binding_mode =
trusted_ingress_asserted`, `trusted_ingress_identity = …`, `asserted_identity_header
= …`). **The presence of asserted-identity headers MUST NOT cause the proxy to
enter Tier 2.** A proxy running in `end_to_end_mtls` mode MUST ignore or reject
Tier-2 asserted-identity metadata even if such headers are present.

### Node-side trusted-ingress authentication is the security gate

The node MUST treat **all** asserted-identity metadata as attacker-controlled
unless the immediate peer is authenticated as a configured trusted ingress over
an authenticated LB↔node channel. Public-side header stripping is required, but
**node-side trusted-ingress authentication is the gate** — the node stays robust
even if a misconfigured ingress fails to strip a spoofed header. If the peer is
not a configured trusted ingress, asserted-identity metadata MUST be ignored or
rejected.

### Asserted-identity header rules

Tier-2 asserted-identity metadata MUST be:

- **single-valued** — duplicate or conflicting asserted-identity headers MUST
  fail closed;
- **well-formed** — malformed metadata MUST fail closed;
- **length-bounded** — oversized values MUST fail closed;
- carried under **explicitly configured** header names;
- treated as **opaque** identity strings unless the configured identity policy
  defines a parser.

This defeats ambiguous inputs (`X-MCPS-Verified-Client-Identity: attacker` +
`: real-client`, or comma-merged variants parsed differently across HTTP stacks).

### Minimum Tier-2 assertion metadata

Required: `asserted_client_identity`, `identity_source`, `ingress_identity`,
`validation_time`, and `client_cert_fingerprint` (if client-cert based).
Optional: `client_cert_issuer`, `client_cert_not_before`, `client_cert_not_after`,
`client_cert_trust_anchor`. The node need not re-validate the client certificate
in Tier 2, but MUST log enough to prove *what* the ingress asserted and *when*.

### Mode naming and audit taxonomy

`transport_binding_mode` MUST be `end_to_end_mtls` or `trusted_ingress_asserted`
— never bare `mtls`, which hides the distinction. Audit events MUST include, at
minimum: `transport_binding_mode`, `node_peer_identity`, `trusted_ingress_identity`
(Tier 2), `asserted_client_identity` (Tier 2), `client_cert_fingerprint` (if
present), `binding_policy_result`, and a `reason_code` on failure. Because Tier 2
carries a downgraded claim, reviewers and incident responders MUST be able to see
which mode was used per request.

### Certificate revocation/lifetime enforcement shift

In Tier 2 the ingress enforces client-cert validation, identity extraction, max
lifetime, and any CRL/OCSP posture. The node enforces the LB↔node channel
identity, that the ingress is trusted, that asserted-identity metadata is present
and well-formed, and the transport-binding policy against the asserted identity.
Audit MUST record the certificate enforcement point as the ingress in Tier 2.
This shift MUST be stated in `security-boundary.md`.

### Tier 3 — LB-signed, request-bound ingress assertion (resolved, issue #71)

An LB-signed, request-bound assertion (the LB signing a statement tying client
identity to the specific request hash) is **Tier 3**. Tier 3 is required if a
deployment wants the node to **cryptographically verify that the ingress
assertion was bound to a specific MCP-S request**, rather than relying only on
the authenticated LB↔node channel. v0.3's `trusted_ingress_asserted` (Tier 2)
accepts authenticated LB↔node mTLS plus strict header handling inside one trust
domain; Tier 3 adds the cryptographic request-binding on top.

Tier 3 is implemented in `mcps-proxy` (issue #71, v0.4 axis-hardening) as the
`LbAssertionBinding` node-side verifier and the `--transport-binding lb-assertion`
/ repeatable `--ingress-lb-key <keyid>:<base64url-ed25519-pub>` configuration:

- **Assertion format.** Fields: `key_id`, `asserted_client_identity`,
  `request_hash` (the MCP-S `sha256:<base64url>` identifier), and a freshness
  `validation_time` (Unix seconds). The **signed preimage** is a deterministic,
  UNAMBIGUOUS **length-prefixed** encoding — a frozen domain-separation tag
  (`mcps/lb-ingress-assertion/v1`) followed, for each variable-length field, by
  its `u64` big-endian byte length then its bytes, then the fixed-width `i64`
  timestamp. Length-prefixing (not delimiter-joining) defeats the
  delimiter-collision class: no field value can be re-split into a different field
  tuple. The LB Ed25519-signs that preimage. The wire form is a single header of
  five `.`-separated base64url fields (the textual fields base64url-encoded so
  they can never contain the `.` separator); the base64url framing is transport
  only — the *signature* covers the length-prefixed preimage.
- **LB key custody.** A small in-proxy trust map of LB verification keys addressed
  by key id (`--ingress-lb-key`). An assertion naming an unknown key id is
  rejected (fail closed).
- **Node-side verification (ordered, fail-closed).** (1) parse/shape; (2) look up
  the LB key by key id — unknown ⇒ reject; (3) Ed25519-verify the signature over
  the canonical preimage — bad ⇒ reject; (4) compare the assertion's bound
  `request_hash` to the **in-hand** request hash the node already holds (the same
  `request_hash` from `verify_request`) — mismatch (cross-request / wrong hash) ⇒
  reject; (5) freshness window — stale (or implausibly future) ⇒ reject. Only then
  is the verified identity yielded, and it binds to the request signer through the
  SAME `TransportBindingPolicy` (`ExactMatchBinding`) the Tier-1/Tier-2 paths use.
- **Replay.** A replayed assertion against a *different* request fails check (4)
  (its bound hash will not match); a replay against the *same* request is caught by
  that request's own replay cache (run in `verify_request` before binding) and by
  the freshness window. The assertion therefore needs no independent nonce.
- **Honesty.** Tier 3 verifies request-bound INGRESS assertion — the LB still
  terminates the client mTLS and is in the TCB — so it is **NOT** end-to-end
  client↔node binding and MUST NOT be surfaced as `end_to_end_mtls`. The guarantee
  string is `request_bound_ingress_assertion`. Object-signature verification is
  unchanged and still runs in `verify_request` independently of and before this
  transport binding. Under `--strict`/`--production` the proxy refuses to enable
  `lb-assertion` silently.

**Integration (issue #71).** The cryptographic verifier, the LB key-custody
trust map, the CLI configuration, AND the live-serve-loop wiring all land in
`mcps-proxy`. The presented assertion header (`mcp-ingress-assertion`) is routed
through the serve path by `IdentityStrategy::LbAssertion` plus a
`serve_once_with_assertion` entry point, and verified at the post-verification
binding step in `Proxy::handle_with_transport` — where the in-hand
`request_hash` is already available, so the binding check sees both the verified
signer and the verified request hash. `serve_once`/`serve` keep their original
arity by delegating to the new entry point, so the demo/transport callers are
unchanged. Object-signature verification still runs first in `verify_request`,
independently of and before this binding. The feature is therefore enforced
end-to-end, with both a unit-level verifier suite and a serve-level acceptance
suite (`tests/proxy_lb_assertion_test.rs`).

## Threat Model

- **Trust boundary:** one operator; in Tier 2 the ingress is part of the TCB.
- **Primary threat (Tier 2):** an attacker forges client identity by supplying a
  `X-MCPS-Verified-*` header directly, hoping the node trusts it. Defeated by the
  explicit-opt-in, node-side-trusted-ingress-auth, and header rules above.
- **Private network location is not authentication:** a request arriving from an
  internal IP, service-network address, or Kubernetes namespace is **not**
  sufficient to enter Tier 2 unless the LB↔node channel authenticates the ingress
  identity.
- **Residual (Tier 2):** a compromised trusted ingress can assert arbitrary
  client identities — accepted as a consequence of placing ingress in the TCB;
  the claim is downgraded accordingly and never described as end-to-end binding.
- **Tier 1:** no LB in the identity path; the ADR-014 binding is intact.

## Conformance Vectors (ADR-MCPS-011)

- Trusted ingress over an authenticated LB↔node channel → accepted.
- Untrusted ingress identity → rejected.
- Missing LB↔node authentication → fail closed.
- **Header-presence-not-enough:** Tier 2 is not activated by header presence
  alone; in `end_to_end_mtls` mode asserted headers are ignored/rejected.
- **Spoof test (non-negotiable):** a client sends `X-MCPS-Verified-Client-Identity`
  directly, without trusted-ingress authentication → rejected/ignored.
- **Duplicate headers** fail closed; **malformed or oversized** metadata fails
  closed.
- **Internal network source** without an authenticated trusted-ingress identity
  → fails closed.
- Public caller-supplied identity header → stripped before the node.
- Wrong asserted identity → transport-binding failure.
- **Cert-enforcement shift:** Tier 2 accepts only when trusted ingress asserts;
  records that client-cert validation was performed by the ingress; rejects if
  required validation metadata fields are absent; audit states cert enforcement
  point = ingress.
- Tier-2 audit includes `transport_binding_mode`, `trusted_ingress_identity`,
  `asserted_client_identity`, and the binding result; distinguishable from Tier 1.
- Tier 2 does **not** bypass MCP-S object signature verification.
- Tier 2 does **not** bypass Phase 5 (ADR-MCPS-013) authorization.

## Rationale

TLS termination at an L7 ingress is common in real deployments; deferring it
entirely would make the multi-node story much less useful. But it genuinely
weakens the transport guarantee, so it must be supported *and* honestly
downgraded — in docs, config names, audit logs, and policy outputs — never
marketed as equal to end-to-end mTLS. The one-trust-domain claim is what makes
placing the ingress in the TCB acceptable at all; making Tier 2 impossible to
enable accidentally or to spoof with headers is what keeps it safe.

## Alternatives Considered

- **Defer Tier 2 entirely** — rejected: too common a deployment shape to omit.
- **Require an LB-signed request-bound assertion in v0.3** — rejected as scope:
  assertion format, LB signing key, expiry, request-hash binding, assertion
  replay handling, rotation, and audit semantics are a separate profile (future
  Tier 3).
- **Allow a plain trusted header / trust by network location** — rejected: the
  classic `X-Client-Cert` spoofing bug; forbidden normatively.

## Consequences

### Positive
- Real-world L7-termination deployments are supported, with an honest, visible
  downgrade, a mandatory anti-spoof posture, and explicit opt-in.

### Negative
- Two transport postures to document, name, and test distinctly; Tier 2 puts the
  ingress in the TCB.

### Neutral
- The pluggable `TransportBindingPolicy` already provides the seam; Tier 2 is a
  new policy, not a core change.

## Compliance and Enforcement

`security-boundary.md`: *"The strongest transport-binding claim requires
end-to-end client↔node mTLS using L4/TLS pass-through ingress. MCP-S also
supports a trusted-ingress mode in which an ingress terminates client mTLS and
re-asserts the verified client identity to the node over an authenticated LB↔node
channel; in this mode the ingress is part of the trusted computing base and the
node relies on the ingress's assertion. This is not cryptographic end-to-end
client↔node channel binding. Tier 2 is explicit opt-in; unauthenticated
client-identity headers and trust-by-network-location are forbidden."*

## Related

- ADR-MCPS-014 (Phase 6 transport hardening, `TransportBindingPolicy`)
- ADR-MCPS-013 (Phase 5 authorization — not bypassed by Tier 2)
- ADR-MCPS-017 (deferred reverse-proxy mTLS)
- ADR-MCPS-011 (conformance-as-specification)

## Open Questions for Review

- The exact authenticated LB↔node assertion envelope (namespaced headers over
  LB↔node mTLS vs. a structured metadata block).
- Whether the migration to Tier 2 needs its own strict-mode guard so it cannot be
  enabled silently in a hardened deployment.
- ~~Future Tier 3 (LB-signed request-bound assertion) — its own ADR when scoped.~~
  RESOLVED (issue #71, v0.4): Tier 3 is specified and implemented in this ADR's
  "Tier 3" section above (`LbAssertionBinding` + `--transport-binding lb-assertion`).

## v0.9/v0.10 Enterprise-Ingress Amendment (2026-07-03)

Outcome of the v0.9/v0.10 enterprise-hardening design review, adversarially
verified against this repo. A **delta amendment** to this ADR — not a new ADR. It
resolves what a *strict* enterprise ingress story is on a cloud L7 load balancer,
and pins the mTLS-certificate-revocation domain (the counterpart to the
signing-key domain in ADR-MCPS-021 §v0.9 addendum).

### Framing: two strict postures, one demoted legacy path

Strict (`--strict`/`--production`) admits **exactly two** ingress postures, with
**different, honestly-labelled trust properties**:

| Mode | Binding | Trust property | Strict | Release |
|---|---|---|---|---|
| **A** | `end_to_end_mtls` + `exact` (existing Tier 1) | client↔node mTLS; no LB in identity path | **default** | shipped |
| **C** | `attested_ingress` (new Tier 4, below) | *attested delegation*: a controlled ingress attestor signs a request-bound assertion over a pinned channel; LB/attestor in TCB but cryptographically accountable | **explicit opt-in** | **v0.10** |
| **B** | header `trusted_ingress_asserted` (Tier 2) / plain `lb-assertion` (Tier 3) | forwarded/asserted identity, LB in TCB, not request-attested-to-strict-bar | **REJECTED** | n/a (legacy/migration only) |

Mode C is **not** trust-equivalent to Mode A and MUST NEVER be surfaced as
`end_to_end_mtls` (this preserves the §Tier-3 "Honesty" rule). It is legitimately
strict *because* it is explicit and cryptographically request-bound over a pinned
channel — but it is *attested delegation*, a distinct and weaker property than
end-to-end binding, recorded as such per request.

### C1. Mode C is a NEW frozen-v2 assertion format — not an extension of Tier 3

The shipped Tier-3 `LbAssertion` binds four fields (`key_id`,
`asserted_client_identity`, `request_hash`, `validation_time`) under the **frozen**
domain tag `mcps/lb-ingress-assertion/v1`. Mode C requires binding additional facts
(certificate-verification result, revocation result + CRL freshness, route/audience/
backend, `expires_at`, and a distinct ingress identity). Because the v1 preimage is
frozen, this is a **new `mcps/lb-ingress-assertion/v2` format** — a new
domain-separation tag, a new length-prefixed layout, and a new node-side verifier
order — **not** an in-place extension. It is the epic's single largest engineering
deliverable and is scoped to **v0.10**.

**No nonce / no assertion-level replay.** The §Tier-3 replay rationale holds
unchanged: a replayed assertion against a *different* request fails the
`request_hash` check; a replay against the *same* request is caught by that
request's own replay cache and the freshness window. The v2 assertion therefore
adds **no independent nonce** and **no parallel assertion-replay cache** — adding one
would reopen a gap the shipped design deliberately closed. (`expires_at` MAY be added
only if a validity shorter than `validation_time`-freshness is genuinely required,
with justification.)

### C2. The attestor is TWO trusted-computing-base components — audit both

"Controlled ingress attestor" is two distinct TCB components, and the ADR must not
fold them into one:

1. **The load balancer** terminates client mTLS and is the *only* component that
   witnesses **proof-of-possession** of the client key. It forwards client-cert
   metadata to the attestor as **spoofable headers**.
2. **The signing filter** (operator-run) reads those headers, checks revocation,
   and Ed25519-signs the v2 assertion. It attests *"the LB reported the cert
   verified"* — it does **not** itself witness PoP.

Consequences, normative:

- The **LB→attestor hop MUST be authenticated/pinned** (or the attestor MUST
  independently re-verify the forwarded full client-cert chain), **with public-side
  header stripping**, so nothing reaching the filter directly can inject headers and
  get an assertion minted. Proof-of-possession honestly **stays with the LB**.
- The **attestor→node hop MUST be pinned mTLS** (or equivalent workload identity).
- Audit records **three** trust facts, never fewer: `delegated_client_identity`
  (from the attestor assertion), `ingress_internal_hop` (the LB→attestor trust
  assumption), and `backend_channel_binding = pinned_mtls` (attestor→node). This
  prevents a later auditor from mistaking Mode C for end-to-end mTLS or for a
  single-component attestor.

### C3. The node binds the assertion; it does NOT re-check the certificate

Preserving §Decision "the node need not re-validate the client certificate": under
Mode C the node verifies the **abstract signed-assertion contract only** — signature
over the v2 preimage, freshness, `request_hash` equality against the in-hand hash,
audience/route, and ingress identity, over the pinned channel. `revocation_result`
and `cert_verification_result` are treated as **opaque asserted facts the node
records/audits** (bind-not-interpret) — the node performs **no** CRL-freshness
computation and pulls **no** certificate-revocation semantics back into itself.

### C4. Normative contract vs. cookbook (SEP scope)

The **ADR-023 normative surface** for Mode C is only the abstract contract: the v2
assertion field set, the length-prefixed preimage + domain tag, the ordered
fail-closed verifier, the pinned-channel requirement, and the three audit facts.
**All Google-specific detail** — GCLB `client_cert_*` header semantics, the Envoy
signing-filter (Wasm/Lua/ext_authz) implementation, CAS CRL lookup, and the
side-door-closing topology (internal ALB + Private Service Connect; Cloud Run
`internal-and-cloud-load-balancing` + disabled `run.app`) — lives in the
**non-normative Google Cloud cookbook**, because **no native GCP primitive** emits a
signed per-request assertion (GCLB forwards unsigned headers; IAP signs user
identity without cert/request-hash binding; the mesh conveys unsigned XFCC). The
attestor is operator-built; the cookbook validates it, it is not a spec requirement.

### A1. Mode A mTLS certificate-revocation — honest, bounded, fail-closed (v0.9)

Mode A terminates client mTLS at the node; on GCP the online-OCSP path is a no-op
(non-default `online_ocsp` feature, and CAS is CRL-only with no OCSP AIA in the
leaf), so Mode A's revocation posture is **short-lived certificates**, with two
net-new v0.9 fail-closed items:

- **Strict cert-lifetime ceiling (net-new).** Today `strict_violations`
  (`cli.rs`) only rejects a *disabled* (`none`/`0`) lifetime and leaves a
  too-long lifetime a warning. v0.9 adds a strict violation rejecting
  `max_client_cert_lifetime > 3600s`, so the "short-lived" audit claim cannot be
  emitted for a long-lived cert. Offline-testable
  (`--strict --max-client-cert-lifetime 24h` ⇒ violation).
- **Static `--client-crl` fails closed on stale (net-new enforcement).** Today
  `build_client_verifier` calls `.with_crls()` with `ExpirationPolicy::Ignore`
  (fails **open** on staleness), and CRLs load once with no reload hook. v0.9 ships
  the `nextUpdate` staleness gate **together with** a minimal in-process reload
  path (or a startup-fail-if-near-`nextUpdate` + documented "restart before
  `nextUpdate`" operator contract). The gate **without** a reloader is a guaranteed
  scheduled self-DoS on CAS's ~daily cadence, so the two are inseparable.
- **OCSP-no-AIA never reports success.** An OCSP lookup that cannot run because the
  leaf carries no responder URL MUST NOT be recorded as a successful revocation
  check.

**Audit revocation vocabulary** (three determinate values; records the *actual*
configured lifetime, never a hardcoded `≤1h`):

- `revocation_mode = short_lived_cert` — `exposure_window = <actual cert lifetime>`,
  `dynamic_revocation = false`.
- `revocation_mode = static_crl_snapshot` — `crl_digest`, `crl_this_update`,
  `crl_next_update`, `dynamic_revocation = false`, `stale_crl_policy = fail_closed`.
- `revocation_mode = delegated_attestor_crl` (Mode C) — `attestor_id`,
  `client_cert_serial`, `crl_digest`, `crl_next_update`, `revocation_result`,
  `dynamic_revocation = true`.

Dynamic mid-life revocation is delivered by **Mode C's attestor** (CAS CRL keyed on
`client_cert_serial`), not Mode A.

### B1. Mode B demotion

The header `trusted_ingress_asserted` (Tier 2) and plain `lb-assertion` (Tier 3)
paths remain **strict-rejected** (existing `strict_violations` guards) and are
excluded from the recommended Google Cloud cookbook. If retained for a concrete
compatibility need they are labelled **legacy/migration compatibility — not strict,
not recommended**, and a conformance test proves strict rejects them. They are never
presented beside Mode A/C as an enterprise option.

### Conformance Vectors (amendment)

**v0.9 (Mode A, offline):** (a) `--strict --max-client-cert-lifetime 24h` → rejected;
(b) a CRL whose `nextUpdate` is in the past → new handshakes fail closed (mint a
past-`nextUpdate` CRL; assert rejection); (c) OCSP-no-AIA is not recorded as a
successful revocation check; (d) `short_lived_cert` audit records the actual
configured lifetime; (e) Mode B strict-rejected.

**v0.10 (Mode C, offline):** node-side rejection when the v2 assertion carries
`revocation_result = revoked`, or a stale CRL-freshness, or a bad signature, or a
cross-request `request_hash` (extend `proxy_lb_assertion_test.rs`); `attested_ingress`
without `--ingress-pinned-mtls` / trust-bundle / assertion-required → rejected; a
forwarded draft-02 request preimage is byte-identical to Mode A (a `deny_unknown_fields`
conformance check proving C-only facts ride the assertion, never the request
preimage). The **live** GCP revoked-cert rejection is attestor QA, supporting-only,
outside the MCP-S evidence spine.

### Compliance and Enforcement (amendment)

`security-boundary.md` gains: *"Strict mode admits two ingress postures. (A)
end-to-end client↔node mTLS. (C) Attested Ingress: a controlled ingress attestor
terminates or receives validated client mTLS, checks certificate revocation, and
signs a request-bound assertion the node verifies over a pinned attestor→node
channel. Mode C is attested delegation, explicit opt-in, and is NOT end-to-end
client↔node binding — the load balancer witnesses proof-of-possession and remains in
the trusted computing base. Raw forwarded-identity headers remain forbidden under
strict."*
