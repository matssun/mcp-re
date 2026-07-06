# MCP-RE Mode C — Attested Ingress on Google Cloud (Cookbook)

**Audience:** an operator or security reviewer standing up MCP-RE **Mode C
(attested ingress)** in front of an `mcp-re-proxy` node on Google Cloud, and anyone
reviewing what that posture does and does **not** prove.

**Status: NON-NORMATIVE.** This cookbook is the Google-specific companion to
[ADR-MCPS-023 §C](adr/adr-mcps-023.md) (§C4). The **normative** surface is only the
abstract contract in the ADR: the `mcp-re/lb-ingress-assertion/v2` field set, the
length-prefixed preimage + domain tag, the ordered fail-closed node verifier, the
pinned-channel requirement, and the three audit facts. Everything below — GCLB
header semantics, the Envoy signing filter, CAS CRL lookup, the side-door-closing
topology — is one **operator-built** way to satisfy that contract on GCP. It is
validated here; it is **not** a spec requirement, and nothing in it is unique to
Google. MCP-RE is experimental and unofficial; this cookbook implies no Google or
Anthropic endorsement.

**Why a cookbook at all — no native GCP primitive fits.** Mode C needs a *signed,
per-request assertion that binds the client identity to the exact MCP-RE request
hash*. No stock GCP component emits one: the external HTTPS load balancer (GCLB)
forwards **unsigned** `client_cert_*` headers; IAP signs a **user** identity with
no client-certificate or request-hash binding; the service mesh conveys **unsigned**
XFCC. So the attestor is a component **you build and run** (an Envoy signing
filter). The rest of this document is how to build it correctly and, just as
importantly, how to avoid the ways it can quietly become insecure.

---

## 1. What Mode C is (and is not)

Mode C is **attested delegation**, an explicit opt-in posture that is legitimately
admitted under `--strict`. It is **NOT** end-to-end client↔node mTLS (Mode A), and
the node **never** labels it `end_to_end_mtls`. In Mode C a controlled ingress
attestor terminates or receives validated client mTLS, checks certificate
revocation, and Ed25519-signs a request-bound assertion the node verifies over a
**pinned attestor→node channel**. The load balancer witnesses proof-of-possession
of the client key and **remains in the trusted computing base**.

| | Mode A (`end_to_end_mtls`) | Mode C (`attested_ingress`) |
|---|---|---|
| Client key reaches the node | yes (node terminates mTLS) | **no** (LB terminates it) |
| Proof-of-possession witnessed by | the node | the **load balancer** (in the TCB) |
| Node trusts | the client cert directly | the **attestor's signature** over the request-bound assertion |
| Guarantee string | `end_to_end_mtls` | `attested_ingress_delegation` |
| Strict mode | default | explicit opt-in |

Use Mode C when you cannot terminate client mTLS at the node (a managed L7 load
balancer sits in front and you want its DoS/TLS/routing features), but you still
want a **cryptographic, per-request** binding of the client identity to the exact
request — stronger than a forwarded, spoofable identity header (Mode B, which
`--strict` rejects).

---

## 2. The two-component attestor — audit both (§C2)

The single phrase "controlled ingress attestor" hides **two distinct TCB
components**. Conflating them is the classic way Mode C is oversold, so the ADR and
this cookbook keep them separate:

```
                        client mTLS (PoP)
   client  ───────────────────────────────────▶  ┌──────────────────────────┐
                                                  │  (1) LOAD BALANCER (GCLB) │
                                                  │  - terminates client mTLS │
                                                  │  - the ONLY witness of    │
                                                  │    proof-of-possession    │
                                                  │  - forwards client-cert   │
                                                  │    metadata as SPOOFABLE  │
                                                  │    headers                │
                                                  └────────────┬─────────────┘
                          pinned / header-stripped internal hop │
                                                  ┌────────────▼─────────────┐
                                                  │  (2) SIGNING FILTER       │
                                                  │      (operator-run Envoy) │
                                                  │  - reads client_cert_*    │
                                                  │  - checks CAS CRL         │
                                                  │  - Ed25519-signs the v2   │
                                                  │    assertion              │
                                                  │  - attests "the LB said   │
                                                  │    the cert verified"     │
                                                  │  - does NOT witness PoP   │
                                                  └────────────┬─────────────┘
                                pinned mTLS (attestor→node)     │
                                                  ┌────────────▼─────────────┐
                                                  │  (3) mcp-re-proxy NODE      │
                                                  │  - verifies the v2        │
                                                  │    assertion (bind-only)  │
                                                  │  - records 3 trust facts  │
                                                  └───────────────────────────┘
```

1. **The load balancer (GCLB)** terminates client mTLS and is the *only* component
   that witnesses **proof-of-possession** of the client key. It forwards the
   client-certificate metadata to the signing filter as **spoofable headers**.
2. **The signing filter** (the Envoy you run) reads those headers, checks
   revocation, and signs the v2 assertion. It attests *"the LB reported the cert
   verified"* — it does **not** itself witness proof-of-possession.

Two consequences are **normative** (from §C2) and are the load-bearing security
requirements of this whole cookbook:

- **The LB→attestor hop MUST be authenticated/pinned, with public-side header
  stripping** — or the attestor must independently re-verify the forwarded full
  client-certificate chain. Otherwise anything that can reach the signing filter
  directly can inject `client_cert_*` headers and mint an assertion for an identity
  it never possessed. Proof-of-possession honestly **stays with the LB**.
- **The attestor→node hop MUST be pinned mTLS** (or equivalent pinned workload
  identity).

---

## 3. The assertion the attestor must mint

The node verifies `mcp-re/lb-ingress-assertion/v2`. This is the exact contract the
signing filter has to produce; it is frozen and version-tagged. (See
`mcp-re-proxy/src/transport.rs` `LbAssertionV2` for the reference encoder/verifier.)

### 3.1 Fields

| Field | Meaning |
|---|---|
| `key_id` | Names the attestor verification key the node trusts (`--ingress-attestor-key <key_id>:<pub>`). |
| `ingress_identity` | The attestor's own identity, **distinct** from `key_id`. The node admits only identities in its trusted set (`--ingress-identity`). |
| `asserted_client_identity` | The delegated client identity (e.g. a SPIFFE URI SAN from the client cert). Becomes `delegated_client_identity`. |
| `request_hash` | The MCP-RE request hash (`sha256:<base64url>`) of the exact request being admitted. **This is the per-request binding.** |
| `audience` | The node's audience/route; must equal the node's configured `--ingress-audience`. |
| `cert_verification_result` | Opaque attestor verdict: `Verified` (disc `1`) or `Failed` (`2`). Node admits only `Verified`. |
| `revocation_result` | Opaque attestor verdict: `Good` (`1`), `Revoked` (`2`), `Unknown` (`3`), `StaleCrl` (`4`). Node admits only `Good`. |
| `validation_time` | Unix seconds the attestor signed at; the node checks freshness against its clock (default window 30s). |
| `crl_next_update` | The `nextUpdate` of the CRL the attestor consulted. **Recorded for audit only** — the node never compares it (§C3). |
| `expires_at` | Optional absolute expiry; present only if a validity shorter than the freshness window is genuinely required. |

The attestor computes revocation itself and asserts a **verdict**. A stale CRL at
the attestor is reported as the explicit `StaleCrl` verdict — the node fails closed
on it **without doing any CRL math of its own** (bind-not-interpret, §C3).

### 3.2 Signing preimage (length-prefixed, unambiguous)

The Ed25519 signature is over this byte sequence — **length-prefixed framing**, never
delimiter-joining, so no field value can collide with a separator to forge a
different field split:

```
"mcp-re/lb-ingress-assertion/v2"
|| u64_be(len(key_id))                   || key_id
|| u64_be(len(ingress_identity))         || ingress_identity
|| u64_be(len(asserted_client_identity)) || asserted_client_identity
|| u64_be(len(request_hash))             || request_hash
|| u64_be(len(audience))                 || audience
|| u8(cert_verification_result)          # 1 = Verified, 2 = Failed
|| u8(revocation_result)                 # 1 = Good, 2 = Revoked, 3 = Unknown, 4 = StaleCrl
|| i64_be(validation_time)
|| i64_be(crl_next_update)
|| u8(expires_at_present)                # 0 = absent; 1 = present, then i64_be(expires_at)
```

The `v2` domain tag is the leading bytes, so a signature minted for the frozen
Tier-3 `v1` assertion can never be re-framed as a `v2` assertion (cross-version
confusion is closed).

### 3.3 Wire form (the header value)

The assertion travels in a single HTTP header, **`mcp-ingress-assertion`**, as
eleven `.`-separated base64url-no-pad fields — every field base64url-encoded so it
can never contain the `.` separator (transport encoding only; the signature is over
the length-prefixed preimage above), signature last:

```
base64url(key_id) . base64url(ingress_identity) . base64url(asserted_client_identity)
  . base64url(request_hash) . base64url(audience)
  . base64url([cert_disc]) . base64url([rev_disc])
  . base64url(i64_be(validation_time)) . base64url(i64_be(crl_next_update))
  . base64url(expires_at_frame) . base64url(signature)
```

where `expires_at_frame` is the single byte `0x00` (absent) or `0x01` followed by
`i64_be(expires_at)` (present).

> **No nonce, by design (§C1).** The v2 assertion carries no independent nonce and
> the node keeps no separate assertion-replay cache. A replay against a *different*
> request fails the `request_hash` check; a replay against the *same* request is
> caught by that request's own replay cache plus the freshness window. Adding a
> nonce would reopen a deliberately-closed gap.

---

## 4. GCP topology

### 4.1 The load balancer → forwarded client-cert headers

Front the attestor with an **external HTTPS load balancer with mTLS
(`ServerTLSPolicy` + `TrustConfig`)**. On a successful client-cert handshake GCLB
injects custom headers derived from the presented certificate — configure a header
mutation that forwards, at minimum:

- the full client leaf/chain (e.g. `X-Client-Cert-Chain`, PEM/DER as your Envoy
  filter expects), and/or the parsed SAN you will use as `asserted_client_identity`;
- the GCLB cert-validation result (so the filter can set `cert_verification_result`);
- the certificate serial, which the filter keys the CAS CRL lookup on.

These headers are **unauthenticated to anything downstream of the LB**. That is
exactly why the LB→attestor hop must be pinned and public-side-stripped (§4.3).

### 4.2 The Envoy signing filter (the attestor)

Run Envoy (standalone, or a sidecar) between the LB and the node. Implement the
signing logic as an `ext_authz` service, a Wasm filter, or a Lua filter — whichever
your operational model prefers. On each request the filter MUST:

1. **Establish the delegated identity** from the forwarded (and trusted — see §4.3)
   client-cert headers. If you cannot pin the LB→attestor hop, the filter MUST
   instead independently re-verify the **full forwarded client-cert chain** before
   trusting any identity from it.
2. **Compute the MCP-RE `request_hash`** of the request body it is about to admit,
   exactly as the node will (`sha256:<base64url>` over the canonical request; the
   `signature.value` field is excluded from the hash preimage, so it matches the
   node's in-hand hash).
3. **Check revocation** against the CAS CRL (§4.4) keyed on the client cert serial,
   and set `revocation_result` to the honest verdict (`Good` / `Revoked` /
   `Unknown` / `StaleCrl`) and `crl_next_update` to the CRL's `nextUpdate`.
4. **Set `cert_verification_result`** from the LB's reported validation
   (`Verified`/`Failed`).
5. **Build the length-prefixed preimage (§3.2)** and **Ed25519-sign** it with the
   attestor key whose public half the node trusts as `key_id`.
6. **Emit** the wire assertion (§3.3) in the `mcp-ingress-assertion` header on the
   request forwarded to the node.

The attestor's Ed25519 private key should live in a non-exporting store (Cloud KMS
`EC_SIGN_ED25519`, or an HSM via PKCS#11 `CKM_EDDSA`) — the same custody bar MCP-RE
applies to response signers. The node only ever holds the **public** half.

### 4.3 Closing the side door — pin the LB→attestor hop and strip public headers

The single most important operational control: **nothing reaching the signing
filter except via the load balancer may be able to set the `client_cert_*` headers.**
If a pod, a debugger, or a second ingress can POST directly to the filter with a
forged `X-Client-Cert-*` header, it mints an assertion for an identity it never
possessed, and Mode C is broken.

Close the side door with **both** of:

- **Strip the forwarded client-cert headers on the public edge** (the LB overwrites/
  removes any client-supplied copy so only the LB's own values survive), and
- **Make the filter reachable only from the LB**: put it behind an **internal**
  Application Load Balancer reachable via **Private Service Connect** / an internal
  VPC path, with firewall rules that admit only the LB's source range; or pin the
  LB→attestor hop with mTLS/workload identity so the filter rejects any peer that is
  not the LB.

For **Cloud Run** attestors/nodes, disable the public `run.app` URL and set ingress
to `internal-and-cloud-load-balancing` so the only route in is the load balancer.

### 4.4 Revocation via CAS

Google **Certificate Authority Service (CAS) is CRL-only** — there is no OCSP AIA in
the leaf, so there is nothing to online-check. The attestor fetches the CAS CRL,
keys the lookup on the client certificate serial, and asserts the verdict. Because
the CRL has a `nextUpdate` (~daily cadence), the filter MUST treat a CRL past
`nextUpdate` as `StaleCrl` (fail closed) rather than silently trusting a stale
snapshot. Dynamic mid-life revocation in MCP-RE is delivered **here**, at the Mode-C
attestor, not at the Mode-A node.

---

## 5. Configuring the node

Run the `mcp-re-proxy` node with the attested-ingress binding and its required,
fail-closed inputs:

```
mcp-re-proxy \
  --strict \
  --transport-binding attested-ingress \
  --ingress-attestor-key attestor-1:<base64url-ed25519-public-key> \
  --ingress-identity   spiffe://example.org/ingress-attestor-1 \
  --ingress-audience   did:example:server-1 \
  --ingress-pinned-mtls \
  ...                         # server signer, trust, durable replay, etc.
```

Every one of these is enforced at startup (fail closed):

- `--transport-binding attested-ingress` selects Mode C. Repeatable
  `--ingress-attestor-key <key_id>:<base64url-ed25519-pub>` adds the trusted
  attestor keys (≥1 required; each must be a valid, unique Ed25519 key).
- `--ingress-identity <id>` adds a trusted ingress identity (≥1 required); a v2
  assertion whose `ingress_identity` is not in the set fails closed.
- `--ingress-audience <aud>` is the node's audience; the assertion's `audience` must
  equal it.
- `--ingress-pinned-mtls` is the **explicit acknowledgement** that the attestor→node
  hop is a pinned mTLS channel (§C2). Absent, the node **refuses to start** — the
  pinned backend channel is load-bearing and cannot be silently missing.

The node resolves identity from the signed assertion, so `attested-ingress` is
mutually exclusive with a reverse-proxy identity header. The plain `lb-assertion`
(Mode B, Tier 3) and the raw `trusted_ingress_asserted` header (Tier 2) remain
**strict-rejected** — legacy/migration only, never an enterprise option.

---

## 6. What the node does with the assertion (bind-not-interpret)

The node verifies the **abstract signed-assertion contract only** (§C3), in this
ordered, fail-closed sequence — the inner server is never reached on any failure:

1. **Signature** — Ed25519 over the length-prefixed v2 preimage, under the trusted
   `key_id`.
2. **Freshness** — `validation_time` within the window; an `expires_at` in the past
   is rejected.
3. **Request binding** — the assertion's `request_hash` equals the node's in-hand
   request hash.
4. **Audience/route** — equals `--ingress-audience`.
5. **Ingress identity** — is in the trusted `--ingress-identity` set.
6. **Recorded-facts admission** — admit only `cert_verification_result = Verified`
   and `revocation_result = Good`; every other verdict fails closed with a distinct,
   auditable reason.

The node performs **no** certificate-path validation and **no** CRL-freshness
computation of its own. `revocation_result` and `cert_verification_result` are
opaque asserted facts it **records and audits**, nothing more.

### The three audit trust facts (§C2)

The node records **three** trust facts, never fewer, so a later auditor cannot
mistake Mode C for end-to-end mTLS or for a single-component attestor:

- `delegated_client_identity` — the client identity the attestor asserted (per
  request);
- `ingress_internal_hop` — the LB→attestor trust assumption (proof-of-possession
  stays with the LB);
- `backend_channel_binding = pinned_mtls` — the attestor→node channel.

Alongside them the node emits `revocation_mode = delegated_attestor_crl`
(`dynamic_revocation = true`) — the CAS-CRL revocation is delivered by the attestor,
keyed on the client cert serial.

---

## 7. Validating your deployment

MCP-RE proves Mode C **offline**, node-side, in the evidence spine
(`mcp-re-proxy/tests/proxy_lb_assertion_test.rs`, mapped in
`mcp-re-conformance/security_traceability_manifest.json`): a v2 assertion carrying
`revocation_result = revoked`, a stale-CRL verdict, a bad signature, or a
cross-request `request_hash` is **rejected before dispatch**, and the forwarded
draft-02 request preimage is **byte-identical** to Mode A (the Mode-C facts ride the
assertion, never the request).

Your **live** GCP validation — presenting a genuinely revoked client cert and
watching the attestor emit `Revoked` — is **attestor QA**. It is supporting evidence
for your operator build, and it sits **outside** the MCP-RE evidence spine (the spine
is the offline node-side rejection above). Recommended live checks:

- a valid client cert round-trips and reaches the inner server;
- a **revoked** client cert (per the CAS CRL) is rejected at the attestor;
- a request with **no** `mcp-ingress-assertion` header (e.g. bypassing the filter)
  is rejected by the node;
- a direct POST to the filter with a **forged** `client_cert_*` header cannot mint
  an assertion (proves §4.3 — the side door is closed).

---

## 8. What Mode C does NOT prove

- **It is not end-to-end mTLS.** The client's key never reaches the node; the load
  balancer witnesses proof-of-possession and is in the trusted computing base. Do
  not present `attested_ingress` as `end_to_end_mtls`.
- **The node does not re-validate the client certificate.** It trusts the attestor's
  asserted `cert_verification_result` and `revocation_result` verdicts. The strength
  of those verdicts is the strength of your attestor build — hence §4.3 and §7.
- **Revocation latency is the attestor's CRL cadence** (CAS, ~daily), not zero-window.
- **The assertion has no nonce.** Replay safety comes from the request-hash binding,
  the freshness window, and the request's own replay cache — not from an
  assertion-level nonce.

For the rationale and the normative contract, see
[ADR-MCPS-023 §C](adr/adr-mcps-023.md) and the two-posture statement in
[`docs/spec/security-boundary.md` §11](spec/security-boundary.md).
