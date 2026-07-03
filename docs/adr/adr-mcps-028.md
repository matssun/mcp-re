<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-028: Native Cloud-KMS Response Signers — AWS KMS and GCP Cloud KMS (Ed25519, non-exporting)

## Status

Proposed (v0.3 follow-up — design). Child of ADR-MCPS-019 (external backends) and
ADR-MCPS-022 (signing key custody at scale). Implementation lands as its own
follow-up PR(s) per the design-PR-then-implementation rhythm. Does **not** change
the MCP-S signature contract: MCP-S Core stays Ed25519-only (ADR-MCPS-004).

**v0.9 hardening addendum (2026-07-03):** the native GCP Cloud KMS custody path
(§C) is **promoted to Accepted for v0.9**, provable offline. The enterprise-custody
deltas — key-version identity, the KMS-lifecycle-vs-verifier-revocation boundary,
the Ed25519-only reaffirmation over the seed's P-256 temptation, the FIPS-L3
live-fact gate, and the offline evidence spine — are recorded in the
[**v0.9 Custody-Hardening Addendum**](#v09-custody-hardening-addendum-2026-07-03)
below (Decisions H–L). No wire change; the draft-02 request preimage is untouched.

## Context

MCP-S signs every response with Ed25519 over the canonical JCS preimage, **directly
— no pre-hash** (`mcps-core/src/crypto.rs`; Ed25519ph is forbidden). The
`ResponseSigner` seam (`mcps-proxy/src/key_source.rs`) already lets a non-exporting
backend drive the full response-signing path without ever surrendering the private
key: `sign_response(preimage) -> Base64URL-no-pad(sig)` + `response_public_key() ->
VerificationKey`. `Pkcs11KeySource` implements this against any PKCS#11 token
(SoftHSM2 in CI; equally AWS CloudHSM, GCP via its PKCS#11 library, Azure Managed
HSM, Luna/Thales, YubiHSM). So HSM custody — the response-signing key never leaving
the device — is **already delivered and live-tested** via the generic PKCS#11 path.

What is missing is **native managed-KMS** custody for operators who use a cloud
KMS's own REST API rather than a PKCS#11 endpoint.

### Provider Ed25519 support (the compatibility-critical fact)

A native KMS adapter is only viable if the KMS can produce a **PureEdDSA Ed25519
signature over raw bytes** — byte-identical to what `SigningKey::sign` /
`CKM_EDDSA` produce, so it verifies under the existing `mcps-core` verifier.

| Provider | Native Ed25519 signing | MCP-S-compatible mode | Native adapter |
|---|---|---|---|
| **AWS KMS** | **Yes** (since 2025-11-07) | key spec `ECC_NIST_EDWARDS25519`, alg `ED25519_SHA_512`, **`MessageType: RAW`** (PureEdDSA) — **not** `ED25519_PH_SHA_512`/`DIGEST` (that is Ed25519ph, forbidden) | **In scope** |
| **GCP Cloud KMS** | **Yes** | purpose `ASYMMETRIC_SIGN`, algorithm `EC_SIGN_ED25519` (PureEdDSA on Edwards25519, raw data input) | **In scope** |
| **PKCS#11 HSM** (incl. AWS CloudHSM, Azure Managed HSM) | Yes (`CKM_EDDSA`) | already implemented (`Pkcs11KeySource`) | **Done** |
| **Azure Key Vault / Managed HSM (native REST)** | **No** (RSA + EC NIST P-curves/secp256k1 only as of current docs) | — | **Unsupported** (see Decision E) |

An earlier internal analysis claimed AWS KMS could not sign Ed25519. That premise
was **stale and is withdrawn**: AWS KMS added EdDSA (Edwards25519) on 2025-11-07.
No protocol change is required for native AWS or GCP support.

## Decision

**A. Keep MCP-S Core Ed25519-only.** Compatibility is delivered by honest adapters
and explicit unsupported boundaries — never by lowering the protocol to the weakest
common KMS algorithm set. No signature-suite agility is introduced by this ADR.

**B. Native AWS KMS `ResponseSigner`** (`AwsKmsKeySource`, feature `aws_kms_keysource`).
Signs via KMS `Sign` with `SigningAlgorithm = ED25519_SHA_512` and
**`MessageType = RAW`** over the canonical preimage; returns the raw 64-byte
signature base64url-no-pad-encoded (identical wire form to every other signer).
`response_public_key()` fetches the KMS public key (SPKI), extracts the raw 32-byte
Ed25519 point, and constructs a `VerificationKey`. The KMS key MUST be
`ECC_NIST_EDWARDS25519`; any other key spec fails closed at construction.

**B.1 Transport — blocking `ureq` + a minimal audited SigV4 signer; NOT the AWS
SDK** *(ratified 2026-06-15).* The adapter reaches KMS over blocking HTTPS (`ureq`,
reusing the in-closure rustls/`ring` provider) and signs requests with a tiny,
self-contained SigV4 implementation (HMAC-SHA256 over the in-closure RustCrypto
primitives). The async `aws-sdk-kms` / `tokio` / Smithy stack is **forbidden** here:
the ADR-MCPS-018 lean-closure / "all Phase-7 backends are SYNC, no async runtime"
rule is a hard architectural constraint, and pulling tokio + a `block_on` bridge
into this firewalled workspace would violate the shape of the system (the OCSP
path's blocking-`ureq` precedent is the model). The client surface is deliberately
TINY — only KMS `GetPublicKey` and `Sign`; no general KMS client, no encrypt/
decrypt, no key-management or policy operations. Credentials are the explicit,
narrow set (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / optional
`AWS_SESSION_TOKEN` / explicit region / optional endpoint override); SDK-style
credential discovery (profiles, IMDS, IRSA) is intentionally NOT provided. The SigV4
signer is proven against AWS's published `get-vanilla` test vector, and EVERY
KMS-returned signature is verified locally against the advertised public key (under
the unmodified `mcps-core` verifier) before it is emitted.

**C. Native GCP Cloud KMS `ResponseSigner`** (`GcpKmsKeySource`, feature
`gcp_kms_keysource`). Signs via `asymmetricSign` against an `EC_SIGN_ED25519` key
version (raw `data`, not `digest`); same raw-64-byte → base64url contract.
`response_public_key()` parses the version's PEM public key to the raw point.

**C.1 Transport — blocking `ureq` + OAuth2 bearer; NOT the google-cloud SDK.**
Mirrors §B.1: Cloud KMS is reached over blocking HTTPS (`ureq`), and the async
google-cloud SDK / tokio stack is **forbidden** (ADR-MCPS-018 lean-sync firewall).
The surface is the two operations only — `getPublicKey` + `asymmetricSign`. The
bearer token comes from a NARROW, explicit set of sources — an operator-supplied
`MCPS_GCP_ACCESS_TOKEN` or the GCE/GKE metadata server (workload identity) — never a
silent application-default-credentials chain; the service-account JWT-file→token
exchange (which needs RSA) is a deliberately deferred follow-up. As in §B, every
KMS-returned signature is verified locally against the advertised public key before
it is emitted.

**D. Non-exporting invariant + fail-closed.** Both adapters implement only the
`ResponseSigner` operations; the private key never crosses the trait boundary
(it never leaves the KMS). A wrong key spec, a prehash/digest mode, a wrong-length
signature, or a public key that is off-curve / non-canonical fails closed
(`KeyError::Malformed`) — never a silent fallback to a local key.

**E. Azure native REST is explicitly unsupported** for MCP-S object signing while
Azure exposes no Ed25519 signing key type. This is recorded as a
**provider-limited** boundary, not an MCP-S gap. Azure HSM custody remains
available through the **PKCS#11** path (Managed HSM) where `CKM_EDDSA` is offered.
Should Azure add Ed25519, a native adapter is a mechanical follow-up; broad
managed-KMS algorithm agility, if ever wanted, is a separate protocol-level ADR and
is **not** opened here.

**F. Repository boundary.** The generic cloud adapters (AWS, GCP) ship in the public
`mcps` repo behind their feature gates. Internal-platform adapters (the in-house
HSM/IDP/KMS) live in the monorepo as private implementations of the **same**
`ResponseSigner` trait — the trait is the only coupling; no internal specifics enter
the public repo.

**G. TLS-key custody — delegated TLS handshake signing.** The object-signing key
(§B–§F) lives in the device/KMS; this item closes the matching gap for the TLS
*server* key, which was still exported via `KeySource::tls_server_key`. The generic
mechanism is implemented: a custom `rustls::sign::SigningKey`
(`DelegatedEd25519SigningKey`) whose `Signer::sign` forwards the to-be-signed
handshake transcript to a non-exporting `RawEd25519TlsSigner` (PKCS#11 token / AWS
or GCP KMS), paired with the public server cert via a `DelegatedCertResolver` and a
`with_cert_resolver` server-config path that shares the exported-key path's
fail-closed client-cert verifier. It is **Ed25519-only**: rustls signs the TLS 1.3
transcript with `SignatureScheme::ED25519` (PureEdDSA over the message), exactly the
raw-sign primitive the KMS/PKCS#11 backends expose, so the TLS certificate MUST be
an Ed25519 cert whose key lives in the device/KMS (a non-Ed25519 TLS cert fails
closed — no scheme offered). The TLS key is a SEPARATE credential from the
object-signing key. Wire-correctness is proven by a real in-process mTLS handshake
in which a rustls client completes the handshake against a server whose TLS key
never reaches rustls. The per-backend TLS-key wiring (a second KMS key id / token
object, plus its CLI flags, and the `KeySource` seam selecting the delegated path)
is sequenced as the immediate follow-up to this mechanism. Note the operational
consequence for the KMS path: delegated TLS makes a KMS `Sign` network call on every
TLS handshake (latency + availability coupling), an accepted trade-off for the
never-export property; the PKCS#11 path signs locally on the token.

**G.1 Completion plan — wiring the backends to the §G mechanism.** The §G mechanism
is generic; making TLS-key custody usable end-to-end requires wiring each real
backend to it. This is the planned, scoped remaining work (tracked as GitHub
issues; design recorded here):

1. *Seam + path selection.* Add `KeySource::tls_delegated_signer(&self) ->
   Option<Arc<dyn RawEd25519TlsSigner>>` defaulting to `None` — the file/env/PKCS#11
   object-signing sources keep exporting the TLS key, so the default build is
   unchanged. When it returns `Some`, the proxy builds the server config via the
   delegated path (`build_server_config_delegated_with_crls`) and does NOT call
   `tls_server_key`. Configuring both an exported `--tls-key` and a delegated TLS
   key is rejected (mutually exclusive, fail closed).
2. *AWS + GCP Cloud KMS.* `KmsEd25519Backend` implements `RawEd25519TlsSigner` keyed
   by a SECOND KMS key (the TLS key, distinct from the object-signing key), reusing
   the existing RAW-Ed25519 `Sign`/`asymmetricSign` path. CLI: `--aws-kms-tls-key-id`
   / `--gcp-kms-tls-key-version`, with `--tls-key` relaxed when set.
3. *PKCS#11.* A second token object (TLS key label) using a `CKM_EDDSA` signing
   operation (`sign_tls_ed25519`), implementing `RawEd25519TlsSigner`. CLI:
   `--pkcs11-tls-key-label`. The PKCS#11 path signs locally on the token (no
   per-handshake network call, unlike KMS).

Each path is proven by a real in-process mTLS handshake under full WebPKI server
validation (chain + validity + hostname + `CertificateVerify` signature) — a
corrupted delegated signature must fail the handshake. The internal-platform TLS
key (§F) is wired privately in the monorepo against the same `RawEd25519TlsSigner`
trait; no internal specifics enter this repo.

## Verification (no-gaming)

Per the live-infra-lane discipline already used for Redis / SoftHSM2 / OCSP, each
adapter is proven by a black-box live test under `MCPS_REQUIRE_LIVE_INFRA=1`:

- **AWS** — LocalStack KMS emulator in CI (creates an `ECC_NIST_EDWARDS25519` key);
  optional nightly lane against real AWS KMS with provided creds.
- **GCP** — Cloud KMS emulator in CI; optional nightly real-endpoint lane.
- **Internal platform** — the in-house KMS test endpoint (monorepo-side adapter).

The load-bearing assertion in every lane: a signature produced by the KMS adapter
over a preimage **verifies under `response_public_key()` using the unmodified
`mcps-core` Ed25519 verifier** — proving byte-level protocol compatibility, and that
the adapter uses PureEdDSA-RAW (a prehash signature would fail this check).

## Consequences

- Native AWS KMS and GCP Cloud KMS become first-class custody backends with the
  response-signing key never leaving the KMS; AWS/GCP/Azure HSM and any PKCS#11
  device remain covered by the existing generic path.
- The v0.3 claim matrix Axis-3 (`shared_remote_signer`) gains concrete, live-verified
  managed-KMS backings beyond PKCS#11.
- Azure-native REST signing is a documented, honest unsupported boundary — surfaced,
  not hidden.
- Default builds are unaffected (both adapters are off-by-default feature gates; the
  cloud SDKs are not linked unless enabled).

## v0.9 Custody-Hardening Addendum (2026-07-03)

Outcome of the v0.9/v0.10 enterprise-hardening design review. This is a **delta
addendum** (not a new ADR): it hardens and schedules the native GCP Cloud KMS
custody path (§C) for v0.9 and records the enterprise-custody boundary decisions.
The parent invariants stand unchanged — **Ed25519-only (§A), non-exporting (§D),
the `ResponseSigner` seam is the only coupling (§F)**. Nothing here adds a draft-02
wire field; `deny_unknown_fields` on the request envelope is preserved.

### Decisions (H–L, extending §A–§G)

**H. Key-version identity rides the existing `(signer, key_id)` slot — no new wire
field.** The GCP Cloud KMS `cryptoKeyVersion` resource name
(`projects/…/cryptoKeys/…/cryptoKeyVersions/N`) maps onto the existing MCP-S
`(signer, key_id)` trust-bundle entry. The requirement "the signer key version
appears in evidence" is satisfied by the `key_id` that is **already in the signed
preimage** — no `key_version` envelope field is added (that would reopen the frozen
draft-02 preimage). Rotation, disable, and revocation are expressed as **trust-bundle
mapping movements**, never wire changes. Audit records `signer` + `key_id`; the
`key_id`→`cryptoKeyVersion` correspondence is operator trust-bundle configuration.

**I. KMS lifecycle ≠ verifier revocation (the load-bearing boundary).** KMS
key-version *disable* / *destroy* controls **future signing authority only**. It does
**not** make verifiers reject already-signed evidence or already-cached public keys.
Verifier acceptance is **trust-policy-driven** — an operator adds/removes/`Revoke`s
the `(signer, key_id)` mapping, and exposure is bounded by the ADR-MCPS-021
trust-propagation window `T` (or invalidated immediately via the Tier-3 push channel).
The verifier **MUST NOT call KMS at verification time**: `getPublicKey` /
`asymmetricSign` live on the SIGNER seam only (§C, `key_source.rs`), so verification
correctness never couples to KMS availability — a KMS outage cannot break
verification of retained audit evidence. `security-boundary.md` states this verbatim:

> KMS lifecycle controls signing authority. MCP-S trust policy controls evidence
> acceptance. Disabling a KMS key version prevents new signatures, but verifiers
> reject existing or cached-key evidence only after the relevant `key_id` is revoked
> or removed from MCP-S trust policy.

A live KMS-status→trust-policy **sync job** MAY exist as operator glue, but it feeds
trust policy; it is never the verification path.

**J. Rotation model — explicit overlap.** Three phases over `(signer, key_id)`
mappings: (1) trust old only; (2) trust old **and** new (overlap; new signatures use
the new version); (3) trust new only, old revoked/removed. Emergency revocation is
phase 3 forced immediately (remove mapping / push `Revoked`), bounded by `T` /
Tier-3 push per §I.

**K. Ed25519-only reaffirmed; P-256 rejected for the GCP profile.** The seed proposed
also supporting P-256 because Google lists it as a general EC recommendation. **Not
adopted.** `GcpKmsKeySource` pins `EC_SIGN_ED25519` and fails closed on any other key
spec (§C, §D). Admitting a second curve would fork the one interop-critical wire
property (Ed25519-only, ADR-MCPS-004) for zero protocol benefit — GCP already offers
`EC_SIGN_ED25519`. If a deployment cannot obtain an Ed25519 key at the required
protection level, it **scopes out the high-assurance claim** for that deployment
rather than adding a curve.

**L. FIPS-140-2 L3 custody is a live-infra fact to verify, not an assumption.**
Before any FIPS-L3 line is written in the Google Cloud cookbook, verify **natively**
whether GCP Cloud KMS exposes `EC_SIGN_ED25519` at **HSM protection level**. The
parent ADR sources HSM-Ed25519 custody from the **PKCS#11 path** (`CKM_EDDSA`, §Context
table) — *not* the native REST adapter this ADR builds; the native adapter pins the
algorithm but says nothing about protection level. If native GCP KMS offers Ed25519
only at **software** protection, the cookbook's L3 story MUST route through
`Pkcs11KeySource`, and the native GCP KMS adapter is honestly labeled
**software-protection custody** — never presented as FIPS-L3. Do not sell native
software-protection custody as HSM/L3.

### Verification (v0.9 evidence spine — offline-first)

Every KMS-lifecycle acceptance property is a **verifier fail-closed** property, which
is provable **offline** and therefore qualifies as an evidence-spine claim (a named
GREEN OFFLINE test in `security_traceability_manifest.json`). A live GCP run proves
only Google's own IAM enforcement, **not** an MCP-S property — so live lanes are
`#[ignore]`d **supporting-only** evidence, never the spine entry for a claim.

The five negatives, correctly scoped:

1. **Disable stops new signatures** — offline via a `FakeGcp` fault variant that
   errors on `asymmetricSign`; the signer fails closed (no local-key fallback, §D).
   *(touches the KMS transport seam only)*
2. **Disable alone ≠ verifier revocation** — evidence signed *before* disable still
   verifies while `(signer, key_id)` remains trusted, proving acceptance is
   trust-policy-driven, not KMS-status-driven. **Pure trust-resolver test, no KMS.**
3. **Pushed `Revoked` / `key_id` removal → verifier rejects** within window `T`, or
   immediately via the Tier-3 push channel. **Trust-resolver / `push_trust` test, no
   KMS.**
4. **Destroy → fresh `getPublicKey` fails closed** (`FakeGcp` fault variant on
   `get_public_key`) while a **pre-pinned** verifier still verifies pre-destroy
   evidence. *(the only other KMS-transport-touching case)*
5. **Rotation overlap** — accept old+new during overlap, then reject old after
   removal. **Trust-resolver test.**

**Construction rule:** negatives (3)–(5) run over a **pinned trust bundle with the KMS
transport unreachable**, which itself proves the verify path makes no `getPublicKey`
call (§I). `FakeGcp` (already the offline stand-in for the two-method
`GcpKmsTransport`) supplies the fault variants for (1) and (4).

### Consequences (v0.9)

- Native GCP Cloud KMS custody is **Accepted for v0.9** and clears the evidence-spine
  gate **without** live GCP — the whole item is offline-provable.
- Audit evidence is unchanged on the wire: `signer` + `key_id` (= the KMS key version)
  are already in the signed preimage; the KMS-lifecycle/verifier-revocation split is
  an operator-and-trust-policy concern (paired with the **ADR-MCPS-021 trust/rotation
  addendum**, the other v0.9 custody item).
- The FIPS-L3 claim is gated behind a live-infra check; software-protection native
  custody is labeled honestly rather than overclaimed.
- P-256 is closed as a non-goal; the Ed25519-only wire contract is preserved.
