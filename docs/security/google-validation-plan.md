<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Google Validation Plan

A staged sub-project to validate MCP-RE against live Google Cloud security
infrastructure, and to demonstrate MCP-RE security events as first-class findings
in Google's commercial security platforms.

## Status

Proposed. This is a validation/evidence sub-project, not a protocol change. It
exercises the **already-shipped** `GcpKmsKeySource` adapter against real Cloud
KMS, then layers event export (Cloud Logging / BigQuery) and findings
integration (Security Command Center) on top. No change to the MCP-RE signature
contract (Ed25519-only, ADR-MCPS-004) is in scope.

## Why Google, and why now

Public security guidance — notably the NSA/CISA MCP hardening direction —
explicitly recommends **signing and verifying MCP messages, expiration
timestamps, replay-protection metadata, and binding requests to time and
context**. That is, line for line, the MCP-RE Core claim. Validating MCP-RE
against a major cloud provider's KMS and security-operations stack turns that
claim into reproducible, third-party-infrastructure evidence.

The pitch to Google is therefore concrete:

> MCP-RE is an open-source implementation of the message-signing, expiry,
> replay-protection, context-binding, and KMS-backed custody controls that
> public MCP security guidance now says deployments need. We want to validate it
> against Google Cloud KMS and show MCP-RE security events as findings in Google
> Security Command Center / Google Security Operations, for the benefit of the
> MCP community.

## What already exists (do not rebuild)

The premise that we "need a Google adapter" is **out of date** — we have one.

| Component | Path | State |
|---|---|---|
| GCP Cloud KMS Ed25519 signer | `mcp-re-proxy/src/gcp_kms_keysource.rs` | Shipped, feature `gcp_kms_keysource` |
| AWS KMS Ed25519 signer | `mcp-re-proxy/src/aws_kms_keysource.rs` | Shipped, feature `aws_kms_keysource` |
| Provider-agnostic KMS trait | `mcp-re-proxy/src/kms_keysource.rs` (`KmsEd25519Backend`) | Shipped |
| `ResponseSigner` / `KeySource` seam | `mcp-re-proxy/src/key_source.rs` | Shipped |
| Frozen audit-event vocabulary | `mcp-re-core/src/audit.rs` (ADR-MCPS-035) | Shipped |
| Frozen error taxonomy | `mcp-re-core/src/error.rs` | Shipped |
| GCP live test harness (object signing) | `mcp-re-proxy/tests/gcp_kms_live_test.rs` | Shipped (needs real/emulated KMS) |
| GCP live test harness (delegated TLS) | `mcp-re-proxy/tests/gcp_kms_delegated_tls_live_test.rs` | Shipped (needs real/emulated KMS) |
| Reproduction harness (one command) | `docs/security/gcloud-kms-validation.sh` | Shipped |
| Design rationale | `docs/adr/adr-mcps-028.md` | Proposed |

`GcpKmsKeySource` already does the security-critical work: `getPublicKey`
(asserting algorithm `EC_SIGN_ED25519`), `asymmetricSign` over **raw canonical
bytes** (PureEdDSA, not a digest), verify-before-return on every signature, and
fail-closed construction if the key algorithm is wrong. Credentials come from
either an operator-supplied OAuth2 token (`MCP_RE_GCP_ACCESS_TOKEN`) or
metadata-server workload identity (`MCP_RE_GCP_USE_METADATA=1`).

**So Stage 1 is not "build the adapter" — it is "prove the shipped adapter
against live Google KMS and capture the evidence."**

## Separation of concerns

Keep KMS/custody validation strictly separate from commercial SIEM/SOAR
validation. The first is cheap, self-serve, and fully under our control; the
second needs sponsored access. Do not block the former on the latter.

## Cost reality (validate before assuming)

- **New-customer free trial:** ~$300 credits; sufficient for a small KMS proof
  many times over.
- **Cloud KMS pricing:** cryptographic operations ~$0.03 per 10,000 ops
  (software/HSM/EXTERNAL), plus per-active-key-version charges; billing must be
  enabled.
- **Autokey free tier** (100 active key versions, 10,000 ops/month): **do not
  assume** it maps to manually created Ed25519 asymmetric-signing keys —
  Autokey targets CMEK-style auto-provisioning, not user-created
  `EC_SIGN_ED25519` keys. Treat as unconfirmed until tested; the paid path is
  cheap enough that it does not gate the proof either way.
- **Security Command Center:** Premium pay-as-you-go exists; **Enterprise
  subscription minimum ~$15,000/yr**. Not a self-serve first experiment — needs
  a trial/evaluation tenant.
- **Google Security Operations (SecOps / Mandiant):** "Contact sales," no public
  free tier. Evaluation/sponsored access only.
- **Model Armor:** standalone, free up to ~2M tokens/month. **Adjacent, not
  MCP-RE Core** — prompt/response screening, not message authenticity. Out of
  scope here; note it as a separate demo if asked.

## Stage 1 — Cloud KMS Ed25519 proof (self-serve, cheap)

**Goal:** prove MCP-RE response signing works end-to-end against a live Google
Cloud KMS `EC_SIGN_ED25519` key, and capture reproducible evidence.

**Services:** Cloud KMS (required), Cloud Logging + BigQuery (evidence, Stage 1b).

**Steps:**
1. Create a key ring and an `ASYMMETRIC_SIGN` key with algorithm
   `EC_SIGN_ED25519`; create a key version.
2. Grant a service account `cloudkms.signerVerifier` (or split
   signer/public-key-viewer) on that key version.
3. Configure MCP-RE: `MCP_RE_GCP_KEY_VERSION=<full resource path>` plus credentials
   (`MCP_RE_GCP_ACCESS_TOKEN` for a first manual run, or
   `MCP_RE_GCP_USE_METADATA=1` on a GCE/GKE host).
4. Run `mcp-re-proxy` built with `--features gcp_kms_keysource`; sign live MCP-RE
   canonical request/response preimages.
5. Verify each signature with the `mcp-re-core` verifier (this is already the
   adapter's verify-before-return path; assert it externally too).
6. **Fail-closed checks:** point the verifier at a different public key and
   confirm `mcp-re.response_sig_invalid`; tamper one preimage byte and confirm
   rejection.
7. Exercise `tests/gcp_kms_live_test.rs` against the live key version.

**Exit criteria:** a clean run log showing (a) public key fetched and algorithm
asserted `EC_SIGN_ED25519`, (b) N signatures produced by Cloud KMS and verified
by `mcp-re-core`, (c) wrong-key and tampered-byte cases rejected with the correct
frozen wire codes, (d) the private key never left KMS (only `getPublicKey` /
`asymmetricSign` calls in the request log).

### Reproducing Stage 1 locally

A one-command harness is committed at `docs/security/gcloud-kms-validation.sh`.
It enables the KMS API, provisions the keys (idempotently — KMS keys cannot be
deleted, so re-runs reuse them), and runs the live test lanes. It contains no
secrets; you supply `PROJECT_ID`.

**First-time Google Cloud setup (once, before you fill in the script).** This is
the part that has no CLI shortcut for a brand-new user:

1. **Google account** — any Google account works.
2. **Sign up for Google Cloud** — accept the terms at
   <https://console.cloud.google.com>. New accounts get ~$300 in free-trial
   credits, ample for this proof.
3. **Billing account** — Cloud KMS requires billing *enabled*, even on the free
   trial (the trial supplies the credits). Create one in the console under
   *Billing*.
4. **A project, linked to billing** — create it in the console, or by CLI:
   `gcloud projects create <id>` then
   `gcloud billing projects link <id> --billing-account=XXXXXX-XXXXXX-XXXXXX`.
5. **Install the gcloud CLI** — <https://cloud.google.com/sdk/docs/install>.
6. **Authenticate** — `gcloud auth login`.

You do **not** need to pre-create the key ring, the keys, or enable the KMS API
by hand — the script does all of that.

**Run it:**

```
PROJECT_ID="<your-project-id>" ./docs/security/gcloud-kms-validation.sh
```

**What runs** (the `#[ignore]` live lanes, built with `--features gcp_kms_keysource`):

- `mcp-re-proxy/tests/gcp_kms_live_test.rs` — object signing: positive verify +
  wrong-identity + bad-token + non-Ed25519 rejection.
- `mcp-re-proxy/tests/gcp_kms_delegated_tls_live_test.rs` — delegated TLS: a real
  mTLS handshake whose server `CertificateVerify` is signed **inside** Cloud KMS,
  plus wrong-key-binding and untrusted-client negatives. Proves the TLS private
  key never leaves the cloud (the cert is minted over the KMS *public* key only).

### Stage 1b — evidence to Cloud Logging / BigQuery

The audit layer (`mcp-re-core/src/audit.rs`) emits `AuditEvent`s with frozen
`event_type` + `reason` tokens. Serialize them as structured JSON at the
transport/host layer (Core does no I/O), ship to **Cloud Logging**, optionally
sink to **BigQuery** for queryable evidence.

The four `event_type` values are fixed (ADR-MCPS-035):
`mcp-re.request.accepted`, `mcp-re.response.signed`, `mcp-re.request.rejected`,
`mcp-re.response.rejected`. Rejection `reason` is always a verbatim
`McpReError::wire_code()` token.

**Exit criteria:** MCP-RE accept/sign/reject events queryable in BigQuery, with
rejection reasons matching the frozen taxonomy.

## Stage 2 — Security Command Center findings

**Goal:** surface MCP-RE security failures as first-class SCC findings.

SCC supports creating findings via its API under a registered `Source`. Map the
frozen MCP-RE rejection taxonomy to `ACTIVE` findings. The mapping is mechanical
because the tokens are frozen and CI-guarded (`audit_vocabulary_guard_test`):

| MCP-RE wire code | Suggested SCC severity | Meaning |
|---|---|---|
| `mcp-re.invalid_signature` | HIGH | Request signature did not verify |
| `mcp-re.response_sig_invalid` | HIGH | Response signature did not verify |
| `mcp-re.replay_detected` | HIGH | Replayed `(signer, audience, nonce)` triple |
| `mcp-re.transport_binding_failed` | HIGH | Channel-binding check failed |
| `mcp-re.response_hash_mismatch` | HIGH | Response not bound to verified request |
| `mcp-re.expired_request` | MEDIUM | Outside freshness window |
| `mcp-re.actor_binding_failed` | MEDIUM | No usable trust binding for signer/key |
| `mcp-re.invalid_audience` | MEDIUM | Audience mismatch |
| `mcp-re.downgrade_forbidden` | MEDIUM | Security downgrade refused |
| `mcp-re.trust_resolver_unavailable` | MEDIUM (operational) | Fail-closed; resolver down |
| `mcp-re.replay_cache_unavailable` | MEDIUM (operational) | Fail-closed; cache down |

(Severities above are a starting proposal, not normative — the wire codes are
the contract; severity is a deployment policy choice.)

**Caveat:** SCC findings need billing/org setup and likely an Enterprise or
trial tenant. Treat Stage 2 as gated on access; do not block Stage 1 on it.

**Exit criteria:** an injected invalid-signature and replay each appear as an
`ACTIVE` SCC finding under an MCP-RE source, carrying the frozen wire code.

## Stage 3 — Google Security Operations evaluation

**Goal:** ingest MCP-RE events into a commercial SIEM/SOAR workflow.

This is where we **request help rather than assume a tier**. Ask Google for:
- a time-boxed evaluation / sponsored OSS-community workspace;
- parser support (or guidance) for the MCP-RE event schema;
- sample detections over the MCP-RE event taxonomy;
- a case/playbook example for replay / signature / trust-failure response;
- a technical contact for parser/detection mapping.

**Exit criteria:** MCP-RE events parsed in SecOps with at least one detection
firing on a replayed or invalid-signature event.

## The ask to Google

Request a **time-boxed evaluation, not indefinite free usage**:

- GCP credits / test-billing sponsorship for the KMS proof;
- Cloud KMS access for `EC_SIGN_ED25519` signing tests (covered by trial credits
  if no sponsorship);
- Security Command Center evaluation access, or guidance for custom findings;
- Google Security Operations trial/evaluation workspace if available;
- a technical contact for parser/detection mapping.

## Sequencing

```
Stage 1  Cloud KMS Ed25519 proof          self-serve, cheap, do first
  └─1b   Cloud Logging / BigQuery evidence self-serve
Stage 2  SCC custom findings              needs billing/org or trial tenant
Stage 3  Google SecOps ingestion          needs evaluation/sponsored access
```

Do not wait for a big-platform trial before testing. Prove the KMS and event
path first (Stage 1 / 1b), then use that clean proof as the artifact that backs
the request for sponsored SCC / SecOps access.

## Deliverables

1. Cloud KMS Ed25519 signing proof (run log + reproduction steps).
2. MCP-RE audit-event taxonomy reference (already frozen; cite ADR-MCPS-035).
3. Cloud Logging / BigQuery evidence (queryable events).
4. Optional SCC custom-findings mapping (this doc's Stage 2 table, implemented).
5. Optional Google SecOps ingestion notes.
6. NSA/CISA-alignment paragraph mapping each control to an MCP-RE guarantee.

## References

- `docs/adr/adr-mcps-028.md` — native Cloud-KMS response signers (AWS + GCP).
- `mcp-re-proxy/src/gcp_kms_keysource.rs` — the GCP adapter under test.
- `mcp-re-core/src/error.rs` — frozen error taxonomy (the wire codes).
- `mcp-re-core/src/audit.rs` — frozen audit-event vocabulary (ADR-MCPS-035).
- `docs/security/README.md` — the broader MCP-RE security-review record.
