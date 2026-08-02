<!-- SPDX-License-Identifier: Apache-2.0 -->

# AWS Ed25519 custody — protection-level finding

**Source ADR:** ADR-MCPS-028 §B (AWS KMS Ed25519 signer) / §Decision L (FIPS-140 L3
is a live-infra fact to verify, not to assert).
**Companion:** [`fips-l3-ed25519-protection-level.md`](fips-l3-ed25519-protection-level.md)
— the same question answered for GCP.
**Type:** investigation + honest-labelling decision. No production signing behaviour
changes; this records the custody claim boundary for AWS.

## Question

The GCP finding established that native Cloud KMS offers `EC_SIGN_ED25519` at
SOFTWARE protection only, and routed any FIPS-140 L3 Ed25519 custody claim to
**PKCS#11 `CKM_EDDSA` on a certified HSM** (`Pkcs11KeySource`).

Two questions follow for AWS:

1. Does **AWS KMS** (`mcp-re-proxy/src/aws_kms_keysource.rs`) hold its
   `ECC_NIST_EDWARDS25519` keys in a FIPS-140-3 Level 3 validated module, in a way
   that substantiates an L3 Ed25519 custody claim?
2. Can **AWS CloudHSM** serve the PKCS#11 `CKM_EDDSA` route the GCP finding chose —
   i.e. is CloudHSM the certified HSM that closes the gap?

## Finding

### 1. AWS KMS Ed25519 is real, and the adapter targets it correctly

AWS KMS supports `ECC_NIST_EDWARDS25519` with `ED25519_SHA_512` + `MessageType: RAW`
(PureEdDSA, no pre-hash), GA November 2025, in all regions including GovCloud and
China. This is exactly the spec and mode the shipped adapter locks to
(`aws_kms_keysource.rs:64-66`). No adapter change is needed.

### 2. The KMS module is L3-validated; the Ed25519 *algorithm* is not in that validation

AWS KMS HSMs hold **CMVP certificate #4884**, FIPS 140-3 overall Level 3 — but the
certificate's approved-algorithm list covers **ECDSA (P-256/P-384/P-521) and RSA
only**. Neither EdDSA nor Ed25519 appears in it.

| Field | Value |
|---|---|
| Module | AWS Key Management Service HSM |
| Hardware / firmware | 3.0 / 1.8.104 |
| Security policy doc | v0.35, 25 October 2024 |
| Validated | 18 November 2024 |
| Sunset | 17 November 2026 |
| Approved signature algorithms | ECDSA KeyGen/SigGen/SigVer (P-256, P-384, P-521); RSA SigGen/SigVer/Signature Primitive |
| EdDSA / Ed25519 | **absent** |

The Ed25519 launch (November 2025) postdates this validation. So the honest
statement is narrower than "AWS KMS is FIPS 140-3 Level 3, therefore our Ed25519
custody is L3":

> The key is held in a hardware module that carries a FIPS 140-3 Level 3
> validation, and is non-exporting. The **Ed25519 algorithm** is not listed among
> the approved algorithms of that validation as published.

This is the same class of trap as the GCP finding, one level deeper: on GCP the
*protection level* excluded Ed25519; on AWS the *module* is right and the
*algorithm* is outside the published validated set.

> Caveat: CMVP listings lag platform capability, and a revalidation may already be
> in flight. The probe below is the reproducible source of truth; re-run it and
> re-read the certificate before publishing any FIPS-L3 language.

### 3. AWS CloudHSM does **not** serve the PKCS#11 `CKM_EDDSA` route

CloudHSM cannot close the gap the GCP finding routed to, for three independent
reasons — any one of which is disqualifying:

- **PKCS#11 has no EdDSA.** The Client SDK 5 PKCS#11 mechanism list is RSA, ECDSA,
  HMAC, CMAC, AES, DES3. There is no `CKM_EDDSA`, and key-pair generation offers
  only `CKM_RSA_*_KEY_PAIR_GEN` / `CKM_EC_KEY_PAIR_GEN` — no
  `CKM_EC_EDWARDS_KEY_PAIR_GEN`. `Pkcs11KeySource` signs with `CKM_EDDSA` and reads
  `CKA_EC_POINT`; neither is available.
- **Ed25519 exists only in non-FIPS mode.** Where CloudHSM does expose Ed25519 (the
  CloudHSM CLI `crypto sign ed25519ph` / EC keygen with `curve ed25519`), it is
  documented as **`hsm2m.medium` instances in non-FIPS mode only**. FIPS mode and
  Ed25519 are mutually exclusive on CloudHSM, so the combination the claim needs
  cannot be configured at all.
- **The interface is the CLI, not PKCS#11.** Even in non-FIPS mode, Ed25519 is
  reached through the CloudHSM CLI (and the OpenSSL 3.2+ provider), not through the
  PKCS#11 library the adapter loads.
- **And that CLI operation is not the same algorithm.** The `crypto sign` category
  offers exactly four subcommands — `ecdsa`, `ed25519ph`, `rsa-pkcs`,
  `rsa-pkcs-pss`. The only Edwards option is `ed25519ph`, i.e. **HashEdDSA**
  (SHA-512 prehash). MCP-RE signs and verifies **PureEdDSA**, and
  `Ed25519(m) != Ed25519ph(SHA-512(m))` — a signature produced this way would not
  verify under `mcp-re-core` at all. CloudHSM offers no PureEdDSA through any
  interface, in either mode.

### 4. A KMS custom key store cannot host the signing key either

The "low-cost alternative" of backing a KMS key with a CloudHSM cluster does not
apply: **AWS CloudHSM key stores support only symmetric encryption KMS keys.**
Asymmetric KMS keys, HMAC keys, and imported key material cannot be created in a
custom key store. An `ECC_NIST_EDWARDS25519` signing key cannot live there.

## The probe (physical check)

AWS KMS has no per-key protection-level knob, so there is no direct analogue of the
GCP `--protection-level=hsm` rejection. The equivalent physical check is the **FIPS
endpoint**: `kms-fips.<region>.amazonaws.com` routes to modules constrained to
approved-mode services, and every commercial region (including `eu-north-1`) offers
one. Whether that endpoint will serve an `ED25519_SHA_512` `Sign` is the platform's
own answer to "is this algorithm in approved mode?".

```bash
# Positive control — the standard endpoint must sign (the algorithm exists):
aws kms sign --region "$REGION" \
  --key-id "$KEY_ARN" --message "$(printf probe | base64)" \
  --message-type RAW --signing-algorithm ED25519_SHA_512

# The finding — same call against the FIPS endpoint:
aws kms sign --region "$REGION" --endpoint-url "https://kms-fips.$REGION.amazonaws.com" \
  --key-id "$KEY_ARN" --message "$(printf probe | base64)" \
  --message-type RAW --signing-algorithm ED25519_SHA_512
```

`scripts/test-aws-cloud.sh.example` runs both, after the live signing lane, and
prints the verdict.

### Attached live evidence — probe run 2026-08-01

Account `455880745808`, region `eu-north-1`, key spec `ECC_NIST_EDWARDS25519`,
`SigningAlgorithm=ED25519_SHA_512`, `MessageType=RAW`.

```text
# CONTROL — standard endpoint (kms.eu-north-1.amazonaws.com):
$ aws kms sign --key-id <arn> --message <b64> --message-type RAW \
    --signing-algorithm ED25519_SHA_512 --query SigningAlgorithm
ED25519_SHA_512                                                   # exit 0

# PROBE — FIPS endpoint:
$ aws kms sign --endpoint-url https://kms-fips.eu-north-1.amazonaws.com \
    --key-id <arn> --message <b64> --message-type RAW \
    --signing-algorithm ED25519_SHA_512 --query SigningAlgorithm
ED25519_SHA_512                                                   # exit 0
```

**Result: ACCEPTED.** The FIPS endpoint served an Ed25519 signature.

**What this does and does not establish.** It establishes that AWS routes
`ED25519_SHA_512` through its FIPS endpoint rather than rejecting it — the platform's
own behaviour, pinned to a run. It does **not** establish that the operation is
covered by a FIPS validation: CMVP #4884's published approved-algorithm list still
contains no EdDSA entry (§2). Endpoint acceptance is not a certificate. The two
observations are in tension and only AWS can resolve it — plausibly a revalidation
not yet reflected in the listing, or an endpoint whose "FIPS" designation covers the
module and transport rather than per-algorithm approval.

Until a CMVP listing for the AWS KMS HSM shows EdDSA in its approved-algorithm
table, the conservative label below stands unchanged.

## Decision — FIPS routing for AWS

1. **`AwsKmsKeySource` is non-exporting hardware-held custody and MUST NOT be
   presented as FIPS-140-3 L3 Ed25519.** It may be described as *"key held in a
   non-exporting HSM-backed KMS"*. The L3 adjective attaches to the module's
   validation, not to the Ed25519 signing path, and must not be transferred across.

2. **AWS CloudHSM is not on the FIPS-L3 Ed25519 path and should not be provisioned
   for it.** The three findings in §3 are independent and documented; a cluster
   would cost hourly and prove nothing the claim needs. If a CloudHSM lane is ever
   built, it is for a *different* algorithm suite (ECDSA), not for the Ed25519
   evidence profile.

3. **The FIPS-L3 Ed25519 route remains PKCS#11 `CKM_EDDSA` on a certified HSM**, per
   the GCP finding. No *cloud* KMS or managed-HSM path provides it — but as of June
   2026 the route is satisfiable off-cloud, so the scope of the negative finding is
   **"not available through managed cloud HSM paths"**, not "not available".

   **CMVP #5302 — YubiHSM 2 Cryptographic Module**, validated 3 June 2026, FIPS
   140-3 **Overall Level 3**, hardware `SLE78CLUFX5000P`, firmware **2.4.1**, lists
   in its approved-algorithm table (CAVP `A5891`):

   | Algorithm | Parameters | Standard |
   |---|---|---|
   | EDDSA KeyGen | Curve ED-25519 | FIPS 186-5 |
   | EDDSA SigGen | Curve ED-25519, **PreHash: No, Pure: Yes** | FIPS 186-5 |
   | EDDSA SigVer | Curve ED-25519 | FIPS 186-5 |

   `Pure: Yes` is the load-bearing cell: it is PureEdDSA, the algorithm
   `mcp-re-core` verifies — not the HashEdDSA variant CloudHSM exposes.

   Two conditions still gate the claim, and neither is settled here:
   - the module **defaults to non-Approved mode**; Approved mode requires the
     documented configuration sequence (including replacing the default
     authentication keys) and is confirmed by a mode-indicator query returning `01`;
   - whether `yubihsm-pkcs11` presents Ed25519 as `CKM_EDDSA` with a
     `CKA_EC_POINT` representation matching `Pkcs11KeySource`'s expectation is an
     **empirical compatibility question, not a documented one** — it must be probed
     against the device before any claim is drafted.

4. **What the AWS lane *does* buy**, independent of FIPS: a second, independent cloud
   KMS proving the provider-agnostic `KmsEd25519Backend` seam is not GCP-shaped. Per
   the standing ruling, the claim after the lane is green is exactly:

   > Native non-exporting delegated-root signing has been validated against Google
   > Cloud KMS and AWS KMS.

## Acceptance criteria

- [x] Recorded that AWS KMS supports `ECC_NIST_EDWARDS25519` / `ED25519_SHA_512` /
      `RAW`, matching the shipped adapter with no code change.
- [x] Recorded that CMVP #4884's approved-algorithm list excludes EdDSA/Ed25519,
      with module version, validation date, and sunset date.
- [x] Recorded that CloudHSM cannot serve the PKCS#11 `CKM_EDDSA` route (no
      mechanism, non-FIPS-mode-only, CLI-not-PKCS#11, HashEdDSA-not-PureEdDSA) and
      that CloudHSM-backed KMS custom key stores are symmetric-only.
- [x] Recorded that CMVP #5302 (YubiHSM 2, firmware 2.4.1) carries PureEdDSA
      Ed25519 in its FIPS 140-3 L3 approved-algorithm table, bounding the negative
      finding to managed cloud HSM paths.
- [ ] `yubihsm-pkcs11` ↔ `Pkcs11KeySource` compatibility probed against hardware.
- [x] `AwsKmsKeySource` custody label decided: non-exporting HSM-backed, **not**
      FIPS-140-3 L3 Ed25519.
- [x] FIPS-endpoint probe run against a live account and its output attached
      (2026-08-01, `eu-north-1`): **ACCEPTED**, recorded above with its limits.

## Sources

- [AWS KMS now supports EdDSA](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/)
- [CMVP certificate #4884 — AWS Key Management Service HSM](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4884)
  and its [security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4884.pdf)
- [Supported mechanisms for the PKCS #11 library for AWS CloudHSM Client SDK 5](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html)
- [CloudHSM CLI `crypto sign ed25519ph`](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_cli-crypto-sign-ed25519ph.html)
  — "only supported on hsm2m.medium instances in non-FIPS mode"
- [Create a KMS key in an AWS CloudHSM key store](https://docs.aws.amazon.com/kms/latest/developerguide/create-cmk-keystore.html)
  — symmetric encryption keys only
- [CloudHSM CLI `crypto sign` category](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_cli-crypto-sign.html)
  — four subcommands; the only Edwards option is HashEdDSA
- [AWS KMS service endpoints](https://docs.aws.amazon.com/general/latest/gr/kms.html) — `kms-fips.*` per region
- [CMVP certificate #5302 — YubiHSM 2 Cryptographic Module](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5302)
  and its [security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5302.pdf)
  — approved table lists EDDSA SigGen, ED-25519, `Pure: Yes`
