<!-- SPDX-License-Identifier: Apache-2.0 -->

# FIPS-140 L3 Ed25519 custody — protection-level finding (MCPS-59)

**Issue:** MCPS-59 — FIPS-140-2 L3 native-Ed25519 protection-level verification gate.
**Source ADR:** ADR-MCPS-028 §Context / Decision L (FIPS-140-2 L3 is a live-infra
fact to verify, not to assert).
**Type:** investigation + honest-labelling decision. No production signing behaviour
changes; this records the custody claim boundary.

## Question

Does **native** GCP Cloud KMS (the REST adapter this repo builds,
`mcp-re-proxy/src/gcp_kms_keysource.rs`) expose `EC_SIGN_ED25519` at **HSM**
protection level — the prerequisite for any FIPS-140-2 Level 3 Ed25519 custody
claim — or only at **SOFTWARE** protection level?

## Finding

**Native GCP Cloud KMS offers `EC_SIGN_ED25519` at SOFTWARE protection level only;
Ed25519 is not available at HSM protection level.** GCP Cloud KMS HSM protection
covers RSA, ECDSA (P-256 / P-384 / secp256k1), and AES key purposes; the
`EC_SIGN_ED25519` algorithm is offered exclusively at the SOFTWARE protection
level. Consequently the native REST adapter's key material is **software-protected**
and cannot substantiate a FIPS-140-2 L3 (hardware-custody) claim.

### Evidence

- **Primary (authoritative, live):** attempting to create an HSM-protected Ed25519
  key is rejected by the API. Run against the target project as the definitive,
  current-as-of-run evidence (this is the physical check that pins the fact to the
  live platform, independent of any doc's freshness):

  ```bash
  # Expected: FAILS — Ed25519 is not offered at HSM protection level.
  gcloud kms keys create ed25519-hsm-probe \
    --location=global --keyring=<ring> \
    --purpose=asymmetric-signing \
    --protection-level=hsm \
    --default-algorithm=ec-sign-ed25519
  # The complementary control SUCCEEDS (software Ed25519), confirming the algorithm
  # itself is supported, only not at HSM protection:
  gcloud kms keys create ed25519-sw-probe \
    --location=global --keyring=<ring> \
    --purpose=asymmetric-signing \
    --protection-level=software \
    --default-algorithm=ec-sign-ed25519
  ```

  **Attached live evidence — probe run 2026-07-09** (project
  `project-b19bbb5e-9be8-4fcb-a2f` "MCP-S tests", keyring `fips-probe-ring`,
  location `global`):

  ```text
  # HSM Ed25519 — REJECTED by the API (the definitive finding):
  $ gcloud kms keys create ed25519-hsm-probe --location=global \
      --keyring=fips-probe-ring --purpose=asymmetric-signing \
      --protection-level=hsm --default-algorithm=ec-sign-ed25519
  ERROR: (gcloud.kms.keys.create) INVALID_ARGUMENT: Algorithm EC_SIGN_ED25519
  is not supported for protection level: HSM
    metadata:
      algorithm: EC_SIGN_ED25519
      protection_level: HSM
    reason: ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL          # exit 1

  # SOFTWARE Ed25519 — ACCEPTED (control: the algorithm IS supported, only not at HSM):
  $ gcloud kms keys create ed25519-sw-probe --location=global \
      --keyring=fips-probe-ring --purpose=asymmetric-signing \
      --protection-level=software --default-algorithm=ec-sign-ed25519
  # exit 0
  $ gcloud kms keys list --location=global --keyring=fips-probe-ring
  NAME              PURPOSE          PROTECTION_LEVEL  ALGORITHM
  ed25519-sw-probe  ASYMMETRIC_SIGN  SOFTWARE          EC_SIGN_ED25519
  ```

  The API's own `ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL` for
  `{EC_SIGN_ED25519, HSM}` is the authoritative, platform-current confirmation.
  Throwaway probe key version scheduled for destruction after the run.

- **Secondary (documentary):** GCP Cloud KMS "Key purposes and algorithms" and
  "Protection levels" reference documentation lists `EC_SIGN_ED25519` under
  SOFTWARE only; HSM-protected asymmetric-signing algorithms are the RSA and
  NIST/secp256k1 ECDSA families.

> Caveat: cloud platform capabilities change. The `gcloud … --protection-level=hsm
> --default-algorithm=ec-sign-ed25519` probe above is the reproducible source of
> truth; re-run it to re-confirm before publishing any L3 language. If a future
> platform revision offers HSM-protected Ed25519, record the exact key spec +
> protection level here and revisit the routing decision below.

## Decision — FIPS-L3 routing

1. **The native GCP KMS adapter (`GcpKmsKeySource`) is software-protection custody
   and MUST NOT be presented as FIPS-140-2 L3 / HSM-backed.** It is already labelled
   this way in code — `mcp-re-proxy/src/gcp_kms_keysource.rs` (module docs): *"labeled
   software-protection custody and MUST NOT be presented as FIPS-140-2 Level 3 /
   HSM-backed."* This finding ratifies that label as correct.

2. **A FIPS-140-2 L3 Ed25519 custody claim routes through the PKCS#11 path
   (`Pkcs11KeySource`, `CKM_EDDSA`) on a FIPS-140-2 L3-certified HSM**, never through
   the native GCP KMS REST adapter. This is the established HSM-Ed25519 custody path
   (ADR-MCPS-028 §Context) and is where any L3 assurance must be proven, against the
   specific certified module and its FIPS certificate.

3. **The deferred Google Cloud cookbook's FIPS language** must therefore not offer
   native GCP KMS Ed25519 as L3. For GCP specifically, an L3 Ed25519 story requires
   either an external/attached FIPS L3 HSM reached over PKCS#11, or a non-Ed25519
   suite at HSM protection — out of scope for the Ed25519 evidence profile.

## Acceptance criteria

- [x] Documented finding: native GCP KMS does **not** offer `EC_SIGN_ED25519` at HSM
      protection (SOFTWARE only), with the reproducible `gcloud` probe as evidence.
- [x] `GcpKmsKeySource` protection-level label is honest (already **software-protection**
      in code; ratified here).
- [x] FIPS-L3 routing decision recorded: **PKCS#11 `CKM_EDDSA` on a certified HSM**,
      not native GCP KMS.

## Physical step (HITL) — DONE (2026-07-09)

The `gcloud … --protection-level=hsm` probe was run on live GCP (project
`project-b19bbb5e-9be8-4fcb-a2f`) on 2026-07-09; the output is attached under
**Evidence → Attached live evidence** above. The HSM create was rejected with
`ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL`, and the software create
succeeded — pinning the finding to the current platform. The finding no longer
rests only on documentary evidence + the conservative label; it is confirmed by
the platform's own API. Re-run the probe before publishing any future L3 language
(cloud capabilities can change); if HSM-protected Ed25519 ever appears, record the
new key spec here and revisit the routing decision.
