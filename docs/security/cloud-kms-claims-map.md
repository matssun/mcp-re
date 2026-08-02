<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cloud-KMS claims map

The authoritative mapping from **capability → canonical test target → runner → the
claim it earns**, for the AWS KMS and GCP Cloud KMS backends.

It exists because "a test file is present" is not coverage, and had been mistaken for
it: the nightly GCP job invoked a target that no longer existed, and the GCP example
script invoked two crates that are not workspace members. Read this table before
making any cross-cloud custody claim.

## Where lanes run

| Runner | Trigger | Blocking | Contents |
|---|---|---|---|
| `.github/workflows/ci.yml` (feature-gated backends job) | every push | **yes** | every non-`#[ignore]` test under the combined backend feature set — i.e. all **offline twins** below |
| `.github/workflows/cloud-kms-live.yml` | nightly 04:00 UTC + manual dispatch | no | the `#[ignore]` **live** lanes, and only when that backend's secrets are present |
| `scripts/test-gcp-cloud.sh.example` | manual, operator-run | no | the GCP live lanes against the operator's own project |
| `scripts/test-aws-cloud.sh.example` | manual, operator-run | no | the AWS live lanes + the FIPS-endpoint probe |

A missing secret set makes a `cloud-kms-live` job a no-op that is reported as *"not
exercised"*, never as passing coverage. The live tests themselves call `require_env`
and hard-fail on any missing variable, so a half-configured lane cannot fake a green.

## Capability matrix

"Offline twin" = a non-`#[ignore]` test exercising the same wiring through the
backend adapter with a local seed and no network. It guards the wiring on every push.
**It is not cloud validation** — only the live lane earns that half of the claim.

| Capability | Test target | Offline twins | In nightly live CI | In operator script | GCP | AWS |
|---|---|---|---|---|---|---|
| Object signing — a real KMS signature verifies under `mcp-re-core` | `{aws,gcp}_kms_live_test` | 0 | yes (both) | yes (both) | ✅ | ✅ |
| **Delegated-required serving + authority flip** | `{aws,gcp}_kms_delegated_required_live_test` | 2 | yes (both) | yes (both) | ✅ | ✅ |
| Delegated-signing custody state machine | `gcp_kms_delegated_signing_live_test` | 1 | no | GCP only | ✅ | ✗ |
| HTTP profile (RFC 9421 + RFC 9530) | `gcp_kms_http_profile_live_test` | 2 | GCP only | GCP only | ✅ | ✗ |
| Delegated TLS — TLS private key stays in KMS | `gcp_kms_delegated_tls_live_test` | 0 | no | GCP only | ✅ | ✗ |
| Root rotation / trust-anchor transition | `gcp_kms_root_rotation_live_test` | 0 | no | `docs/security/gcp-kms-root-rotation.sh` | ✅ | ✗ |

AWS gaps are deliberate scope, not defects. `--aws-kms-tls-key-id` is wired in the
CLI, so the delegated-TLS gap is a missing lane rather than a missing capability.

## What each claim requires

**"A real KMS signature verifies under the unmodified `mcp-re-core` verifier."**
Earned by the object-signing lane alone. Available for both clouds.

**"Native non-exporting delegated-root signing has been validated against Google
Cloud KMS and AWS KMS."**
Requires the **delegated-required** lane on both clouds, not the object-signing lane.
Under ADR-MCPRE-052 the root never signs a response: it *issues* a short-TTL
credential and an in-memory delegated key signs the operational response. The
object-signing lane never reaches that chain, so it cannot earn this wording. The
delegated-required lane proves the full chain — production `build_delegated_signing`
+ `new_delegated` wiring, zero per-request KMS ops at the serving altitude, rotation
to a successor, the revocation seam in both directions, pre-052 direct-root rejection,
and the trust-epoch flip.

Status: **earned on both clouds.** Run against real AWS KMS on 2026-08-01 (account
`455880745808`, region `eu-north-1`, key spec `ECC_NIST_EDWARDS25519`):

```text
aws_kms_signature_verifies_under_mcp_re_core ... ok      # object signing
aws_kms_delegated_required_serving_live ... ok           # delegated-root serving
aws_kms_authority_flip_live ... ok                       # authority/epoch/revocation flip
```

The delegated-root sentence is therefore now defensible for both clouds, with the
`opt-in adapter` qualifier below.

**Both adapters are opt-in.** `aws_kms_keysource` and `gcp_kms_keysource` are both in
`_PROXY_EXT_FEATURES` (`mcp-re-proxy/BUILD.bazel`); the default `:mcp_re_proxy` target
links neither. Any claim must say *opt-in adapter*, never imply that a default proxy
binary carries KMS support.

**FIPS is a separate axis and must not ride along.** See
[`aws-kms-fips-protection-level.md`](aws-kms-fips-protection-level.md) and
[`fips-l3-ed25519-protection-level.md`](fips-l3-ed25519-protection-level.md). A
delegated-root interoperability result says nothing about FIPS coverage, and the two
conclusions are recorded separately on purpose.

## Lanes with no live runner

Client-side KMS custody and the integrated four-hop lanes targeted the
`mcp-re-client-proxy-cli` and `mcp-re-walkthrough` crates. Neither is a workspace
member, so those lanes have no runner. This is a **known coverage gap**, recorded
here rather than silently dropped: no client-side KMS custody claim is currently
evidenced on either cloud.
