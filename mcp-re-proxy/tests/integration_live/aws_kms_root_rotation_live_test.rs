// SPDX-License-Identifier: Apache-2.0
//! LIVE AWS KMS trust-anchor (master/root key) rotation (ADR-MCPRE-052 §H) — the AWS
//! twin of `gcp_kms_root_rotation_live_test`, running the same
//! `run_rotation_scenario` the hermetic `root_authority_manifest_test` runs, but with
//! the two roots held in REAL AWS KMS. Proves root rotation / overlap / revocation
//! across TWO cloud roots whose credential signatures are produced by KMS `Sign` and
//! verified against the KMS-reported public keys.
//!
//! Self-provisioning, NO human-in-the-loop: the fenced runner
//! [`docs/security/aws-kms-root-rotation.sh`](../../docs/security/aws-kms-root-rotation.sh)
//! creates TWO DISPOSABLE `ECC_NIST_EDWARDS25519` keys (never the shared
//! `mcp-re-ed25519-object` root), exports them here, runs this lane, then schedules
//! both for deletion. `#[ignore]` — it needs those live keys.
//!
//! Env (set by the runner):
//!   * `MCP_RE_AWS_ROOT_A_KEY_ID` / `MCP_RE_AWS_ROOT_B_KEY_ID` — two DISTINCT
//!     `ECC_NIST_EDWARDS25519` key ids/ARNs/aliases (the two disposable roots).
//!   * `MCP_RE_AWS_KMS_REGION` — the region both live in.
//!   * Credentials: either the static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
//!     pair, or `MCP_RE_AWS_USE_WEB_IDENTITY=1` to take the IRSA path (which is what
//!     the on-EKS run uses — see `docs/security/eks-slo-baseline-runbook.md`).
//!   * `MCP_RE_AWS_KMS_ENDPOINT` — OPTIONAL emulator override.

#![cfg(feature = "aws_kms_keysource")]

use crate::common;

use common::run_rotation_scenario;
use common::RootAuthority;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_proxy::AwsKmsConfig;
use mcp_re_proxy::AwsKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

/// Read a REQUIRED env var or fail the lane — a missing configuration is a lane
/// FAILURE, never a silent skip (the anti-gaming rule every live lane follows).
fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "aws-kms live root-rotation lane: required env var {name} is not set — run via \
             docs/security/aws-kms-root-rotation.sh; this lane does not pass without verifying"
        ),
    }
}

/// A KMS-backed root: its credential JWS is signed by AWS KMS `Sign` over this key,
/// and its public key is the KMS-reported one. Wire-identical to an in-memory root
/// through the same issuance seam.
fn kms_root(key_id_env: &str, issuer_kid: &str) -> RootAuthority {
    let config = AwsKmsConfig {
        region: require_env("MCP_RE_AWS_KMS_REGION"),
        key_id: require_env(key_id_env),
        endpoint: std::env::var("MCP_RE_AWS_KMS_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    // Both custody paths reach the SAME KMS key; which one this lane takes is the
    // runner's choice, and on EKS it is IRSA — the point being that the rotation
    // proof holds identically when no IAM key material is in the pod.
    let backend = if std::env::var("MCP_RE_AWS_USE_WEB_IDENTITY").is_ok_and(|v| v == "1") {
        AwsKmsEd25519Backend::from_web_identity(
            &config,
            std::env::var("MCP_RE_AWS_STS_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
        )
        .expect("connect the disposable KMS root backend through IRSA")
    } else {
        AwsKmsEd25519Backend::from_env(&config).expect("connect the disposable KMS root backend")
    };
    let signer = KmsResponseSigner::new(Box::new(backend));
    let public_key = signer.response_public_key().expect("KMS root public key");
    RootAuthority::new(
        issuer_kid,
        public_key,
        Box::new(move |input: &[u8]| {
            b64url_decode(
                &signer
                    .sign_response(input)
                    .expect("KMS Sign over the JWS input"),
            )
            .expect("KMS returns a base64url raw Ed25519 signature")
        }),
    )
}

#[test]
#[ignore = "requires two DISPOSABLE live AWS KMS Ed25519 keys; run via docs/security/aws-kms-root-rotation.sh"]
fn aws_kms_root_rotation_live() {
    // Two REAL AWS KMS roots (disposable keys provisioned by the fenced runner).
    let root_a = kms_root("MCP_RE_AWS_ROOT_A_KEY_ID", "aws-kms-root-a");
    let root_b = kms_root("MCP_RE_AWS_ROOT_B_KEY_ID", "aws-kms-root-b");
    // The org/admin manifest-signing key is in-memory here — trust-ANCHOR rotation is
    // under test, not manifest-key custody (a separate org concern). The rotation,
    // overlap window, cutover, and revocation are proven with KMS-produced credentials.
    let org_key = SigningKey::from_seed_bytes(&[7u8; 32]);
    run_rotation_scenario(&root_a, &root_b, &org_key);
}
