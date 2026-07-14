// SPDX-License-Identifier: Apache-2.0
//! LIVE Cloud KMS trust-anchor (master/root key) rotation (ADR-MCPRE-052 §H) — the
//! same `run_rotation_scenario` the hermetic `root_authority_manifest_test` runs, but
//! with the two roots held in REAL Cloud KMS. Proves root rotation / overlap /
//! revocation across TWO cloud roots whose credential signatures are produced by KMS
//! `asymmetricSign` and verified against the KMS-reported public keys.
//!
//! Self-provisioning, NO human-in-the-loop: the fenced runner
//! [`docs/security/gcp-kms-root-rotation.sh`](../../docs/security/gcp-kms-root-rotation.sh)
//! creates TWO DISPOSABLE KMS Ed25519 key versions under a test-only keyring (never the
//! shared `mcps-ed25519-object` root), exports them here, runs this lane, then schedules
//! the versions for destruction. `#[ignore]` — it needs those live key versions.
//!
//! Env (set by the runner):
//!   * `MCP_RE_ROOT_A_KEY_VERSION` / `MCP_RE_ROOT_B_KEY_VERSION` — two DISTINCT
//!     `EC_SIGN_ED25519` key-version resource paths (the two disposable roots).
//!   * `MCP_RE_GCP_ACCESS_TOKEN` (bearer) or `MCP_RE_GCP_USE_METADATA=1`.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL emulator override.

#![cfg(feature = "gcp_kms_keysource")]

mod common;

use common::run_rotation_scenario;
use common::RootAuthority;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("live root-rotation lane requires {key} (run via docs/security/gcp-kms-root-rotation.sh)"))
}

/// A KMS-backed root: its credential JWS is signed by Cloud KMS `asymmetricSign` over
/// this key version, and its public key is the KMS-reported one. Wire-identical to an
/// in-memory root through the same issuance seam.
fn kms_root(version_env: &str, issuer_kid: &str) -> RootAuthority {
    let config = GcpKmsConfig {
        key_version_name: require_env(version_env),
        endpoint: std::env::var("MCP_RE_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCP_RE_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("connect the disposable KMS root backend");
    let signer = KmsResponseSigner::new(Box::new(backend));
    let public_key = signer.response_public_key().expect("KMS root public key");
    RootAuthority::new(
        issuer_kid,
        public_key,
        Box::new(move |input: &[u8]| {
            b64url_decode(&signer.sign_response(input).expect("KMS asymmetricSign over the JWS input"))
                .expect("KMS returns a base64url raw Ed25519 signature")
        }),
    )
}

#[test]
#[ignore = "requires two DISPOSABLE live Cloud KMS Ed25519 key versions; run via docs/security/gcp-kms-root-rotation.sh"]
fn gcp_kms_root_rotation_live() {
    // Two REAL Cloud KMS roots (disposable versions provisioned by the fenced runner).
    let root_a = kms_root("MCP_RE_ROOT_A_KEY_VERSION", "gcp-kms-root-a");
    let root_b = kms_root("MCP_RE_ROOT_B_KEY_VERSION", "gcp-kms-root-b");
    // The org/admin manifest-signing key is in-memory here — trust-ANCHOR rotation is
    // under test, not manifest-key custody (a separate org concern). The rotation,
    // overlap window, cutover, and revocation are proven with KMS-produced credentials.
    let org_key = SigningKey::from_seed_bytes(&[7u8; 32]);
    run_rotation_scenario(&root_a, &root_b, &org_key);
}
