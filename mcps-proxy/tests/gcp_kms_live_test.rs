//! Live GCP Cloud KMS verification lane (ADR-MCPS-028 §C, guardrail #7).
//!
//! The lane that lets MCP-S CLAIM GCP Cloud KMS support: a signature produced by a
//! REAL Cloud KMS `asymmetricSign` (real endpoint or an emulator) MUST verify under
//! the UNMODIFIED `mcps-core` Ed25519 verifier with the key the same KMS reports via
//! `getPublicKey`. Compiling is NOT support; this assertion is.
//!
//! `#[ignore]` by default (needs network + a configured Ed25519 key version); run in
//! the live-infra lane with `cargo test --features gcp_kms_keysource -- --ignored`.
//! FAILS LOUDLY if its required configuration is absent — never a silent pass.
//!
//! Required environment:
//!   * `MCPS_GCP_KEY_VERSION`  — full resource path
//!     `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`
//!     (algorithm `EC_SIGN_ED25519`).
//!   * one of: `MCPS_GCP_ACCESS_TOKEN` (operator bearer token) — or set
//!     `MCPS_GCP_USE_METADATA=1` to use the workload-identity metadata server.
//!   * `MCPS_GCP_KMS_ENDPOINT` — OPTIONAL endpoint override (emulator).
#![cfg(feature = "gcp_kms_keysource")]

use mcps_core::verify_ed25519;
use mcps_proxy::GcpKmsConfig;
use mcps_proxy::GcpKmsEd25519Backend;
use mcps_proxy::KmsResponseSigner;
use mcps_proxy::ResponseSigner;

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms live lane: required env var {name} is not set — this lane must run against a \
             real/emulated Cloud KMS; it does not pass without verifying"
        ),
    }
}

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCPS_GCP_* set)"]
fn gcp_kms_signature_verifies_under_mcps_core() {
    let config = GcpKmsConfig {
        key_version_name: require_env("MCPS_GCP_KEY_VERSION"),
        endpoint: std::env::var("MCPS_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCPS_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        // Fail loudly now if neither credential source is configured.
        require_env("MCPS_GCP_ACCESS_TOKEN");
    }
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    let signer = KmsResponseSigner::new(Box::new(backend));

    let preimage = b"mcps canonical response preimage (live GCP KMS lane)";
    let sig = signer.sign_response(preimage).expect("Cloud KMS asymmetricSign");
    let pubkey = signer.response_public_key().expect("Cloud KMS public key");

    verify_ed25519(preimage, &sig, &pubkey)
        .expect("a live Cloud KMS Ed25519 signature MUST verify under the mcps-core verifier");
    assert!(
        verify_ed25519(b"tampered", &sig, &pubkey).is_err(),
        "signature must not verify over a different preimage"
    );
}
