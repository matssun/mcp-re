//! Live GCP Cloud KMS verification lane (ADR-MCPS-028 §C, guardrail #7).
//!
//! The lane that lets MCP-RE CLAIM GCP Cloud KMS support: a signature produced by a
//! REAL Cloud KMS `asymmetricSign` (real endpoint or an emulator) MUST verify under
//! the UNMODIFIED `mcp-re-core` Ed25519 verifier with the key the same KMS reports via
//! `getPublicKey`. Compiling is NOT support; this assertion is.
//!
//! `#[ignore]` by default (needs network + a configured Ed25519 key version); run in
//! the live-infra lane with `cargo test --features gcp_kms_keysource -- --ignored`.
//! FAILS LOUDLY if its required configuration is absent — never a silent pass.
//!
//! Required environment:
//!   * `MCP_RE_GCP_KEY_VERSION`  — full resource path
//!     `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`
//!     (algorithm `EC_SIGN_ED25519`).
//!   * one of: `MCP_RE_GCP_ACCESS_TOKEN` (operator bearer token) — or set
//!     `MCP_RE_GCP_USE_METADATA=1` to use the workload-identity metadata server.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL endpoint override (emulator).
#![cfg(feature = "gcp_kms_keysource")]

use mcp_re_core::verify_ed25519;
use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::KeyError;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

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
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_signature_verifies_under_mcp_re_core() {
    let config = GcpKmsConfig {
        key_version_name: require_env("MCP_RE_GCP_KEY_VERSION"),
        endpoint: std::env::var("MCP_RE_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCP_RE_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        // Fail loudly now if neither credential source is configured.
        require_env("MCP_RE_GCP_ACCESS_TOKEN");
    }
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    let signer = KmsResponseSigner::new(Box::new(backend));

    let preimage = b"mcp-re canonical response preimage (live GCP KMS lane)";
    let sig = signer.sign_response(preimage).expect("Cloud KMS asymmetricSign");
    let pubkey = signer.response_public_key().expect("Cloud KMS public key");

    verify_ed25519(preimage, &sig, &pubkey)
        .expect("a live Cloud KMS Ed25519 signature MUST verify under the mcp-re-core verifier");
    assert!(
        verify_ed25519(b"tampered", &sig, &pubkey).is_err(),
        "signature must not verify over a different preimage"
    );

    // Negative 1 — wrong IDENTITY: the live signature must NOT verify under a
    // foreign key. The tampered-preimage check above covers wrong MESSAGE; this
    // covers wrong KEY, i.e. a response signed by some other party is rejected.
    let foreign = mcp_re_core::SigningKey::from_seed_bytes(&[0x07; 32]).public_key();
    assert!(
        verify_ed25519(preimage, &sig, &foreign).is_err(),
        "a Cloud KMS signature must NOT verify under a different public key"
    );

    // Negative 2 — wrong SETUP fails closed: a bad access token must make backend
    // construction (getPublicKey) error, never silently build a usable signer.
    // Only meaningful on the bearer-token path, not the workload-identity metadata
    // path (which ignores MCP_RE_GCP_ACCESS_TOKEN).
    if !use_metadata {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().expect("env lock");
        let saved = std::env::var("MCP_RE_GCP_ACCESS_TOKEN").ok();
        std::env::set_var("MCP_RE_GCP_ACCESS_TOKEN", "not-a-valid-token");
        let result = GcpKmsEd25519Backend::new(&config, false);
        // Restore BEFORE asserting so a failed assert can't leak the bad token.
        match saved {
            Some(v) => std::env::set_var("MCP_RE_GCP_ACCESS_TOKEN", v),
            None => std::env::remove_var("MCP_RE_GCP_ACCESS_TOKEN"),
        }
        assert!(
            result.is_err(),
            "an invalid GCP access token must fail backend construction (fail closed), \
             not produce a working signer"
        );
    }
}

/// Negative 3 — a non-Ed25519 key version must be REJECTED at construction: MCP-RE
/// must never adopt a disallowed signing algorithm. Gated on its own env var so the
/// default lane stays runnable; provision an RSA/EC-P256 signing key once and point
/// `MCP_RE_GCP_KEY_VERSION_RSA` at it to exercise this.
#[test]
#[ignore = "requires a provisioned non-Ed25519 GCP key version (MCP_RE_GCP_KEY_VERSION_RSA)"]
fn gcp_kms_non_ed25519_key_rejected() {
    let Ok(rsa_version) = std::env::var("MCP_RE_GCP_KEY_VERSION_RSA") else {
        return; // not provisioned in this lane — skip without failing
    };
    require_env("MCP_RE_GCP_ACCESS_TOKEN");
    let config = GcpKmsConfig {
        key_version_name: rsa_version,
        endpoint: std::env::var("MCP_RE_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    // Tighten beyond `is_err()`: the rejection must be the ALGORITHM check
    // (Malformed naming EC_SIGN_ED25519), not an unrelated auth/path failure that
    // would also error — otherwise this test could pass for the wrong reason.
    match GcpKmsEd25519Backend::new(&config, false) {
        Ok(_) => panic!("a non-Ed25519 key version must be rejected at construction"),
        Err(KeyError::Malformed(msg)) => assert!(
            msg.contains("EC_SIGN_ED25519"),
            "expected an algorithm-rejection error naming EC_SIGN_ED25519, got: {msg}"
        ),
        Err(other) => panic!(
            "expected KeyError::Malformed (algorithm rejected), got {other:?} — \
             construction may have failed for an unrelated reason (auth/path), not the \
             non-Ed25519 algorithm check this test is meant to exercise"
        ),
    }
}
