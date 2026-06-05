//! Black-box end-to-end test for the PKCS#11-backed response signer (issue
//! #4034), exercised against an INDEPENDENT SoftHSM2 token.
//!
//! This proves the real device path: open a token, sign a preimage with the
//! Ed25519 key that NEVER leaves the token (`CKM_EDDSA` / `C_Sign`), then verify
//! the returned signature against the token's exported public key using
//! `mcps_core`'s ordinary verifier — exactly what a relying party does. It also
//! proves a tampered preimage does NOT verify.
//!
//! # Environment gating
//! The test runs ONLY when `MCPS_TEST_PKCS11_MODULE` is set; otherwise it prints
//! a skip notice and returns success (not every environment has SoftHSM2
//! provisioned, and this build does not bundle a token). When run, it reads:
//!   * `MCPS_TEST_PKCS11_MODULE`      — path to the PKCS#11 provider module
//!     (e.g. `/usr/lib/softhsm/libsofthsm2.so` or
//!     `/opt/homebrew/lib/softhsm/libsofthsm2.so`).
//!   * `MCPS_TEST_PKCS11_PIN`         — the token User PIN.
//!   * `MCPS_TEST_PKCS11_TOKEN_LABEL` — the token label.
//!   * `MCPS_TEST_PKCS11_KEY_LABEL`   — the CKA_LABEL of the Ed25519 key pair.
//!
//! # Provisioning a test token (run once by a human / CI, NOT by this test)
//! ```sh
//! # 1. Point SoftHSM2 at a scratch token directory (so this never touches a
//! #    host/production token store):
//! export SOFTHSM2_CONF="$PWD/softhsm2.conf"
//! mkdir -p "$PWD/softhsm-tokens"
//! printf 'directories.tokendir = %s/softhsm-tokens\n' "$PWD" > "$SOFTHSM2_CONF"
//!
//! # 2. Initialise a fresh token:
//! softhsm2-util --init-token --free \
//!     --label mcps-test --so-pin 0000 --pin 1234
//!
//! # 3. Generate an Ed25519 key pair ON the token (private key non-extractable),
//! #    labelled so the key source can find it. Using pkcs11-tool (OpenSC):
//! softhsm2-util --show-slots   # note the assigned slot id, e.g. 12345
//! pkcs11-tool --module "$MCPS_TEST_PKCS11_MODULE" \
//!     --login --pin 1234 --slot <SLOT_ID> \
//!     --keypairgen --key-type EC:edwards25519 \
//!     --label mcps-response-signing --id 01
//!
//! # 4. Export the env vars this test reads:
//! export MCPS_TEST_PKCS11_MODULE="$MCPS_TEST_PKCS11_MODULE"
//! export MCPS_TEST_PKCS11_PIN=1234
//! export MCPS_TEST_PKCS11_TOKEN_LABEL=mcps-test
//! export MCPS_TEST_PKCS11_KEY_LABEL=mcps-response-signing
//!
//! # 5. Run the feature-gated test:
//! cargo test -p mcps-proxy --features pkcs11_keysource \
//!     --test pkcs11_keysource_e2e_test
//! ```
//! SoftHSM2 is an INDEPENDENT software token; nothing here references any host
//! security system.
#![cfg(feature = "pkcs11_keysource")]

use mcps_core::verify_ed25519_with;
use mcps_core::McpsError;
use mcps_proxy::Pkcs11KeySource;
use mcps_proxy::ResponseSigner;

/// Read all four env vars; `None` (skip) unless `MCPS_TEST_PKCS11_MODULE` is set.
/// The other three default to the values used by the provisioning recipe above so
/// a minimal `MCPS_TEST_PKCS11_MODULE=... cargo test` works against a token built
/// with those labels/PIN.
fn pkcs11_env() -> Option<(String, String, String, String)> {
    let Ok(module) = std::env::var("MCPS_TEST_PKCS11_MODULE") else {
        if std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
            panic!(
                "MCPS_REQUIRE_LIVE_INFRA is set but MCPS_TEST_PKCS11_MODULE is unavailable \
                 — this live e2e MUST run under CI, not skip"
            );
        }
        return None;
    };
    let pin = std::env::var("MCPS_TEST_PKCS11_PIN").unwrap_or_else(|_| "1234".to_string());
    let token_label =
        std::env::var("MCPS_TEST_PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "mcps-test".to_string());
    let key_label = std::env::var("MCPS_TEST_PKCS11_KEY_LABEL")
        .unwrap_or_else(|_| "mcps-response-signing".to_string());
    Some((module, pin, token_label, key_label))
}

/// The TLS material paths are not exercised by this signing test (the token
/// custodies only the response-signing key), but `Pkcs11KeySource::open` takes
/// them; point them at this crate's own `Cargo.toml` (a file that always exists)
/// so `open` does not need real TLS fixtures. The TLS accessors are NOT called
/// here, so the file contents are never parsed.
const PLACEHOLDER_TLS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

#[test]
fn pkcs11_sign_verifies_against_token_public_key() {
    let Some((module, pin, token_label, key_label)) = pkcs11_env() else {
        eprintln!(
            "SKIP pkcs11_sign_verifies_against_token_public_key: \
             MCPS_TEST_PKCS11_MODULE is unset (no SoftHSM2 token provisioned). \
             See this test's module doc for softhsm2-util provisioning commands."
        );
        return;
    };

    let source = Pkcs11KeySource::open(
        &module,
        &pin,
        &token_label,
        &key_label,
        PLACEHOLDER_TLS_PATH,
        PLACEHOLDER_TLS_PATH,
        PLACEHOLDER_TLS_PATH,
    )
    .expect("open PKCS#11 token + locate Ed25519 key");

    let preimage = b"test-preimage-mcps-4034-pkcs11-response-signing";
    let signature = source
        .sign_response(preimage)
        .expect("sign_response over the token (CKM_EDDSA)");
    let public_key = source
        .response_public_key()
        .expect("read the token's exported Ed25519 public key");

    // A signature produced ON the token must verify under its exported public key
    // using the SAME verifier a relying party uses.
    verify_ed25519_with(
        preimage,
        &signature,
        &public_key,
        McpsError::ResponseSigInvalid,
    )
    .expect("token signature must verify under the token's public key");

    // Negative: a tampered preimage must NOT verify under the same signature.
    let tampered = b"test-preimage-mcps-4034-pkcs11-response-signing-XXX";
    let tampered_result = verify_ed25519_with(
        tampered,
        &signature,
        &public_key,
        McpsError::ResponseSigInvalid,
    );
    assert!(
        tampered_result.is_err(),
        "a tampered preimage must NOT verify under the token signature"
    );
}
