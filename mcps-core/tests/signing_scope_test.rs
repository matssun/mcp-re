// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-026 conformance: the signed/unsigned `_meta` partition (SEP-2575),
//! proven end-to-end through `verify_request`.
//!
//! The signer and verifier share one `signing_preimage`, so the exclusion of W3C
//! Trace Context keys (`traceparent` / `tracestate` / `baggage`) and the
//! inclusion of everything else (a per-request `protocolVersion`, unknown keys)
//! must agree. These vectors sign a real request carrying both a trace field and
//! a protocolVersion, then mutate each after signing:
//!
//! - mutating a trace field MUST still verify (it is out of signing scope);
//! - mutating `protocolVersion` MUST fail (`mcps.invalid_signature`) — it is in
//!   scope and therefore integrity-protected.

use mcps_core::error::McpsError;
use mcps_core::ids::REQUEST_META_KEY;
use mcps_core::request_signing_preimage;
use mcps_core::verify_request;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use serde_json::json;
use serde_json::Value;

const SIGNER_SEED: [u8; 32] = [1u8; 32];
const SIGNER_ID: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTHORIZATION_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const ISSUED_EPOCH: i64 = 1_779_998_400;
const SKEW: i64 = 30;
const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SIGNER_SEED)
}

fn config() -> VerificationConfig {
    VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: SKEW,
    }
}

fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER_ID, SIGNER_KEY_ID, signer_key().public_key());
    r
}

fn now() -> i64 {
    ISSUED_EPOCH + 60
}

/// A signed request carrying a `traceparent` (excluded) and a `protocolVersion`
/// (in scope) as peer keys alongside the MCP-S request envelope.
fn signed_request_with_trace_and_protocol() -> Value {
    let mut obj = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "text": "hi" },
            "_meta": {
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                "protocolVersion": "2026-07-28",
                REQUEST_META_KEY: {
                    "version": "draft-01",
                    "signer": SIGNER_ID,
                    "on_behalf_of": ON_BEHALF_OF,
                    "audience": AUDIENCE,
                    "authorization_hash": AUTHORIZATION_HASH,
                    "nonce": NONCE,
                    "issued_at": ISSUED_AT,
                    "expires_at": EXPIRES_AT,
                    "signature": { "alg": "Ed25519", "key_id": SIGNER_KEY_ID, "value": null }
                }
            }
        }
    });
    obj["params"]["_meta"][REQUEST_META_KEY]["signature"]
        .as_object_mut()
        .expect("sig obj")
        .remove("value");
    let preimage = request_signing_preimage(&obj).expect("preimage");
    let sig = signer_key().sign(&preimage);
    obj["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(sig);
    obj
}

fn raw(obj: &Value) -> Vec<u8> {
    serde_json::to_vec(obj).expect("serialize")
}

#[test]
fn baseline_request_with_trace_and_protocol_verifies() {
    let mut replay = InMemoryReplayCache::new(SKEW);
    let obj = signed_request_with_trace_and_protocol();
    assert!(verify_request(&raw(&obj), &resolver(), &mut replay, &config(), now()).is_ok());
}

#[test]
fn mutating_traceparent_after_signing_still_verifies() {
    // A tracing middle box rewrites traceparent in flight. Because it is out of
    // signing scope, the signature still verifies.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let mut obj = signed_request_with_trace_and_protocol();
    obj["params"]["_meta"]["traceparent"] =
        Value::String("00-1111111111111111111111111111111111-2222222222222222-01".into());
    assert!(
        verify_request(&raw(&obj), &resolver(), &mut replay, &config(), now()).is_ok(),
        "rewriting an out-of-scope trace field must not break verification"
    );
}

#[test]
fn mutating_protocol_version_after_signing_fails_verification() {
    // protocolVersion is in signing scope (ADR-026 rule 2): altering it after
    // signing is a downgrade attempt and MUST fail closed.
    let mut replay = InMemoryReplayCache::new(SKEW);
    let mut obj = signed_request_with_trace_and_protocol();
    obj["params"]["_meta"]["protocolVersion"] = Value::String("2025-06-18".into());
    assert_eq!(
        verify_request(&raw(&obj), &resolver(), &mut replay, &config(), now()),
        Err(McpsError::InvalidSignature)
    );
}
