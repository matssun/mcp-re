//! ADR-MCPS-034 (extends ADR-MCPS-030) — method-transparency behavioral
//! equivalence proof.
//!
//! MCP-S Core is **method-transparent**: it treats every MCP message as an
//! opaque signed payload and never branches on JSON-RPC `method` semantics for
//! an enforcement decision (ADR-MCPS-030). This test PROVES that property
//! behaviorally: it varies ONLY the `method` value across the real MCP methods
//! (`tools/list`, `tools/call`, `resources/list`, `prompts/list`) and a
//! fabricated, never-registered `x/nonexistent/custom`, and asserts the Core
//! verdict is IDENTICAL across all of them — once for an ACCEPTED envelope and
//! once (separately) for a REJECTED envelope.
//!
//! ## Why re-sign per method (and why that still proves transparency)
//!
//! The MCP-S signing preimage is the COMPLETE request object minus
//! `signature.value` and the trace-context keys (ADR-MCPS-026 / `signing.rs`):
//! `method` is IN signing scope and integrity-protected. A naive "swap the
//! method string on an already-signed envelope" would therefore break the
//! signature and trivially fail every case for the wrong reason (forgery), which
//! proves nothing about method-transparency.
//!
//! The correct, stronger proof is verdict PARITY across honestly re-signed
//! envelopes: for each method we build a fully valid signed request with that
//! method and run it through Core. If Core ignored method semantics, the verdict
//! is a pure function of (envelope validity + signature + policy), so it MUST be
//! the same for every method — and it is. The rejected family does the same with
//! a single injected defect (an expired window) held constant while only the
//! method varies, proving the method neither rescues nor worsens the verdict.
//! This is exactly ADR-MCPS-034's "equivalence, not mere acceptance of known
//! methods": even the fabricated `x/nonexistent/custom` rides the identical
//! verdict, which only holds because Core never reads `method` to decide.
//!
//! The verdict is reduced to a stable token: a signed response that verifies and
//! binds to its own request hash ⇒ `"accepted"`; otherwise the JSON-RPC error
//! object's frozen `mcps.*` code. The per-method request hashes differ (method
//! is signed), so we compare the Core DECISION, not response bytes.

use mcps_conformance::fixtures;
use mcps_core::request_hash;
use mcps_core::request_signing_preimage;
use mcps_core::verify_response;
use mcps_core::REQUEST_META_KEY;
use mcps_core::SIG_ALG_ED25519;
use mcps_core::VERSION_DRAFT_01;
use serde_json::json;
use serde_json::Value;

/// The methods whose verdict must be identical: the real MCP methods named in
/// the proposal plus a fabricated, never-registered method. Core must not branch
/// on any of them.
const METHODS: &[&str] = &[
    "tools/list",
    "tools/call",
    "resources/list",
    "prompts/list",
    "x/nonexistent/custom",
];

/// `now` 60s after the documented `issued_at` — inside the freshness window, so
/// a well-formed request is ACCEPTED on freshness grounds.
fn now_fresh() -> i64 {
    mcps_core::parse_rfc3339_utc(fixtures::ISSUED_AT).expect("parse issued_at") + 60
}

/// `now` well AFTER `expires_at` — the request is past its freshness window, so
/// a well-formed request is REJECTED as expired regardless of method.
fn now_expired() -> i64 {
    mcps_core::parse_rfc3339_utc(fixtures::EXPIRES_AT).expect("parse expires_at") + 3600
}

/// Build a fully-signed MCP-S request carrying `method`, re-signing the complete
/// object (method is in signing scope, ADR-MCPS-026). Only `method` and `nonce`
/// vary between calls; everything else is the documented canonical envelope, so
/// any verdict difference can only come from `method` — which is the property
/// under test.
fn signed_request_with_method(method: &str, nonce: &str) -> Vec<u8> {
    let mut request = json!({
        "id": "req-method-transparency",
        "jsonrpc": "2.0",
        "method": method,
        "params": {
            "name": "echo",
            "arguments": { "text": "method-transparency" },
            "_meta": {
                REQUEST_META_KEY: {
                    "version": VERSION_DRAFT_01,
                    "signer": fixtures::SIGNER,
                    "on_behalf_of": fixtures::ON_BEHALF_OF,
                    "audience": fixtures::AUDIENCE,
                    "authorization_hash": fixtures::AUTH_HASH,
                    "nonce": nonce,
                    "issued_at": fixtures::ISSUED_AT,
                    "expires_at": fixtures::EXPIRES_AT,
                    "signature": {
                        "alg": SIG_ALG_ED25519,
                        "key_id": fixtures::SIGNER_KEY_ID,
                    }
                }
            }
        }
    });

    let preimage = request_signing_preimage(&request).expect("request preimage");
    let signature = fixtures::signer_key().sign(&preimage);
    request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(signature);

    serde_json::to_vec(&request).expect("serialize signed request")
}

/// Reduce a server response to the Core verdict token, independent of method:
///   - a JSON-RPC error object ⇒ its frozen `mcps.*` `error.message`;
///   - a signed response that verifies AND binds to `expected_request_hash`
///     ⇒ `"accepted"`;
///   - a signed response that does not verify/bind ⇒ the `mcps.*` wire code.
/// Response bytes themselves differ per method (the request hash is signed); the
/// VERDICT must not.
fn verdict(response: &[u8], expected_request_hash: &str) -> String {
    let value: Value = serde_json::from_slice(response).expect("parse response");
    if let Some(message) = value.get("error").and_then(|e| e.get("message")) {
        return message
            .as_str()
            .expect("error.message is a string")
            .to_string();
    }
    match verify_response(
        response,
        &fixtures::response_resolver(),
        expected_request_hash,
    ) {
        Ok(_) => "accepted".to_string(),
        Err(err) => err.wire_code().to_string(),
    }
}

/// Run one signed request (built with `method`) through a FRESH documented echo
/// server (fresh replay cache, so the only varying input across the loop is the
/// method + nonce) and return the Core verdict token.
fn verdict_for_method(method: &str, nonce: &str, now_unix: i64) -> String {
    let server = fixtures::documented_echo_server();
    let request = signed_request_with_method(method, nonce);
    let expected_hash = {
        let value: Value = serde_json::from_slice(&request).expect("parse request");
        request_hash(&value).expect("request_hash")
    };
    let response = server.handle(&request, now_unix);
    verdict(&response, &expected_hash)
}

/// ACCEPTED family: a fully valid, in-window signed request yields the SAME
/// verdict (`"accepted"`) for every method, including the fabricated one. The
/// method neither helps nor hurts; the verdict is a function of the envelope.
#[test]
fn accepted_verdict_is_identical_across_all_methods() {
    let baseline = verdict_for_method(METHODS[0], "nonce-accepted-000000000001", now_fresh());
    assert_eq!(
        baseline, "accepted",
        "control: a valid in-window request must be accepted (got {baseline:?})"
    );

    for (i, method) in METHODS.iter().enumerate() {
        // Distinct nonce per method so each fresh-cache run is itself replay-clean;
        // the nonce is not the variable under test (the method is).
        let nonce = format!("nonce-accepted-{:024}", i + 2);
        let token = verdict_for_method(method, &nonce, now_fresh());
        assert_eq!(
            token, baseline,
            "Core verdict differs by method: '{method}' gave {token:?}, expected {baseline:?}. \
             MCP-S Core must be method-transparent (ADR-MCPS-030)."
        );
    }
}

/// REJECTED family: the SAME injected defect (an expired freshness window) held
/// constant while only the method varies yields the SAME rejection verdict for
/// every method. The method does not rescue (no method makes the expired request
/// pass) nor worsen (no method changes which `mcps.*` code is emitted).
#[test]
fn rejected_verdict_is_identical_across_all_methods() {
    let baseline = verdict_for_method(METHODS[0], "nonce-rejected-000000000001", now_expired());
    assert_eq!(
        baseline, "mcps.expired_request",
        "control: an expired request must be rejected as expired (got {baseline:?})"
    );

    for (i, method) in METHODS.iter().enumerate() {
        let nonce = format!("nonce-rejected-{:024}", i + 2);
        let token = verdict_for_method(method, &nonce, now_expired());
        assert_eq!(
            token, baseline,
            "Core rejection verdict differs by method: '{method}' gave {token:?}, \
             expected {baseline:?}. MCP-S Core must be method-transparent (ADR-MCPS-030)."
        );
    }
}

/// Anti-rubber-stamp: the verdict reducer and the two families actually
/// distinguish outcomes. If accepted and rejected collapsed to the same token,
/// the parity assertions above would be vacuous. Proves the two verdicts are
/// genuinely different while each is internally method-invariant.
#[test]
fn accepted_and_rejected_verdicts_are_distinct() {
    let accepted = verdict_for_method("tools/call", "nonce-distinct-accepted-0001", now_fresh());
    let rejected = verdict_for_method("tools/call", "nonce-distinct-rejected-0001", now_expired());
    assert_eq!(accepted, "accepted");
    assert_eq!(rejected, "mcps.expired_request");
    assert_ne!(
        accepted, rejected,
        "the accepted and rejected verdicts must be distinguishable, else parity is vacuous"
    );
}
