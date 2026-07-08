//! Issue #71 (ADR-MCPS-023 Tier 3) — LB-signed, request-bound ingress assertion
//! wired into the proxy serving path.
//!
//! These are SERVE-LEVEL acceptance tests: they drive the SAME
//! `Proxy::handle_with_transport` entry point the production serve loop calls
//! (`main.rs` -> `tls::serve_once_with_assertion`), proving the Tier-3 assertion is
//! ENFORCED end-to-end — not merely that the unit verifier in `transport.rs` works.
//!
//! The proxy is built with `with_lb_assertion(..)` + the SAME `ExactMatchBinding`
//! the direct-TLS path uses, mirroring `main.rs`'s `BindingKind::LbAssertion` wiring.
//! An inner server records whether it was reached, so "rejected before dispatch" is
//! an observable, black-box fact (the inner is never called on a rejection).
//!
//! Coverage:
//!   * a valid assertion bound to THIS request's hash → inner reached, response
//!     returned (and the signed response verifies against the request hash);
//!   * a cross-request assertion (bound to a different request) → rejected;
//!   * a tampered assertion (mutated wire field) → rejected;
//!   * an unknown-LB-key assertion → rejected;
//!   * a stale assertion (outside the freshness window) → rejected;
//!   * a MISSING assertion header under LB mode → rejected;
//!   * the object-sig-before-binding invariant: a tampered object signature fails
//!     regardless of a perfectly valid assertion (object verify runs first).
//! Every rejection asserts the inner was NEVER reached.

use std::sync::Mutex;
use std::sync::Arc;

use mcp_re_core::b64url_encode;
use mcp_re_core::request_hash;
use mcp_re_core::verify_response;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_proxy::AttestedCertVerification;
use mcp_re_proxy::AttestedRevocation;
use mcp_re_proxy::ExactMatchBinding;
use mcp_re_proxy::IdentitySource;
use mcp_re_proxy::LbAssertion;
use mcp_re_proxy::LbAssertionBinding;
use mcp_re_proxy::LbAssertionV2;
use mcp_re_proxy::LbAssertionV2Binding;
use mcp_re_proxy::Proxy;
use mcp_re_proxy::TransportIdentity;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "spiffe://example.org/agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;
const LB_KEY_ID: &str = "lb-1";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn lb_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[7u8; 32])
}
fn now() -> i64 {
    mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}
fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

type Calls = Arc<Mutex<Vec<Value>>>;

/// A proxy wired EXACTLY as `main.rs` wires `BindingKind::LbAssertion`: the SAME
/// ExactMatchBinding plus the Tier-3 verifier trusting `lb_key` under `LB_KEY_ID`.
fn lb_proxy() -> (Proxy, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let calls_for_inner = Arc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.lock().unwrap().push(value);
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } })).unwrap()
    };
    let mut binding = LbAssertionBinding::new(IdentitySource::UriSan);
    binding.add_key(LB_KEY_ID, lb_key().public_key());
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_transport_binding(Box::new(ExactMatchBinding::new()))
    .with_lb_assertion(binding);
    (proxy, calls)
}

fn signed_request(nonce: &str) -> Vec<u8> {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": "hello" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs")
}

/// The `request_hash` the proxy will bind against — derived from the SAME canonical
/// request the proxy verifies (signature.value is excluded from the hash preimage,
/// so signing does not perturb it). Mirrors `proxy.rs`'s `expected_request_hash`.
fn request_hash_of(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse signed request");
    request_hash(&value).expect("request_hash")
}

/// Mint a Tier-3 assertion the SAME way an LB would (and the SAME way the
/// `transport.rs` unit tests do): length-prefixed canonical preimage signed by the
/// LB key, then the five-field base64url wire form.
fn mint_assertion(
    lb: &SigningKey,
    key_id: &str,
    identity: &str,
    bound_request_hash: &str,
    validation_time: i64,
) -> String {
    let assertion = LbAssertion {
        key_id: key_id.to_string(),
        asserted_client_identity: identity.to_string(),
        request_hash: bound_request_hash.to_string(),
        validation_time,
    };
    let signature = lb.sign(&assertion.signing_preimage());
    format!(
        "{}.{}.{}.{}.{}",
        b64url_encode(key_id.as_bytes()),
        b64url_encode(identity.as_bytes()),
        b64url_encode(bound_request_hash.as_bytes()),
        b64url_encode(&validation_time.to_be_bytes()),
        signature,
    )
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"]
        .as_str()
        .expect("message")
        .to_string()
}

// ---- happy path: a valid, request-bound assertion reaches the inner ----

#[test]
fn valid_request_bound_assertion_reaches_inner_and_response_verifies() {
    let (proxy, calls) = lb_proxy();
    let nonce = "nonce-lb-ok-1";
    let req = signed_request(nonce);
    let rh = request_hash_of(&req);
    // The asserted client identity equals the request signer so ExactMatchBinding
    // admits it (the assertion SUPPLIES the verified identity the policy checks).
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, now());

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 1, "a valid request-bound assertion must reach the inner");
    // The returned envelope is a real signed, request-bound response.
    verify_response(&response, &server_resolver(), &rh)
        .expect("the response must be a signed, request-bound envelope");
}

// ---- rejections: each must be BEFORE dispatch (inner never reached) ----

#[test]
fn cross_request_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-cross-1");
    // The assertion is validly signed but bound to a DIFFERENT request's hash.
    let other_hash = request_hash_of(&signed_request("nonce-lb-cross-OTHER"));
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &other_hash, now());

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 0, "a cross-request assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn tampered_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-tamper-1");
    let rh = request_hash_of(&req);
    let valid = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, now());
    // Flip the last character of the wire form (the signature field) — the Ed25519
    // signature no longer verifies under the LB key.
    let mut tampered = valid.clone();
    let last = tampered.pop().expect("non-empty assertion");
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    let response = proxy.handle_with_transport(&req, now(), None, Some(&tampered));

    assert_eq!(calls.lock().unwrap().len(), 0, "a tampered assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn unknown_lb_key_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-unknown-1");
    let rh = request_hash_of(&req);
    // Signed by an UNTRUSTED LB key id the proxy does not know.
    let rogue = SigningKey::from_seed_bytes(&[9u8; 32]);
    let assertion = mint_assertion(&rogue, "lb-rogue", SIGNER, &rh, now());

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 0, "an unknown-key assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn stale_assertion_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-stale-1");
    let rh = request_hash_of(&req);
    // validation_time far in the past relative to `now()` (default window 30s).
    let stale_time = now() - (mcp_re_proxy::DEFAULT_LB_ASSERTION_MAX_AGE_SECS + 60);
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, stale_time);

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 0, "a stale assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn missing_assertion_header_under_lb_mode_is_rejected_before_dispatch() {
    let (proxy, calls) = lb_proxy();
    let req = signed_request("nonce-lb-missing-1");
    // No assertion header presented while the LB verifier is configured.
    let response = proxy.handle_with_transport(&req, now(), None, None);

    assert_eq!(calls.lock().unwrap().len(), 0, "a missing assertion header must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

// ---- core invariant: object signature is verified BEFORE the assertion binding ----

#[test]
fn tampered_object_signature_fails_regardless_of_a_valid_assertion() {
    // No transport downgrade: object verification runs first and fails closed, so a
    // perfectly valid request-bound assertion can NEVER rescue a tampered object
    // signature. The inner is never reached and the failure is the SIGNATURE error,
    // not the transport-binding one — proving the ordering.
    let (proxy, calls) = lb_proxy();
    let nonce = "nonce-lb-objtamper-1";
    let req = signed_request(nonce);
    // The assertion is bound to the ORIGINAL request's hash and is fully valid.
    let rh = request_hash_of(&req);
    let assertion = mint_assertion(&lb_key(), LB_KEY_ID, SIGNER, &rh, now());

    // Tamper a signed field AFTER minting the assertion; the object signature no
    // longer matches (and the hash now differs too, but object verify fails first).
    let mut value: Value = serde_json::from_slice(&req).expect("parse signed request");
    value["params"]["arguments"]["text"] = Value::String("tampered".to_string());
    let tampered = serde_json::to_vec(&value).expect("reserialize");

    let response = proxy.handle_with_transport(&tampered, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 0, "a tampered object must never reach the inner");
    assert_eq!(
        error_message(&response),
        "mcp-re.invalid_signature",
        "object-signature verification must fail BEFORE the assertion binding is consulted"
    );
}

// ===========================================================================
// ADR-MCPS-023 §C (v0.10) Mode C attested ingress — offline evidence spine
// (MCPS-62). Node-side rejection of the v2 assertion for each negative fact,
// draft-02 preimage invariance vs Mode A, and Mode-B demotion.
// ===========================================================================

const INGRESS_ID: &str = "spiffe://example.org/ingress-attestor-1";
const ATTESTOR_KEY_ID: &str = "attestor-1";

/// The ingress-attestor signing key (distinct seed from the v1 `lb_key`).
fn attestor_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}

/// A proxy wired EXACTLY as `main.rs` wires `BindingKind::AttestedIngress`: the
/// SAME ExactMatchBinding plus the v2 verifier trusting `attestor_key` under
/// `ATTESTOR_KEY_ID`, the node audience `AUDIENCE`, and the trusted `INGRESS_ID`.
fn attested_ingress_proxy() -> (Proxy, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let calls_for_inner = Arc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.lock().unwrap().push(value);
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } })).unwrap()
    };
    let mut binding = LbAssertionV2Binding::new(IdentitySource::UriSan, AUDIENCE);
    binding.add_key(ATTESTOR_KEY_ID, attestor_key().public_key());
    binding.permit_ingress_identity(INGRESS_ID);
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_transport_binding(Box::new(ExactMatchBinding::new()))
    .with_attested_ingress(binding);
    (proxy, calls)
}

/// A canonical valid v2 assertion for `bound_request_hash`: delegated client =
/// `SIGNER` (so ExactMatchBinding admits it), audience = `AUDIENCE`, ingress =
/// `INGRESS_ID`, cert Verified, revocation Good.
fn v2_valid(bound_request_hash: &str) -> LbAssertionV2 {
    LbAssertionV2 {
        key_id: ATTESTOR_KEY_ID.to_string(),
        ingress_identity: INGRESS_ID.to_string(),
        asserted_client_identity: SIGNER.to_string(),
        request_hash: bound_request_hash.to_string(),
        audience: AUDIENCE.to_string(),
        cert_verification_result: AttestedCertVerification::Verified,
        revocation_result: AttestedRevocation::Good,
        validation_time: now(),
        crl_next_update: now() + 86_400,
        expires_at: None,
    }
}

/// Sign `assertion` with the trusted attestor key and render the v2 wire form.
fn mint_v2(assertion: &LbAssertionV2) -> String {
    assertion.to_wire(&attestor_key().sign(&assertion.signing_preimage()))
}

// ---- happy path ----

#[test]
fn mode_c_valid_assertion_reaches_inner_and_response_verifies() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-ok-1");
    let rh = request_hash_of(&req);
    let assertion = mint_v2(&v2_valid(&rh));

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 1, "a valid Mode-C assertion must reach the inner");
    verify_response(&response, &server_resolver(), &rh)
        .expect("the response must be a signed, request-bound envelope");
}

// ---- node-side rejection of each negative asserted fact (ADR §Conformance) ----

#[test]
fn mode_c_revoked_is_rejected_before_dispatch() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-revoked-1");
    let rh = request_hash_of(&req);
    let mut a = v2_valid(&rh);
    a.revocation_result = AttestedRevocation::Revoked;

    let response = proxy.handle_with_transport(&req, now(), None, Some(&mint_v2(&a)));

    assert_eq!(calls.lock().unwrap().len(), 0, "a revoked-cert assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_stale_crl_freshness_is_rejected_before_dispatch() {
    // The attestor's own CRL was stale (past nextUpdate) — surfaced as an explicit
    // StaleCrl verdict. The node fails closed WITHOUT itself doing CRL math (§C3).
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-stalecrl-1");
    let rh = request_hash_of(&req);
    let mut a = v2_valid(&rh);
    a.revocation_result = AttestedRevocation::StaleCrl;

    let response = proxy.handle_with_transport(&req, now(), None, Some(&mint_v2(&a)));

    assert_eq!(calls.lock().unwrap().len(), 0, "a stale-CRL assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_bad_signature_is_rejected_before_dispatch() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-badsig-1");
    let rh = request_hash_of(&req);
    // Signed by an UNTRUSTED attestor key: the trusted key id, wrong signer.
    let rogue = SigningKey::from_seed_bytes(&[123u8; 32]);
    let a = v2_valid(&rh);
    let forged = a.to_wire(&rogue.sign(&a.signing_preimage()));

    let response = proxy.handle_with_transport(&req, now(), None, Some(&forged));

    assert_eq!(calls.lock().unwrap().len(), 0, "a bad-signature assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_cross_request_hash_is_rejected_before_dispatch() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-cross-1");
    // Bound to a DIFFERENT request's hash.
    let other = request_hash_of(&signed_request("nonce-c-cross-OTHER"));
    let assertion = mint_v2(&v2_valid(&other));

    let response = proxy.handle_with_transport(&req, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 0, "a cross-request assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_untrusted_ingress_identity_is_rejected_before_dispatch() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-rogueingress-1");
    let rh = request_hash_of(&req);
    let mut a = v2_valid(&rh);
    a.ingress_identity = "spiffe://example.org/rogue-ingress".to_string();

    let response = proxy.handle_with_transport(&req, now(), None, Some(&mint_v2(&a)));

    assert_eq!(calls.lock().unwrap().len(), 0, "an untrusted-ingress assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_audience_mismatch_is_rejected_before_dispatch() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-aud-1");
    let rh = request_hash_of(&req);
    let mut a = v2_valid(&rh);
    a.audience = "did:example:some-other-server".to_string();

    let response = proxy.handle_with_transport(&req, now(), None, Some(&mint_v2(&a)));

    assert_eq!(calls.lock().unwrap().len(), 0, "an audience-mismatch assertion must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_missing_assertion_header_is_rejected_before_dispatch() {
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-missing-1");
    // No assertion header while the Mode-C verifier requires it (assertion-required).
    let response = proxy.handle_with_transport(&req, now(), None, None);

    assert_eq!(calls.lock().unwrap().len(), 0, "a missing assertion header must not reach the inner");
    assert_eq!(error_message(&response), "mcp-re.transport_binding_failed");
}

#[test]
fn mode_c_object_signature_fails_regardless_of_a_valid_assertion() {
    // Object verification runs first: a valid Mode-C assertion can never rescue a
    // tampered object signature, and the failure is the SIGNATURE error.
    let (proxy, calls) = attested_ingress_proxy();
    let req = signed_request("nonce-c-objtamper-1");
    let rh = request_hash_of(&req);
    let assertion = mint_v2(&v2_valid(&rh));
    let mut value: Value = serde_json::from_slice(&req).expect("parse");
    value["params"]["arguments"]["text"] = Value::String("tampered".to_string());
    let tampered = serde_json::to_vec(&value).expect("reserialize");

    let response = proxy.handle_with_transport(&tampered, now(), None, Some(&assertion));

    assert_eq!(calls.lock().unwrap().len(), 0, "a tampered object must never reach the inner");
    assert_eq!(error_message(&response), "mcp-re.invalid_signature");
}

// ---- draft-02 preimage invariance: C-only facts ride the assertion ----

#[test]
fn mode_c_forwarded_request_is_byte_identical_to_mode_a() {
    // The request the inner receives under Mode C must be BYTE-IDENTICAL to the one
    // it receives under Mode A (end_to_end_mtls / exact) for the same signed request:
    // Mode-C facts ride the v2 assertion, never the forwarded draft-02 request
    // preimage. The inner strips the MCP-RE envelope identically in both modes.
    let captured_a: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_c: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    let req = signed_request("nonce-c-invariance-1");
    let rh = request_hash_of(&req);

    // Mode A: exact binding, identity supplied at the connection seam.
    {
        let cap = Arc::clone(&captured_a);
        let inner = move |request: &[u8]| -> Vec<u8> {
            *cap.lock().unwrap() = Some(request.to_vec());
            let value: Value = serde_json::from_slice(request).expect("parse");
            let id = value.get("id").cloned().unwrap_or(Value::Null);
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": {} })).unwrap()
        };
        let proxy = Proxy::new(
            server_key(), SERVER, SERVER_KEY_ID, Box::new(resolver()), AUDIENCE, SKEW,
            Box::new(inner),
        )
        .with_transport_binding(Box::new(ExactMatchBinding::new()));
        let identity = TransportIdentity::new(SIGNER, IdentitySource::UriSan);
        let _ = proxy.handle_with_transport(&req, now(), Some(&identity), None);
    }

    // Mode C: attested ingress, identity from the v2 assertion.
    {
        let cap = Arc::clone(&captured_c);
        let inner = move |request: &[u8]| -> Vec<u8> {
            *cap.lock().unwrap() = Some(request.to_vec());
            let value: Value = serde_json::from_slice(request).expect("parse");
            let id = value.get("id").cloned().unwrap_or(Value::Null);
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": {} })).unwrap()
        };
        let mut binding = LbAssertionV2Binding::new(IdentitySource::UriSan, AUDIENCE);
        binding.add_key(ATTESTOR_KEY_ID, attestor_key().public_key());
        binding.permit_ingress_identity(INGRESS_ID);
        let proxy = Proxy::new(
            server_key(), SERVER, SERVER_KEY_ID, Box::new(resolver()), AUDIENCE, SKEW,
            Box::new(inner),
        )
        .with_transport_binding(Box::new(ExactMatchBinding::new()))
        .with_attested_ingress(binding);
        let _ = proxy.handle_with_transport(&req, now(), None, Some(&mint_v2(&v2_valid(&rh))));
    }

    let a = captured_a.lock().unwrap().clone().expect("Mode A forwarded a request");
    let c = captured_c.lock().unwrap().clone().expect("Mode C forwarded a request");
    assert_eq!(
        a, c,
        "the forwarded draft-02 request preimage under Mode C must be byte-identical \
         to Mode A — C-only facts ride the assertion, never the request"
    );
}
