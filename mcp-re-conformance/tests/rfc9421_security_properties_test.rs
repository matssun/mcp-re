// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 security-property witnesses for the §A capability-claim matrix
//! (ADR-MCPS-036 gate item 1; ADR-MCPRE-050 sole carrier).
//!
//! Each named test here is the green traceability witness for one §A capability on
//! the RFC 9421 + RFC 9530 carrier — message authenticity, integrity, audience
//! binding, authorization binding, freshness, replay, trust resolution, key
//! admission, transport binding, response binding, and verified-context authorship.
//! Every property is proven through `verify_request_full` /
//! `verify_response_bound_full` and the RFC 9421 request evidence block on the HTTP
//! message.

use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::verify_response_bound_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_core::SigningKey;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_KEY_ID: &str = "server-key-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}
fn client_identity() -> ActorIdentity {
    ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:host-a".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
}
fn server_identity() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server-1".into(),
        keyid: SERVER_KEY_ID.into(),
    }
}
fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}
/// The trust seam: client key for the Request slot, server key for the Response
/// slot. An unknown keyid or a key presented on the wrong slot resolves to `None`.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + Clone {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: client_identity(),
            verification_key: client_key().public_key(),
            slot,
        }),
        (SERVER_KEY_ID, SignerSlot::Response) => Some(ResolvedActor {
            identity: server_identity(),
            verification_key: server_key().public_key(),
            slot,
        }),
        _ => None,
    }
}
fn block() -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
    }
}
fn base_request(body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: body.to_vec(),
    }
}
fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}
const CALL: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

/// Sign a request and return (request, evidence).
fn signed(nonce: &str, body: &[u8]) -> (HttpRequest, mcp_re_http_profile::RequestEvidence) {
    let mut req = base_request(body);
    let ev = sign_request_full(&mut req, &block(), &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
        .expect("sign");
    (req, ev)
}

// ---- §A: Message authenticity ------------------------------------------------
#[test]
fn tampered_request_body_is_rejected() {
    let (mut req, _) = signed("n-auth", CALL);
    // Control: the untampered request verifies.
    verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).expect("control verifies");
    // Tamper the body AFTER signing → Content-Digest / signature must reject.
    req.body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"WRITE"}}"#.to_vec();
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).is_err(),
        "a tampered request body must be rejected"
    );
}

// ---- §A: Integrity (body + id) ----------------------------------------------
#[test]
fn mutated_payload_is_rejected() {
    let (mut req, _) = signed("n-int", CALL);
    // Mutate the JSON-RPC id (inside the signed body) → rejected.
    req.body = br#"{"jsonrpc":"2.0","id":999,"method":"tools/call","params":{"name":"read"}}"#.to_vec();
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).is_err(),
        "a mutated JSON-RPC id in the signed payload must be rejected"
    );
}

// ---- §A: Audience binding ----------------------------------------------------
#[test]
fn wrong_audience_is_rejected() {
    let (req, _) = signed("n-aud", CALL);
    let wrong = AudienceTuple {
        audience_id: "verifier-OTHER".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    };
    assert!(
        verify_request_full(&req, &wrong, &no_material(), &resolver(), NOW).is_err(),
        "a request bound to a different audience must be rejected"
    );
}

// ---- §A: Delegation / authorization binding ---------------------------------
#[test]
fn authorization_artifact_binding_is_bound_and_verified() {
    let (req, _) = signed("n-authz", CALL);
    let verified =
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).expect("verifies");
    let bindings = &verified.request_block.expect("block").artifact_bindings;
    assert!(!bindings.is_empty(), "the request carries a bound authorization artifact");
    assert_eq!(bindings[0].artifact_type, ArtifactType::OauthDpop);
}

// ---- §A: Freshness -----------------------------------------------------------
/// The freshness window is widened by the verifier policy's bounded clock-skew
/// tolerance (#415 rev 2 §5.1), so "expired" means past `expires` + that bound —
/// not past `expires` alone. Both edges are pinned below.
const SKEW: i64 = mcp_re_http_profile::VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW;

#[test]
fn expired_request_is_rejected() {
    let (req, _) = signed("n-fresh", CALL);
    // Verify past `expires` AND past the tolerated skew → stale-window rejection.
    assert!(
        verify_request_full(
            &req,
            &audience(),
            &no_material(),
            &resolver(),
            EXPIRES + SKEW + 10
        )
        .is_err(),
        "a request beyond its freshness window plus the skew bound must be rejected"
    );
}

/// Skew is a bounded tolerance for honest clock disagreement, not a policy
/// escape: just inside the bound is accepted, just outside is not. This pins the
/// tolerance as a real, tested edge rather than an unexercised default.
#[test]
fn request_within_the_skew_bound_is_accepted_but_beyond_it_is_not() {
    let (req, _) = signed("n-skew", CALL);
    assert!(
        verify_request_full(
            &req,
            &audience(),
            &no_material(),
            &resolver(),
            EXPIRES + SKEW - 1
        )
        .is_ok(),
        "within the declared skew bound, a just-expired request is honest clock drift"
    );
    assert!(
        verify_request_full(
            &req,
            &audience(),
            &no_material(),
            &resolver(),
            EXPIRES + SKEW + 1
        )
        .is_err(),
        "one second past the bound, the tolerance is exhausted and it fails closed"
    );
}

/// The symmetric edge: a `created` slightly in the FUTURE is the same honest
/// clock disagreement and gets the same bounded tolerance.
#[test]
fn future_dated_request_within_the_skew_bound_is_accepted() {
    let (req, _) = signed("n-future", CALL);
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &resolver(), CREATED - SKEW + 1)
            .is_ok(),
        "a slightly future-dated request is tolerated within the bound"
    );
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &resolver(), CREATED - SKEW - 1)
            .is_err(),
        "beyond the bound, a future-dated request fails closed"
    );
}

/// The strict-production tier (skew = 0) restores exact-time semantics through
/// the same seam — the policy is the only thing that moved.
#[test]
fn strict_tier_policy_restores_exact_freshness() {
    use mcp_re_http_profile::verify_request_with_policy;
    use mcp_re_http_profile::VerifierPolicy;
    let (req, _) = signed("n-strict", CALL);
    let strict = VerifierPolicy::new(&["ed25519"], 0).expect("strict tier is a valid bound");
    assert!(
        verify_request_with_policy(&req, &resolver(), &strict, EXPIRES).is_err(),
        "at skew 0 the window closes exactly at `expires`"
    );
    assert!(
        verify_request_with_policy(&req, &resolver(), &strict, EXPIRES - 1).is_ok(),
        "and remains open right up to it"
    );
}

// ---- §A: Replay resistance ---------------------------------------------------
#[test]
fn replayed_request_is_rejected_by_the_replay_tier() {
    use mcp_re_core::InMemoryReplayCache;
    use mcp_re_core::ReplayDecision;
    let (req, _) = signed("n-replay", CALL);
    let verified =
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).expect("verifies");
    let key = mcp_re_http_profile::prepare_http_dispatch(&verified, None)
        .expect("dispatch prep")
        .0;
    let cache = InMemoryReplayCache::new(0);
    assert_eq!(key.check_and_insert(&cache, EXPIRES).unwrap(), ReplayDecision::Fresh);
    assert_eq!(
        key.check_and_insert(&cache, EXPIRES).unwrap(),
        ReplayDecision::Replay,
        "a second submission of the same nonce is a replay"
    );
}

// ---- §A: Revocation / trust propagation -------------------------------------
#[test]
fn untrusted_signer_key_is_rejected() {
    // A resolver that trusts NO request key → actor_binding_failed.
    let empty = |_k: &str, _s: SignerSlot| None;
    let (req, _) = signed("n-revoke", CALL);
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &empty, NOW).is_err(),
        "a signer key not in the authorized set must fail closed"
    );
}

// ---- §A: Key custody / blast radius -----------------------------------------
#[test]
fn unauthorized_key_id_is_rejected() {
    // Sign with the client key but present a keyid the resolver does not admit.
    let mut req = base_request(CALL);
    sign_request_full(&mut req, &block(), &client_key(), "unknown-key-99", CREATED, EXPIRES, "n-key")
        .expect("sign");
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).is_err(),
        "a keyid outside the admitted set must be rejected"
    );
}

// ---- §A: Ingress / transport binding ----------------------------------------
#[test]
fn transport_identity_binds_to_the_request_actor() {
    // The verified request actor id is the stable identity a transport binding ties
    // the channel identity to (proxy Mode-A ExactMatch binds `resolved_actor.actor_id()`).
    let (req, _) = signed("n-ingress", CALL);
    let verified =
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).expect("verifies");
    assert_eq!(
        verified.resolved_actor.identity.keyid, CLIENT_KEY_ID,
        "the verified request actor is the identity a transport binding checks the channel against"
    );
}

// ---- §A: Response binding ----------------------------------------------------
#[test]
fn response_bound_to_the_wrong_request_is_rejected() {
    let (req_a, ev_a) = signed("n-respA", CALL);
    let (req_b, _ev_b) = signed("n-respB", br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list"}}"#);
    let verified_b =
        verify_request_full(&req_b, &audience(), &no_material(), &resolver(), NOW).expect("verifies B");
    // Sign a response bound to request B.
    let mut resp = HttpResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response_full(&mut resp, &req_b, &verified_b.evidence, &server_identity(), &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("sign response for B");
    // The client that sent request A must NOT accept a response bound to B.
    assert!(
        verify_response_bound_full(&resp, &req_a, &ev_a, &resolver(), NOW).is_err(),
        "a response bound to the WRONG request must be rejected"
    );
}

// ---- §A: Verified security context ------------------------------------------
#[test]
fn caller_supplied_proxy_meta_is_not_the_signed_authority() {
    // The signed request evidence block is authored by the client core and covered by
    // Content-Digest; a caller cannot pre-seed a DIFFERENT top-level _meta and have it
    // survive as signed evidence — verify recomputes the digest over the signed body.
    let (mut req, _) = signed("n-ctx", CALL);
    // Inject a forged top-level _meta AFTER signing → digest mismatch, rejected.
    req.body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"},"_meta":{"forged":true}}"#.to_vec();
    assert!(
        verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW).is_err(),
        "a caller-injected _meta not covered by the signature must be rejected"
    );
}
