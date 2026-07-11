// SPDX-License-Identifier: Apache-2.0
//! Seed Work Item 3 — the minimal standards-profile proof path with its
//! negative battery: request roundtrip, response roundtrip bound to the
//! request, then body tamper, response splice, wrong content-digest, missing
//! covered component, stale window, wrong keyid, foreign tag, and
//! content-encoding rejection. All negatives assert the typed fail-closed
//! error, not printed diagnostics (S8).

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_response;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::verify_response;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const CLIENT2_SEED: [u8; 32] = [33u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

fn client2_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT2_SEED)
}

/// The trust seam (MCPRE-100): resolves a keyid to a resolved actor identity —
/// role authorization is decided HERE, per signing slot. `client-key-1` and
/// `client-key-2` are trusted only for the Request slot; `server-key-1` only for
/// the Response slot. A keyid presented in the wrong slot resolves to `None`,
/// exactly like an unknown keyid.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            ("client-key-1", SignerSlot::Request) => ("client", client_key()),
            ("client-key-2", SignerSlot::Request) => ("client", client2_key()),
            ("server-key-1", SignerSlot::Response) => ("server", server_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
    }
}

fn request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp?route=a".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    }
}

fn signed_request() -> HttpRequest {
    let mut req = request();
    sign_request(
        &mut req,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("signing succeeds");
    req
}

fn signed_exchange() -> (HttpRequest, HttpResponse) {
    let req = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(
        &mut rsp,
        &req,
        &server_key(),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("response signing succeeds");
    (req, rsp)
}

// ---------- positive paths -------------------------------------------------

#[test]
fn request_roundtrip_verifies_and_yields_split_form_evidence() {
    let req = signed_request();
    let verified = verify_request(&req, &resolver(), NOW).expect("verifies");
    assert_eq!(verified.evidence.digest_alg, "sha256");
    assert_eq!(verified.nonce, "nonce-1");
    assert_eq!(verified.key_id, "client-key-1");
}

#[test]
fn signer_and_verifier_derive_the_same_evidence_handle() {
    let mut req = request();
    let signer_evidence = sign_request(
        &mut req,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("signing succeeds");
    let verified = verify_request(&req, &resolver(), NOW).expect("verifies");
    assert_eq!(signer_evidence, verified.evidence);
}

#[test]
fn response_roundtrip_bound_to_request_verifies() {
    let (req, rsp) = signed_exchange();
    verify_response(&rsp, &req, &resolver(), NOW).expect("response verifies");
}

#[test]
fn authorization_header_is_covered_when_present() {
    let mut req = request();
    req.headers
        .push(("Authorization".into(), "Bearer token-abc".into()));
    sign_request(
        &mut req,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "n",
    )
    .expect("signing succeeds");
    verify_request(&req, &resolver(), NOW).expect("verifies with authorization covered");

    // Tampering with the bearer token after signing must break the signature.
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("authorization") {
            h.1 = "Bearer token-EVIL".into();
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::InvalidSignature);
}

// ---------- the seed's negative battery ------------------------------------

#[test]
fn body_tamper_fails_closed() {
    let mut req = signed_request();
    req.body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm"}}"#.to_vec();
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ContentDigestMismatch);
    // MCPRE-92: a content-digest mismatch is its own precise code now, no
    // longer folded onto invalid_signature.
    assert_eq!(err.wire_code(), "mcp-re.digest_mismatch");
}

#[test]
fn response_splice_fails_closed() {
    // Two independent exchanges; splice exchange B's response onto request A.
    let (req_a, _rsp_a) = signed_exchange();
    let mut req_b = request();
    req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
    sign_request(
        &mut req_b,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-2",
    )
    .expect("signing succeeds");
    let mut rsp_b = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(
        &mut rsp_b,
        &req_b,
        &server_key(),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("response signing succeeds");

    // rsp_b verifies against its own request but MUST NOT verify against req_a:
    verify_response(&rsp_b, &req_b, &resolver(), NOW).expect("own request ok");
    let err = verify_response(&rsp_b, &req_a, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ResponseSignatureInvalid);
    assert_eq!(err.wire_code(), "mcp-re.response_sig_invalid");
}

#[test]
fn wrong_content_digest_fails_closed() {
    let mut req = signed_request();
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("content-digest") {
            h.1 = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into();
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ContentDigestMismatch);
}

#[test]
fn missing_covered_component_fails_closed() {
    let mut req = signed_request();
    // Rewrite Signature-Input to drop content-digest from the covered set.
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"content-digest\"", "");
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(
        err,
        HttpProfileError::MissingCoveredComponent("content-digest")
    );
    assert_eq!(err.wire_code(), "mcp-re.missing_envelope");
}

#[test]
fn stale_window_fails_closed() {
    let req = signed_request();
    let after_expiry = EXPIRES + 1;
    let err = verify_request(&req, &resolver(), after_expiry).unwrap_err();
    assert_eq!(err, HttpProfileError::StaleWindow);
    assert_eq!(err.wire_code(), "mcp-re.expired_request");

    let before_created = CREATED - 1;
    let err = verify_request(&req, &resolver(), before_created).unwrap_err();
    assert_eq!(err, HttpProfileError::StaleWindow);
}

#[test]
fn wrong_keyid_fails_closed() {
    let mut req = request();
    // Signed with the client key but claiming an unknown keyid: trust
    // resolution must reject before any signature check.
    sign_request(
        &mut req,
        &client_key(),
        "rogue-key-9",
        CREATED,
        EXPIRES,
        "n",
    )
    .expect("signing succeeds");
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    assert_eq!(err.wire_code(), "mcp-re.actor_binding_failed");
}

#[test]
fn keyid_swap_to_another_trusted_key_fails_the_signature() {
    let mut req = request();
    // Signed by client-key-1 but claiming client-key-2 — another key trusted for
    // the SAME (Request) slot: resolution succeeds, but the signature must not
    // verify under the wrong key.
    sign_request(
        &mut req,
        &client_key(),
        "client-key-2",
        CREATED,
        EXPIRES,
        "n",
    )
    .expect("signing succeeds");
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::InvalidSignature);
}

#[test]
fn foreign_tag_fails_closed() {
    let mut req = signed_request();
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 =
                h.1.replace("tag=\"mcp-re-http-v1\"", "tag=\"someone-elses-profile\"");
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::UnknownProfileTag);
    assert_eq!(err.wire_code(), "mcp-re.unsupported_version");
}

#[test]
fn content_encoding_fails_closed() {
    let mut req = signed_request();
    req.headers.push(("Content-Encoding".into(), "gzip".into()));
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ContentEncodingPresent);
    assert_eq!(err.wire_code(), "mcp-re.serialization_failed");
}

#[test]
fn unsigned_request_fails_closed() {
    let req = request();
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert!(matches!(err, HttpProfileError::MissingEvidence(_)));
}

#[test]
fn duplicate_authorization_fails_closed() {
    let mut req = request();
    req.headers
        .push(("Authorization".into(), "Bearer one".into()));
    req.headers
        .push(("authorization".into(), "Bearer two".into()));
    let err = sign_request(
        &mut req,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "n",
    )
    .unwrap_err();
    assert_eq!(err, HttpProfileError::DuplicateHeader("authorization"));
}

// ---------- MCPRE-100: resolved actor identity seam ------------------------

/// (1)(7) A request signed by a request-slot actor verifies AND the result
/// exposes the resolved actor identity — keyid is a wire selector, `actor_id` is
/// the trust-resolution output.
#[test]
fn verified_request_exposes_resolved_actor_identity() {
    let req = signed_request();
    let v = verify_request(&req, &resolver(), NOW).expect("verifies");
    assert_eq!(v.key_id, "client-key-1");
    assert_eq!(v.resolved_actor.identity.role, "client");
    assert_eq!(v.resolved_actor.identity.keyid, "client-key-1");
    assert_eq!(v.resolved_actor.slot, SignerSlot::Request);
    // actor_id is the trust-resolution output, NOT the raw keyid.
    let actor_id = v.resolved_actor.actor_id();
    assert_ne!(actor_id, v.key_id);
    assert!(actor_id.starts_with("client:"));
    // deterministic + stable.
    assert_eq!(actor_id, v.resolved_actor.identity.actor_id());
    // full verified evidence context carried forward.
    assert_eq!(v.profile_id, "mcp-re-http-v1");
    assert_eq!(v.signature_label, "mcp-re");
    assert!(v.content_digest.starts_with("sha-256=:"));
}

/// (2)(8) A response signed by a response-slot actor verifies AND the result
/// exposes the resolved server actor identity for downstream body-block wiring.
#[test]
fn verified_response_exposes_resolved_server_actor() {
    let (req, rsp) = signed_exchange();
    let v = verify_response(&rsp, &req, &resolver(), NOW).expect("verifies");
    assert_eq!(v.resolved_server_actor.identity.role, "server");
    assert_eq!(v.resolved_server_actor.slot, SignerSlot::Response);
    assert!(v.resolved_server_actor.actor_id().starts_with("server:"));
    assert_eq!(v.response_signature_base_digest.digest_alg, "sha256");
    assert!(v.bound_request_evidence.is_none());
}

/// (3) A request signed by a response-only actor fails actor_binding_failed:
/// role authorization is a trust-resolution decision, not a signature outcome.
#[test]
fn request_signed_by_response_only_actor_fails_actor_binding() {
    let mut req = request();
    sign_request(
        &mut req,
        &server_key(),
        "server-key-1", // only trusted for the Response slot
        CREATED,
        EXPIRES,
        "n",
    )
    .expect("signing succeeds");
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    assert_eq!(err.wire_code(), "mcp-re.actor_binding_failed");
}

/// (4) A response signed by a request-only actor fails actor_binding_failed.
#[test]
fn response_signed_by_request_only_actor_fails_actor_binding() {
    let req = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(
        &mut rsp,
        &req,
        &client_key(),
        "client-key-1", // only trusted for the Request slot
        CREATED,
        EXPIRES,
    )
    .expect("response signing succeeds");
    let err = verify_response(&rsp, &req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    assert_eq!(err.wire_code(), "mcp-re.actor_binding_failed");
}

/// (6) The same keyid registered under different slots/roles does not collapse
/// to the same actor_id — client and server identities can never be confused.
#[test]
fn same_keyid_different_slots_do_not_collapse_actor_id() {
    let dual = |_key_id: &str, slot: SignerSlot| {
        let role = match slot {
            SignerSlot::Request => "client",
            SignerSlot::Response => "server",
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: "shared-key".into(),
            },
            verification_key: client_key().public_key(),
            slot,
        })
    };
    let as_request = dual("shared-key", SignerSlot::Request).unwrap();
    let as_response = dual("shared-key", SignerSlot::Response).unwrap();
    assert_ne!(as_request.actor_id(), as_response.actor_id());
}

/// Defense-in-depth: a resolver that hands back an actor vouched for the wrong
/// slot is caught by the verifier's typed cross-check (still actor_binding_failed
/// at the wire layer). The seam is the primary authority; this is the backstop.
#[test]
fn resolver_returning_wrong_slot_is_rejected() {
    let liar = |key_id: &str, _slot: SignerSlot| {
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: key_id.into(),
            },
            verification_key: client_key().public_key(),
            slot: SignerSlot::Response, // wrong: verify_request asks for Request
        })
    };
    let req = signed_request();
    let err = verify_request(&req, &liar, NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ActorSlotMismatch);
    assert_eq!(err.wire_code(), "mcp-re.actor_binding_failed");
}
