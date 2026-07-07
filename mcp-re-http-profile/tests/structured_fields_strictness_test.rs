// SPDX-License-Identifier: Apache-2.0
//! Normative Structured Fields strictness (ADR-MCPRE-050 §Resolved-owner
//! ruling 3, MCPRE-98).
//!
//! The HTTP profile parses `Signature-Input` under a CLOSED component set and a
//! CLOSED, ORDERED parameter set (strict RFC 8941 / RFC 9421 for v1). This is
//! deliberate, not an implementation accident: any of the following fails
//! closed rather than being tolerated or silently normalized —
//!
//! - a covered component outside the closed set;
//! - a signature parameter outside the closed set;
//! - a `;req` component on a request signature;
//! - a duplicated required component;
//! - a duplicated signature parameter;
//! - parameters presented out of the profile's canonical order (which the
//!   verifier would otherwise re-canonicalize and silently accept);
//! - a reordered covered-component list (changes the signature base);
//! - a foreign profile `tag`.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        ("client-key-1", SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: key_id.into(),
            },
            verification_key: client_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

fn signed_request() -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    };
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

/// Rewrite the `Signature-Input` header value with `f`.
fn edit_signature_input(req: &mut HttpRequest, f: impl Fn(&str) -> String) {
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = f(&h.1);
        }
    }
}

fn verify_err(req: &HttpRequest) -> HttpProfileError {
    verify_request(req, &resolver(), NOW).unwrap_err()
}

#[test]
fn closed_component_set_rejects_a_foreign_component() {
    let mut req = signed_request();
    // Inject an unknown covered component into the inner list.
    edit_signature_input(&mut req, |v| {
        v.replace("(\"@method\"", "(\"x-foreign-component\" \"@method\"")
    });
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("unknown covered component")
    );
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

#[test]
fn closed_parameter_set_rejects_a_foreign_parameter() {
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| format!("{v};custom=\"x\""));
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("unknown signature parameter")
    );
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

#[test]
fn parameter_reordering_fails_closed() {
    // The signer always emits created;expires;nonce;keyid;alg;tag. Present keyid
    // before created: the verifier would re-canonicalize and silently accept, so
    // it must reject the non-canonical order structurally instead.
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| {
        // Move `keyid="client-key-1"` to the front of the parameter list.
        let with_marker = v.replace(";keyid=\"client-key-1\"", "");
        with_marker.replace(");created=", ");keyid=\"client-key-1\";created=")
    });
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("signature parameter order")
    );
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

#[test]
fn duplicated_parameter_fails_closed() {
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| format!("{v};tag=\"mcp-re-http-v1\""));
    // A second `tag` has rank not strictly after the first -> rejected.
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("signature parameter order")
    );
}

#[test]
fn component_reordering_changes_the_base_and_fails() {
    // Swap @method and @target-uri in the covered list. The verifier rebuilds
    // the base in the presented order, which no longer matches what was signed.
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| {
        v.replace(
            "(\"@method\" \"@target-uri\"",
            "(\"@target-uri\" \"@method\"",
        )
    });
    let err = verify_err(&req);
    assert_eq!(err, HttpProfileError::InvalidSignature);
}

#[test]
fn req_component_on_a_request_fails_closed() {
    // Keep all required components plain and add an extra `;req` component: a
    // request signature must not carry response-bound (`;req`) components.
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| {
        v.replace(
            "\"content-type\"",
            "\"content-type\" \"content-length\";req",
        )
    });
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("req component on a request")
    );
}

#[test]
fn foreign_tag_fails_closed() {
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| {
        v.replace("tag=\"mcp-re-http-v1\"", "tag=\"not-mcp-re\"")
    });
    assert_eq!(verify_err(&req), HttpProfileError::UnknownProfileTag);
}

#[test]
fn canonical_order_still_verifies() {
    // Guard against over-tightening: the untouched, canonically-ordered message
    // must still verify.
    let req = signed_request();
    verify_request(&req, &resolver(), NOW).expect("canonical form verifies");
}
