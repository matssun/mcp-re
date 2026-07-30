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
//! - a foreign profile `tag`;
//! - a string parameter carrying a `"`, a `\`, or a control character, which
//!   RFC 8941 cannot express verbatim — refused at BOTH ends rather than escaped,
//!   so that no two wire spellings collapse to one signature base (the same rule
//!   the non-canonical integer forms above are refused under).
//!
//! And one parsing property rather than a rejection: the dictionary and parameter
//! splitters honour RFC 8941 escapes, so a NEIGHBOURING signature member — the
//! ordinary multi-signer case — cannot swallow the separator that ends it and take
//! this profile's member with it.

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

/// RFC 9421 §2.5 requires an error when a component identifier is added to the
/// signature base twice. Beyond conformance: `signature_base` emits one line per
/// occurrence, so admitting duplicates would give ONE message many valid bases and
/// therefore many distinct evidence handles for the same bytes — the handle would
/// stop being a function of the message, which is what MRTR continuation re-linking
/// and audit correlation rely on.
#[test]
fn a_duplicated_covered_component_fails_closed() {
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| {
        v.replace("(\"@method\"", "(\"@method\" \"@method\"")
    });
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("duplicate covered component")
    );
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

/// RFC 8941 §3.3.1 admits exactly one spelling of an integer: optional `-`, then
/// digits with no leading zero. Rust's `i64::from_str` also takes `+1700000000` and
/// `0017`, and the verifier rebuilds `@signature-params` from the PARSED values —
/// so every accepted spelling would collapse to one signature base. An intermediary
/// could then rewrite `created` in flight and the signature would still verify,
/// leaving anything that reads the raw header looking at bytes other than the signed
/// ones. Both alternate spellings must be refused structurally.
#[test]
fn non_canonical_integer_parameter_forms_fail_closed() {
    for mutate in [
        // A leading `+` on created.
        |v: &str| v.replace(";created=1700000000", ";created=+1700000000"),
        // Leading zeros on created.
        |v: &str| v.replace(";created=1700000000", ";created=01700000000"),
        // Leading zeros on expires.
        |v: &str| v.replace(";expires=1700000300", ";expires=01700000300"),
    ] {
        let mut req = signed_request();
        edit_signature_input(&mut req, mutate);
        let err = verify_err(&req);
        assert_eq!(
            err,
            HttpProfileError::MalformedEvidence("integer signature parameter"),
            "an RFC 8941-illegal integer spelling must be refused, not normalized"
        );
    }
}

#[test]
fn canonical_order_still_verifies() {
    // Guard against over-tightening: the untouched, canonically-ordered message
    // must still verify.
    let req = signed_request();
    verify_request(&req, &resolver(), NOW).expect("canonical form verifies");
}

// --- RFC 8941 string parameters (C092) ---------------------------------------

/// A `nonce` carrying a quote must not be EMITTED. Every conforming RFC 8941
/// parser reads such a header differently from this profile, so a signer that
/// produced one would be publishing bytes whose meaning it does not control.
///
/// Refused rather than escaped, for the reason `parse_i64` already gives about
/// `created=+1`: the base is rebuilt from parsed values, so admitting escapes would
/// let two wire spellings collapse to one signature base, and an intermediary could
/// rewrite between them without breaking the signature.
#[test]
fn a_string_parameter_that_rfc_8941_cannot_carry_is_never_signed() {
    for bad in [
        "nonce\"with-quote",
        "nonce\\with-backslash",
        "nonce\twith-tab",
    ] {
        let mut req = HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: b"{}".to_vec(),
        };
        let err = sign_request(
            &mut req,
            &client_key(),
            "client-key-1",
            CREATED,
            EXPIRES,
            bad,
        )
        .expect_err("signing must refuse a nonce RFC 8941 cannot carry verbatim");
        assert!(
            matches!(err, HttpProfileError::MalformedEvidence(_)),
            "{bad:?} produced {err:?}"
        );
        assert!(
            !req.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("signature-input")),
            "{bad:?} must leave no Signature-Input behind"
        );
    }
}

/// The same rule on the way in: a keyid or nonce carrying a quote, a backslash, or
/// a control character is refused rather than unescaped.
#[test]
fn a_string_parameter_carrying_an_escape_fails_closed_on_verify() {
    for injected in [
        r#"\"evil\""#,
        r#"a\\b"#,
        // A bare quote inside the value: what the escape-blind splitter used to
        // mis-parse before anything could reject the value.
        r#"a"b"#,
    ] {
        let mut req = signed_request();
        edit_signature_input(&mut req, |v| {
            let start = v.find(";nonce=\"").expect("nonce parameter present");
            let rest = &v[start + ";nonce=\"".len()..];
            let end = rest.find('"').expect("nonce value closes");
            format!(
                "{}{};nonce=\"{}\"{}",
                &v[..start],
                "",
                injected,
                &rest[end + 1..]
            )
        });
        let err = verify_err(&req);
        assert!(
            matches!(err, HttpProfileError::MalformedEvidence(_)),
            "nonce {injected:?} produced {err:?} instead of a malformed-evidence rejection"
        );
    }
}

/// The dictionary splitter must not let one member's string value swallow the
/// top-level comma that ends it.
///
/// A `\"` inside a member used to toggle the in-quotes state and leave it odd, so
/// the comma separating it from the NEXT member was not seen as a separator and the
/// two merged. The profile then read the merged text as one member's parameters —
/// before any value validation could object to the escape that caused it.
///
/// The observable consequence is here: a decoy member placed before this profile's
/// own, carrying a legal escaped quote, must not prevent `mcp-re=` from resolving to
/// its own member. With the escape honoured the real member is found and verifies;
/// escape-blind, the decoy eats the comma and the lookup lands on merged text.
#[test]
fn an_escaped_quote_in_a_neighbouring_member_does_not_merge_it() {
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| {
        format!("decoy=(\"@method\");keyid=\"a\\\"b\", {v}")
    });
    verify_request(&req, &resolver(), NOW)
        .expect("this profile's member is found and verified beside a decoy");
}

/// The same for the `Signature` dictionary, which is looked up by the same splitter.
#[test]
fn a_decoy_signature_member_does_not_merge_into_this_profiles_member() {
    let mut req = signed_request();
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature") {
            h.1 = format!("decoy=:AAAA:, {}", h.1);
        }
    }
    edit_signature_input(&mut req, |v| {
        format!("decoy=(\"@method\");keyid=\"a\\\"b\", {v}")
    });
    verify_request(&req, &resolver(), NOW)
        .expect("the signature member is found beside a decoy carrying an escape");
}

/// A semicolon inside a quoted value is part of the value, not a parameter
/// separator.
///
/// The escape-blind split cut the nonce in half and produced `keyid=evil` as a
/// SEPARATE parameter that was never on the wire — which surfaced as "unknown
/// signature parameter" or, worse, as a second `keyid`. Split correctly, the whole
/// string is one nonce; the base then differs from the signed one, so it fails as a
/// signature mismatch. That distinction is the test: rejected for the right reason.
#[test]
fn a_semicolon_inside_a_quoted_value_does_not_split_parameters() {
    let mut req = signed_request();
    edit_signature_input(&mut req, |v| v.replace("nonce-1", "a;keyid=evil"));
    let err = verify_err(&req);
    assert_eq!(
        err,
        HttpProfileError::InvalidSignature,
        "the tampered nonce must fail as a base mismatch, not as invented parameters"
    );
}

/// The mirror: an ordinary base64url nonce and a configured keyid are unaffected.
#[test]
fn ordinary_string_parameters_still_sign_and_verify() {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: b"{}".to_vec(),
    };
    sign_request(
        &mut req,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "AbCd-_0123456789xyz",
    )
    .expect("a base64url nonce signs");
    verify_request(&req, &resolver(), NOW).expect("and verifies");
}
