// SPDX-License-Identifier: Apache-2.0
//! The pre-ADR-MCPRE-052 direct-root response emitters, retained as NEGATIVE-TEST
//! fixtures only.
//!
//! `delegated-required` is MCP-RE's only response-signing mode. A directly
//! root-signed response is therefore something the product must REFUSE, and
//! refusal cannot be proven without the ability to produce one. That is the whole
//! reason these three bodies still exist: they are the adversary in
//! `direct_root_response_rejected_in_delegated_required_mode` and in the `h18` /
//! `h19` conformance vectors, not a supported way to emit a response.
//!
//! Two properties keep that status legible rather than remembered:
//!
//! - **The names say so.** `sign_accepted_202` and `sign_response` were neutral
//!   names, and a neutral name is exactly what let a removed mode keep a public
//!   export. Every item here carries `pre_052` and `for_negative_test`.
//! - **They do not exist in a product build.** The module is gated on
//!   `any(test, feature = "pre_052_fixtures")`, so the shipped library has no
//!   direct-root response signer at all — the compiler, not a review, is what
//!   stops a production caller.
//!
//! The gate is `any(test, …)` and not the feature alone on purpose: a feature-only
//! gate compiles this crate's own batteries to zero tests and reports green, which
//! is this repository's documented false-green class.
//!
//! This module is a CHILD of `rejection` because the bodies need `rejection_body`
//! and `request_id`, which are private to it. A crate-root module would have forced
//! widening two production items so a fixture could compile.

use mcp_re_core::SigningKey;
use serde_json::Value;

use crate::block::HttpResponseEvidenceBlock;
use crate::block::RequestEvidenceDigest;
use crate::body::insert_meta_block;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::PROFILE_TAG;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sign::sign_response_unbound;
use crate::sign::sign_response_with_signer;

use super::rejection_body;
use super::request_id;
use super::ActorIdentity;
use super::RejectionReason;

/// Full-profile response signing (MCPRE-101) by the ROOT key: compose the response
/// evidence block (`se.syncom/mcp-re.http.response`) carrying the `server_signer`
/// identity and the `request_evidence` this response answers into the body `_meta`,
/// then sign with the `;req` binding to `request`.
///
/// The live emitter is `sign_delegated_response_full`, which populates
/// `server_delegation`. This one leaves it `None`, which is the shape a verifier in
/// `delegated-required` mode must reject.
#[allow(clippy::too_many_arguments)]
pub fn sign_pre_052_direct_root_response_for_negative_test(
    response: &mut HttpResponse,
    request: &HttpRequest,
    request_evidence: &RequestEvidence,
    server_signer: &ActorIdentity,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpProfileError> {
    let block = HttpResponseEvidenceBlock {
        profile: PROFILE_TAG.to_owned(),
        server_signer: server_signer.clone(),
        server_delegation: None,
        request_evidence: RequestEvidenceDigest {
            digest_alg: request_evidence.digest_alg.clone(),
            digest_value: request_evidence.digest_value.clone(),
        },
    };
    response.body = insert_meta_block(&response.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block)?;
    sign_pre_052_direct_root_response_base_for_negative_test(
        response, request, key, key_id, created, expires,
    )
}

/// Sign `response` in place with the ROOT key, binding it to the verified
/// originating request via the `;req` components (v0.11 grill C.1). Label
/// `mcp-re-response`, same profile tag.
///
/// The local-key signing expression is inlined rather than reaching for
/// `sign::local_sig`: that helper is private to `sign`, and a fixture is not a
/// reason to widen it. The contract of the seam is unchanged — the closure returns
/// the RAW Ed25519 bytes, so this signs byte-identically to the live
/// `sign_response_with_signer` path.
pub fn sign_pre_052_direct_root_response_base_for_negative_test(
    response: &mut HttpResponse,
    request: &HttpRequest,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpProfileError> {
    sign_response_with_signer(
        response,
        request,
        |base| {
            mcp_re_core::b64url_decode(&key.sign(base))
                .map_err(|_| HttpProfileError::InvalidSignature)
        },
        key_id,
        created,
        expires,
    )
    .map(|_base| ())
}

/// Build a ROOT-signed rejection response. When `request` is `Some`, the response
/// is bound to it via `;req` (and echoes its id); when `None`, it is signed
/// response-only (a failure before request context).
///
/// The live rejection emitters are `build_delegated_rejection` and
/// `build_delegated_rejection_preflight`. The `None` arm still calls the live
/// `sign_response_unbound`, which is not residue: `sign_delegated_response_unbound`
/// is its production caller.
#[allow(clippy::too_many_arguments)]
pub fn build_pre_052_direct_root_rejection_for_negative_test(
    request: Option<&HttpRequest>,
    reason: &RejectionReason,
    status: u16,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let id = request.map(request_id).unwrap_or(Value::Null);
    let mut response = HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: rejection_body(id, reason),
    };
    match request {
        Some(req) => sign_pre_052_direct_root_response_base_for_negative_test(
            &mut response,
            req,
            key,
            key_id,
            created,
            expires,
        )?,
        None => sign_response_unbound(&mut response, key, key_id, created, expires)?,
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::build_pre_052_direct_root_rejection_for_negative_test as build_rejection;
    use crate::error::HttpProfileError;
    use crate::policy::VerifierPolicy;
    use crate::rejection::tests::client_key;
    use crate::rejection::tests::reason;
    use crate::rejection::tests::request;
    use crate::rejection::tests::resolver;
    use crate::rejection::tests::server_key;
    use crate::rejection::tests::CREATED;
    use crate::rejection::tests::EXPIRES;
    use crate::rejection::tests::NOW;
    use crate::rejection::verify_signed_rejection;
    use crate::verifier::Verifier;

    #[test]
    fn bound_rejection_verifies_and_exposes_the_wire_code() {
        let req = request();
        let rejection = build_rejection(
            Some(&req),
            &reason(),
            403,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        let verdict = verify_signed_rejection(
            &rejection,
            Some(&req),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .expect("verify");
        assert_eq!(verdict.wire_code, "mcp-re.invalid_audience");
        assert_eq!(verdict.status, 403);
        // The body must carry Content-Digest + Signature (label mcp-re-response).
        assert!(rejection
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-digest")));
        let sig = rejection
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
            .unwrap();
        assert!(sig.1.starts_with("mcp-re-response="));
    }

    #[test]
    fn unbound_rejection_verifies_without_request_context() {
        let rejection = build_rejection(
            None,
            &reason(),
            400,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        let verdict = verify_signed_rejection(
            &rejection,
            None,
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .expect("verify");
        assert_eq!(verdict.wire_code, "mcp-re.invalid_audience");
        assert_eq!(verdict.status, 400);
    }

    #[test]
    fn spliced_rejection_onto_a_different_request_fails() {
        let req_a = request();
        let mut req_b = request();
        req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
        let rejection = build_rejection(
            Some(&req_a),
            &reason(),
            403,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        // Bound to req_a; presenting it as the answer to req_b must fail.
        let err = verify_signed_rejection(
            &rejection,
            Some(&req_b),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::ResponseSignatureInvalid);
    }

    #[test]
    fn tampered_message_does_not_change_the_trusted_wire_code() {
        // The human message is not authoritative; tampering it breaks the
        // signature (it is under Content-Digest), so a client can never be
        // fooled by an edited message either.
        let req = request();
        let mut rejection = build_rejection(
            Some(&req),
            &reason(),
            403,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        rejection.body = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-31000,"message":"LIES","data":{"mcp_re_error":{"wire_code":"mcp-re.expired_request"}}}}"#.to_vec();
        let err = verify_signed_rejection(
            &rejection,
            Some(&req),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::ContentDigestMismatch);
    }

    #[test]
    fn wire_code_is_read_only_after_signature_verifies() {
        // A rejection signed by an UNTRUSTED key must fail before the body's
        // wire code is ever surfaced.
        let req = request();
        let rejection = build_rejection(
            Some(&req),
            &reason(),
            403,
            &client_key(),
            "rogue-key",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        let err = verify_signed_rejection(
            &rejection,
            Some(&req),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    }
}
