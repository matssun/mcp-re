// SPDX-License-Identifier: Apache-2.0
//! Bodyless component sets: the signed `202 Accepted` and the bodyless request
//! (#415 rev 2 §3.4/§8.1, issues #424/#418).
//!
//! A one-way MCP notification is NOT unauthenticable. It has no JSON-RPC
//! *response*, but the notification POST is an ordinary HTTP request and is
//! signed by the ordinary request rules — no new signing rules, no new
//! vocabulary. What was missing is the other half: an acknowledgement the client
//! can verify. MCP Streamable HTTP already says an accepted notification gets
//! `202 Accepted` with no body, so the only thing to define is how to sign a
//! message that has nothing to sign over.
//!
//! **What a signed 202 means, exactly.** THE ENFORCEMENT BOUNDARY AUTHENTICATED
//! AND ACCEPTED THIS MESSAGE. That is the whole claim. It does NOT mean a
//! requested cancellation completed, that the inner application observed the
//! notification, or that any action was taken. A client that reads "202" as
//! "cancelled" has been misled, and describing it as more would be exactly the
//! overclaim this protocol exists to avoid (#418).
//!
//! **Why these are NAMED sets rather than relaxations.** A verifier is told which
//! set it is checking and enforces that set exactly; it never *notices* a body is
//! absent and drops a requirement. Otherwise "no content-type because there is no
//! content" and "content-type stripped in flight" would be the same observation.
//! Under named sets a bodied message missing its content-type still fails, and a
//! bodyless message carrying one also fails.
//!
//! **Why `content-digest` over empty content.** A digest of nothing is not
//! ceremony: it makes "this message has no body" a *signed statement* rather than
//! an absence. Without it, a body stripped in flight and an intentionally empty
//! one would be indistinguishable to the verifier.
//!
//! **Where the request binding lives.** A bodyless 202 has no body, so it cannot
//! carry the response evidence block that a bodied response uses to restate its
//! `request_evidence`. The binding is therefore purely cryptographic: the `;req`
//! covered components resolve against the originating request, so a 202 signed
//! for notification A cannot be replayed as the acknowledgement of notification B.
//! There is no body-level defense-in-depth here because there is no body — which
//! is precisely why the `;req` set is mandatory rather than optional.

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;

use crate::block::ResolvedActor;
use crate::block::SignerSlot;
use crate::digest::content_digest_sha256;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::BODYLESS_REQUEST_COMPONENTS;
use crate::ids::BODYLESS_RESPONSE_COMPONENTS;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_LABEL;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_LABEL;
use crate::ids::STATUS_ACCEPTED;
use crate::message::reject_content_encoding;
use crate::message::required_header;
use crate::message::single_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::sigbase::signature_base;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;
use crate::sigbase::SourceMessage;

/// Fail closed if a bodyless message carries content metadata or content.
///
/// `content-type` present on a bodyless message is a profile violation, not a
/// harmless extra: the named set says there is no content, and a content-type
/// asserts otherwise. Non-empty content on a message signed under a bodyless set
/// is the same contradiction from the other side.
fn require_bodyless(
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), HttpProfileError> {
    if single_header(headers, "content-type")?.is_some() {
        return Err(HttpProfileError::MalformedEvidence(
            "content-type on a bodyless message",
        ));
    }
    if !body.is_empty() {
        return Err(HttpProfileError::MalformedEvidence(
            "content on a bodyless message",
        ));
    }
    Ok(())
}

fn params_for(key_id: &str, created: i64, expires: i64, nonce: Option<&str>) -> SignatureParams {
    SignatureParams {
        created: Some(created),
        expires: Some(expires),
        nonce: nonce.map(str::to_owned),
        keyid: Some(key_id.to_owned()),
        alg: Some(crate::ids::ALG_ED25519.to_owned()),
        tag: Some(PROFILE_TAG.to_owned()),
    }
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value));
}

fn emit(
    headers: &mut Vec<(String, String)>,
    label: &str,
    components: &[CoveredComponent],
    params: &SignatureParams,
    base: &[u8],
    key: &mcp_re_core::SigningKey,
) -> Result<(), HttpProfileError> {
    let sig = mcp_re_core::b64url_decode(&key.sign(base))
        .map_err(|_| HttpProfileError::InvalidSignature)?;
    if sig.len() != 64 {
        return Err(HttpProfileError::InvalidSignature);
    }
    set_header(
        headers,
        "Signature-Input",
        format!("{label}={}", params.serialize_with(components)),
    );
    set_header(
        headers,
        "Signature",
        format!("{label}=:{}:", crate::sign::base64_standard_encode(&sig)),
    );
    Ok(())
}

/// Sign a bodyless `202 Accepted` acknowledging `request` (§3.4, #418).
///
/// `request` is the originating notification/response POST — an ordinary bodied,
/// signed request. The 202 binds to it via the mandatory `;req` components, so
/// the acknowledgement cannot be lifted onto a different notification.
///
/// The emitted response has NO body and NO `content-type`; its `content-digest`
/// commits to empty content.
pub fn sign_accepted_202(
    request: &HttpRequest,
    key: &mcp_re_core::SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let mut response = HttpResponse {
        status: STATUS_ACCEPTED,
        headers: vec![(
            "Content-Digest".to_owned(),
            content_digest_sha256(&[]),
        )],
        body: Vec::new(),
    };
    let mut components: Vec<CoveredComponent> = BODYLESS_RESPONSE_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    components.extend(
        REQUIRED_RESPONSE_REQ_COMPONENTS
            .iter()
            .map(|n| CoveredComponent::req(n)),
    );
    let params = params_for(key_id, created, expires, None);
    let base = signature_base(
        &components,
        &params,
        &SourceMessage::Response {
            response: &response,
            request,
        },
    )?;
    emit(
        &mut response.headers,
        RESPONSE_LABEL,
        &components,
        &params,
        &base,
        key,
    )?;
    Ok(response)
}

/// Verify a signed bodyless `202 Accepted` against the exact request it
/// acknowledges (§3.4, #418).
///
/// On success the caller learns EXACTLY this: the enforcement boundary
/// authenticated and accepted that request. Nothing about what happened next.
pub fn verify_accepted_202(
    response: &HttpResponse,
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    policy: &VerifierPolicy<'_>,
    now: i64,
) -> Result<ResolvedActor, HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    require_bodyless(&response.headers, &response.body)?;
    if response.status != STATUS_ACCEPTED {
        return Err(HttpProfileError::MalformedEvidence(
            "bodyless acknowledgement status",
        ));
    }

    // The digest of empty content is checked like any other: it is a signed
    // statement that there is no body, so it must be true of the bytes received.
    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    let parsed = crate::verify::parse_signature_input_for(
        &response.headers,
        RESPONSE_LABEL,
        "response signature-input",
    )?;
    // The NAMED bodyless response set, enforced exactly: `@status` and
    // `content-digest`, plus the full `;req` binding. `content-type` is absent
    // from the set and rejected as a covered component below.
    crate::verify::require_components_for(
        &parsed.components,
        &BODYLESS_RESPONSE_COMPONENTS,
        &REQUIRED_RESPONSE_REQ_COMPONENTS,
    )?;
    if parsed
        .components
        .iter()
        .any(|c| !c.req && c.name == "content-type")
    {
        return Err(HttpProfileError::MalformedEvidence(
            "content-type covered on a bodyless message",
        ));
    }
    let (_c, _e, _n, key_id) =
        crate::verify::check_params_for(&parsed.params, policy, now, false)?;
    let actor = crate::verify::resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Response)?;

    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = crate::verify::signature_value_for(&response.headers, RESPONSE_LABEL)?;
    verify_ed25519_with(
        &base,
        &sig,
        &actor.verification_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::ResponseSignatureInvalid)?;
    Ok(actor)
}

/// Sign a bodyless REQUEST (§8.1): `@method`, `@target-uri`, and a
/// `content-digest` over empty content. No `content-type`.
pub fn sign_bodyless_request(
    request: &mut HttpRequest,
    key: &mcp_re_core::SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
    nonce: &str,
) -> Result<RequestEvidence, HttpProfileError> {
    reject_content_encoding(&request.headers)?;
    request.body.clear();
    request
        .headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
    set_header(
        &mut request.headers,
        "Content-Digest",
        content_digest_sha256(&[]),
    );
    let components: Vec<CoveredComponent> = BODYLESS_REQUEST_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    let params = params_for(key_id, created, expires, Some(nonce));
    let base = signature_base(&components, &params, &SourceMessage::Request(request))?;
    emit(
        &mut request.headers,
        REQUEST_LABEL,
        &components,
        &params,
        &base,
        key,
    )?;
    Ok(RequestEvidence::from_signature_base(&base))
}

/// Verify a bodyless REQUEST (§8.1) under the named bodyless request set.
pub fn verify_bodyless_request(
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    policy: &VerifierPolicy<'_>,
    now: i64,
) -> Result<(ResolvedActor, RequestEvidence), HttpProfileError> {
    reject_content_encoding(&request.headers)?;
    require_bodyless(&request.headers, &request.body)?;

    let digest_header = required_header(&request.headers, "content-digest")?;
    verify_content_digest_sha256(digest_header, &request.body)?;

    let parsed = crate::verify::parse_signature_input_for(
        &request.headers,
        REQUEST_LABEL,
        "signature-input",
    )?;
    crate::verify::require_components_for(&parsed.components, &BODYLESS_REQUEST_COMPONENTS, &[])?;
    if parsed.components.iter().any(|c| c.req) {
        return Err(HttpProfileError::MalformedEvidence(
            "req component on a request",
        ));
    }
    if parsed.components.iter().any(|c| c.name == "content-type") {
        return Err(HttpProfileError::MalformedEvidence(
            "content-type covered on a bodyless message",
        ));
    }
    let (_c, _e, _n, key_id) =
        crate::verify::check_params_for(&parsed.params, policy, now, true)?;
    let actor = crate::verify::resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Request)?;
    let base = signature_base(&parsed.components, &parsed.params, &SourceMessage::Request(request))?;
    let sig = crate::verify::signature_value_for(&request.headers, REQUEST_LABEL)?;
    verify_ed25519_with(&base, &sig, &actor.verification_key, McpReError::InvalidSignature)
        .map_err(|_| HttpProfileError::InvalidSignature)?;
    Ok((actor, RequestEvidence::from_signature_base(&base)))
}
