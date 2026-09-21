// SPDX-License-Identifier: Apache-2.0
//! The pre-ADR-MCPRE-052 ROOT-signed bodyless `202`, retained as a NEGATIVE-TEST
//! fixture only.
//!
//! `delegated-required` is MCP-RE's only response-signing mode, so the live
//! acknowledgement emitter is `sign_delegated_accepted_202` and the live verifier is
//! `verify_delegated_accepted_202`. The pair here signs and verifies the ROOT-signed
//! shape, which exists for exactly one purpose: to be the message a verifier in the
//! required mode must refuse. `d10_required_rejects_direct_root` and the
//! `bodyless_202_test` negatives are its consumers.
//!
//! `sign_accepted_202` and `verify_accepted_202` were the old names. Neutral names are
//! how a removed mode kept a public export through a whole release, so the fixtures
//! carry `pre_052` and `for_negative_test` instead.
//!
//! Gated on `any(test, feature = "pre_052_fixtures")`: absent from a product build, and
//! still compiled by this crate's own batteries, which a feature-only gate would silently
//! reduce to zero tests.
//!
//! A CHILD of `bodyless` because the bodies need `require_bodyless`, `params_for`, `emit`,
//! `request_evidence_header` and `check_request_evidence` — all private to the parent. The
//! crate root would have cost five production widenings to compile a fixture.

use super::*;

// The §3.4 published bodyless response set. After the pre-052 emitters left `bodyless`,
// this fixture module is its only in-crate consumer; the parent no longer imports it.
use crate::ids::BODYLESS_RESPONSE_COMPONENTS;

/// Sign a bodyless `202 Accepted` acknowledging `request` (§3.4, #418).
///
/// `request` is the originating notification/response POST — an ordinary bodied,
/// signed request. The 202 binds to it via the mandatory `;req` components, so
/// the acknowledgement cannot be lifted onto a different notification.
///
/// The emitted response has NO body and NO `content-type`; its `content-digest`
/// commits to empty content.
pub fn sign_pre_052_root_signed_202_for_negative_test(
    request: &HttpRequest,
    key: &mcp_re_core::SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let mut response = HttpResponse {
        status: STATUS_ACCEPTED,
        headers: vec![
            ("Content-Digest".to_owned(), content_digest_sha256(&[])),
            // C019b: the per-instance coordinate. Covered below, so the
            // acknowledgement binds to THIS transmission.
            request_evidence_header(request)?,
        ],
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
pub fn verify_pre_052_root_signed_202_for_negative_test<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    verifier: &crate::verifier::Verifier<'_, R>,
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

    // C019b: the acknowledgement names the exact request TRANSMISSION it answers, and
    // the verifier re-derives that name from the request rather than trusting it.
    check_request_evidence(&response.headers, request)?;

    let parsed = parse_signature_input_for(
        &response.headers,
        RESPONSE_LABEL,
        "response signature-input",
    )?;
    // The NAMED bodyless response set, enforced exactly: `@status` and
    // `content-digest`, plus the full `;req` binding. `content-type` is absent
    // from the set and rejected as a covered component below.
    require_components(
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
    let (_c, _e, _n, key_id, algorithm) =
        check_params(&parsed.params, verifier.policy(), now, false)?;
    let seam = verifier.resolve_actor();
    let actor = resolve_actor_for_slot(seam, &key_id, SignerSlot::Response)?;

    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "signature", RESPONSE_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &actor.verification_key,
        McpReError::ResponseSigInvalid,
    )?;
    Ok(actor)
}
