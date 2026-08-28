// SPDX-License-Identifier: Apache-2.0
//! The response's cryptographic floor, bound and unbound (THM-0016 / THM-0017).
//!
//! One authority: **this response's body matches its digest and its signature verifies
//! under a key the deployment trusts for the Response slot.**
//!
//! Bound and unbound are two functions rather than one with a flag because they are two
//! security propositions, and the difference is what `;req` means. The bound form resolves
//! `;req` against a concrete request, so its signature covers that request's components;
//! the unbound form REFUSES `;req` as malformed, because there is no request to resolve it
//! against and a component that cannot be resolved must not be silently ignored. Their
//! products are two types for the same reason.

use mcp_re_core::McpReError;

use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_LABEL;
use crate::message::reject_content_encoding;
use crate::message::require_json_media_type;
use crate::message::required_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::sigbase::signature_base;
use crate::sigbase::SourceMessage;
use crate::verified_response::CryptographicFloorVerifiedBoundResponse;
use crate::verified_response::CryptographicFloorVerifiedUnboundResponse;

use super::components::require_components;
use super::params::check_params;
use super::sf_dictionary::member_value;
use super::signature::signature_value_b64url;
use super::signature::verify_under;
use super::signature_input::parse_signature_input;
use super::trust_slot::resolve_actor_for_slot;

/// [`verify_response`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn floor_bound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<CryptographicFloorVerifiedBoundResponse, HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    // JSON mode (§3.4): an SSE response to a covered request is a profile
    // violation, not a streaming opt-in.
    require_json_media_type(&response.headers, "response content-type")?;

    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    let input_header = required_header(&response.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("response signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, RESPONSE_LABEL)?)?;
    require_components(
        &parsed.components,
        &REQUIRED_RESPONSE_COMPONENTS,
        &REQUIRED_RESPONSE_REQ_COMPONENTS,
    )?;
    let (_created, _expires, _nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, false)?;

    // Trust resolution for the RESPONSE slot: a request-signer key presented on
    // a response fails actor_binding_failed.
    let resolved_server_actor =
        resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Response)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &resolved_server_actor.verification_key,
        McpReError::ResponseSigInvalid,
    )?;
    Ok(CryptographicFloorVerifiedBoundResponse {
        resolved_server_actor,
        response_signature_base_digest: RequestEvidence::from_response_signature_base(&base),
    })
}
/// [`verify_response_unbound`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn floor_unbound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<CryptographicFloorVerifiedUnboundResponse, HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    // JSON mode (§3.4): an SSE response to a covered request is a profile
    // violation, not a streaming opt-in.
    require_json_media_type(&response.headers, "response content-type")?;

    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    let input_header = required_header(&response.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("response signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, RESPONSE_LABEL)?)?;
    require_components(&parsed.components, &REQUIRED_RESPONSE_COMPONENTS, &[])?;
    if parsed.components.iter().any(|c| c.req) {
        return Err(HttpProfileError::MalformedEvidence(
            "req component without request context",
        ));
    }
    let (_created, _expires, _nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, false)?;

    let resolved_server_actor =
        resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Response)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::ResponseOnly(response),
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &resolved_server_actor.verification_key,
        McpReError::ResponseSigInvalid,
    )?;
    Ok(CryptographicFloorVerifiedUnboundResponse {
        resolved_server_actor,
        response_signature_base_digest: RequestEvidence::from_response_signature_base(&base),
    })
}
