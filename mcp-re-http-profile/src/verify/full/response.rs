// SPDX-License-Identifier: Apache-2.0
//! Full-profile response verification for the trust-seam-authorized path (THM-0018).
//!
//! One authority: **this response's evidence block names the identity that actually signed
//! it, and the request it claims to answer is THE REQUEST THIS VERIFICATION WAS GIVEN.**
//!
//! Both checks are defence in depth over a floor that already bound the response to the
//! request cryptographically through `;req`. They are not redundant: the `;req` floor
//! refuses a SPLICE, while these refuse a block that MISDESCRIBES a signature that is
//! genuinely over these bytes — a signer naming a keyid it did not sign as, or a block
//! advertising another exchange's evidence.
//!
//! The handle is DERIVED from `request` here rather than supplied alongside it. It used to
//! be a second operand, and nothing related the two: a caller could pass request A and
//! handle B, and a success then meant cryptographic binding to A and semantic equality with
//! B and nothing about A and B being one exchange. See [`crate::verify::bound_request`].

use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::body::extract_meta_block;
use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::verified_response::VerifiedMcpResponse;
use crate::verify::bound_request::request_evidence_of;
use crate::verify::floor::floor_bound_response;

/// [`verify_response_bound_full`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn full_bound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<VerifiedMcpResponse, HttpProfileError> {
    // 1. Cryptographic floor incl. the ;req binding to `request`.
    let floor = floor_bound_response(response, request, resolve_actor, policy, now)?;

    // 2. Parse the response evidence block (protected by content-digest).
    let block: HttpResponseEvidenceBlock = extract_meta_block(
        &response.body,
        RESPONSE_EVIDENCE_BLOCK_KEY,
        "response evidence block",
    )?;
    block.validate(PROFILE_TAG)?;

    // The handle OF this request. Derived, never accepted: there is no second operand to
    // disagree with the first. Derived AFTER the block parses, so the two values the
    // comparison below reads are produced next to each other.
    let bound_request_evidence = request_evidence_of(request)?;

    // 3. server_signer must be the identity that actually signed.
    if block.server_signer.keyid != floor.resolved_server_actor.identity.keyid {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    // 4. Explicit request-evidence comparison: body handle == the signature-base
    //    digest of THIS request. This is the precise `request_binding_mismatch` path
    //    (the ;req floor already rejects a cryptographic splice above).
    if block.request_evidence.digest_alg != bound_request_evidence.digest_alg
        || block.request_evidence.digest_value != bound_request_evidence.digest_value
    {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    Ok(VerifiedMcpResponse::from_block(
        floor,
        bound_request_evidence,
        &block,
    ))
}
