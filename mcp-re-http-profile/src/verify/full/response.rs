// SPDX-License-Identifier: Apache-2.0
//! Full-profile response verification for the trust-seam-authorized path (THM-0018).
//!
//! One authority: **this response's evidence block names the identity that actually signed
//! it, and the request it claims to answer is the one the caller holds a handle for.**
//!
//! Both checks are defence in depth over a floor that already bound the response to the
//! request cryptographically through `;req`. They are not redundant: the `;req` floor
//! refuses a SPLICE, while these refuse a block that MISDESCRIBES a signature that is
//! genuinely over these bytes — a signer naming a keyid it did not sign as, or a block
//! advertising another exchange's evidence.

use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::body::extract_meta_block;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::PROFILE_TAG;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::verified_response::VerifiedMcpResponse;
use crate::verify::floor::floor_bound_response;

/// [`verify_response_bound_full`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn full_bound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    bound_request_evidence: &RequestEvidence,
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

    // 3. server_signer must be the identity that actually signed.
    if block.server_signer.keyid != floor.resolved_server_actor.identity.keyid {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    // 4. Explicit request-evidence comparison: body handle == the request
    //    signature-base digest the caller holds. This is the precise
    //    `request_binding_mismatch` path (the ;req floor already rejects a
    //    cryptographic splice above).
    if block.request_evidence.digest_alg != bound_request_evidence.digest_alg
        || block.request_evidence.digest_value != bound_request_evidence.digest_value
    {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    Ok(VerifiedMcpResponse::from_block(
        floor,
        bound_request_evidence.clone(),
        &block,
    ))
}
