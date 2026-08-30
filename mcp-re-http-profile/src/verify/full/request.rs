// SPDX-License-Identifier: Apache-2.0
//! Full-profile request verification (THM-0015).
//!
//! One authority: **this request's evidence block is a well-formed MCP-RE statement, it is
//! addressed to THIS verifier, and every artifact it declares is enforced.** The floor is
//! consumed, never re-derived: the full product is CONSTRUCTED from the floor value, so
//! there is no path producing a `VerifiedMcpRequest` that did not pass the floor.
//!
//! [`enforce_full_profile_bindings`] is `pub(crate)` and shared with chain reconstruction
//! rather than restated there. Reconstruction's verdict is embedded in a SCITT Signed
//! Statement, so "served" and "accounted for" have to be the SAME verdict — two copies of
//! this rule would let a record be labelled `Complete` under checks the enforcement
//! boundary had since tightened.

use crate::artifact::verify_artifact_binding;
use crate::block::ArtifactBinding;
use crate::block::ArtifactType;
use crate::block::AudienceTuple;
use crate::block::HttpRequestEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::body::authorization_bearer_bytes;
use crate::body::extract_meta_block;
use crate::error::HttpProfileError;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::message::HttpRequest;
use crate::pdp_decision::pdp_decision_evidence;
use crate::pdp_decision::verify_pdp_decision_binding;
use crate::policy::VerifierPolicy;
use crate::verified_request::VerifiedMcpRequest;
use crate::verify::floor::floor_request;

/// [`verify_request_full`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn full_request<R: Into<ResolverOutcome>>(
    request: &HttpRequest,
    expected_audience: &AudienceTuple,
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<VerifiedMcpRequest, HttpProfileError> {
    // 1. Cryptographic floor: content digest, evidence, trust, signature.
    let floor = floor_request(request, resolve_actor, policy, now)?;

    // 2. Parse the request evidence block — protected because content-digest is a
    //    covered component of the signature just verified.
    let block: HttpRequestEvidenceBlock = extract_meta_block(
        &request.body,
        REQUEST_EVIDENCE_BLOCK_KEY,
        "request evidence block",
    )?;
    block.validate(floor.profile_id())?;

    // 3-4. Audience binding and strict artifact enforcement.
    enforce_full_profile_bindings(request, &block, expected_audience, artifact_material)?;

    // 5. The full product is CONSTRUCTED from the floor one, not the floor one relabelled.
    //    There is no path that produces a `VerifiedMcpRequest` without reaching here.
    Ok(VerifiedMcpRequest {
        audience_hash: block.audience.audience_hash(),
        audience: block.audience.clone(),
        request_block: block,
        floor,
    })
}
/// The two full-profile checks that need inputs the request cannot supply for itself:
/// audience-tuple equality and `artifact_bindings[]`.
///
/// Shared with chain reconstruction rather than restated there. Reconstruction's verdict
/// is embedded in a SCITT Signed Statement, so "served" and "accounted for" have to be
/// the same verdict — two copies of this rule would let a record be labelled `Complete`
/// under checks the enforcement boundary had tightened.
///
/// The artifact loop is the closed dispatch THM-0008 is stated over, and
/// `http_profile.artifact_verification_boundary` is its review unit: an artifact type with
/// no supported typed verification branch is refused here, never skipped.
///
/// The audience test is equality against the VERIFIER's own tuple plus consistency
/// between that tuple's `target_uri` and the request's `@target-uri`, which guards routed
/// and reverse-proxied deployments where a label could alias two dispatch boundaries.
/// Artifact enforcement is strict: a binding whose credential surface is unavailable
/// fails `artifact_binding_failed` rather than being skipped.
pub(crate) fn enforce_full_profile_bindings(
    request: &HttpRequest,
    block: &HttpRequestEvidenceBlock,
    expected_audience: &AudienceTuple,
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
) -> Result<(), HttpProfileError> {
    if block.audience != *expected_audience || expected_audience.target_uri != request.target_uri {
        return Err(HttpProfileError::AudienceMismatch);
    }
    for binding in &block.artifact_bindings {
        // The ADR-MCPRE-065 Slice 2 evidence form carries its artifact in the block beside
        // the binding, so its material is already in hand and its typed verifier is its own.
        // Dispatching it through `verify_artifact_binding` would mean widening a function
        // whose proved postcondition is *an `Ok` result is one of the three OAuth types* —
        // weakening a theorem to save a match arm. Every OTHER non-OAuth type still has no
        // verifier, and is still refused rather than silently treated as verified.
        if let Some(decision) = pdp_decision_evidence(binding, block) {
            verify_pdp_decision_binding(binding, decision)
                .map_err(|_| HttpProfileError::ArtifactBindingFailed)?;
            continue;
        }
        let credential = resolve_artifact_credential(binding, &request.headers, artifact_material)
            .ok_or(HttpProfileError::ArtifactBindingFailed)?;
        verify_artifact_binding(binding, &credential)?;
    }
    Ok(())
}
/// Obtain the credential bytes a binding commits to. DPoP `ath` binds the access
/// token in the covered `Authorization` header (falling back to caller material
/// if the header is absent); every other artifact type is caller-supplied. A
/// `None` here means the credential surface is unavailable — the caller treats
/// that as `artifact_binding_failed`.
fn resolve_artifact_credential(
    binding: &ArtifactBinding,
    headers: &[(String, String)],
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    match binding.artifact_type {
        ArtifactType::OauthDpop => {
            authorization_bearer_bytes(headers).or_else(|| artifact_material(binding))
        }
        _ => artifact_material(binding),
    }
}
