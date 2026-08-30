// SPDX-License-Identifier: Apache-2.0
//! What makes ONE retained hop part of a complete record.
//!
//! Four independent facts, asked in this order because each one's inputs come from the
//! previous: the two instants the messages are verified at, the request and its evidence
//! block, the response bound to that request, the link back to the predecessor, and the
//! turn's place in the chain's shape.
//!
//! Every one of them answers with an [`IncompleteReason`] rather than a bare failure. The
//! label a reconstruction produces NAMES the hop that broke and why, because it is embedded
//! in a SCITT Signed Statement: an auditor is better served by *hop 2's continuation does
//! not link* than by a bare `false`.
//!
//! Nothing here decides where the reconstruction stops. [`super::reconstruct_chain`] does
//! that, and it stops at the first break — past that point the record is already not
//! complete, and continuing would invite reporting later hops as fine when nothing links
//! them to a beginning.

use crate::block::HttpRequestEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::body::extract_meta_block;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUEST_LABEL;
use crate::ids::RESPONSE_LABEL;
use crate::verifier::Verifier;
use crate::verify::DelegationExpectations;

use super::hop_instant;
use super::ChainAudit;
use super::HopEvidence;
use super::HopInstantError;
use super::IncompleteReason;
use super::RetainedHop;

use super::record::check_chain_shape;
use super::record::link_to_predecessor;

/// The inputs that are fixed for a whole reconstruction.
///
/// The trust seam, what a delegation must satisfy, what the record's requests must have
/// been addressed to, and the audit instant. Bundled because they are constant across every
/// hop: a per-hop function taking them positionally would be free to be handed a different
/// verifier for one hop than for another, and a record verified under two trust seams is not
/// one record.
pub(super) struct ChainVerification<'a, R: Into<ResolverOutcome>> {
    pub(super) verifier: &'a Verifier<'a, R>,
    pub(super) expect: &'a DelegationExpectations<'a>,
    pub(super) audit: &'a ChainAudit<'a>,
    pub(super) is_revoked: &'a dyn Fn(&str) -> bool,
    pub(super) now: i64,
}

/// Where one hop sits in the record.
///
/// Both facts are about the RECORD rather than about the hop, which is why they arrive from
/// outside: whether this turn must be terminal depends on how many hops were submitted, and
/// what it must link back to depends on which of them have already verified.
pub(in crate::chain) struct HopPosition<'a> {
    pub(in crate::chain) index: usize,
    /// The predecessor's two handles, or `None` for the hop that opens the record.
    pub(in crate::chain) previous: Option<&'a HopEvidence>,
    pub(in crate::chain) is_last: bool,
}

impl<R: Into<ResolverOutcome>> ChainVerification<'_, R> {
    /// The instants this hop's two messages are verified at.
    ///
    /// Each message is verified at its OWN covered `created`, bounded above by the audit
    /// instant so a record cannot contain evidence from the future. [`hop_instant`] carries
    /// the reasoning for why a retained record is not held to the live clock.
    fn instants(&self, hop: &RetainedHop) -> Result<(i64, i64), IncompleteReason> {
        let request_at = hop_instant(
            &hop.request.headers,
            REQUEST_LABEL,
            "request signature-input",
            self.verifier.policy(),
            self.now,
        )
        .map_err(|e| match e {
            HopInstantError::Unreadable(e) => IncompleteReason::RequestUnverifiable(e),
            HopInstantError::AfterAuditInstant => IncompleteReason::HopAfterAuditInstant,
        })?;
        let response_at = hop_instant(
            &hop.response.headers,
            RESPONSE_LABEL,
            "response signature-input",
            self.verifier.policy(),
            self.now,
        )
        .map_err(|e| match e {
            HopInstantError::Unreadable(e) => IncompleteReason::ResponseUnverifiable(e),
            HopInstantError::AfterAuditInstant => IncompleteReason::HopAfterAuditInstant,
        })?;
        Ok((request_at, response_at))
    }

    /// The hop's request, and the evidence block inside it.
    ///
    /// The cryptographic floor is not enough. It stops at the RFC 9421 signature and the MCP
    /// transport contract and never looks inside the block, so a hop with no block at all, or
    /// one whose block fails its own structural rules, or one whose audience names a target
    /// other than the URI the request was actually sent to, verified all the same — and a
    /// record could be labelled `Complete`, with a Signed Statement issued over it, while
    /// containing requests the enforcement boundary would have refused.
    ///
    /// The audience tuple and `artifact_bindings[]` are enforced through the SAME function
    /// the live path uses, against the caller-supplied [`ChainAudit`]. One implementation, so
    /// an auditor's `Complete` cannot mean less than an admission. "Served" and "accounted
    /// for" have to be the same verdict.
    fn verify_request(
        &self,
        hop: &RetainedHop,
        at: i64,
    ) -> Result<(crate::evidence::RequestEvidence, HttpRequestEvidenceBlock), IncompleteReason>
    {
        let unverifiable = IncompleteReason::RequestUnverifiable;
        let verified = self
            .verifier
            .verify_request_floor(&hop.request, at)
            .map_err(unverifiable)?;
        let block: HttpRequestEvidenceBlock = extract_meta_block(
            &hop.request.body,
            REQUEST_EVIDENCE_BLOCK_KEY,
            "request evidence block",
        )
        .map_err(unverifiable)?;
        block.validate(&verified.profile_id).map_err(unverifiable)?;
        crate::verify::enforce_full_profile_bindings(
            &hop.request,
            &block,
            self.audit.expected_audience,
            self.audit.artifact_material,
        )
        .map_err(unverifiable)?;
        Ok((verified.evidence, block))
    }

    /// Everything that must hold for one hop to join the verified prefix.
    pub(super) fn verify_hop(
        &self,
        hop: &RetainedHop,
        position: &HopPosition<'_>,
    ) -> Result<HopEvidence, IncompleteReason> {
        let (request_at, response_at) = self.instants(hop)?;
        let (request_evidence, block) = self.verify_request(hop, request_at)?;
        // The response must verify AND be bound to that request.
        let verified_rsp = self
            .verifier
            .verify_delegated_bound_response(
                &hop.response,
                &hop.request,
                self.expect,
                self.is_revoked,
                response_at,
            )
            .map_err(IncompleteReason::ResponseUnverifiable)?;
        link_to_predecessor(position, block.continuation.as_ref())?;
        check_chain_shape(position.is_last, &hop.response.body)?;
        Ok(HopEvidence {
            request_evidence,
            response_evidence: verified_rsp
                .signature_facts
                .response_signature_base_digest
                .clone(),
        })
    }
}
