// SPDX-License-Identifier: Apache-2.0
//! The two seam-authorized REQUEST-BOUND response products.
//!
//! Each carries the `;req` binding to a concrete request and the signer the signature was
//! accepted under, with the signer authorized by the trust seam. The delegation-authorized
//! bound product is `delegated_bound`, because its authorization proposition is not the
//! seam's.
//!
//! They live apart from the unbound products because bound and unbound are different
//! propositions rather than an API convenience, which is the whole argument in [`super`].

use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolvedActor;
use crate::RequestEvidence;

use super::facts::AcceptedResponseSigner;
use super::facts::BoundRequestEvidenceAgreement;
use super::facts::BoundResponseSignatureFacts;

/// A response whose cryptographic floor holds, **bound to a concrete request**, with its
/// signer authorized by the **trust seam**.
///
/// A successful `verify_bound_response_floor` establishes [`BoundResponseSignatureFacts`],
/// and in addition that the
/// presented keyid was resolved through the trust seam in the `Response` slot — the
/// resolved actor IS the accepted signer.
///
/// It does **not** mean the response evidence block was read, and it does not mean the
/// block agrees with the request. That is [`VerifiedMcpResponse`]. It says nothing about
/// delegation: a delegated response is authorized by a credential and never reaches this
/// type.
#[derive(Debug, Clone)]
pub struct CryptographicFloorVerifiedBoundResponse {
    resolved_server_actor: ResolvedActor,
    response_signature_base_digest: RequestEvidence,
}

impl CryptographicFloorVerifiedBoundResponse {
    /// Assemble from what the trust seam resolved; `crate::verify` is the only producer.
    pub(crate) fn new(
        resolved_server_actor: ResolvedActor,
        response_signature_base_digest: RequestEvidence,
    ) -> Self {
        Self {
            resolved_server_actor,
            response_signature_base_digest,
        }
    }

    /// The resolved server/response signer — identity, key, and `Response` slot.
    pub fn resolved_server_actor(&self) -> &ResolvedActor {
        &self.resolved_server_actor
    }

    /// The response signature-base handle, under the response role label.
    pub fn response_signature_base_digest(&self) -> &RequestEvidence {
        &self.response_signature_base_digest
    }

    /// The authorization-independent facts, as the delegated bound product carries them.
    ///
    /// A projection rather than a stored field: the seam resolution ENTAILS the accepted
    /// signer, and storing both would represent one fact twice.
    pub fn signature_facts(&self) -> BoundResponseSignatureFacts {
        BoundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: self.resolved_server_actor.identity.clone(),
                verification_key: self.resolved_server_actor.verification_key.clone(),
            },
            response_signature_base_digest: self.response_signature_base_digest.clone(),
        }
    }
}

/// A response verified under the **full MCP-RE profile**, bound to a request, with its
/// signer authorized by the **trust seam**.
///
/// A successful `verify_bound_response` establishes everything
/// [`CryptographicFloorVerifiedBoundResponse`] does, and in
/// addition that the response evidence block parsed and validated, that the block's
/// `server_signer.keyid` equals the keyid the signature was accepted under, and that its
/// `request_evidence` equals the handle the caller expected. The signer identity this
/// product carries is `floor.resolved_server_actor.identity`, the seam's answer.
///
/// The expected handle is an INPUT, not a second assurance axis. A server passes
/// `verified_request.evidence()`; a client passes the handle it kept from signing. Where
/// it came from is the caller's business and does not change what this product proves.
///
/// A cryptographic floor is not a full profile, and no consumer can accept one for the
/// other by accident:
///
/// ```compile_fail
/// use mcp_re_http_profile::{CryptographicFloorVerifiedBoundResponse, VerifiedMcpResponse};
/// fn needs_full(_: &VerifiedMcpResponse) {}
/// fn from_floor(floor: &CryptographicFloorVerifiedBoundResponse) {
///     needs_full(floor);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedMcpResponse {
    floor: CryptographicFloorVerifiedBoundResponse,
    request_evidence_agreement: BoundRequestEvidenceAgreement,
}

impl VerifiedMcpResponse {
    /// The seam-authorized bound floor proposition this product also establishes.
    pub fn floor(&self) -> &CryptographicFloorVerifiedBoundResponse {
        &self.floor
    }

    /// The block agreement with the caller's expected request-evidence handle.
    pub fn request_evidence_agreement(&self) -> &BoundRequestEvidenceAgreement {
        &self.request_evidence_agreement
    }

    /// Assemble from the floor product and the block facts the full path established.
    pub(crate) fn from_block(
        floor: CryptographicFloorVerifiedBoundResponse,
        bound_request_evidence: RequestEvidence,
        block: &HttpResponseEvidenceBlock,
    ) -> Self {
        VerifiedMcpResponse {
            floor,
            request_evidence_agreement: block_agreement(bound_request_evidence, block),
        }
    }
}

/// The agreement record both full bound paths build, from the caller's handle and the
/// block whose handle was just compared equal to it.
pub(crate) fn block_agreement(
    bound_request_evidence: RequestEvidence,
    block: &HttpResponseEvidenceBlock,
) -> BoundRequestEvidenceAgreement {
    BoundRequestEvidenceAgreement {
        bound_request_evidence,
        body_request_evidence: RequestEvidence {
            digest_alg: block.request_evidence.digest_alg.clone(),
            digest_value: block.request_evidence.digest_value.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ActorIdentity;
    use crate::block::RequestEvidenceDigest;
    use crate::block::SignerSlot;
    use crate::PROFILE_TAG;
    use mcp_re_core::SigningKey;

    fn actor(keyid: &str) -> ResolvedActor {
        ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: keyid.into(),
            },
            verification_key: SigningKey::from_seed_bytes(&[9u8; 32]).public_key(),
            slot: SignerSlot::Response,
        }
    }

    fn bound_floor() -> CryptographicFloorVerifiedBoundResponse {
        CryptographicFloorVerifiedBoundResponse {
            resolved_server_actor: actor("resp-1"),
            response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
        }
    }

    #[test]
    fn a_bound_full_response_states_its_binding_without_an_option() {
        let expected = RequestEvidence::from_signature_base(b"req");
        let other = RequestEvidence::from_signature_base(b"other");
        let block = HttpResponseEvidenceBlock {
            profile: PROFILE_TAG.into(),
            server_signer: actor("resp-1").identity,
            server_delegation: None,
            request_evidence: RequestEvidenceDigest {
                digest_alg: other.digest_alg.clone(),
                digest_value: other.digest_value.clone(),
            },
        };
        let full = VerifiedMcpResponse::from_block(bound_floor(), expected.clone(), &block);
        assert_eq!(
            full.request_evidence_agreement.bound_request_evidence,
            expected
        );
        assert_eq!(full.request_evidence_agreement.body_request_evidence, other);
        assert_ne!(
            full.request_evidence_agreement.body_request_evidence,
            expected
        );
    }

    /// The seam-authorized floor ENTAILS the shared facts, and the projection is that
    /// entailment: the accepted signer is exactly what the seam resolved. The delegated
    /// product carries the projection's type and no `ResolvedActor`, so nothing in it can
    /// be read as "the trust seam vouched for this signing key".
    #[test]
    fn the_seam_authorized_floor_projects_the_signer_it_resolved() {
        let floor = bound_floor();
        let facts = floor.signature_facts();
        assert_eq!(
            facts.accepted_signer.identity.keyid,
            floor.resolved_server_actor.identity.keyid
        );
        assert_eq!(
            facts.response_signature_base_digest,
            floor.response_signature_base_digest
        );
    }
}
