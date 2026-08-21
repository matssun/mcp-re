// SPDX-License-Identifier: Apache-2.0
//! The three REQUEST-BOUND response products.
//!
//! Each carries [`BoundResponseSignatureFacts`] — the `;req` binding to a concrete
//! request, and the signer the signature was accepted under — and adds its own
//! authorization proposition on top: the trust seam for the two seam-authorized products,
//! a verified credential chain for the delegated one.
//!
//! They live apart from the unbound products because bound and unbound are different
//! propositions rather than an API convenience, which is the whole argument in [`super`].

use crate::block::ActorIdentity;
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
    /// The resolved server/response signer — identity, key, and `Response` slot.
    pub resolved_server_actor: ResolvedActor,
    /// The response signature-base handle, under the response role label.
    pub response_signature_base_digest: RequestEvidence,
}

impl CryptographicFloorVerifiedBoundResponse {
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
/// addition that the response evidence block parsed and validated, that its `server_signer`
/// is the identity the signature was actually accepted under, and that its
/// `request_evidence` equals the handle the caller expected.
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
    /// The seam-authorized bound floor proposition this product also establishes.
    pub floor: CryptographicFloorVerifiedBoundResponse,
    /// The block agreement with the caller's expected request-evidence handle.
    pub request_evidence_agreement: BoundRequestEvidenceAgreement,
    /// The `server_signer` identity the block declared, verified to carry the keyid the
    /// signature was accepted under. It is retained separately from
    /// `floor.resolved_server_actor.identity` because only the KEYID was compared: the
    /// remaining coordinates are the block's claim, not the seam's answer.
    pub server_signer: ActorIdentity,
}

/// A **delegation-authorized** bound response: the full bound proposition, with the signer
/// authorized by a verified delegation chain rather than by a trust-store entry
/// (ADR-MCPRE-052 §3).
///
/// `delegation-required` is the only response-signing mode, so this is the product the
/// serving path actually produces. The issuer kid is present unconditionally: a product
/// that proves a delegation chain is not the same product with `Some`.
///
/// It deliberately does NOT contain a [`CryptographicFloorVerifiedBoundResponse`] or a
/// [`VerifiedMcpResponse`]. Those types mean "the presented keyid was resolved through the
/// trust seam", which is false here: the seam resolved the credential's ROOT ISSUER key,
/// and the delegated signing key appears in no trust map. What the two paths share is
/// [`BoundResponseSignatureFacts`] and [`BoundRequestEvidenceAgreement`], and that is
/// exactly what is carried.
///
/// An unbound receipt cannot stand in for a request-bound answer. It is not a weaker
/// value of the same type — it is a different type, and the compiler says so:
///
/// ```compile_fail
/// use mcp_re_http_profile::{VerifiedDelegatedMcpResponse, VerifiedDelegatedUnboundResponse};
/// fn needs_bound(_: &VerifiedDelegatedMcpResponse) {}
/// fn from_unbound(receipt: &VerifiedDelegatedUnboundResponse) {
///     needs_bound(receipt);
/// }
/// ```
///
/// And a delegation-authorized response is not a trust-seam-authorized one. There is no
/// field, projection or conversion that yields the seam-authorized product, so a consumer
/// whose reasoning depends on the trust map having vouched for the SIGNING key cannot be
/// handed a credential-authorized value:
///
/// ```compile_fail
/// use mcp_re_http_profile::{VerifiedDelegatedMcpResponse, VerifiedMcpResponse};
/// fn needs_seam_authorized(_: &VerifiedMcpResponse) {}
/// fn from_delegated(delegated: &VerifiedDelegatedMcpResponse) {
///     needs_seam_authorized(&delegated.response);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedMcpResponse {
    /// The bound cryptographic facts. `accepted_signer` carries the DELEGATED key and the
    /// block's declared identity; nothing in the trust map vouches for that key.
    pub signature_facts: BoundResponseSignatureFacts,
    /// The block agreement with the caller's expected request-evidence handle — the same
    /// proposition the direct path establishes.
    pub request_evidence_agreement: BoundRequestEvidenceAgreement,
    /// The ROOT issuer kid the credential chained to — the stable server-identity
    /// coordinate under ADR-MCPRE-052, since the delegated kid rotates every TTL. The seam
    /// resolved THIS kid, not the signing kid.
    pub delegation_issuer_kid: String,
}

impl VerifiedMcpResponse {
    /// Assemble from the floor product and the block facts the full path established.
    ///
    /// `pub(crate)` because `verify` is the only legitimate producer inside this crate and
    /// no crate outside it should assemble a verdict; the fields above are `pub` for the
    /// prover's sake, so this is a convenience, not a seal.
    pub(crate) fn from_block(
        floor: CryptographicFloorVerifiedBoundResponse,
        bound_request_evidence: RequestEvidence,
        block: &HttpResponseEvidenceBlock,
    ) -> Self {
        VerifiedMcpResponse {
            floor,
            request_evidence_agreement: block_agreement(bound_request_evidence, block),
            server_signer: block.server_signer.clone(),
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
    use crate::block::SignerSlot;
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

    fn agreement(handle: RequestEvidence) -> BoundRequestEvidenceAgreement {
        BoundRequestEvidenceAgreement {
            bound_request_evidence: handle.clone(),
            body_request_evidence: handle,
        }
    }

    #[test]
    fn a_bound_full_response_states_its_binding_without_an_option() {
        let expected = RequestEvidence::from_signature_base(b"req");
        let full = VerifiedMcpResponse {
            floor: bound_floor(),
            request_evidence_agreement: agreement(expected.clone()),
            server_signer: actor("resp-1").identity,
        };
        assert_eq!(
            full.request_evidence_agreement.bound_request_evidence,
            expected
        );
        assert_eq!(
            full.request_evidence_agreement.body_request_evidence,
            full.request_evidence_agreement.bound_request_evidence
        );
        assert_eq!(full.server_signer.keyid, "resp-1");
    }

    #[test]
    fn a_delegated_response_states_its_issuer_without_an_option() {
        let expected = RequestEvidence::from_signature_base(b"req");
        let delegated = VerifiedDelegatedMcpResponse {
            signature_facts: bound_floor().signature_facts(),
            request_evidence_agreement: agreement(expected),
            delegation_issuer_kid: "root-1".into(),
        };
        // The chain fact is not an `Option` that a consumer must interpret: the type is
        // reached only by a path that verified the chain.
        assert_eq!(delegated.delegation_issuer_kid, "root-1");
        assert_eq!(
            delegated.signature_facts.accepted_signer.identity.keyid,
            "resp-1"
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
