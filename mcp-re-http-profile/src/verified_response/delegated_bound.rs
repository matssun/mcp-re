// SPDX-License-Identifier: Apache-2.0
//! The delegation-authorized request-bound response product.
//!
//! Apart from `bound` because its authorization proposition — a verified credential
//! chain — is not the trust seam's.

use super::facts::BoundRequestEvidenceAgreement;
use super::facts::BoundResponseSignatureFacts;

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
///     needs_seam_authorized(delegated);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedMcpResponse {
    signature_facts: BoundResponseSignatureFacts,
    request_evidence_agreement: BoundRequestEvidenceAgreement,
    delegation_issuer_kid: String,
}

impl VerifiedDelegatedMcpResponse {
    /// Assemble from the facts a verified credential chain authorized; `crate::verify` is
    /// the only producer.
    pub(crate) fn new(
        signature_facts: BoundResponseSignatureFacts,
        request_evidence_agreement: BoundRequestEvidenceAgreement,
        delegation_issuer_kid: String,
    ) -> Self {
        Self {
            signature_facts,
            request_evidence_agreement,
            delegation_issuer_kid,
        }
    }

    /// The bound cryptographic facts. `accepted_signer` carries the DELEGATED key and the
    /// block's declared identity; nothing in the trust map vouches for that key.
    pub fn signature_facts(&self) -> &BoundResponseSignatureFacts {
        &self.signature_facts
    }

    /// The block agreement with the caller's expected request-evidence handle — the same
    /// proposition the direct path establishes.
    pub fn request_evidence_agreement(&self) -> &BoundRequestEvidenceAgreement {
        &self.request_evidence_agreement
    }

    /// The ROOT issuer kid the credential chained to — the stable server-identity
    /// coordinate under ADR-MCPRE-052, since the delegated kid rotates every TTL. The seam
    /// resolved THIS kid, not the signing kid.
    pub fn delegation_issuer_kid(&self) -> &str {
        &self.delegation_issuer_kid
    }
}

#[cfg(test)]
mod tests {
    use super::super::facts::AcceptedResponseSigner;
    use super::*;
    use crate::block::ActorIdentity;
    use crate::RequestRoleEvidence;
    use crate::ResponseRoleEvidence;
    use mcp_re_core::SigningKey;

    #[test]
    fn a_delegated_response_states_its_issuer_without_an_option() {
        let expected = RequestRoleEvidence::from_signature_base(b"req");
        let facts = BoundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: ActorIdentity {
                    role: "server".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:server".into(),
                    keyid: "resp-1".into(),
                },
                verification_key: SigningKey::from_seed_bytes(&[9u8; 32]).public_key(),
            },
            response_signature_base_digest: ResponseRoleEvidence::from_signature_base(b"r"),
        };
        let delegated = VerifiedDelegatedMcpResponse::new(
            facts,
            BoundRequestEvidenceAgreement {
                bound_request_evidence: expected.clone(),
                body_request_evidence: expected.to_digest(),
            },
            "root-1".into(),
        );
        // The chain fact is not an `Option` that a consumer must interpret: the type is
        // reached only by a path that verified the chain.
        assert_eq!(delegated.delegation_issuer_kid(), "root-1");
        assert_eq!(
            delegated.signature_facts().accepted_signer.identity.keyid,
            "resp-1"
        );
    }
}
