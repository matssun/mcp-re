// SPDX-License-Identifier: Apache-2.0
//! The facts a verified response establishes REGARDLESS of what authorized its signer.
//!
//! A response signature is accepted under a key, and something has to make that key
//! acceptable. There are two such somethings and they are not the same proposition:
//!
//! ```text
//!   trust-seam authorization ───────┐
//!                                   ├──> [Bound|Unbound]ResponseSignatureFacts
//!   delegation-chain authorization ─┘
//! ```
//!
//! On the direct path the presented keyid is resolved through the deployment's trust seam
//! for the `Response` slot, and the seam's answer IS the accepted signer. On the delegated
//! path (ADR-MCPRE-052 §3) the seam resolves the credential's ROOT ISSUER; the signing key
//! is a delegated key that appears in no trust map, and what authorizes it is the
//! credential chain.
//!
//! This module owns the shared half and nothing else. It carries no `ResolvedActor`, no
//! credential and no issuer kid, so no value defined here can be read as a statement about
//! WHY a signer was acceptable — that belongs to the product that contains these facts,
//! in [`super`].

use mcp_re_core::VerificationKey;

use crate::block::ActorIdentity;
use crate::RequestEvidence;

/// The signer a response signature was accepted under: the identity the verifier
/// attributed the response to, and the public key the signature actually verified under.
///
/// It records WHO, and never WHY. Whether the deployment's trust seam vouched for that
/// keyid or a delegation credential authorized it is a different proposition, carried by
/// the product that contains these facts. Holding this alone establishes neither.
#[derive(Debug, Clone)]
pub struct AcceptedResponseSigner {
    /// The identity the response is attributed to.
    pub identity: ActorIdentity,
    /// The key the signature verified under.
    pub verification_key: VerificationKey,
}

/// The cryptographic facts a successfully verified **request-bound** response establishes,
/// whatever authorized its signer.
///
/// The covered `Content-Digest` agreed with the body, the signature parameters were
/// admitted as current, and the RFC 9421 signature verified over a base whose `;req`
/// components were resolved against the concrete request supplied to the call, under
/// [`AcceptedResponseSigner::verification_key`].
///
/// It is a different type from [`UnboundResponseSignatureFacts`] because the coverage
/// difference is the security difference, not a field.
#[derive(Debug, Clone)]
pub struct BoundResponseSignatureFacts {
    /// The signer the signature was accepted under — WHO, not WHY.
    pub accepted_signer: AcceptedResponseSigner,
    /// The response signature-base handle, under the response role label.
    pub response_signature_base_digest: RequestEvidence,
}

/// The cryptographic facts a successfully verified **unbound** response establishes,
/// whatever authorized its signer.
///
/// The covered `Content-Digest` agreed with the body, the signature parameters were
/// admitted as current, and the signature verified over a base covering ONLY response
/// components — a `;req` component is refused as malformed, because no request exists to
/// resolve it against.
#[derive(Debug, Clone)]
pub struct UnboundResponseSignatureFacts {
    /// The signer the signature was accepted under — WHO, not WHY.
    pub accepted_signer: AcceptedResponseSigner,
    /// The response signature-base handle, under the response role label.
    pub response_signature_base_digest: RequestEvidence,
}

/// The block agreement a **full-profile bound** response establishes, on either
/// authorization path: the response evidence block parsed and validated under the profile
/// tag, and the `request_evidence` handle it carried equals the handle the caller supplied.
///
/// Both handles are retained because an audit record wants the received value, not only
/// the verdict that it matched.
#[derive(Debug, Clone)]
pub struct BoundRequestEvidenceAgreement {
    /// The request evidence handle the caller required this response to bind to.
    pub bound_request_evidence: RequestEvidence,
    /// The handle the response block carried, compared equal to
    /// [`Self::bound_request_evidence`].
    pub body_request_evidence: RequestEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;

    fn identity(keyid: &str) -> ActorIdentity {
        ActorIdentity {
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
            keyid: keyid.into(),
        }
    }

    /// The shared facts name a signer and a base handle, and NOTHING that could be read as
    /// an authorization decision. That absence is the module's whole contribution: a
    /// consumer holding these facts cannot mistake them for a trust-store answer.
    #[test]
    fn the_shared_facts_carry_who_signed_and_no_authorization() {
        let facts = BoundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: identity("resp-1"),
                verification_key: SigningKey::from_seed_bytes(&[9u8; 32]).public_key(),
            },
            response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
        };
        assert_eq!(facts.accepted_signer.identity.keyid, "resp-1");
        assert_eq!(facts.response_signature_base_digest.digest_alg, "sha256");
    }

    /// Bound and unbound facts are DIFFERENT TYPES because the coverage difference is the
    /// security difference. Their fields are identical, which is exactly why a single type
    /// would have been the tempting mistake.
    #[test]
    fn bound_and_unbound_facts_are_not_the_same_type() {
        fn needs_unbound(_: &UnboundResponseSignatureFacts) {}
        let unbound = UnboundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: identity("resp-2"),
                verification_key: SigningKey::from_seed_bytes(&[8u8; 32]).public_key(),
            },
            response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
        };
        needs_unbound(&unbound);
    }

    #[test]
    fn an_agreement_records_both_handles_not_only_the_verdict() {
        let handle = RequestEvidence::from_signature_base(b"req");
        let agreement = BoundRequestEvidenceAgreement {
            bound_request_evidence: handle.clone(),
            body_request_evidence: handle.clone(),
        };
        assert_eq!(agreement.bound_request_evidence, handle);
        assert_eq!(agreement.body_request_evidence, handle);
    }
}
