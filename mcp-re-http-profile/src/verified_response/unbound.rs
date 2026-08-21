// SPDX-License-Identifier: Apache-2.0
//! The two UNBOUND response products — a receipt with no request context at all.
//!
//! Each carries [`UnboundResponseSignatureFacts`]: a signature over response components
//! only, with `;req` refused as malformed because there is no request to resolve it
//! against. As on the bound side, the containing product states what authorized the
//! signer — the trust seam, or a verified credential chain.
//!
//! Neither type has a field a consumer could mistake for a request binding, and that is
//! the point of them being their own types rather than the bound ones with something
//! missing.

use crate::block::ResolvedActor;
use crate::RequestEvidence;

use super::facts::AcceptedResponseSigner;
use super::facts::UnboundResponseSignatureFacts;

/// A response whose cryptographic floor holds **with no request context at all**, with its
/// signer authorized by the **trust seam**.
///
/// The rejection-before-parse case: a signature covering only response components. A `;req`
/// component here is malformed, because there is no request to resolve it against.
///
/// This is a genuinely different proposition from
/// [`CryptographicFloorVerifiedBoundResponse`], not the same one with a field missing —
/// which is why it is a different type rather than an `Option`.
#[derive(Debug, Clone)]
pub struct CryptographicFloorVerifiedUnboundResponse {
    /// The resolved server/response signer — identity, key, and `Response` slot.
    pub resolved_server_actor: ResolvedActor,
    /// The response signature-base handle, under the response role label.
    pub response_signature_base_digest: RequestEvidence,
}

impl CryptographicFloorVerifiedUnboundResponse {
    /// The authorization-independent facts, as the delegated unbound product carries them.
    pub fn signature_facts(&self) -> UnboundResponseSignatureFacts {
        UnboundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: self.resolved_server_actor.identity.clone(),
                verification_key: self.resolved_server_actor.verification_key.clone(),
            },
            response_signature_base_digest: self.response_signature_base_digest.clone(),
        }
    }
}

/// A **delegation-authorized** preflight or rejection response, verified **explicitly
/// without request binding** (MCPRE-122).
///
/// The credential chain and the response signature under `cnf.jwk` are verified exactly as
/// in the bound case, but the signature covers only response components and no
/// request-evidence comparison is made — no trustworthy request context exists. The
/// block's `request_evidence`, if any, is diagnostic and is **not** carried here, because
/// carrying it would invite a consumer to treat it as a binding.
///
/// As with the bound delegated product, it carries the shared facts rather than a
/// [`CryptographicFloorVerifiedUnboundResponse`]: the signer is credential-authorized, not
/// seam-resolved.
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedUnboundResponse {
    /// The unbound cryptographic facts, with the credential-authorized signer. Its
    /// `accepted_signer.identity` is the block's declared `server_signer`, whose keyid was
    /// checked against the credential's delegated kid.
    pub signature_facts: UnboundResponseSignatureFacts,
    /// The ROOT issuer kid the credential chained to.
    pub delegation_issuer_kid: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ActorIdentity;
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

    #[test]
    fn the_unbound_products_carry_no_request_binding_to_misread() {
        let unbound = CryptographicFloorVerifiedUnboundResponse {
            resolved_server_actor: actor("resp-2"),
            response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
        };
        assert_eq!(unbound.resolved_server_actor.slot, SignerSlot::Response);
        assert_eq!(
            unbound.signature_facts().accepted_signer.identity.keyid,
            "resp-2"
        );
    }

    /// A delegated receipt carries the shared facts and the ROOT issuer kid, and no
    /// `ResolvedActor`: the seam answered for the root, never for the signing key, and the
    /// two are different values.
    #[test]
    fn a_delegated_receipt_carries_no_trust_seam_resolution_to_misread() {
        let delegated = VerifiedDelegatedUnboundResponse {
            signature_facts: UnboundResponseSignatureFacts {
                accepted_signer: AcceptedResponseSigner {
                    identity: actor("delegated-1").identity,
                    verification_key: SigningKey::from_seed_bytes(&[4u8; 32]).public_key(),
                },
                response_signature_base_digest: RequestEvidence::from_response_signature_base(b"r"),
            },
            delegation_issuer_kid: "root-1".into(),
        };
        assert_eq!(
            delegated.signature_facts.accepted_signer.identity.keyid,
            "delegated-1"
        );
        assert_eq!(delegated.delegation_issuer_kid, "root-1");
        assert_ne!(
            delegated.delegation_issuer_kid,
            delegated.signature_facts.accepted_signer.identity.keyid
        );
    }
}
