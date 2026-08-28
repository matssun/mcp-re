// SPDX-License-Identifier: Apache-2.0
//! What a verified bodyless acknowledgement establishes (#418, ADR-MCPRE-052 §4).

use crate::block::ResolvedActor;
use crate::delegation::VerifiedDelegation;

/// What a verified bodyless acknowledgement establishes.
///
/// Two facts, and they are handed out together because the second one used to be
/// recovered by re-parsing the response's own headers AFTER verification had already
/// proved it. That re-parse read untrusted bytes to answer a question the verifier had
/// answered: the credential header is a COVERED component of the 202's signature (an
/// uncovered one is refused), the root signature covers the JWS header, and the credential
/// verifier requires `header.kid == claims.issuer_kid` — so the anchor is a verified
/// product, not a self-asserted label, and only this type may say so.
///
/// The representation is private and this module is its only producer. A caller pinning a
/// route's expected server signer therefore compares against the anchor the response
/// PROVABLY chained to, with no second reader of the wire bytes to disagree with the first.
#[derive(Debug)]
pub struct AcknowledgedDelegation {
    /// The delegated server actor the acknowledgement is attributed to.
    actor: ResolvedActor,
    /// The ROOT issuer kid of the delegation credential — the trust anchor this response
    /// chained to, as the credential verifier established it.
    issuer_kid: String,
}

impl AcknowledgedDelegation {
    /// Record what a completed credential verification established.
    ///
    /// Takes the whole [`VerifiedDelegation`] rather than an actor and a kid, so the two
    /// cannot be supplied from different verifications: the anchor and the signing actor
    /// are projections of ONE proved credential, and this is where that is stated.
    ///
    /// `pub(super)`, and the reason at the point of widening is that the parent module IS
    /// the verifier: it is the only code that has proved the response's signature under the
    /// delegated key and the credential under the root. No sibling exists, and a sibling
    /// added later would be inside the bodyless verifier — which is where a second producer
    /// would have to justify itself.
    pub(super) fn established(verified: VerifiedDelegation) -> Self {
        AcknowledgedDelegation {
            actor: ResolvedActor {
                identity: crate::block::ActorIdentity {
                    role: "server".to_owned(),
                    trust_domain: String::new(),
                    subject: verified.server_signer,
                    keyid: verified.delegated_kid,
                },
                verification_key: verified.delegated_key,
                slot: crate::block::SignerSlot::Response,
            },
            issuer_kid: verified.issuer_kid,
        }
    }

    /// The delegated server actor this acknowledgement is attributed to.
    pub fn actor(&self) -> &ResolvedActor {
        &self.actor
    }

    /// Take the actor, discarding the anchor.
    pub fn into_actor(self) -> ResolvedActor {
        self.actor
    }

    /// The ROOT issuer kid the credential chains to — the coordinate a route pins.
    ///
    /// Not the delegated kid, which rotates every TTL.
    pub fn issuer_kid(&self) -> &str {
        &self.issuer_kid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acknowledged(issuer_kid: &str) -> AcknowledgedDelegation {
        AcknowledgedDelegation::established(VerifiedDelegation {
            delegated_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]).public_key(),
            delegated_kid: "delegated-kid-1".to_owned(),
            server_signer: "did:example:server".to_owned(),
            issuer_kid: issuer_kid.to_owned(),
            nbf: 0,
            exp: i64::MAX,
            trust_epoch: "epoch-1".to_owned(),
        })
    }

    #[test]
    fn the_pinned_coordinate_is_the_root_anchor_and_not_the_rotating_delegated_kid() {
        // The whole reason the anchor is carried rather than re-read. A route pins the
        // ROOT issuer, which survives every delegated-key rotation; pinning the delegated
        // kid would fail the next time the short-TTL credential turned over.
        let acknowledged = acknowledged("root-kid-1");
        assert_eq!(acknowledged.issuer_kid(), "root-kid-1");
        assert_ne!(
            acknowledged.issuer_kid(),
            acknowledged.actor().identity.keyid,
            "the anchor and the signing key are different coordinates"
        );
    }

    #[test]
    fn taking_the_actor_is_the_only_way_to_consume_one() {
        // Private fields, one producer. The anchor cannot be supplied beside an actor that
        // never chained to it.
        assert_eq!(
            acknowledged("root-kid-1").into_actor().identity.subject,
            "did:example:server"
        );
    }
}
