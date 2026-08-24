// SPDX-License-Identifier: Apache-2.0
//! The request-side adapter — the ONE producer of a verified request subject, and a CHILD
//! of the binding authority so that it is the only descendant reaching the constructor.
//!
//! The same shape as the `rustls` and X.509 adapters: the foreign dependency is confined to
//! one file, and what crosses the boundary is a named semantic value rather than a
//! representation. Nothing else in `communication_assurance` sees a request type.
//!
//! # Which coordinate is taken, and which is deliberately not
//!
//! [`ActorIdentity`] separates four facts, and only one of them is *who this actor is*:
//!
//! ```text
//! role          the trust ROLE the resolver assigned          request-side trust fact
//! trust_domain  the resolution CONTEXT                        request-side trust fact
//! subject       WHO the resolved actor is                     <- the binding coordinate
//! keyid         which SIGNING CREDENTIAL verified it          request-side trust fact
//! ```
//!
//! `ActorIdentity::actor_id()` is the injective `role:trust_domain:subject:keyid` join, and
//! it is the canonical coordinate for replay keys, audit and trusted-key identity. It is
//! the WRONG operand for *the same principal*, and using it had two concrete costs:
//! requiring `keyid` in a certificate couples TLS certificate issuance to every signing-key
//! rotation, and requiring `trust_domain` asserts a channel-side fact the channel never
//! established. Both are exactly the authority conflation ADR-MCPRE-063 and -064 exist to
//! remove.
//!
//! Nothing is weakened by taking the subject alone. The role, the trust domain, the signing
//! key and the signer slot were all established by the request verifier and the trust seam
//! before this adapter runs, and they remain facts owned by those authorities.

use mcp_re_http_profile::ResolvedActor;

use super::VerifiedRequestSubject;

/// The subject the request verifier resolved for this request's signer.
///
/// `pub(crate)`: the serving path lives outside this module tree and needs to turn its
/// verified request into the semantic value. The widening buys exactly one capability —
/// projecting the resolved actor's subject — and the CONSTRUCTOR it calls stays private to
/// the owner, so widening this entrance does not widen production.
pub(crate) fn verified_request_subject(actor: &ResolvedActor) -> VerifiedRequestSubject {
    VerifiedRequestSubject::resolved(actor.identity.subject.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::SignerSlot;

    fn actor(role: &str, trust_domain: &str, subject: &str, keyid: &str) -> ResolvedActor {
        ResolvedActor {
            identity: ActorIdentity {
                role: role.to_string(),
                trust_domain: trust_domain.to_string(),
                subject: subject.to_string(),
                keyid: keyid.to_string(),
            },
            verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]).public_key(),
            slot: SignerSlot::Request,
        }
    }

    #[test]
    fn the_subject_is_taken_and_the_composite_actor_id_is_not() {
        // The ruling, as a measurement. `actor_id()` is the replay/audit coordinate; the
        // binding coordinate is the subject alone. If these were ever equal, a deployment
        // would have to mint its escaped composite into a certificate SAN.
        let resolved = actor(
            "client",
            "example.org",
            "spiffe://example.org/agent-1",
            "key-a",
        );
        let subject = verified_request_subject(&resolved);

        assert_eq!(subject.as_str(), "spiffe://example.org/agent-1");
        assert_ne!(
            subject.as_str(),
            resolved.actor_id(),
            "the composite is not a communication-peer identifier"
        );
    }

    #[test]
    fn a_signing_key_rotation_does_not_change_the_binding_coordinate() {
        // The control that pins WHY the subject is the operand. Requiring `keyid` would
        // couple certificate issuance to every signing-key rotation: the same principal,
        // one new key, and every certificate in the fleet would have to be reissued.
        let before = verified_request_subject(&actor(
            "client",
            "example.org",
            "spiffe://example.org/agent-1",
            "key-a",
        ));
        let after = verified_request_subject(&actor(
            "client",
            "example.org",
            "spiffe://example.org/agent-1",
            "key-b-rotated",
        ));
        assert_eq!(
            before, after,
            "rotating a signing credential does not make the peer a different principal"
        );
    }

    #[test]
    fn a_different_subject_is_a_different_coordinate_under_the_same_role_and_domain() {
        // The negative that keeps the projection from being vacuous: role and trust domain
        // are held fixed, so only the subject can account for the difference.
        let a = verified_request_subject(&actor(
            "client",
            "example.org",
            "spiffe://example.org/agent-1",
            "key-a",
        ));
        let b = verified_request_subject(&actor(
            "client",
            "example.org",
            "spiffe://example.org/agent-2",
            "key-a",
        ));
        assert_ne!(a, b);
    }
}
