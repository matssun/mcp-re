// SPDX-License-Identifier: Apache-2.0
//! The actor coordinate authorization decides over — ADR-MCPRE-065 Law A-2.
//!
//! # Why this is a product and not a string
//!
//! The two authorities below this one each bind over a different coordinate, and both are
//! right about their own question:
//!
//! ```text
//! request <-> peer binding  ->  subject equality      "same principal?"
//! admission assertion       ->  actor_id() equality   "issued to this exact signing actor"
//! ```
//!
//! Picking either one as *the* authorization coordinate would fix a single comparison
//! operand for every policy proposition anyone will ever write, and then force the facts to
//! fit it. That is the mistake ADR-MCPRE-064 Slice 4 escaped, where an operand chosen for
//! convenience made a fleet's certificates serialize the request verifier's internal trust
//! record.
//!
//! So the boundary supplies the verified dimensions and the POLICY selects the relation:
//!
//! | policy proposition | dimensions |
//! |---|---|
//! | principal-level permission | [`subject`](VerifiedAuthorizationActor::subject) |
//! | credential-specific grant | `subject` + [`keyid`](VerifiedAuthorizationActor::keyid), or [`canonical_actor_id`](VerifiedAuthorizationActor::canonical_actor_id) |
//! | trust-domain scoped role | [`role`](VerifiedAuthorizationActor::role) + [`trust_domain`](VerifiedAuthorizationActor::trust_domain) + `subject` |
//!
//! # Originating together
//!
//! These are not four independently supplied strings. A caller that could assemble them
//! would be able to pair a real subject with a role nobody resolved, and every policy above
//! would then be deciding over a half-verified actor. The representation is private to this
//! module and [`interpret_authorization_actor`] is the only producer, so an inhabitant is
//! always four facts one verifier established about one signature.
//!
//! `canonical_actor_id` is a DERIVED PROJECTION of that product, offered because a
//! credential-scoped policy legitimately wants the whole signing actor as one key. It is
//! not a second authority: it is computed here from the same identity, never accepted from
//! a caller and never re-parsed back into dimensions.

use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ResolvedActor;

/// The verifier-resolved actor, as authorization sees it.
///
/// Sealed: the representation and the constructor are private to this module, so the only
/// inhabitants are the ones [`interpret_authorization_actor`] built from a `ResolvedActor`
/// the request verifier produced. A caller cannot assert an actor, and cannot assert one
/// dimension of a real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorizationActor {
    /// Carried WHOLE rather than destructured into four fields (R-COMPOSE): the identity is
    /// the verifier's product, and `canonical_actor_id` must be ITS projection rather than
    /// a join this module reinvents.
    identity: ActorIdentity,
}

impl VerifiedAuthorizationActor {
    /// The trust role the resolver assigned.
    pub fn role(&self) -> &str {
        &self.identity.role
    }

    /// The trust domain the subject belongs to.
    pub fn trust_domain(&self) -> &str {
        &self.identity.trust_domain
    }

    /// The resolved subject — the principal, independent of which key signed.
    pub fn subject(&self) -> &str {
        &self.identity.subject
    }

    /// The RFC 9421 keyid the signature was verified under.
    pub fn keyid(&self) -> &str {
        &self.identity.keyid
    }

    /// The canonical, injective `role:trust_domain:subject:keyid` join.
    ///
    /// A derived projection for policies whose grant is scoped to the complete signing
    /// actor. Computed from this product's own identity by the authority that owns the
    /// join, so it cannot disagree with the dimensions above.
    pub fn canonical_actor_id(&self) -> String {
        self.identity.actor_id()
    }
}

/// Interpret the verifier's resolved actor as the authorization actor coordinate.
///
/// THE construction operation, and a total one: every resolved actor is a legal
/// authorization actor. There is nothing to refuse here — whether the key legitimately
/// represents the subject was settled by the trust seam before this runs, and re-deciding
/// it would be recreating an owner's semantics (R-COMPOSE).
pub fn interpret_authorization_actor(actor: &ResolvedActor) -> VerifiedAuthorizationActor {
    VerifiedAuthorizationActor {
        identity: actor.identity.clone(),
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::interpret_authorization_actor;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::ResolvedActor;
    use mcp_re_http_profile::SignerSlot;

    fn resolved(role: &str, trust_domain: &str, subject: &str, keyid: &str) -> ResolvedActor {
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
    fn every_verified_dimension_is_projected_separately() {
        // Law A-2: a policy conditioned on role receives a ROLE. It must not have to parse
        // one out of a joined string, which is how `actor_id()` became an operand of a
        // relation it was never the coordinate for.
        let a = interpret_authorization_actor(&resolved(
            "client",
            "example.org",
            "spiffe://example.org/agent-1",
            "key-a",
        ));
        assert_eq!(a.role(), "client");
        assert_eq!(a.trust_domain(), "example.org");
        assert_eq!(a.subject(), "spiffe://example.org/agent-1");
        assert_eq!(a.keyid(), "key-a");
    }

    #[test]
    fn the_canonical_id_is_the_identity_owner_s_join_not_a_second_one() {
        // A projection, not a second authority: it must equal what the identity owner
        // computes, escaping included, or two coordinates for the same actor exist.
        let actor = resolved("client", "example.org", "did:example:a:b", "key-a");
        assert_eq!(
            interpret_authorization_actor(&actor).canonical_actor_id(),
            actor.identity.actor_id()
        );
    }

    #[test]
    fn a_rotated_key_is_the_same_subject_and_a_different_canonical_actor() {
        // Both halves of Law A-2 in one control. A principal-scoped policy must not be
        // disturbed by a signing-key rotation; a credential-scoped one must be. Neither
        // reading is imposed globally — the dimensions carry both.
        let a = interpret_authorization_actor(&resolved("client", "d", "s", "key-a"));
        let b = interpret_authorization_actor(&resolved("client", "d", "s", "key-b"));
        assert_eq!(a.subject(), b.subject());
        assert_ne!(a.canonical_actor_id(), b.canonical_actor_id());
    }

    #[test]
    fn distinct_trust_domains_are_distinct_actors_under_the_same_subject() {
        // The dimension the transport binding deliberately does NOT consider. It is
        // available here because a trust-domain scoped policy is a legitimate proposition —
        // that is exactly what "the policy selects the relation" means.
        let a = interpret_authorization_actor(&resolved("client", "one.example", "s", "k"));
        let b = interpret_authorization_actor(&resolved("client", "two.example", "s", "k"));
        assert_eq!(a.subject(), b.subject());
        assert_ne!(a.trust_domain(), b.trust_domain());
        assert_ne!(a.canonical_actor_id(), b.canonical_actor_id());
    }
}
