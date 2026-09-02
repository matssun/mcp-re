// SPDX-License-Identifier: Apache-2.0
//! The actor operand of a continuation key.

/// The actor operand of a continuation key: the actor a VERIFIER resolved.
///
/// # Why this is a type and not a `&str`
///
/// The claim above the key is that the scope is the resolved actor and never one the
/// request asserted. As a `&str` operand that was a property of every call site — true
/// today because both legs happened to pass the exchange's actor, and re-decided by the
/// next site that formats an identifier of its own. The invariant belongs to the operand,
/// so the operand carries it: the only constructor takes a [`ResolvedActor`], and there is
/// no `From<String>`, no public field and no parse. A request-supplied identifier cannot be
/// made into one, which is a different statement from "no caller currently tries".
pub struct ResolvedActorId(String);

impl ResolvedActorId {
    /// The identifier of the actor the verifier resolved — the sole way to obtain one.
    pub fn of(actor: &mcp_re_http_profile::ResolvedActor) -> Self {
        ResolvedActorId(actor.actor_id())
    }

    /// The identifier, for the audit and attribution surfaces that carry it as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operand is the resolved identity, and two resolutions that differ anywhere
    /// give two operands. A control here rather than only at the key, because the key
    /// cannot tell a collision in this projection from a collision of its own.
    #[test]
    fn the_operand_is_the_resolved_identity_and_separates_its_fields() {
        let actor = |subject: &str, keyid: &str| mcp_re_http_profile::ResolvedActor {
            identity: mcp_re_http_profile::ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: keyid.into(),
            },
            verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]).public_key(),
            slot: mcp_re_http_profile::SignerSlot::Request,
        };
        let a = actor("did:example:host-a", "k-1");
        assert_eq!(
            ResolvedActorId::of(&a).as_str(),
            a.actor_id(),
            "the operand IS the resolved identity, not a re-derivation of it"
        );
        assert_ne!(
            ResolvedActorId::of(&actor("did:example:host-a", "k-1")).as_str(),
            ResolvedActorId::of(&actor("did:example:host-b", "k-1")).as_str()
        );
        assert_ne!(
            ResolvedActorId::of(&actor("did:example:host-a", "k-1")).as_str(),
            ResolvedActorId::of(&actor("did:example:host-a", "k-2")).as_str()
        );
    }
}
