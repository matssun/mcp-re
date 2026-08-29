// SPDX-License-Identifier: Apache-2.0
//! The delegated response-signing credential this deployment mints — ADR-MCPRE-052.
//!
//! One proposition, and five parameters OF it: the rotation window, the epoch the
//! credential is bound to, and the two coordinates it is issued under. They were five
//! top-level fields sharing a name prefix, which is a family by spelling rather than by
//! type — ADR-MCPRE-067 §7's shape, without a selector.
//!
//! Nothing here is a mechanism. Which key signs the credential is
//! [`ResponseSigningRequest`](super::ResponseSigningRequest)'s; this is what the credential
//! SAYS and how long it says it for.

/// What the delegated response-signing credential is minted with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DelegatedSigningRequest {
    /// The credential's lifetime, in seconds. The rotation window's outer bound.
    pub ttl_secs: i64,
    /// How long a superseded credential stays acceptable, in seconds. Strictly inside the
    /// TTL — a rotation with no overlap has a gap, and one as wide as the TTL has no
    /// rotation.
    pub overlap_secs: i64,
    /// The trust epoch the credential is bound to. ADR-MCPRE-052 §7's hard gate: absent,
    /// no credential is minted, because a credential no epoch can invalidate is one an
    /// operator cannot withdraw.
    pub trust_epoch: Option<String>,
    /// The issuer key id stamped on it. Defaults to this deployment's own server key id.
    pub issuer_kid: Option<String>,
    /// The audience hash it is scoped to. Defaults to this deployment's own audience.
    pub audience_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two derived coordinates are `None` by default, which is what lets the owner
    /// tell an omitted value from a named one — a defaulted-at-parse field could not.
    #[test]
    fn the_derived_coordinates_start_unnamed() {
        let request = DelegatedSigningRequest::default();
        assert_eq!(request.issuer_kid, None);
        assert_eq!(request.audience_hash, None);
        assert_eq!(request.trust_epoch, None);
    }
}
