// SPDX-License-Identifier: Apache-2.0
//! The deployment act that enables the carrier, and the capability it confers.
//!
//! One file because they are one decision: the capability's ONLY producer is the
//! `Trusted` branch of the decision, and putting the witness anywhere else would
//! give it a second producer that never made the decision.

use std::marker::PhantomData;

/// Whether a deployment has an explicitly trusted channel to its inner server.
///
/// Default is [`VerifiedContextPolicy::Disabled`]: a PEP does not hand its
/// conclusions to a server it cannot prove it alone can reach.
///
/// # ASSUMES — the premise this value records
///
/// `Trusted` records an operator's assertion that nothing but this proxy can reach
/// the inner server. Nothing in this crate checks it and nothing can: there is no
/// signature over the carrier, by design (see the module doc). The premise is
/// discharged by the deployment topology — a loopback socket, a same-pod sidecar, a
/// UNIX socket — and by whoever reviews it. This file states the premise; it does
/// not establish it, and no code here should be read as doing so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifiedContextPolicy {
    /// Do not carry verified context. The inner server sees clean MCP only.
    #[default]
    Disabled,
    /// The channel to the inner server is trusted: only this PEP can write to it
    /// (loopback / same-pod sidecar / UNIX socket). The operator asserts this;
    /// nothing here can check it.
    Trusted,
}

impl VerifiedContextPolicy {
    /// The capability to write the carrier, if this deployment declared the channel
    /// trusted.
    ///
    /// [`super::insert_verified_context`] takes a [`TrustedInnerChannel`] by value
    /// and this is the only function that produces one, so the write is reachable
    /// only from a branch on the policy.
    ///
    /// The witness borrows `self`, so it cannot outlive the policy value it was read
    /// from and cannot be cached past the request that consulted it.
    pub fn trusted_inner_channel(&self) -> Option<TrustedInnerChannel<'_>> {
        match self {
            VerifiedContextPolicy::Disabled => None,
            VerifiedContextPolicy::Trusted => Some(TrustedInnerChannel(PhantomData)),
        }
    }
}

/// The capability to write the PEP's conclusion into a forwarded body.
///
/// # What possession establishes, exactly
///
/// That a branch on a [`VerifiedContextPolicy`] was taken and took the `Trusted`
/// arm. That is all, and it is worth stating precisely because the useful property
/// is narrow: **a caller cannot FORGET to consult the policy**, because
/// [`super::insert_verified_context`] does not accept bytes without one of these.
///
/// It does NOT establish that an operator configured this deployment `Trusted`.
/// [`VerifiedContextPolicy`] is a public enum and `Trusted` is a public data-free
/// variant, so any code in any crate can name it and read a witness out of it. The
/// private field stops a witness being conjured from nothing; it does not stop the
/// policy value being conjured. Whether the policy value in hand came from the
/// parsed deployment configuration is the configuration owner's property — in this
/// workspace `mcp-re-proxy`'s `serving_capabilities::verified_context_carrier`,
/// which projects it from `config_state::VerifiedContextState` — and it is an
/// ASSUMES here, not a check.
///
/// Neither `Clone` nor `Copy`, and consumed by value: one read of the policy
/// authorizes one write.
#[derive(Debug)]
pub struct TrustedInnerChannel<'p>(PhantomData<&'p VerifiedContextPolicy>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_trusted_deployment_yields_the_carrier_capability() {
        assert!(VerifiedContextPolicy::Trusted
            .trusted_inner_channel()
            .is_some());
        assert!(VerifiedContextPolicy::Disabled
            .trusted_inner_channel()
            .is_none());
    }

    #[test]
    fn the_default_deployment_cannot_carry_the_block() {
        assert_eq!(
            VerifiedContextPolicy::default(),
            VerifiedContextPolicy::Disabled
        );
        assert!(VerifiedContextPolicy::default()
            .trusted_inner_channel()
            .is_none());
    }
}
