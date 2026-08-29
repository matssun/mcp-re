// SPDX-License-Identifier: Apache-2.0
//! The load-balancer ingress-assertion form (ADR-MCPS-023 Tier 3).

/// The load balancer's assertion-verification material.
///
/// Only this form can hold it. It used to be a sibling field of the `binding` selector, so
/// a deployment could name a load-balancer key while binding end-to-end — a value nothing
/// would consult, and a boundary clause existed to say so.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IngressAssertionRequest {
    /// `(key_id, base64url-ed25519-pub)` of the load balancers whose assertions this node
    /// verifies. An empty set verifies nothing, which the boundary refuses: the form would
    /// reject every request while reporting that request-bound ingress is in force.
    pub verification_keys: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty set is representable and refused elsewhere — it is a state an operator
    /// can ask for, not one the type should hide.
    #[test]
    fn the_verification_set_can_be_empty_and_is_judged_at_the_boundary() {
        assert!(IngressAssertionRequest::default()
            .verification_keys
            .is_empty());
    }
}
