// SPDX-License-Identifier: Apache-2.0
//! What a request that declares no admission evidence means to the deployment.
//!
//! A posture, not a decision: the §7 gate ([`super::AdmissionEnforcer`]) reads it when a call
//! carries neither a binding nor an assertion, and nothing else consults it.

/// What a request that carries NO admission evidence means to this deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionEnforcement {
    /// Serve it. For a deployment that has not rolled admission out to every client
    /// yet — the binding is honoured when present and absent is not an error.
    Optional,
    /// Refuse it. The only setting under which "every served call acted under a
    /// current admission" is a true statement about the deployment.
    Required,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two postures are two values. A deployment that has not rolled admission out must
    /// never read as one that requires it, so the one that serves an evidence-free call and
    /// the one that refuses it cannot compare equal.
    #[test]
    fn the_two_postures_are_distinct() {
        assert_ne!(
            AdmissionEnforcement::Optional,
            AdmissionEnforcement::Required
        );
    }
}
