// SPDX-License-Identifier: Apache-2.0
//! Where a retained multi-round-trip continuation base lives (ADR-MCPS-047).

use super::SharedStoreRequest;

/// The continuation store this deployment asks for.
///
/// `None` is a POSTURE and not missing configuration: cross-replica MRTR is opportunistic,
/// its absence is announced, and an answer arriving at a replica with no correlated
/// continuation is refused rather than guessed.
///
/// Its own type rather than a second use of replay's, because it is a different fact.
/// The two may name the same Redis — that is then an operator's deployment choice, and it
/// is expressible precisely because the two roles state their stores separately (CF-12).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContinuationStoreRequest {
    /// The shared store retained continuation bases live in, where one is configured.
    pub shared: Option<SharedStoreRequest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absent is the single-replica posture, and it is the default.
    #[test]
    fn no_shared_store_is_the_default_posture() {
        assert_eq!(ContinuationStoreRequest::default().shared, None);
    }

    /// Two roles pointing at one Redis is an operator's choice the model can express,
    /// because the roles state their stores separately rather than sharing a field.
    #[test]
    fn one_redis_can_serve_two_roles_without_the_roles_becoming_one() {
        let continuation = ContinuationStoreRequest {
            shared: Some(SharedStoreRequest::redis("redis://h:6379")),
        };
        let admission = crate::deployment_request::AdmissionGateRequest {
            authority_kid: "a".to_string(),
            authority_pubkey_b64url: "k".to_string(),
            store: SharedStoreRequest::redis("redis://h:6379"),
            availability: crate::deployment_request::AdmissionAvailabilityRequest::FailClosed,
        };
        assert_eq!(
            continuation
                .shared
                .as_ref()
                .map(SharedStoreRequest::locator),
            Some(admission.store.locator())
        );
    }
}
