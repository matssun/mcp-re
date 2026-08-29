// SPDX-License-Identifier: Apache-2.0
//! What an enforcing admission gate is inhabited by.

use super::AdmissionAvailabilityRequest;
use crate::deployment_request::SharedStoreRequest;

/// The inputs an applied gate cannot exist without.
///
/// Members rather than siblings, and that is the whole of the change: a gate that is
/// applied HAS an authority and a record, so "enforcing without one" is not a state to
/// refuse but a value that cannot be built. What is still representable — and still refused
/// at the boundary — is an authority that names nothing, because a `String` can be empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionGateRequest {
    /// The key id an assertion must present for its issuer to be recognised. A kid never
    /// introduces trust: an assertion naming any other issuer is refused.
    pub authority_kid: String,
    /// The authority's Ed25519 public key, base64url, no padding.
    pub authority_pubkey_b64url: String,
    /// The shared authoritative record a revocation is written to and every replica reads.
    pub store: SharedStoreRequest,
    /// What this deployment does when that record cannot be reached.
    pub availability: AdmissionAvailabilityRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store is a member, so an applied gate always names one. The clause that refused
    /// an enforcing deployment with no record has no configuration left to examine.
    #[test]
    fn an_applied_gate_always_names_the_record_it_compares_against() {
        let gate = AdmissionGateRequest {
            authority_kid: "a".to_string(),
            authority_pubkey_b64url: "k".to_string(),
            store: SharedStoreRequest::redis("redis://h:6379"),
            availability: AdmissionAvailabilityRequest::FailClosed,
        };
        assert_eq!(gate.store.locator(), "redis://h:6379");
    }
}
