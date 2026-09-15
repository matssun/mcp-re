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
    /// How old a record read from that store may be and still be acted on — the
    /// deployment's revocation-currentness promise for the AUTHENTICATED record.
    ///
    /// A member of the applied gate rather than an optional sibling: a signed record that
    /// never goes out of date is one a party with store-write access can restore forever,
    /// so a deployment that verifies records has, necessarily, said how long one lives.
    /// `NonZeroU64` because a zero-width window admits nobody — that is a broken gate, not
    /// a stricter one.
    pub record_max_age_secs: std::num::NonZeroU64,
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
            record_max_age_secs: std::num::NonZeroU64::new(60).expect("nonzero"),
        };
        assert_eq!(gate.store.locator(), "redis://h:6379");
    }
}
