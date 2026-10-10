// SPDX-License-Identifier: Apache-2.0
//! The authoritative admission state a PEP holds for ONE workload — #415 §4.3, THM-0004.
//!
//! # Why this is a module and not two public fields
//!
//! The state carried a generation and a status and nothing else. Both are *properties of*
//! an admission; neither says WHICH admission they are properties of. A generation is a
//! per-workload counter, so generations collide across workloads by construction, and a
//! value describing workload B is therefore a perfectly plausible answer to a question
//! about workload A: same shape, same `generation`, `Admitted`.
//!
//! Nothing in the type refused that. What refused it was that every lookup on the serving
//! path happened to pass the id it had just looked up. That is a convention held at the
//! call sites, and the R-SEAL test asks the opposite question — *can the check be deleted
//! and still leave an invalid value unconstructible?* A state with no subject coordinate
//! fails it outright: there is no check to delete, because there was never anything to
//! compare.
//!
//! So the subject is a member: a state cannot be built without naming the workload it
//! describes. `#[non_exhaustive]` makes [`AuthoritativeAdmission::new`] the only way to
//! build one outside this crate, which is what forces the subject to be named; that is all
//! it does. An adapter that reads a record out of a store must therefore name the id it
//! looked the record up under, which the store's own key already carried.
//!
//! # What this type does not seal
//!
//! This type is the semantic fact and is deliberately freely constructible: `new` is `pub`
//! and checks nothing, the fields are `pub`, and the type is `Clone`, so any holder can
//! build or overwrite one. Possessing an `AuthoritativeAdmission` therefore says nothing
//! about who asserted it, and the postcondition of `check_admission` is conditional on the
//! caller supplying authenticated state.
//!
//! The fields are `pub` because the PROVER requires it. Verus refuses
//! `external_type_specification` on a datatype with non-public fields, and the contract on
//! `check_admission` is this theorem's primary evidence: `state.admission_id@ ==
//! binding.admission_id@` is a conjunct of the postcondition, not a step in the body. The
//! alternative is an opaque datatype with the three members re-introduced as uninterpreted
//! spec functions: three new trusted assumptions, and generation and status demoted from
//! transparent field reads to axioms. Private fields would cost the machine-checked
//! conjunct, so the fact is not sealed.
//!
//! Authenticated provenance is owned by [`record::CurrentAdmissionState`], whose
//! representation is private and whose only constructor is
//! [`record::verify_admission_state_record`]. The enforcement point obtains state only
//! through it and passes `state()` to the currency check.

/// The AUTHENTICATED form of this fact: what the admission authority publishes, and the
/// verification that is the only way to obtain a state the enforcement point will act on.
///
/// A submodule rather than a sibling because it is the same fact with a provenance: the
/// type here is what the currency check consumes, and `record` is what says the deployment
/// is entitled to consume it.
pub mod record;

use crate::admission::AdmissionStatus;

/// The authoritative state an admission authority holds for one workload (§4.3).
///
/// Fed by Layer 1 push-invalidation; how it is fed is out of scope here. What is in scope
/// is that the value says whose state it is, so a currency comparison cannot silently be
/// made against another workload's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthoritativeAdmission {
    /// The workload this state is ABOUT. Compared against the call's binding before
    /// generation or status can establish anything.
    pub admission_id: String,
    /// The current generation. A call bound to an OLDER generation is stale.
    pub generation: u64,
    /// The current status. Only `Admitted` permits a call.
    pub status: AdmissionStatus,
}

impl AuthoritativeAdmission {
    /// The authoritative state for `admission_id`, at `generation`, with `status`.
    ///
    /// Builds the semantic fact for a named workload, with no provenance check. A caller
    /// must say which workload it is describing, because the fact is not well formed
    /// without naming it.
    pub fn new(admission_id: String, generation: u64, status: AdmissionStatus) -> Self {
        AuthoritativeAdmission {
            admission_id,
            generation,
            status,
        }
    }

    /// The workload this state describes.
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }

    /// The authority's current generation for that workload.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The authority's current status for that workload.
    pub fn status(&self) -> AdmissionStatus {
        self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subject_is_projected_back_exactly_as_supplied() {
        let state = AuthoritativeAdmission::new("wl-a".to_owned(), 7, AdmissionStatus::Admitted);
        assert_eq!(state.admission_id(), "wl-a");
        assert_eq!(state.generation(), 7);
        assert_eq!(state.status(), AdmissionStatus::Admitted);
    }

    #[test]
    fn two_workloads_at_the_same_generation_are_different_states() {
        // The collision the identity coordinate exists for. Before it, these two values
        // were EQUAL, and a lookup returning the wrong one was undetectable.
        let a = AuthoritativeAdmission::new("wl-a".to_owned(), 7, AdmissionStatus::Admitted);
        let b = AuthoritativeAdmission::new("wl-b".to_owned(), 7, AdmissionStatus::Admitted);
        assert_ne!(a, b);
    }
}
