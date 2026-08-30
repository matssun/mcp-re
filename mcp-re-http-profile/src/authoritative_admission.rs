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
//! So the subject is a member, and it is the one that must be supplied by name. The fields
//! are not public: [`AuthoritativeAdmission::new`] is the only construction, and it cannot
//! be called without saying whose state this is. An adapter that reads a record out of a
//! store must therefore name the id it looked the record up under, which is the honest
//! answer and the one the store's own key already carried.
//!
//! # Why the fields are `pub(crate)` and not private
//!
//! The Verus contract on `crate::admission::check_admission` is this theorem's primary
//! evidence, and it is stated over these members — `state.admission_id@ ==
//! binding.admission_id@` is a conjunct of the postcondition, not a step in the body. That
//! contract lives in `admission.rs` and its type specifications in `verus_std_specs.rs`,
//! both siblings of this module, so spec-mode access to the representation is what lets the
//! prover see the relation at all. Crate visibility is bounded by exactly those two
//! consumers and by this authority's own decision procedure.
//!
//! It is NOT widened for tests, and it is not a seal against them: outside the crate — the
//! admission-source adapters in `mcp-re-proxy`, and every integration test — the
//! representation is unreachable and `new` plus the projections below are the whole
//! surface.

use crate::admission::AdmissionStatus;

/// The authoritative state an admission authority holds for one workload (§4.3).
///
/// Fed by Layer 1 push-invalidation; how it is fed is out of scope here. What is in scope
/// is that the value says whose state it is, so a currency comparison cannot silently be
/// made against another workload's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeAdmission {
    /// The workload this state is ABOUT. Compared against the call's binding before
    /// generation or status can establish anything.
    pub(crate) admission_id: String,
    /// The current generation. A call bound to an OLDER generation is stale.
    pub(crate) generation: u64,
    /// The current status. Only `Admitted` permits a call.
    pub(crate) status: AdmissionStatus,
}

impl AuthoritativeAdmission {
    /// The authoritative state for `admission_id`, at `generation`, with `status`.
    ///
    /// The only construction. A caller that does not know which workload it is describing
    /// cannot produce a value at all, which is the point: this is a fact about one
    /// admission and it is not well formed without naming it.
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
