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
//! # What seals it, given that the fields are `pub`
//!
//! `#[non_exhaustive]`, and here that is not the weak choice the workspace rules warn
//! about. Those rules say `#[non_exhaustive]` seals nothing BECAUSE it binds only other
//! crates, and an owner's consumers usually live in the owner's own crate. That premise is
//! false for this owner: every consumer of authoritative admission state — the Redis
//! source, the in-memory source, the enforcer, every integration test — is in
//! `mcp-re-proxy`. Out there the struct literal is refused outright, so [`Self::new`] is
//! the only construction and it cannot be called without naming the workload. Inside this
//! crate the consumers are `check_admission`, which is this authority's own decision
//! procedure, and its Verus contract.
//!
//! The fields are `pub` because the PROVER requires it. Verus refuses
//! `external_type_specification` on a datatype with non-public fields, and the contract on
//! `check_admission` is this theorem's primary evidence: `state.admission_id@ ==
//! binding.admission_id@` is a conjunct of the postcondition, not a step in the body. The
//! alternative is an opaque datatype with the three members re-introduced as uninterpreted
//! spec functions — three new trusted assumptions, and generation and status demoted from
//! transparent field reads to axioms, to buy a seal `#[non_exhaustive]` already gives
//! against every actual consumer. Private fields would cost the machine-checked conjunct
//! and buy nothing.
//!
//! Reading a field cannot produce an illegal value; only construction can, and construction
//! is what is closed.

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
