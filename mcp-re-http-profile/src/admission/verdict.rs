// SPDX-License-Identifier: Apache-2.0
//! What one admission check established, as two kinds of answer.
//!
//! Its own file because the distinction it draws is an authority boundary, not a field.
//! [`VerifiedAdmission`](super::VerifiedAdmission) says what is true of the CALL;
//! [`AdmissionVerdict`] says what this check could SEE, and only the second decides whether
//! a stateful owner may serve. Keeping them in one type is what let a `degraded: bool` be
//! read past — R11-014.

use super::VerifiedAdmission;

/// What ONE call's check established — and, for the degraded arm, what it did NOT.
///
/// Replaces a `degraded: bool` on the verdict body. The distinction is not a property of
/// the admitted call, it is a property of what this check could SEE, and a boolean is a
/// thing a second enforcement point can read past without the compiler noticing. Here the
/// two arms are two types of answer, so a consumer that wants permission has to say which
/// one it is handling.
///
/// Neither arm is a replica-wide statement. Elapsed outage time is replica HISTORY, not a
/// property of one assertion, and this relation is stateless: it sees one call against one
/// snapshot and cannot establish how long the authority has been unreachable. That bound
/// is the stateful admission enforcer's, through its own monotonic `DegradedWindow`, and
/// THM-0005 says in as many words that it does not establish it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// The authoritative current-state relation holds: the state is about this workload,
    /// at the bound generation, and admitted.
    Live(VerifiedAdmission),
    /// Authoritative state was unavailable, the deployment explicitly opted into degraded
    /// operation, and the assertion satisfies the assertion-level freshness rules.
    ///
    /// **A CANDIDATE, NOT A PERMISSION.** Turning one into a serve is the stateful owner's
    /// decision and requires its window to say this replica is still inside P. A consumer
    /// that maps this arm straight onto success has reproduced the defect the type exists
    /// to prevent — R11-014, where the bound lived at one call site rather than in the
    /// value that decides.
    DegradedCandidate(VerifiedAdmission),
}

impl AdmissionVerdict {
    /// The admitted call, whichever arm established it.
    ///
    /// Both arms carry the same facts about the CALL — id, generation, presenter, status.
    /// They differ only in what was seen, so a consumer reading the call's identity does
    /// not have to branch; one deciding whether to SERVE does.
    #[must_use]
    pub fn verified(&self) -> &VerifiedAdmission {
        match self {
            AdmissionVerdict::Live(v) | AdmissionVerdict::DegradedCandidate(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmissionStatus;

    fn admitted() -> VerifiedAdmission {
        VerifiedAdmission {
            admission_id: "workload-7".to_owned(),
            generation: 5,
            admitted_actor: "did:example:caller#k1".to_owned(),
            status: AdmissionStatus::Admitted,
        }
    }

    /// Both arms carry the same facts about the CALL, so a consumer reading the workload it
    /// was checked against does not have to branch.
    ///
    /// This is what keeps the split from costing anything at the sites that are not
    /// deciding: the branch exists for the decision, not for the identity.
    #[test]
    fn both_arms_project_the_same_facts_about_the_call() {
        let live = AdmissionVerdict::Live(admitted());
        let candidate = AdmissionVerdict::DegradedCandidate(admitted());
        assert_eq!(live.verified(), candidate.verified());
        assert_eq!(live.verified().admission_id, "workload-7");
        assert_eq!(live.verified().status, AdmissionStatus::Admitted);
    }

    /// The two arms are DISTINGUISHABLE, which is the whole of what the type buys over the
    /// `degraded: bool` it replaced.
    ///
    /// Stated as a control because the property that matters is exactly that they do not
    /// compare equal: a derive that made them equal, or a future arm folded onto another,
    /// would let a consumer reach permission without naming which answer it had.
    #[test]
    fn a_candidate_is_not_a_live_verdict() {
        assert_ne!(
            AdmissionVerdict::Live(admitted()),
            AdmissionVerdict::DegradedCandidate(admitted()),
        );
    }

    /// `VerifiedAdmission` carries NO degraded flag.
    ///
    /// The regression this catches is the tempting compatibility shim: re-adding a boolean
    /// beside the variants so an old consumer keeps compiling. Two representations of one
    /// fact can disagree, and the boolean is the one a second enforcement point reads past
    /// — which is R11-014 itself. The check is structural: the struct's debug rendering is
    /// its field list, and a re-added flag appears in it.
    #[test]
    fn the_admitted_call_carries_no_degraded_flag() {
        let rendered = format!("{:?}", admitted());
        assert!(
            !rendered.contains("degraded"),
            "the degraded fact belongs to the verdict's arm, not to a field: {rendered}"
        );
    }
}
