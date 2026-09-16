// SPDX-License-Identifier: Apache-2.0
//! What completing the retention obligation established about one exchange.
//!
//! Its own file because it is a VERDICT and [`Retention`](super::Retention) is the actor.
//! The three cases are the authority: *nothing was owed*, *the record landed* and *the
//! completion did not land* are three different facts about the store's obligation, and the
//! third is the one every two-valued shape destroys.

/// What completing the retention obligation established about THIS exchange.
///
/// Three cases, and the third is the one a `bool` destroys. *Nothing was owed* and *the
/// record landed* are both "the store owes nothing further"; *the completion failed* is
/// neither, and it is the case whose marker an operator reconciles against. Collapsing it
/// into the safe side is the defect [[do-not-collapse-execution-certainty]] names.
///
/// `#[must_use]` on purpose: a post-dispatch terminal that drops this has silently forgotten
/// whether the exchange it served is accounted for, and the compiler is the only thing that
/// notices. The obligation is the ruling's, independent of which exits retain.
#[must_use = "a terminal that drops its retention outcome has forgotten whether the exchange it served is accounted for"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http_profile_serve) enum RetentionOutcome {
    /// Retention is not configured for this deployment; no crossing was ever recorded.
    NotConfigured,
    /// The terminal exchange is durable. The crossing is discharged and its marker cleared.
    Retained,
    /// The completion did not land. The crossing stands and its marker SURVIVES, which is
    /// the true statement about this exchange and not a failure to clean up.
    Failed,
}

impl RetentionOutcome {
    /// Did this exchange leave a durable retained terminal behind it?
    ///
    /// `NotConfigured` answers yes in the only sense that matters to a caller deciding
    /// whether to refuse: nothing is owed, so nothing is outstanding. The distinction
    /// between it and `Retained` is for the record, not for the decision.
    pub(in crate::http_profile_serve) fn is_accounted_for(self) -> bool {
        matches!(
            self,
            RetentionOutcome::Retained | RetentionOutcome::NotConfigured
        )
    }
}
