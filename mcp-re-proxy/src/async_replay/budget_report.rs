// SPDX-License-Identifier: Apache-2.0
//! Saying that a refusal was a BUDGET refusal and not a store outage.
//!
//! The wire token is frozen and says only `replay_cache_unavailable`, which is also what a
//! genuine backend outage says. Without a line an operator paging on that token investigates
//! store health while the real cause is one signature-valid peer over its quota — the very
//! mechanism the budget added, otherwise unobservable.
//!
//! One owner rather than one per store, because both levels refuse for the same reason and
//! had written the same sentence twice. Two copies of an operator-facing line are two
//! chances for them to drift into describing different things.
//!
//! # Two rules, and each of them is why this is not an `eprintln!` at the refusal site
//!
//! **Outside the guard.** Both callers decide under a mutex that every serving core shares.
//! A blocking stderr write inside it serialises the whole tier behind a file descriptor the
//! proxy does not control, in a future with no await point, on a path any signature-valid
//! peer can drive.
//!
//! **Non-panicking.** `eprintln!` panics when the write fails — a closed pipe, a full buffer
//! with a dead reader. Unwinding at the refusal site would do it with the guard held,
//! poisoning the mutex permanently, after which every reserve on the replica refuses for the
//! process lifetime. A diagnostic must not be able to take the control down, so the write
//! result is discarded: losing the line is the correct outcome.
//!
//! # Paced by the process, not by the caller
//!
//! A peer over its quota drives the refusal on every request. One line per refusal would
//! hand that peer the write rate of this process's stderr. The first is reported, then a
//! decade scale — 1, 10, 100, … — and every line carries the running total, so a reader can
//! tell a single over-quota actor from a sustained one without a line per refusal.

use std::sync::atomic::{AtomicU64, Ordering};

/// Why one reserve was refused, as a value that outlives the guard.
///
/// The numbers are read under the lock and the sentence is built after it is dropped, which
/// is the whole point: a refusal is a fact about state, and rendering it is not.
pub(super) struct BudgetRefusal {
    /// What the actor already holds.
    pub(super) held: usize,
    /// What its fair share is.
    pub(super) budget: usize,
    /// What the level is holding in total.
    pub(super) level: usize,
    /// The level's ceiling.
    pub(super) max_entries: usize,
}

impl BudgetRefusal {
    /// The four numbers, read under the guard.
    pub(super) fn new(held: usize, budget: usize, level: usize, max_entries: usize) -> Self {
        BudgetRefusal {
            held,
            budget,
            level,
            max_entries,
        }
    }

    /// The frozen wire outcome. `replay_cache_unavailable` is the only token there is, so
    /// the detail string is where the two levels say which of them refused.
    pub(super) fn into_unavailable(self, level: &'static str) -> super::ReplayStoreError {
        super::ReplayStoreError::Unavailable {
            details: format!(
                "{level}: actor holds {} of its {} retained-entry budget while the {level} \
                 is at {} of {} entries",
                self.held, self.budget, self.level, self.max_entries
            ),
        }
    }
}

/// A per-level counter that paces the line. Never taken under the refusal's lock.
#[derive(Debug, Default)]
pub(super) struct BudgetRefusalReporter {
    reported: AtomicU64,
}

impl BudgetRefusalReporter {
    /// Refuse: report at the paced rate, and hand back the wire outcome.
    ///
    /// One call rather than a struct literal plus a report plus an error at each site —
    /// the two levels then cannot come to render the same refusal differently, which is
    /// what they had done.
    pub(super) fn refuse(
        &self,
        level_name: &'static str,
        refusal: BudgetRefusal,
        actor: &str,
    ) -> super::ReplayStoreError {
        let _ = self.report(level_name, &refusal, actor);
        refusal.into_unavailable(level_name)
    }

    /// Report `refusal` if this is the first, or the next on the decade scale.
    ///
    /// `level` names which of the two budget levels refused, so one line is not mistaken
    /// for the other. Returns whether a line was emitted — which is what lets a battery
    /// COUNT the emissions instead of re-deriving the pacing rule and agreeing with itself.
    pub(super) fn report(&self, level: &'static str, refusal: &BudgetRefusal, actor: &str) -> bool {
        use std::io::Write;
        let seen = self.reported.fetch_add(1, Ordering::Relaxed);
        // Class C: `ilog10` of a non-zero `u64` is at most 19 and the `min` caps the
        // exponent at 6, so the `pow` cannot overflow.
        #[allow(clippy::arithmetic_side_effects)]
        let decade = 10u64.pow(seen.checked_ilog10().unwrap_or(0).min(6));
        if seen != 0 && !seen.is_multiple_of(decade) {
            return false;
        }
        let total = seen.saturating_add(1);
        let _ = writeln!(
            std::io::stderr().lock(),
            "mcp-re-proxy: replay budget refusal (NOT a store outage): actor holds {} of its \
             {} entries with the {level} at {} of {}; actor={actor}; {total} such refusals so \
             far on this replica",
            refusal.held,
            refusal.budget,
            refusal.level,
            refusal.max_entries,
        );
        true
    }

    /// How many refusals have been counted. Every refusal is counted even when its line is
    /// suppressed, so the total the reported lines carry stays true.
    #[cfg(test)]
    pub(super) fn counted(&self) -> u64 {
        self.reported.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal() -> BudgetRefusal {
        BudgetRefusal {
            held: 4,
            budget: 3,
            level: 4,
            max_entries: 4,
        }
    }

    /// A peer over its quota cannot set this process's stderr write rate. 120 refusals do
    /// not make 120 lines — and every one is still counted, so the totals stay true.
    #[test]
    fn refusals_are_paced_by_the_process_and_counted_in_full() {
        let reporter = BudgetRefusalReporter::default();
        // COUNTED, not predicted. Re-deriving the pacing rule here would produce a test
        // that agrees with the implementation by construction and would keep agreeing
        // with it after the rule was weakened.
        let lines = (0..120u64)
            .filter(|_| reporter.report("tier", &refusal(), "greedy"))
            .count();
        assert_eq!(reporter.counted(), 120, "every refusal is counted");
        assert!(
            lines < 30,
            "120 refusals must not produce 120 lines, produced {lines}"
        );
        assert!(lines > 0, "the first refusal is always reported");
        // The shape the pacing promises: the first, then thinning out. Without this a
        // reporter that emitted ONLY the first line would pass the bound above.
        assert!(
            lines > 2,
            "the scale must keep reporting as the total grows, emitted {lines}"
        );
    }

    /// The write result is discarded rather than unwrapped, so a failed write cannot take
    /// the caller down. Exercised by reporting with no assumption about stderr's state —
    /// the property is that this returns at all.
    #[test]
    fn reporting_never_panics() {
        let reporter = BudgetRefusalReporter::default();
        assert!(reporter.report("store", &refusal(), "actor-with-\u{1F}-control-bytes"));
    }
}
