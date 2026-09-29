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
//! hand that peer the write rate of this process's stderr. The first refusal is reported,
//! then at most one line per `LINE_INTERVAL_MS` for the whole level, each carrying the
//! running total, so a sustained refuser stays visible at any count.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// The shortest gap between two lines from one level.
const LINE_INTERVAL_MS: u64 = 10_000;

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
#[derive(Debug)]
pub(super) struct BudgetRefusalReporter {
    reported: AtomicU64,
    origin: Instant,
    last_line_ms: AtomicU64,
}

impl Default for BudgetRefusalReporter {
    fn default() -> Self {
        BudgetRefusalReporter {
            reported: AtomicU64::new(0),
            origin: Instant::now(),
            last_line_ms: AtomicU64::new(0),
        }
    }
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
        if let Some(total) = self.admit_line(self.elapsed_ms()) {
            write_line(
                &mut std::io::stderr().lock(),
                level_name,
                &refusal,
                actor,
                total,
            );
        }
        refusal.into_unavailable(level_name)
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Count this refusal; `Some(running total)` when a line is due at `now_ms`.
    ///
    /// The first refusal is always due; after that one line per `LINE_INTERVAL_MS`, and
    /// under concurrency only the caller that wins the window's swap gets it.
    fn admit_line(&self, now_ms: u64) -> Option<u64> {
        let seen = self.reported.fetch_add(1, Ordering::Relaxed);
        let total = seen.saturating_add(1);
        if seen == 0 {
            self.last_line_ms.store(now_ms, Ordering::Relaxed);
            return Some(total);
        }
        let last = self.last_line_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < LINE_INTERVAL_MS {
            return None;
        }
        self.last_line_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .ok()
            .map(|_| total)
    }

    /// How many refusals have been counted. Every refusal is counted even when its line is
    /// suppressed, so the total the reported lines carry stays true.
    #[cfg(test)]
    pub(super) fn counted(&self) -> u64 {
        self.reported.load(Ordering::Relaxed)
    }
}

/// The write result is discarded: a failed diagnostic write is lost, never unwound. The
/// actor is peer-influenced, so it is rendered `{:?}`-escaped and cannot end the field or
/// the line.
fn write_line(
    sink: &mut impl std::io::Write,
    level: &'static str,
    refusal: &BudgetRefusal,
    actor: &str,
    total: u64,
) {
    let _ = writeln!(
        sink,
        "mcp-re-proxy: replay budget refusal (NOT a store outage): actor holds {} of its \
         {} entries with the {level} at {} of {}; actor={actor:?}; {total} such refusals so \
         far on this replica",
        refusal.held, refusal.budget, refusal.level, refusal.max_entries,
    );
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

    /// 120 refusals inside one window make one line, and every one is still counted.
    #[test]
    fn a_burst_within_one_window_yields_one_line_and_is_counted_in_full() {
        let reporter = BudgetRefusalReporter::default();
        let lines = (0..120u64)
            .filter(|_| reporter.admit_line(0).is_some())
            .count();
        assert_eq!(lines, 1);
        assert_eq!(reporter.counted(), 120, "every refusal is counted");
    }

    /// The pacing does not thin out with the count: a new window reports again.
    #[test]
    fn a_sustained_refuser_stays_visible_at_any_count() {
        let reporter = BudgetRefusalReporter::default();
        for _ in 0..200_000u64 {
            let _ = reporter.admit_line(0);
        }
        assert_eq!(reporter.admit_line(LINE_INTERVAL_MS), Some(200_001));
        assert_eq!(reporter.admit_line(LINE_INTERVAL_MS), None);
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed pipe"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("closed pipe"))
        }
    }

    /// The write result is discarded rather than unwrapped, so a failed write cannot take
    /// the caller down.
    #[test]
    fn a_failed_diagnostic_write_does_not_unwind() {
        write_line(&mut FailingWriter, "store", &refusal(), "actor", 1);
        let reached = true;
        assert!(reached);
    }

    #[test]
    fn the_actor_cannot_forge_a_line_or_a_field() {
        let actor = "a\u{1F}b\nmcp-re-proxy: replay budget refusal (NOT a store outage); \
                     actor=victim; 0 such refusals so far on this replica";
        let mut out = Vec::new();
        write_line(&mut out, "store", &refusal(), actor, 7);
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text.matches('\n').count(), 1);
        assert!(text.ends_with('\n'));
        assert!(text.ends_with("; 7 such refusals so far on this replica\n"));
        assert!(text.contains("\\n"));
        assert!(text.contains("\\u{1f}"));
    }
}
