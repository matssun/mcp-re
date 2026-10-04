// SPDX-License-Identifier: Apache-2.0
//! What an inner plane says about how long a dispatch it granted may still be running.
//!
//! Its own file because it is its own authority. [`PreparedInnerDispatch`] owns the
//! CAPABILITY to transmit; this owns the plane's statement about COMPLETION, and the
//! serving path needs the second to decide, before the execution threshold, whether the
//! response it will sign can still be fresh when the dispatch ends. Two facts, two owners
//! — and keeping them apart is what stops a caller holding a capability from one plane
//! beside a bound from another.

use std::time::Duration;

/// How long a dispatch begun from a prepared capability may still be running.
///
/// A property of the INNER PLANE, projected by the plane that took the capability. The
/// serving path needs it to decide, before the execution threshold, whether the response
/// it will eventually sign can still be fresh when the dispatch reaches its worst
/// permitted completion instant — and it must not reach through this seam to a concrete
/// pool's timeout field to find out, because an inner plane is whatever implements the
/// trait.
///
/// [`Unstated`](DispatchCompletionBound::Unstated) is a real answer and not a default. An
/// implementation that cannot bound its own completion cannot support a claim about what
/// is true at that completion, and the serving path refuses rather than choosing a number
/// on its behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchCompletionBound {
    /// The plane gives up after this long, so a dispatch begun at `t` has resolved — with
    /// an answer, or as [`DispatchedOutcome::Indeterminate`] — no later than `t + this`.
    Within(Duration),
    /// This plane states no finite bound on how long a dispatch may run.
    Unstated,
}

impl DispatchCompletionBound {
    /// The latest unix second a dispatch begun at `started` may still be running.
    ///
    /// `None` when the bound is [`Unstated`](DispatchCompletionBound::Unstated) — there is
    /// no such instant — and saturating at `i64::MAX`, so an absurd configured timeout
    /// yields the end of representable time rather than wrapping into the past.
    #[must_use]
    pub fn latest_completion(self, started: i64) -> Option<i64> {
        let DispatchCompletionBound::Within(d) = self else {
            return None;
        };
        Some(started.saturating_add(Self::whole_seconds(d)))
    }

    /// `d` as whole unix seconds, ROUNDED UP.
    ///
    /// The question downstream is asked in whole seconds, so a sub-second remainder still
    /// ends inside the next one: rounding down would claim the dispatch finishes earlier
    /// than it may, and the case it gets wrong is exactly the one at the edge of the
    /// window. Saturating, so an absurd configured timeout yields the end of representable
    /// time rather than wrapping into the past.
    fn whole_seconds(d: Duration) -> i64 {
        let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
        if d.subsec_nanos() > 0 {
            secs.saturating_add(1)
        } else {
            secs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DispatchCompletionBound;
    use std::time::Duration;

    #[test]
    fn an_unstated_bound_has_no_completion_instant() {
        assert_eq!(DispatchCompletionBound::Unstated.latest_completion(1_000), None);
    }

    #[test]
    fn a_sub_second_remainder_is_counted_as_the_next_whole_second() {
        let at = |d| DispatchCompletionBound::Within(d).latest_completion(1_000);
        assert_eq!(at(Duration::ZERO), Some(1_000));
        assert_eq!(at(Duration::from_secs(30)), Some(1_030));
        assert_eq!(at(Duration::from_millis(29_500)), Some(1_030));
        assert_eq!(at(Duration::from_nanos(1)), Some(1_001));
    }

    #[test]
    fn a_bound_past_the_end_of_representable_time_saturates_rather_than_wrapping() {
        let max = i64::MAX.unsigned_abs();
        assert_eq!(
            DispatchCompletionBound::Within(Duration::from_secs(max)).latest_completion(1_000),
            Some(i64::MAX)
        );
        assert_eq!(
            DispatchCompletionBound::Within(Duration::new(max, 1)).latest_completion(0),
            Some(i64::MAX)
        );
        assert_eq!(
            DispatchCompletionBound::Within(Duration::MAX).latest_completion(0),
            Some(i64::MAX)
        );
    }
}
