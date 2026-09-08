// SPDX-License-Identifier: Apache-2.0
//! The REGISTRATION BUDGET.
//!
//! One fact: **how long a registration may take, and how often it may ask.**
//!
//! It is the auditor's, not the service's. A transparency service answering `202` names
//! where to poll and may suggest how long to wait; how long this auditor is willing to
//! wait is a decision the operator made before the run, and a client that took its bound
//! from the response would have no bound at all.
//!
//! Sealed: the constructor is the only producer, and it refuses a budget that cannot
//! terminate.

use std::time::Duration;

/// The widest budget a registration may be given.
///
/// An unbounded wait is not patience, it is a run with no failure mode: the auditor
/// blocks and an operator cannot tell a slow service from a dead one.
const MAX_TIMEOUT: Duration = Duration::from_secs(3_600);

/// How long a registration may take, and how often it may poll.
///
/// # What construction proved
///
/// The interval is non-zero, the timeout is at least one interval, and the timeout is
/// bounded. A zero interval is not "poll as fast as possible" — it is a loop with no
/// progress condition, and the whole point of this value is that the run terminates.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationPolicy {
    timeout: Duration,
    interval: Duration,
}

impl RegistrationPolicy {
    /// A budget, or the first rule it breaks.
    pub fn new(timeout: Duration, interval: Duration) -> Result<Self, String> {
        if interval.is_zero() {
            return Err(
                "registration poll interval must be greater than zero: a zero \
                        interval is a loop with no progress condition"
                    .to_owned(),
            );
        }
        if timeout < interval {
            return Err(format!(
                "registration timeout {timeout:?} is shorter than its poll interval \
                 {interval:?}, so the budget allows no poll at all",
            ));
        }
        if timeout > MAX_TIMEOUT {
            return Err(format!(
                "registration timeout {timeout:?} exceeds {MAX_TIMEOUT:?}; a run that can \
                 block indefinitely has no failure mode an operator can observe",
            ));
        }
        Ok(RegistrationPolicy { timeout, interval })
    }

    /// The whole budget for one registration, submission included.
    pub(super) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The wait between polls.
    pub(super) fn interval(&self) -> Duration {
        self.interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounded_budget_is_a_policy() {
        let policy = RegistrationPolicy::new(Duration::from_secs(300), Duration::from_secs(2))
            .expect("a legal budget");
        assert_eq!(policy.timeout(), Duration::from_secs(300));
        assert_eq!(policy.interval(), Duration::from_secs(2));
    }

    /// The interval and the timeout are the same fact seen twice, so a budget that allows
    /// no poll is refused rather than silently rounded to one.
    #[test]
    fn a_budget_that_cannot_poll_is_refused() {
        assert!(
            RegistrationPolicy::new(Duration::from_secs(10), Duration::ZERO).is_err(),
            "a zero interval has no progress condition",
        );
        assert!(
            RegistrationPolicy::new(Duration::from_millis(500), Duration::from_secs(2)).is_err(),
            "a timeout shorter than one interval allows no poll",
        );
    }

    #[test]
    fn an_unbounded_wait_is_refused() {
        assert!(
            RegistrationPolicy::new(Duration::from_secs(3_601), Duration::from_secs(2)).is_err(),
        );
        assert!(RegistrationPolicy::new(MAX_TIMEOUT, Duration::from_secs(2)).is_ok());
    }

    /// A sub-second interval is legal. It is an aggressive operator choice, not an illegal
    /// one, and the budget's job is to terminate rather than to have opinions about pace.
    #[test]
    fn a_sub_second_interval_is_legal() {
        assert!(
            RegistrationPolicy::new(Duration::from_millis(20), Duration::from_millis(1)).is_ok(),
        );
    }
}
