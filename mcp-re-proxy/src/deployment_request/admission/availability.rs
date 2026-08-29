// SPDX-License-Identifier: Apache-2.0
//! What an enforcing deployment does when the admission authority is unreachable.

use std::num::NonZeroU64;

/// Fail closed, or serve on last-known state for a bounded window.
///
/// A tagged value rather than a `bool` beside a number. The pair could state two things no
/// deployment can be in — a bound where nothing reads it, and a degraded window of zero
/// width — and each had a boundary clause. Neither can be written now: the bound belongs to
/// the arm that opens a window, and it is a [`NonZeroU64`].
///
/// The bound is P, a FLOOR on the window rather than the whole of it: the PEP serves for
/// `P + max_clock_skew` seconds, which is why zero was never a disabled window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdmissionAvailabilityRequest {
    /// An unreachable authority refuses the call. No window.
    #[default]
    FailClosed,
    /// An unreachable authority is tolerated for a bounded window.
    Degraded {
        /// P, in seconds.
        bound_secs: NonZeroU64,
    },
}

impl AdmissionAvailabilityRequest {
    /// The window's floor in seconds, where a window opens.
    pub fn bound_secs(self) -> Option<u64> {
        match self {
            AdmissionAvailabilityRequest::FailClosed => None,
            AdmissionAvailabilityRequest::Degraded { bound_secs } => Some(bound_secs.get()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Failing closed is the default: a deployment that said nothing about an unreachable
    /// authority refuses the call rather than opening a window it never asked for.
    #[test]
    fn failing_closed_is_the_default_and_carries_no_window() {
        assert_eq!(
            AdmissionAvailabilityRequest::default(),
            AdmissionAvailabilityRequest::FailClosed
        );
        assert_eq!(AdmissionAvailabilityRequest::default().bound_secs(), None);
    }
}
