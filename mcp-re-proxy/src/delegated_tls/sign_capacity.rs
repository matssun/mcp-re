// SPDX-License-Identifier: Apache-2.0
//! The operator-chosen capacity of the listener's handshake-signature budget.
//!
//! Holding a [`HandshakeSignCapacity`] is the statement that both its terms are within
//! their bounds. There is no other way to obtain one: the fields are private, the only
//! constructor checks both, and [`super::TlsHandshakeSignBudget`] is built from nothing
//! else.

/// A sustained rate and a burst allowance, each within its bound.
///
/// The bounds exist on both sides, and for different reasons:
///
/// - **Zero is refused, not clamped.** A rate or burst of `0` would refuse every delegated
///   handshake on the listener — an outage spelled as a setting. Startup says so instead.
/// - **The upper bounds keep the budget a budget.** [`Self::MAX_RATE_PER_SEC`] and
///   [`Self::MAX_BURST`] are ten times the defaults: room for a deployment with a larger
///   signing quota to raise the ceiling by an order of magnitude, while a mistyped value
///   cannot set a ceiling so high that the bucket no longer limits what reaches the remote
///   signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeSignCapacity {
    rate_per_sec: u32,
    burst: u32,
}

impl HandshakeSignCapacity {
    /// The sustained ceiling, in handshake signatures per second, when the operator states
    /// none.
    ///
    /// Sized against what legitimate traffic needs: a connection costs a signature only on
    /// a full handshake (a session-store miss: first contact, eviction, an auth-epoch
    /// advance, a restart), and the all-miss case under `max_connection_age` (300s) with
    /// `max_concurrent_connections` (256 per core) is a re-handshake rate near one
    /// signature per core per second. 100/s leaves a large multiple of that for connection
    /// churn and rolling deploys while staying well inside a KMS account's
    /// cryptographic-operation quota.
    pub const DEFAULT_RATE_PER_SEC: u32 = 100;
    /// The burst allowance when the operator states none — how many signatures may be
    /// drawn back-to-back before the sustained rate binds. One rolling deploy reconnects a
    /// whole fleet at once, and a restart or epoch advance is a miss spike, so twice the
    /// per-second rate absorbs that without letting a flood accumulate credit.
    pub const DEFAULT_BURST: u32 = 200;
    /// The largest sustained rate an operator may configure.
    pub const MAX_RATE_PER_SEC: u32 = 1_000;
    /// The largest burst allowance an operator may configure.
    pub const MAX_BURST: u32 = 2_000;

    /// A capacity of `rate_per_sec` sustained signatures with a `burst` allowance, or the
    /// reason one of them is out of bounds.
    pub fn new(rate_per_sec: u32, burst: u32) -> Result<Self, String> {
        if !(1..=Self::MAX_RATE_PER_SEC).contains(&rate_per_sec) {
            return Err(format!(
                "the TLS handshake-signing rate must be within 1..={} signatures per second; \
                 got {rate_per_sec}",
                Self::MAX_RATE_PER_SEC
            ));
        }
        if !(1..=Self::MAX_BURST).contains(&burst) {
            return Err(format!(
                "the TLS handshake-signing burst must be within 1..={} signatures; got {burst}",
                Self::MAX_BURST
            ));
        }
        Ok(HandshakeSignCapacity {
            rate_per_sec,
            burst,
        })
    }

    /// The same capacity with its sustained rate replaced, or the reason the rate is out of
    /// bounds.
    pub fn with_rate_per_sec(self, rate_per_sec: u32) -> Result<Self, String> {
        Self::new(rate_per_sec, self.burst)
    }

    /// The same capacity with its burst allowance replaced, or the reason the burst is out
    /// of bounds.
    pub fn with_burst(self, burst: u32) -> Result<Self, String> {
        Self::new(self.rate_per_sec, burst)
    }

    /// The sustained rate, in signatures per second.
    pub fn rate_per_sec(&self) -> u32 {
        self.rate_per_sec
    }

    /// The burst allowance, in signatures.
    pub fn burst(&self) -> u32 {
        self.burst
    }
}

impl Default for HandshakeSignCapacity {
    fn default() -> Self {
        HandshakeSignCapacity {
            rate_per_sec: Self::DEFAULT_RATE_PER_SEC,
            burst: Self::DEFAULT_BURST,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HandshakeSignCapacity;

    #[test]
    fn a_zero_rate_or_burst_is_refused_rather_than_clamped() {
        assert!(HandshakeSignCapacity::new(0, 10).is_err());
        assert!(HandshakeSignCapacity::new(10, 0).is_err());
    }

    #[test]
    fn a_term_above_its_ceiling_is_refused_and_the_ceiling_itself_is_accepted() {
        let max_rate = HandshakeSignCapacity::MAX_RATE_PER_SEC;
        let max_burst = HandshakeSignCapacity::MAX_BURST;
        assert!(HandshakeSignCapacity::new(max_rate + 1, 10).is_err());
        assert!(HandshakeSignCapacity::new(10, max_burst + 1).is_err());
        let at = HandshakeSignCapacity::new(max_rate, max_burst).expect("the bounds are inclusive");
        assert_eq!((at.rate_per_sec(), at.burst()), (max_rate, max_burst));
    }

    #[test]
    fn replacing_one_term_keeps_the_other_and_checks_the_new_one() {
        let base = HandshakeSignCapacity::default();
        let raised = base.with_rate_per_sec(250).expect("in bounds");
        assert_eq!((raised.rate_per_sec(), raised.burst()), (250, base.burst()));
        let deeper = base.with_burst(500).expect("in bounds");
        assert_eq!(
            (deeper.rate_per_sec(), deeper.burst()),
            (base.rate_per_sec(), 500)
        );
        assert!(base.with_rate_per_sec(0).is_err());
        assert!(base
            .with_burst(HandshakeSignCapacity::MAX_BURST + 1)
            .is_err());
    }

    #[test]
    fn the_defaults_are_themselves_within_bounds() {
        let d = HandshakeSignCapacity::default();
        assert_eq!(
            HandshakeSignCapacity::new(d.rate_per_sec(), d.burst()),
            Ok(d)
        );
    }
}
