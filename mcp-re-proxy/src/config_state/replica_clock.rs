// SPDX-License-Identifier: Apache-2.0
//! The declared bound on how far two replicas' clocks may disagree, as one owned fact.
//!
//! A shared replay store expires a record on the clock of the replica that wrote it:
//! `PX` and the etcd lease TTL are both `retain_until - now`, with `now` read from that
//! replica's host. A replica whose clock runs `d` seconds ahead of a correct one therefore
//! writes a record that lapses `d` seconds before the correct replica stops accepting the
//! request it stands for, and the nonce is `Fresh` again for those `d` seconds. Nothing in
//! the stores can observe `d`.
//!
//! The mechanism makes that gap closeable instead of assumed away: the deployment DECLARES
//! a bound, and every record is kept that much longer. What stays an environmental premise
//! is that the actual divergence is no larger than the declared bound (ASM-0061); what no
//! longer depends on the environment is the arithmetic, which is safe for every clock that
//! satisfies it.
//!
//! The retention is lengthened and never shortened, and only the STORE'S expiry moves: the
//! verifier's acceptance window is untouched, so the padding cannot widen what is accepted.

/// The widest divergence a deployment can declare. The same ceiling as the verifier's
/// skew tolerance: beyond it the clocks are not synchronised in any sense the freshness
/// gate relies on, and every record would be retained for a window that is mostly padding.
pub const MAX_REPLICA_CLOCK_DIVERGENCE_SECS: i64 =
    mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND;

/// What a deployment that states no bound is held to: replicas disciplined by NTP agree to
/// well under a second, and this leaves an order of magnitude over that.
pub const DEFAULT_REPLICA_CLOCK_DIVERGENCE_SECS: i64 = 5;

/// The declared bound on inter-replica clock divergence, in whole seconds.
///
/// The representation is private and [`ReplicaClockDivergence::new`] is the only producer
/// of a non-default value, so possessing one IS the statement that the bound is within
/// `0..=`[`MAX_REPLICA_CLOCK_DIVERGENCE_SECS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaClockDivergence {
    secs: i64,
}

impl ReplicaClockDivergence {
    /// The bound `secs`, or `None` outside `0..=`[`MAX_REPLICA_CLOCK_DIVERGENCE_SECS`].
    ///
    /// Zero is a declaration, not an absence: it says the replicas share one clock, which
    /// is true of a single process and of a test fixture and is a claim about everything
    /// else.
    pub fn new(secs: i64) -> Option<Self> {
        (0..=MAX_REPLICA_CLOCK_DIVERGENCE_SECS)
            .contains(&secs)
            .then_some(Self { secs })
    }

    /// The bound a deployment is held to when it states none.
    pub fn deployment_default() -> Self {
        Self {
            secs: DEFAULT_REPLICA_CLOCK_DIVERGENCE_SECS,
        }
    }

    /// What a request's declaration resolves to, or why it is refused.
    ///
    /// Said nothing resolves to the deployment default HERE, after the request has kept the
    /// difference between choosing a value and not choosing one. Outside the ceiling there is
    /// no coherent padding: a negative bound would shorten retention and so reopen the replay
    /// window it exists to close.
    pub fn resolve(declared: Option<i64>) -> Result<Self, String> {
        let Some(secs) = declared else {
            return Ok(Self::deployment_default());
        };
        Self::new(secs).ok_or_else(|| {
            format!(
                "--replay-clock-divergence-secs must be 0..={MAX_REPLICA_CLOCK_DIVERGENCE_SECS} \
                 seconds, got {secs}: it is how much longer every shared replay record is kept \
                 than the verifier's window, to cover replicas whose clocks disagree, so a \
                 negative value would shorten retention and a larger one is mostly padding"
            )
        })
    }

    /// The declared bound, for a posture line or a refusal that has to quote it.
    pub fn secs(&self) -> i64 {
        self.secs
    }

    /// The clock a shared store derives its expiry from: the replica's own reading held back
    /// by the declared bound.
    ///
    /// Every store computes a TTL as `retain_until - now`, so reading `now` this much earlier
    /// is exactly keeping the record this much longer, in all four stores through the one
    /// value they already take. The store's reading is only ever moved EARLIER, so a record
    /// is never kept shorter than the verifier's horizon says. Saturating, so an extreme
    /// reading stays extreme rather than wrapping.
    pub fn retention_clock(
        &self,
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Box<dyn Fn() -> i64 + Send + Sync> {
        let secs = self.secs;
        Box::new(move || clock().saturating_sub(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_is_zero_to_the_ceiling_and_nothing_else() {
        assert!(ReplicaClockDivergence::new(0).is_some());
        assert!(ReplicaClockDivergence::new(MAX_REPLICA_CLOCK_DIVERGENCE_SECS).is_some());
        assert!(ReplicaClockDivergence::new(-1).is_none());
        assert!(ReplicaClockDivergence::new(MAX_REPLICA_CLOCK_DIVERGENCE_SECS + 1).is_none());
    }

    #[test]
    fn the_retention_clock_reads_exactly_the_declared_bound_earlier() {
        let bound = ReplicaClockDivergence::new(7).expect("inside the ceiling");
        assert_eq!(bound.retention_clock(Box::new(|| 1_000))(), 993);
        let none = ReplicaClockDivergence::new(0).expect("zero is a declaration");
        assert_eq!(none.retention_clock(Box::new(|| 1_000))(), 1_000);
    }

    #[test]
    fn an_extreme_reading_saturates_instead_of_wrapping() {
        let bound = ReplicaClockDivergence::new(300).expect("the ceiling");
        assert_eq!(bound.retention_clock(Box::new(|| i64::MIN))(), i64::MIN);
        // The unreadable-clock sentinel stays far past every retain_until.
        assert!(bound.retention_clock(Box::new(|| i64::MAX))() > i64::MAX - 301);
    }

    #[test]
    fn saying_nothing_resolves_to_the_default_and_a_bad_declaration_is_refused() {
        assert_eq!(
            ReplicaClockDivergence::resolve(None),
            Ok(ReplicaClockDivergence::deployment_default())
        );
        assert_eq!(
            ReplicaClockDivergence::resolve(Some(9)).map(|b| b.secs()),
            Ok(9)
        );
        for bad in [
            -1,
            MAX_REPLICA_CLOCK_DIVERGENCE_SECS + 1,
            i64::MIN,
            i64::MAX,
        ] {
            let refusal = ReplicaClockDivergence::resolve(Some(bad)).expect_err("outside");
            assert!(
                refusal.contains("--replay-clock-divergence-secs"),
                "{refusal}"
            );
        }
    }

    #[test]
    fn the_default_is_inside_the_ceiling() {
        assert_eq!(
            ReplicaClockDivergence::new(DEFAULT_REPLICA_CLOCK_DIVERGENCE_SECS),
            Some(ReplicaClockDivergence::deployment_default())
        );
    }
}
