// SPDX-License-Identifier: Apache-2.0
//! How many live continuation entries a store may hold at once.
//!
//! Holding a [`ContinuationCapacity`] is the statement that the bound is within its range.
//! The field is private and the only constructor checks it, so no store is ever built with
//! a bound of zero or an unbounded one.

/// The most live continuation entries a store holds; a create beyond it is refused.
///
/// Every open leg that is never answered leaves an entry for its whole TTL, so without a
/// bound the shared tier's population is limited only by the verified request rate times
/// the TTL. The bound makes it finite whatever that rate is.
///
/// - **Zero is refused, not clamped.** A bound of `0` would refuse every open leg — an
///   outage spelled as a setting.
/// - **The ceiling keeps the bound a bound.** [`Self::MAX_LIVE_ENTRIES`] is a hundred times
///   the default, so a deployment with heavy multi-round-trip traffic can raise it while a
///   mistyped value cannot make it unlimited in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationCapacity {
    max_live_entries: u32,
}

impl ContinuationCapacity {
    /// The bound when the operator states none.
    ///
    /// An entry is its key (a prefix and a 43-character digest), two evidence handles, and
    /// one sorted-set member of the key — under 200 bytes — so 100,000 entries is about
    /// 20 MB of Redis memory. At the 300-second TTL that admits a sustained 333 unanswered
    /// open legs per second across the fleet.
    pub const DEFAULT: ContinuationCapacity = ContinuationCapacity {
        max_live_entries: 100_000,
    };
    /// The largest bound an operator may configure.
    pub const MAX_LIVE_ENTRIES: u32 = 10_000_000;

    /// A bound of `max_live_entries`, or the reason it is out of range.
    pub fn new(max_live_entries: u64) -> Result<Self, String> {
        match u32::try_from(max_live_entries) {
            Ok(n) if (1..=Self::MAX_LIVE_ENTRIES).contains(&n) => Ok(ContinuationCapacity {
                max_live_entries: n,
            }),
            _ => Err(format!(
                "--continuation-max-live-entries must be within 1..={}; got {max_live_entries}",
                Self::MAX_LIVE_ENTRIES
            )),
        }
    }

    /// The bound.
    pub fn max_live_entries(self) -> u32 {
        self.max_live_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_within_range_is_kept_and_the_default_is_in_range() {
        for n in [
            1,
            100_000,
            u64::from(ContinuationCapacity::MAX_LIVE_ENTRIES),
        ] {
            let capacity = ContinuationCapacity::new(n).expect("in range");
            assert_eq!(u64::from(capacity.max_live_entries()), n);
        }
        let default = ContinuationCapacity::DEFAULT.max_live_entries();
        assert_eq!(
            ContinuationCapacity::new(u64::from(default)),
            Ok(ContinuationCapacity::DEFAULT)
        );
    }

    #[test]
    fn zero_and_values_past_the_ceiling_are_refused() {
        let past = u64::from(ContinuationCapacity::MAX_LIVE_ENTRIES) + 1;
        for n in [0, past, u64::MAX] {
            let refused = ContinuationCapacity::new(n).expect_err("out of range");
            assert!(
                refused.contains("--continuation-max-live-entries"),
                "{refused}"
            );
        }
    }
}
