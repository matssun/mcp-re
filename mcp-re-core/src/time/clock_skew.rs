// SPDX-License-Identifier: Apache-2.0
//! The bounded clock skew of MCP_RE_SPEC §5.1, as a value that cannot hold anything else.
//!
//! Every freshness mechanism is defined in terms of one tolerance: how far a peer's clock
//! may disagree with this one. A verifier widens a message's validity window by it, and a
//! replay store keeps a nonce for it past the message's expiry. A negative tolerance would
//! narrow both — a store would forget a nonce before the verifier stopped accepting it —
//! and an unbounded one stops freshness meaning anything.
//!
//! The representation is private and [`MaxClockSkew::new`] is its only producer, so
//! holding one is the statement that the tolerance is within `0..=BOUND_SECS`. It says
//! nothing about what a caller does with it: each consumer decides what instant it
//! derives.

/// A clock-skew tolerance in seconds, within `0..=`[`MaxClockSkew::BOUND_SECS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxClockSkew(i64);

impl MaxClockSkew {
    /// The widest tolerance (§5.1 "bounded"). Five minutes is the widest disagreement a
    /// deployment can declare and still call itself conforming.
    pub const BOUND_SECS: i64 = 300;

    /// `None` for a negative tolerance or one above [`Self::BOUND_SECS`].
    pub const fn new(secs: i64) -> Option<Self> {
        if secs >= 0 && secs <= Self::BOUND_SECS {
            Some(Self(secs))
        } else {
            None
        }
    }

    /// The tolerance in seconds.
    pub const fn secs(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tolerance_inside_the_bound_is_held_exactly() {
        for secs in [0, 1, 30, MaxClockSkew::BOUND_SECS] {
            assert_eq!(MaxClockSkew::new(secs).map(MaxClockSkew::secs), Some(secs));
        }
    }

    #[test]
    fn a_negative_or_unbounded_tolerance_is_not_constructible() {
        for secs in [i64::MIN, -1, MaxClockSkew::BOUND_SECS + 1, i64::MAX] {
            assert_eq!(MaxClockSkew::new(secs), None, "secs={secs}");
        }
    }
}
