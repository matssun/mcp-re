// SPDX-License-Identifier: Apache-2.0
//! The trust epoch a delegated credential is minted under.
//!
//! An epoch is a base label, optionally extended by a shared counter to `<base>#<counter>`.
//! Verifiers accept credentials by label, so the label is the whole of what a credential
//! says about which epoch it belongs to. A custody may only move its epoch FORWARD: to a
//! counter at or above the one it holds, under the same base. A step back would mint
//! under a label an operator already advanced past, which is the revocation the counter
//! exists to make; that ordering is this type's, not the caller's that feeds it.
//!
//! The base holds no `#`, so `<base>#<counter>` names exactly one (base, counter) pair.

use std::fmt;
use std::str::FromStr;

/// A base label and, where a shared counter is configured, the counter extending it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEpoch {
    base: String,
    counter: Option<i64>,
}

/// Why a string is not a trust-epoch base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEpochRefusal {
    /// An empty base names no deployment.
    Empty,
    /// A base holding `#` renders a label two (base, counter) pairs share.
    HoldsSeparator,
    /// Longer than [`TrustEpoch::MAX_BASE_LEN`] bytes.
    TooLong,
}

impl TrustEpoch {
    /// The longest base, in bytes; it is minted into every credential.
    pub const MAX_BASE_LEN: usize = 128;

    /// An epoch with no shared counter: its label is the base itself.
    pub fn fixed(base: impl Into<String>) -> Result<Self, TrustEpochRefusal> {
        let base = base.into();
        if base.is_empty() {
            return Err(TrustEpochRefusal::Empty);
        }
        if base.contains('#') {
            return Err(TrustEpochRefusal::HoldsSeparator);
        }
        if base.len() > Self::MAX_BASE_LEN {
            return Err(TrustEpochRefusal::TooLong);
        }
        Ok(Self {
            base,
            counter: None,
        })
    }

    /// The same base at `counter`: the epoch a custody STARTS under when the counter is read
    /// from shared state. Once a custody holds an epoch, only [`forward_to`] moves it.
    ///
    /// [`forward_to`]: Self::forward_to
    pub fn at(&self, counter: i64) -> Self {
        Self {
            base: self.base.clone(),
            counter: Some(counter),
        }
    }

    /// The base label, without any counter.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The shared counter, where one extends the base.
    pub fn counter(&self) -> Option<i64> {
        self.counter
    }

    /// The label minted into credentials: `<base>#<counter>`, or the base alone.
    pub fn label(&self) -> String {
        self.to_string()
    }

    /// The epoch at `counter`, unless that is behind this one: the counter held, or any
    /// above it. Any counter is ahead of an epoch that has none.
    pub(super) fn forward_to(&self, counter: i64) -> Option<Self> {
        self.counter
            .is_none_or(|held| counter >= held)
            .then(|| self.at(counter))
    }
}

impl fmt::Display for TrustEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.counter {
            Some(counter) => write!(f, "{}#{counter}", self.base),
            None => f.write_str(&self.base),
        }
    }
}

/// Parses a BASE, as [`TrustEpoch::fixed`] does; a rendered `<base>#<counter>` label is not
/// an input, since the counter comes from shared state, never from text.
impl FromStr for TrustEpoch {
    type Err = TrustEpochRefusal;

    fn from_str(base: &str) -> Result<Self, Self::Err> {
        Self::fixed(base)
    }
}

impl fmt::Display for TrustEpochRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustEpochRefusal::Empty => f.write_str("the trust-epoch base is empty"),
            TrustEpochRefusal::HoldsSeparator => {
                f.write_str("the trust-epoch base holds '#', which separates base from counter")
            }
            TrustEpochRefusal::TooLong => write!(
                f,
                "the trust-epoch base is longer than {} bytes",
                TrustEpoch::MAX_BASE_LEN
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_is_refused_when_empty_separated_or_too_long() {
        assert_eq!(TrustEpoch::fixed(""), Err(TrustEpochRefusal::Empty));
        assert_eq!(
            TrustEpoch::fixed("a#1"),
            Err(TrustEpochRefusal::HoldsSeparator)
        );
        let long = "e".repeat(TrustEpoch::MAX_BASE_LEN + 1);
        assert_eq!(TrustEpoch::fixed(long), Err(TrustEpochRefusal::TooLong));
        assert!(TrustEpoch::fixed("e".repeat(TrustEpoch::MAX_BASE_LEN)).is_ok());
    }

    #[test]
    fn the_label_is_the_base_alone_or_base_hash_counter() {
        let base = TrustEpoch::fixed("epoch-1").expect("base");
        assert_eq!(base.label(), "epoch-1");
        assert_eq!(base.at(7).label(), "epoch-1#7");
        assert_eq!("epoch-1".parse::<TrustEpoch>(), Ok(base));
    }

    /// The custody's epoch never moves below the counter it holds.
    #[test]
    fn an_epoch_never_moves_below_the_counter_it_holds() {
        let base = TrustEpoch::fixed("epoch-1").expect("base");
        assert_eq!(base.forward_to(0), Some(base.at(0)));
        let at_5 = base.at(5);
        assert_eq!(at_5.forward_to(6), Some(base.at(6)));
        assert_eq!(at_5.forward_to(5), Some(base.at(5)));
        assert_eq!(at_5.forward_to(4), None);
    }
}
