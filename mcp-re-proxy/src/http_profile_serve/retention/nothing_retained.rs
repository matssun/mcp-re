// SPDX-License-Identifier: Apache-2.0
//! The witness that a deployment owes the evidence store nothing.
//!
//! *This deployment retains nothing* is a fact about the deployment's [`Retention`], and the
//! two lifecycle enums that carry it past the retention step live in
//! [`crate::request_stages`], a module that cannot see this one's representation. Without a
//! witness their `NotConfigured` arms were constructible by anyone who could name the enum, so
//! "nothing was owed" was a value a caller could write rather than one the owner stated: a
//! configured deployment handed a `NotConfigured` disposition would skip the obligation, and
//! nothing downstream could tell.
//!
//! [`NothingRetained`] carries the owner's statement. Its field is private and its only
//! constructor is visible to the retention owner alone, which calls it from the one place that
//! has established there is no store.
//!
//! [`Retention`]: super::Retention

/// A statement, made by the retention owner and carried in both `NotConfigured` arms, that no
/// store was installed.
#[derive(Debug)]
pub(crate) struct NothingRetained {
    /// Private, so no struct literal outside this module can state it.
    _sealed: (),
}

impl NothingRetained {
    /// The owner's statement. Visible to the retention module tree only, and used only where
    /// `Retention` holds no store.
    pub(super) fn minted_by_retention() -> Self {
        NothingRetained { _sealed: () }
    }

    /// A statement for a test that builds a `NotConfigured` state directly. Test builds only:
    /// no production path can reach it.
    #[cfg(test)]
    pub(crate) fn for_a_test() -> Self {
        NothingRetained { _sealed: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The witness exists and is distinguishable from nothing at all: holding one is the
    /// only way to inhabit a `NotConfigured` arm.
    #[test]
    fn the_witness_is_a_value_the_owner_hands_out() {
        let witness = NothingRetained::minted_by_retention();
        assert!(format!("{witness:?}").contains("NothingRetained"));
    }
}
