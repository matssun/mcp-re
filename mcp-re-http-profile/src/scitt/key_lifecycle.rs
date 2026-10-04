// SPDX-License-Identifier: Apache-2.0
//! The LIFECYCLE of one transparency-service key.
//!
//! One fact: **whether a transparency-service key may vouch for a receipt at the instant
//! the verifier judges it.**
//!
//! A key is acceptable at `now` iff `valid_from <= now`, `now < valid_until` when a
//! `valid_until` is stated, and `now < revoked_at` when a `revoked_at` is stated. All three
//! are Unix seconds.
//!
//! `now` is the verifier's TRUSTED CURRENT TIME, and nothing else. No time a receipt or a
//! statement carries is an input: a timestamp signed by the key under judgment is that
//! key's own assertion, so a revoked or expired key could date its receipt into its own
//! valid window, and a statement's `issued_at` dates the statement, not the receipt.
//! [`super::verify_receipt_offline`] is purely cryptographic and does not consult this
//! type; a caller judges the receipt's key with [`TransparencyKeyLifecycle::admits_at`]
//! at its own trusted current time.
//!
//! # Limitation: archived receipts
//!
//! Nothing here establishes that a receipt existed while its key was acceptable. Once
//! `now` is at or past `revoked_at` or `valid_until`, every receipt under that key is
//! refused, whatever its own or its statement's times say. Revocation therefore distrusts
//! the key's history as well as its future, and ordinary expiry is not given stronger
//! archival semantics than can be proved: an archived receipt judged after `valid_until`
//! is refused too. Accepting such a receipt would need independent evidence of its
//! existence inside the window — a separately trusted timestamp or an independently signed
//! archival record — and that would be a separate mechanism, which does not exist.

/// The window in which one transparency-service key may vouch for a receipt.
///
/// # What construction proved
///
/// `valid_until`, when stated, is after `valid_from`, and `revoked_at`, when stated, is not
/// before it. A lifecycle that admits no instant through an inverted window is refused
/// rather than held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparencyKeyLifecycle {
    valid_from: i64,
    valid_until: Option<i64>,
    revoked_at: Option<i64>,
}

/// A lifecycle whose bounds contradict each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleError {
    /// `valid_until` is at or before `valid_from`.
    ValidUntilNotAfterValidFrom,
    /// `revoked_at` is before `valid_from`.
    RevokedBeforeValidFrom,
}

/// Why a key is not acceptable at the instant it was judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleRefusal {
    /// The instant is before `valid_from`.
    NotYetValid,
    /// The instant is at or after `valid_until`.
    Expired,
    /// The instant is at or after `revoked_at`.
    Revoked,
}

impl TransparencyKeyLifecycle {
    /// A lifecycle, or the contradiction in its bounds.
    pub fn new(
        valid_from: i64,
        valid_until: Option<i64>,
        revoked_at: Option<i64>,
    ) -> Result<Self, KeyLifecycleError> {
        if valid_until.is_some_and(|until| until <= valid_from) {
            return Err(KeyLifecycleError::ValidUntilNotAfterValidFrom);
        }
        if revoked_at.is_some_and(|revoked| revoked < valid_from) {
            return Err(KeyLifecycleError::RevokedBeforeValidFrom);
        }
        Ok(TransparencyKeyLifecycle {
            valid_from,
            valid_until,
            revoked_at,
        })
    }

    /// Whether the key is acceptable at `now`, the verifier's trusted current time.
    ///
    /// Revocation is reported ahead of expiry when both have passed: it is the stronger
    /// statement about the key.
    pub fn admits_at(&self, now: i64) -> Result<(), KeyLifecycleRefusal> {
        if now < self.valid_from {
            return Err(KeyLifecycleRefusal::NotYetValid);
        }
        if self.revoked_at.is_some_and(|revoked| now >= revoked) {
            return Err(KeyLifecycleRefusal::Revoked);
        }
        if self.valid_until.is_some_and(|until| now >= until) {
            return Err(KeyLifecycleRefusal::Expired);
        }
        Ok(())
    }
}

impl KeyLifecycleError {
    /// The stable code for this contradiction.
    pub fn wire_code(&self) -> &'static str {
        match self {
            KeyLifecycleError::ValidUntilNotAfterValidFrom => {
                "ts_key_valid_until_not_after_valid_from"
            }
            KeyLifecycleError::RevokedBeforeValidFrom => "ts_key_revoked_before_valid_from",
        }
    }
}

impl std::fmt::Display for KeyLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire_code())
    }
}

impl std::error::Error for KeyLifecycleError {}

impl KeyLifecycleRefusal {
    /// The stable code for this refusal.
    pub fn wire_code(&self) -> &'static str {
        match self {
            KeyLifecycleRefusal::NotYetValid => "ts_key_not_yet_valid",
            KeyLifecycleRefusal::Expired => "ts_key_expired",
            KeyLifecycleRefusal::Revoked => "ts_key_revoked",
        }
    }
}

impl std::fmt::Display for KeyLifecycleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire_code())
    }
}

impl std::error::Error for KeyLifecycleRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM: i64 = 1_700_000_000;
    const UNTIL: i64 = 1_800_000_000;
    const REVOKED: i64 = 1_750_000_000;

    #[test]
    fn valid_from_itself_is_admitted_and_the_instant_before_is_not() {
        let lifecycle = TransparencyKeyLifecycle::new(FROM, None, None).expect("legal");
        assert_eq!(lifecycle.admits_at(FROM), Ok(()));
        assert_eq!(
            lifecycle.admits_at(FROM - 1),
            Err(KeyLifecycleRefusal::NotYetValid)
        );
    }

    #[test]
    fn valid_until_itself_is_expired() {
        let lifecycle = TransparencyKeyLifecycle::new(FROM, Some(UNTIL), None).expect("legal");
        assert_eq!(lifecycle.admits_at(UNTIL - 1), Ok(()));
        assert_eq!(
            lifecycle.admits_at(UNTIL),
            Err(KeyLifecycleRefusal::Expired)
        );
        assert_eq!(
            lifecycle.admits_at(UNTIL + 1),
            Err(KeyLifecycleRefusal::Expired)
        );
    }

    #[test]
    fn revoked_at_itself_is_revoked() {
        let lifecycle =
            TransparencyKeyLifecycle::new(FROM, Some(UNTIL), Some(REVOKED)).expect("legal");
        assert_eq!(lifecycle.admits_at(REVOKED - 1), Ok(()));
        assert_eq!(
            lifecycle.admits_at(REVOKED),
            Err(KeyLifecycleRefusal::Revoked)
        );
        assert_eq!(
            lifecycle.admits_at(UNTIL),
            Err(KeyLifecycleRefusal::Revoked),
            "past both bounds, revocation is the reason reported",
        );
    }

    #[test]
    fn a_key_revoked_at_its_first_instant_admits_nothing() {
        let lifecycle = TransparencyKeyLifecycle::new(FROM, None, Some(FROM)).expect("legal");
        assert_eq!(lifecycle.admits_at(FROM), Err(KeyLifecycleRefusal::Revoked));
    }

    #[test]
    fn an_open_ended_lifecycle_admits_the_far_future() {
        let lifecycle = TransparencyKeyLifecycle::new(FROM, None, None).expect("legal");
        assert_eq!(lifecycle.admits_at(i64::MAX), Ok(()));
    }

    #[test]
    fn contradictory_bounds_are_refused() {
        assert_eq!(
            TransparencyKeyLifecycle::new(FROM, Some(FROM), None),
            Err(KeyLifecycleError::ValidUntilNotAfterValidFrom)
        );
        assert_eq!(
            TransparencyKeyLifecycle::new(FROM, Some(FROM - 1), None),
            Err(KeyLifecycleError::ValidUntilNotAfterValidFrom)
        );
        assert_eq!(
            TransparencyKeyLifecycle::new(FROM, None, Some(FROM - 1)),
            Err(KeyLifecycleError::RevokedBeforeValidFrom)
        );
    }

    #[test]
    fn every_refusal_has_a_distinct_code() {
        let codes = [
            KeyLifecycleRefusal::NotYetValid.to_string(),
            KeyLifecycleRefusal::Expired.to_string(),
            KeyLifecycleRefusal::Revoked.to_string(),
        ];
        assert_eq!(
            codes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }
}
