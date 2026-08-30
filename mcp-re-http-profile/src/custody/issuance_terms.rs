// SPDX-License-Identifier: Apache-2.0
//! The arithmetic terms of one credential's life: when a successor is due, when a declining
//! root may be approached again, and what a fresh credential may be minted with.
//!
//! One authority — every number the custody state machine decides a lifecycle step ON —
//! and it is separated because none of these terms is safe to compute in the obvious way.
//! [`CustodyConfig`](super::CustodyConfig) carries `ttl` and `overlap` as bare `i64`
//! fields; the `0 < overlap < ttl <= MAX_DELEGATED_TTL_SECS` guard that bounds them belongs
//! to the proxy's configuration owner and does not reach this type, so any other
//! construction site — an embedder, a test, a future caller — can present values these
//! operations cannot take.
//!
//! Every one of them therefore fails in the RESTRICTIVE direction. A rotation threshold
//! that cannot be computed reads as reached, not as far away. An expiry or an ordinal that
//! cannot be represented refuses the issuance rather than minting a wrapped one. A retry
//! hold-off that cannot be computed lands in the far future, never in the past.
//! `docs/dev/partial-operations.md` records why each of those directions is the safe one.

use super::CustodyError;

/// How many issuance attempts one rotation-overlap window may spend on a root that
/// is declining. The overlap window is the budget the rotation contract already
/// allocates to getting a successor minted, so the retry interval is derived from it
/// rather than configured separately.
const ISSUANCE_ATTEMPTS_PER_OVERLAP: i64 = 10;

/// Floor on the retry interval, for a configuration whose overlap window is smaller
/// than the attempt budget (and for a non-positive overlap).
const MIN_ISSUANCE_RETRY_SECS: i64 = 1;

/// Whether the credential expiring at `exp` has entered its rotation-overlap window.
///
/// A threshold that cannot be computed reads as REACHED. Wrapping would put it far in the
/// future and answer `false`, keeping the key in service past the window it should have
/// been replaced in — a restrictive value turned permissive by an arithmetic accident.
pub(super) fn rotation_due(exp: i64, overlap: i64, now: i64) -> bool {
    exp.checked_sub(overlap).is_none_or(|at| now >= at)
}

/// The two values an issuance cannot proceed without: the credential's expiry, and the
/// ordinal that will name it.
///
/// Decided BEFORE a key is generated, an ordinal spent or the root approached, because
/// either being unrepresentable is a reason this issuance cannot produce a valid
/// credential at all.
///
/// The expiry, because a wrapped `exp` is minted into the credential and into the audit
/// event describing it, and every `now < exp` test downstream reads the wrapped value. The
/// ordinal, because `jti` is a REVOCATION identifier and this counter distinguishes two
/// credentials minted over the same key material — a wrapped counter re-issues a `jti` that
/// already names a different credential, so revoking one revokes the other.
pub(super) fn mintable(now: i64, ttl: i64, counter: u64) -> Result<(i64, u64), CustodyError> {
    now.checked_add(ttl)
        .zip(counter.checked_add(1))
        .ok_or(CustodyError::FailClosedIssuance)
}

/// The instant a signature made now may claim validity until: `now + ttl`, never past the
/// credential's own `exp`, and `exp` alone when that sum leaves `i64`.
///
/// `exp` is the fail-closed bound — a signer MUST stop signing off a snapshot once
/// `now >= exp` — so a signature whose stated validity outlived it would advertise a
/// freshness window longer than the credential authorizing the key that made it.
pub(super) fn signature_valid_until(now: i64, ttl: i64, exp: i64) -> i64 {
    now.checked_add(ttl).map_or(exp, |until| until.min(exp))
}

/// When a failed root may be approached again, given the moment it declined.
///
/// Saturating IS the rule: this only ever delays the next approach to a root that is
/// already failing, so the far future is the restrictive end. Wrapping would land in the
/// past and re-open exactly the per-request root traffic the hold-off exists to prevent.
pub(super) fn next_attempt_after(now: i64, overlap: i64) -> i64 {
    now.saturating_add(retry_interval(overlap))
}

/// Minimum seconds between two issuance attempts after one has failed.
///
/// `.max` on the divisor's result rather than on the divisor: the division is by a nonzero
/// constant, and the floor exists for an overlap smaller than the attempt budget.
fn retry_interval(overlap: i64) -> i64 {
    (overlap / ISSUANCE_ATTEMPTS_PER_OVERLAP).max(MIN_ISSUANCE_RETRY_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each term fails in the restrictive direction for values `CustodyConfig` admits but
    /// the arithmetic cannot take. These are the cases the audit added checks for, stated
    /// against the owner rather than through the state machine that consumes it.
    #[test]
    fn every_term_fails_restrictively() {
        assert!(
            rotation_due(0, i64::MIN, 1),
            "an uncomputable threshold reads as reached"
        );
        assert!(!rotation_due(1_000, 60, 100), "a live window is not due");
        assert!(
            rotation_due(1_000, 60, 940),
            "the window opens at exp - overlap"
        );

        assert!(mintable(1_000, i64::MAX, 0).is_err());
        assert!(mintable(1_000, i64::MAX, u64::MAX).is_err());
        assert!(mintable(0, i64::MAX, u64::MAX).is_err());
        assert_eq!(mintable(1_000, 300, 7), Ok((1_300, 8)));

        assert_eq!(
            signature_valid_until(1_000, i64::MAX, 1_300),
            1_300,
            "an uncomputable window clamps to the credential"
        );
        assert_eq!(signature_valid_until(1_000, 300, 1_300), 1_300);
        assert_eq!(signature_valid_until(1_000, 100, 1_300), 1_100);

        assert_eq!(
            next_attempt_after(i64::MAX, 600),
            i64::MAX,
            "a hold-off never lands in the past"
        );
        assert_eq!(next_attempt_after(1_000, 600), 1_060);
    }

    /// The floor applies to an overlap too small to divide into the attempt budget, and to
    /// a non-positive one.
    #[test]
    fn the_retry_interval_has_a_floor() {
        assert_eq!(retry_interval(600), 60);
        assert_eq!(retry_interval(5), MIN_ISSUANCE_RETRY_SECS);
        assert_eq!(retry_interval(0), MIN_ISSUANCE_RETRY_SECS);
        assert_eq!(retry_interval(-100), MIN_ISSUANCE_RETRY_SECS);
    }
}
