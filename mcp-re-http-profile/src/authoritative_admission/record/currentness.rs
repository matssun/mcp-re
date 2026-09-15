// SPDX-License-Identifier: Apache-2.0
//! The deployment's currentness budget, and every reason a stored record is not the
//! authority's current statement.
//!
//! One authority over one question: *given a record that parsed, how long may it still be
//! read?* Separate from the verifier because the budget is the DEPLOYMENT's number and the
//! record is the AUTHORITY's artifact, and a single module holding both invites the
//! publisher's `exp` to be read as the answer.

use super::AdmissionStateClaims;

/// Why a record present in the store is not the authority's current statement.
///
/// Every variant is a DEFINITIVE NEGATIVE, never an outage. That distinction is the whole
/// point of the taxonomy: an outage reaches the §5.2 degraded fork, which serves on the
/// caller's own assertion within P, so classifying a forged or stale record as "the
/// authority could not be reached" would make corrupting a record a cheaper un-revoke than
/// issuing one. A reachable store that answered with something has answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRecordRefusal {
    /// Not a well-formed record of this kind at all — shape, encoding, `typ`, `alg`, or a
    /// header/claims disagreement about the issuer.
    Malformed,
    /// The named issuer is not one this deployment configured as its admission authority.
    /// A kid never introduces trust.
    IssuerUntrusted,
    /// The signature does not verify under the resolved authority key.
    SignatureInvalid,
    /// The record belongs to a different evidence profile.
    ProfileMismatch,
    /// The record is about a different workload than the one it was read for.
    SubjectMismatch,
    /// Past the currentness ceiling: outside its own `[nbf, exp]` window (± skew), issued
    /// in the future, or carrying an inverted window. This is the clause that bounds a
    /// RESTORED, legitimately signed record — see [`check_currentness`] for why there is
    /// no separate staleness variant beside it.
    Expired,
    /// The issuer asked for a validity window wider than the deployment's declared budget.
    /// Refused rather than clamped: a record whose own bound outruns the deployment's
    /// promise is a disagreement about the promise, and silently narrowing it would let an
    /// operator believe the authority had agreed.
    WindowExceedsBudget,
    /// The record's publication sequence is older than one this verifier has already
    /// accepted for this workload. Hardening — see
    /// [`CurrentAdmissionState::state_revision`](super::CurrentAdmissionState::state_revision).
    RevisionRewound,
}

impl std::fmt::Display for AdmissionRecordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AdmissionRecordRefusal::Malformed => "malformed",
            AdmissionRecordRefusal::IssuerUntrusted => "issuer is not the configured authority",
            AdmissionRecordRefusal::SignatureInvalid => "signature invalid",
            AdmissionRecordRefusal::ProfileMismatch => "wrong evidence profile",
            AdmissionRecordRefusal::SubjectMismatch => "record is about another workload",
            AdmissionRecordRefusal::Expired => "past the declared currentness ceiling",
            AdmissionRecordRefusal::WindowExceedsBudget => {
                "issuer window exceeds the declared currentness budget"
            }
            AdmissionRecordRefusal::RevisionRewound => "publication sequence rewound",
        })
    }
}

/// The deployment's declared budget for how current an authoritative record must be.
///
/// Both members are the DEPLOYMENT's, not the publisher's. `max_record_age` is the
/// revocation-currentness promise — after a revocation, no replica may still be acting on a
/// record older than this — and `max_clock_skew` is the same tolerance every other window
/// on this path already gets, no wider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionStateCurrentness {
    /// How old a record may be, in seconds, measured from its `iat`.
    pub max_record_age: i64,
    /// Clock-skew tolerance, shared with the assertion path.
    pub max_clock_skew: i64,
}

/// The currentness argument: two clauses, and the ceiling they compose to.
///
/// # Why there is no separate "older than the budget" clause
///
/// The first draft had three: the record's own window, the budget CEILING on that window,
/// and an age cap `now - iat > max_record_age + skew`. The third is unreachable, and its own
/// batteries said so. An accepted record satisfies `exp <= iat + max_record_age`, so
/// `now > iat + max_record_age + skew` implies `now >= exp + skew`, which the window clause
/// has already refused. A branch nothing can reach is not defence in depth; it is a refusal
/// vocabulary claiming a distinction the legality model does not admit.
///
/// What the two remaining clauses compose to is the property the ruling asks for: an
/// accepted record is inside its own window AND that window started no earlier than
/// `max_record_age` before it ends, so **no record is read later than
/// `iat + max_record_age + skew`**, whatever window its issuer asked for. A publisher may
/// choose a shorter life; it cannot choose a longer one.
///
/// SATURATING throughout, matching every other freshness gate on this path: these operands
/// come straight out of a JWS payload, so an extreme `iat` would wrap in a release build —
/// silently passing the very cap the expression exists to enforce — and panic in any build
/// with overflow checks.
pub(super) fn check_currentness(
    claims: &AdmissionStateClaims,
    currentness: &AdmissionStateCurrentness,
    now: i64,
) -> Result<(), AdmissionRecordRefusal> {
    let skew = currentness.max_clock_skew;
    if claims.nbf.saturating_sub(skew) > now
        || claims.exp.saturating_add(skew) <= now
        || claims.exp <= claims.nbf
        || claims.iat > now.saturating_add(skew)
    {
        return Err(AdmissionRecordRefusal::Expired);
    }
    // The issuer may ask for LESS than the deployment allows; it may not ask for more.
    // Together with the window clause above, this is what bounds a RESTORED record: its
    // signature is valid and nothing detected the substitution, and it stops being read
    // anyway.
    if claims.exp.saturating_sub(claims.iat) > currentness.max_record_age {
        return Err(AdmissionRecordRefusal::WindowExceedsBudget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::claims;
    use super::*;

    fn budget(max_record_age: i64, max_clock_skew: i64) -> AdmissionStateCurrentness {
        AdmissionStateCurrentness {
            max_record_age,
            max_clock_skew,
        }
    }

    /// The fixture is issued at 1000 with a 60s window, so a 60s budget admits it exactly.
    #[test]
    fn a_record_inside_both_its_own_window_and_the_budget_is_current() {
        assert_eq!(
            check_currentness(&claims("wl", 7, 1), &budget(60, 5), 1_030),
            Ok(())
        );
    }

    /// **The rollback bound.** A legitimately signed ADMITTED record restored by a party
    /// with store-write access stops being read once the ceiling passes — the signature is
    /// still valid and nothing detected the substitution.
    ///
    /// The fixture is issued at 1000 with `exp = 1060` and the budget allows 60, so the
    /// ceiling is `exp + skew = 1065` and 1064 is the last second it is read.
    #[test]
    fn a_legitimately_signed_record_stops_being_read_at_the_ceiling() {
        let c = claims("wl", 7, 1);
        let b = budget(60, 5);
        assert_eq!(
            check_currentness(&c, &b, 1_064),
            Ok(()),
            "inside the ceiling"
        );
        assert_eq!(
            check_currentness(&c, &b, 1_065),
            Err(AdmissionRecordRefusal::Expired),
            "at iat + budget + skew the restored record is refused"
        );
    }

    /// The budget bites INDEPENDENTLY of the record's own window: an issuer that asks for
    /// longer than the deployment allows is refused, so `exp` cannot buy a wider one.
    #[test]
    fn an_issuer_window_wider_than_the_budget_is_refused_not_clamped() {
        let mut c = claims("wl", 7, 1);
        c.exp = 100_000; // an hour-wide window from a deployment that declared 60s
        assert_eq!(
            check_currentness(&c, &budget(60, 5), 1_030),
            Err(AdmissionRecordRefusal::WindowExceedsBudget)
        );
    }

    /// A publisher may choose a SHORTER life than the budget allows, and then that is the
    /// life the record has. The ceiling is a maximum, not a grant.
    #[test]
    fn a_shorter_issuer_window_is_the_one_that_applies() {
        let mut c = claims("wl", 7, 1);
        c.exp = 1_020; // a 20-second window under a 60-second budget
        let b = budget(60, 5);
        assert_eq!(check_currentness(&c, &b, 1_024), Ok(()));
        assert_eq!(
            check_currentness(&c, &b, 1_025),
            Err(AdmissionRecordRefusal::Expired),
            "the record's own window ends it well before the budget would"
        );
    }

    /// The ceiling is composed, not asserted: for EVERY window an issuer can ask for and
    /// have accepted, the record stops being read by `iat + budget + skew`. This is the
    /// conjunction the deleted staleness clause was trying to state on its own.
    #[test]
    fn no_accepted_window_is_read_past_the_budget_ceiling() {
        let b = budget(60, 5);
        for window in [1_i64, 7, 30, 59, 60] {
            let mut c = claims("wl", 7, 1);
            c.exp = c.iat.saturating_add(window);
            let ceiling = 1_000 + 60 + 5;
            assert!(
                check_currentness(&c, &b, ceiling).is_err(),
                "a {window}s window must not be read at the ceiling"
            );
        }
        // And a window the budget refuses cannot buy a later one.
        let mut wide = claims("wl", 7, 1);
        wide.exp = 1_000 + 61;
        assert_eq!(
            check_currentness(&wide, &b, 1_030),
            Err(AdmissionRecordRefusal::WindowExceedsBudget)
        );
    }

    #[test]
    fn a_record_issued_in_the_future_is_refused() {
        // A future `iat` would floor the staleness computation at zero and pass the budget
        // for the record's whole window — the same defect the assertion path already
        // refuses.
        let mut c = claims("wl", 7, 1);
        c.iat = 2_000;
        assert_eq!(
            check_currentness(&c, &budget(60, 5), 1_030),
            Err(AdmissionRecordRefusal::Expired)
        );
    }

    #[test]
    fn a_record_before_its_nbf_is_refused() {
        assert_eq!(
            check_currentness(&claims("wl", 7, 1), &budget(60, 5), 990),
            Err(AdmissionRecordRefusal::Expired)
        );
    }

    /// An inverted window is not a window. Without this clause an `exp <= nbf` record would
    /// be admitted whenever skew happened to cover the gap.
    #[test]
    fn an_inverted_window_is_refused() {
        let mut c = claims("wl", 7, 1);
        c.nbf = 1_060;
        c.exp = 1_000;
        assert_eq!(
            check_currentness(&c, &budget(60, 5), 1_030),
            Err(AdmissionRecordRefusal::Expired)
        );
    }

    /// Saturation, not wraparound. An extreme `iat` is what a store-write adversary would
    /// reach for if `now - iat` could wrap past the cap.
    #[test]
    fn extreme_coordinates_saturate_rather_than_wrap() {
        let mut c = claims("wl", 7, 1);
        c.iat = i64::MIN;
        c.nbf = i64::MIN;
        c.exp = i64::MAX;
        assert!(matches!(
            check_currentness(&c, &budget(60, 5), 1_030),
            Err(AdmissionRecordRefusal::WindowExceedsBudget)
        ));

        let mut c = claims("wl", 7, 1);
        c.iat = i64::MAX;
        assert_eq!(
            check_currentness(&c, &budget(60, 5), 1_030),
            Err(AdmissionRecordRefusal::Expired)
        );
    }
}
