// SPDX-License-Identifier: Apache-2.0
//! What a store that ANSWERED has said — the one owner of the classification every
//! admission source implements.
//!
//! # The fork this exists to make structural
//!
//! An admission source has two failures with opposite consequences. A store that could not
//! be reached is an OUTAGE, and the serving path routes an outage to the §5.2 degraded
//! fork: served, if the deployment opted in, and only within P. A store that answered with
//! something this deployment will not act on — absent, malformed, wrongly signed, wrongly
//! issued, about another workload, or past the currentness budget — is a DEFINITIVE
//! NEGATIVE, and serving on it would mean the caller is served on its own assertion.
//! Corrupting a `revoked` record would then be a cheaper un-revoke than issuing a new
//! admission.
//!
//! Each source used to spell that mapping out for itself: the in-memory one as
//! `verify(..).ok()`, the shared one as a `match` with an operator line in the refusal arm.
//! Two spellings of one rule is two chances for one of them to route a refusal to the
//! degraded fork, and the claim is quantified over every source.
//!
//! So the rule is a type here rather than a convention there. [`AnsweredAs`] has **no
//! outage inhabitant**: a source that has an answer cannot produce an
//! [`AdmissionSourceError`] from it, because this classification cannot express one. The
//! outage stays where it belongs — at the call that did not come back — and deleting every
//! comment in every source cannot move it.
//!
//! # What this does NOT own
//!
//! Whether the bytes are authentic. That is
//! [`AdmissionRecordVerifier`](super::AdmissionRecordVerifier)'s, and this calls it rather
//! than restating any part of it. Nor what a source tells an operator: the refusal CLASS is
//! carried out so a source that paces operator lines can say which one fired, and pacing is
//! that source's own authority.

use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;
use mcp_re_http_profile::authoritative_admission::record::CurrentAdmissionState;

use super::verifier::AdmissionRecordVerifier;

/// What a reachable store's answer means.
///
/// Three cases, and every one of them is a statement the deployment can act on. There is
/// deliberately no fourth for "could not tell": a source holding an answer has been told
/// something, and the absence of an outage variant is what makes the degraded fork
/// unreachable from here.
#[derive(Debug)]
pub enum AnsweredAs {
    /// The answer is this deployment's current authoritative state for the workload.
    State(CurrentAdmissionState),
    /// The store holds no record for the workload. A negative, not an absence of
    /// information: the authority publishes what it means, and silence from a reachable
    /// store means nothing is admitted.
    NoRecord,
    /// The store answered with something this deployment will not act on, and which class
    /// of thing it was.
    ///
    /// The class travels with the answer to the gate, which records it as the refusal's
    /// cause: a forged record and an absent one are different facts, and the durable audit
    /// record is where a deployment finds out which one it had. The shared source also
    /// names the class on a paced operator line.
    Refused(AdmissionRecordRefusal),
}

/// Classify a reachable store's answer. `raw` is `None` when the store holds no record.
pub(crate) fn classify_answer(
    verifier: &AdmissionRecordVerifier,
    admission_id: &str,
    raw: Option<&str>,
    now: i64,
) -> AnsweredAs {
    let Some(raw) = raw else {
        return AnsweredAs::NoRecord;
    };
    match verifier.verify(admission_id, raw, now) {
        Ok(verified) => AnsweredAs::State(verified),
        Err(refusal) => AnsweredAs::Refused(refusal),
    }
}

/// Classify a reachable store's answer given as the bytes it holds. `raw` is `None` when
/// the store holds no record. Bytes that are not UTF-8 cannot be a record, so they are
/// [`AdmissionRecordRefusal::Malformed`] — the store answered, with something unusable.
/// Only a store holding bytes rather than text needs it: the `redis_replay` build's.
#[cfg(any(feature = "redis_replay", test))]
pub(crate) fn classify_stored_bytes(
    verifier: &AdmissionRecordVerifier,
    admission_id: &str,
    raw: Option<&[u8]>,
    now: i64,
) -> AnsweredAs {
    match raw.map(std::str::from_utf8) {
        None => AnsweredAs::NoRecord,
        Some(Ok(text)) => classify_answer(verifier, admission_id, Some(text), now),
        Some(Err(_)) => AnsweredAs::Refused(AdmissionRecordRefusal::Malformed),
    }
}

/// The store answered the read with a reply that cannot hold a record at all: an error
/// about the key it holds, or a value of another type. That is an answer about this
/// workload's key, so it is a definitive negative and never an outage — a party that can
/// write the store chooses what type a key holds.
#[cfg(any(feature = "redis_replay", test))]
pub(crate) fn classify_unreadable_reply() -> AnsweredAs {
    AnsweredAs::Refused(AdmissionRecordRefusal::Malformed)
}

#[cfg(test)]
mod tests {
    use super::classify_answer;
    use super::classify_stored_bytes;
    use super::classify_unreadable_reply;
    use super::AnsweredAs;
    use crate::admission_source::test_support::{signed_admitted, signed_revoked, verifier_for};
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;
    use mcp_re_http_profile::AdmissionStatus;

    fn authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[3u8; 32])
    }

    /// The ACCEPTING half, so nothing below is satisfied by a classifier that refuses
    /// everything.
    #[test]
    fn a_current_record_from_the_configured_authority_is_state() {
        let key = authority();
        let v = verifier_for(&key, 60, 5);
        let record = signed_admitted(&key, "wl", 7, 1, 1_000);
        let AnsweredAs::State(state) = classify_answer(&v, "wl", Some(&record), 1_030) else {
            panic!("a current record signed by the configured authority is state");
        };
        assert_eq!(state.state().status(), AdmissionStatus::Admitted);
        assert_eq!(state.state().admission_id(), "wl");
    }

    /// A REVOCATION is state the source returns, not a failure to obtain state. Routing it
    /// to the degraded fork would make a revocation serve the caller.
    #[test]
    fn a_signed_revocation_is_state_and_not_a_failure_to_obtain_state() {
        let key = authority();
        let v = verifier_for(&key, 60, 5);
        let record = signed_revoked(&key, "wl", 7, 2, 1_010);
        let AnsweredAs::State(state) = classify_answer(&v, "wl", Some(&record), 1_020) else {
            panic!("a revocation is a statement");
        };
        assert_eq!(state.state().status(), AdmissionStatus::Revoked);
    }

    /// Everything a store writer without the signing authority can produce, and the
    /// currentness budget, classify as a definitive negative — never as an outage, which
    /// this type cannot express.
    #[test]
    fn every_unacceptable_answer_is_a_definitive_negative_with_its_class() {
        let key = authority();
        let attacker = SigningKey::from_seed_bytes(&[4u8; 32]);
        let v = verifier_for(&key, 60, 5);

        assert!(matches!(
            classify_answer(&v, "wl", None, 1_030),
            AnsweredAs::NoRecord
        ));
        assert!(matches!(
            classify_answer(&v, "wl", Some("5:admitted"), 1_030),
            AnsweredAs::Refused(AdmissionRecordRefusal::Malformed)
        ));
        assert!(matches!(
            classify_answer(
                &v,
                "wl",
                Some(&signed_admitted(&attacker, "wl", 9, 1, 1_000)),
                1_030
            ),
            AnsweredAs::Refused(AdmissionRecordRefusal::SignatureInvalid)
        ));
        assert!(matches!(
            classify_answer(
                &v,
                "wl-b",
                Some(&signed_admitted(&key, "wl-a", 7, 1, 1_000)),
                1_030
            ),
            AnsweredAs::Refused(AdmissionRecordRefusal::SubjectMismatch)
        ));
    }

    /// The budget is part of the classification and not only of a verifier read in
    /// isolation: the SAME bytes are state inside the window and a negative outside it.
    #[test]
    fn the_same_bytes_are_state_inside_the_budget_and_a_negative_outside_it() {
        let key = authority();
        let record = signed_admitted(&key, "wl", 7, 1, 1_000);

        let inside = verifier_for(&key, 60, 5);
        assert!(matches!(
            classify_answer(&inside, "wl", Some(&record), 1_030),
            AnsweredAs::State(_)
        ));

        let outside = verifier_for(&key, 60, 5);
        assert!(matches!(
            classify_answer(&outside, "wl", Some(&record), 1_066),
            AnsweredAs::Refused(AdmissionRecordRefusal::Expired)
        ));
    }

    /// The store's bytes are what a reader classifies, and bytes a writer chose need not be
    /// text. Non-UTF-8 bytes are a malformed record — a negative — while the same record as
    /// bytes classifies exactly as it does as text.
    #[test]
    fn stored_bytes_that_are_not_text_are_a_malformed_record_and_not_an_outage() {
        let key = authority();
        let v = verifier_for(&key, 60, 5);
        assert!(matches!(
            classify_stored_bytes(&v, "wl", Some(&[0xff, 0xfe, b'x']), 1_030),
            AnsweredAs::Refused(AdmissionRecordRefusal::Malformed)
        ));
        assert!(matches!(
            classify_stored_bytes(&v, "wl", None, 1_030),
            AnsweredAs::NoRecord
        ));
        let record = signed_revoked(&key, "wl", 7, 2, 1_010);
        let AnsweredAs::State(state) =
            classify_stored_bytes(&v, "wl", Some(record.as_bytes()), 1_020)
        else {
            panic!("a genuine record is state whether it arrives as text or bytes");
        };
        assert_eq!(state.state().status(), AdmissionStatus::Revoked);
    }

    /// A reply that cannot hold a record is still the store's answer about the key.
    #[test]
    fn a_reply_that_cannot_hold_a_record_is_a_malformed_record() {
        assert!(matches!(
            classify_unreadable_reply(),
            AnsweredAs::Refused(AdmissionRecordRefusal::Malformed)
        ));
    }
}
