// SPDX-License-Identifier: Apache-2.0
//! The one place a stored record becomes authoritative state.
//!
//! Every admission source — the shared Redis store, the single-process one — reads bytes
//! somebody else wrote and has to decide what they are worth. That decision is the same
//! decision in both, and it is the security boundary, so it is ONE owner rather than a
//! procedure each adapter remembers to call: a source that forgot to verify would be a
//! source that hands the gate whatever was in the store.
//!
//! What this owner holds is everything the decision needs that is NOT in the record —
//! which authority this deployment trusts, which evidence profile it speaks, how current a
//! record must be, and what publication sequence it has already seen. The record supplies
//! the rest, under signature.

use std::collections::HashMap;
use std::sync::Mutex;

use mcp_re_http_profile::authoritative_admission::record::{
    verify_admission_state_record, AdmissionRecordRefusal, AdmissionStateCurrentness,
    CurrentAdmissionState,
};

use crate::http_profile_serve::AdmissionAuthorityResolver;

/// Decides whether stored bytes are the admission authority's current statement.
pub struct AdmissionRecordVerifier {
    /// Resolves a record's `issuer_kid` to the configured authority key. The SAME seam the
    /// assertion path uses, and in a correct deployment the same one-entry closure: the
    /// authority that admits a workload is the authority that says whether it still is.
    resolve_authority: AdmissionAuthorityResolver,
    /// The evidence profile this deployment speaks.
    profile: &'static str,
    /// The deployment's declared currentness budget.
    currentness: AdmissionStateCurrentness,
    /// The highest publication sequence accepted per workload, so far, in THIS process.
    ///
    /// Hardening, not the boundary — see
    /// [`CurrentAdmissionState::state_revision`]. It is a plain `HashMap` behind a `Mutex`
    /// rather than anything cleverer because the contended case is one lock-free read of a
    /// small map per admitted request, and because a floor that is occasionally forgotten
    /// is exactly as sound as one that never existed: what it can never do is ADMIT
    /// something the budget refuses.
    observed_revisions: Mutex<HashMap<String, u64>>,
}

impl AdmissionRecordVerifier {
    /// The verifier a deployment's validated admission state implies.
    pub fn new(
        resolve_authority: AdmissionAuthorityResolver,
        profile: &'static str,
        currentness: AdmissionStateCurrentness,
    ) -> Self {
        AdmissionRecordVerifier {
            resolve_authority,
            profile,
            currentness,
            observed_revisions: Mutex::new(HashMap::new()),
        }
    }

    /// Decide `raw`, read under `admission_id`, as of `now`.
    ///
    /// On success the workload's observed publication floor advances, so a later read of an
    /// older publication is refused for as long as this process lives.
    pub fn verify(
        &self,
        admission_id: &str,
        raw: &str,
        now: i64,
    ) -> Result<CurrentAdmissionState, AdmissionRecordRefusal> {
        let resolve = &self.resolve_authority;
        let verified = verify_admission_state_record(
            raw,
            admission_id,
            self.profile,
            &self.currentness,
            self.observed_floor(admission_id),
            now,
            |kid: &str| resolve(kid),
        )?;
        self.record_observed(admission_id, verified.state_revision());
        Ok(verified)
    }

    /// The highest publication sequence already accepted for `admission_id`.
    ///
    /// A poisoned map yields `None`, which DROPS the hardening rather than refusing the
    /// call. That is the right way round: the floor narrows a window the budget already
    /// closes, so losing it costs a little and refusing on it would let a panic anywhere in
    /// this process become a fleet-wide admission outage. The budget, which needs no
    /// memory, is untouched either way.
    fn observed_floor(&self, admission_id: &str) -> Option<u64> {
        self.observed_revisions
            .lock()
            .ok()?
            .get(admission_id)
            .copied()
    }

    fn record_observed(&self, admission_id: &str, revision: u64) {
        let Ok(mut observed) = self.observed_revisions.lock() else {
            return;
        };
        let floor = observed.entry(admission_id.to_owned()).or_insert(revision);
        *floor = (*floor).max(revision);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_source::test_support::{
        issue, signed_admitted, verifier_for, AUTHORITY_KID, PROFILE,
    };
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::AdmissionStatus;

    #[test]
    fn a_record_signed_by_the_configured_authority_verifies() {
        let key = SigningKey::from_seed_bytes(&[3u8; 32]);
        let v = verifier_for(&key, 60, 5);
        let state = v
            .verify("wl-a", &signed_admitted(&key, "wl-a", 7, 1, 1_000), 1_030)
            .unwrap_or_else(|e| panic!("a current record must verify: {e}"));
        assert_eq!(state.state().generation(), 7);
        assert_eq!(state.state().status(), AdmissionStatus::Admitted);
    }

    /// The floor advances on a successful verification, so a later read of an older
    /// publication is refused by a replica that was already running.
    #[test]
    fn accepting_a_publication_raises_the_floor_for_that_workload() {
        let key = SigningKey::from_seed_bytes(&[3u8; 32]);
        let v = verifier_for(&key, 60, 5);
        let older = signed_admitted(&key, "wl-a", 7, 1, 1_000);
        let newer = signed_admitted(&key, "wl-a", 7, 4, 1_000);

        assert!(v.verify("wl-a", &older, 1_030).is_ok(), "no floor yet");
        assert!(v.verify("wl-a", &newer, 1_030).is_ok());
        assert_eq!(
            v.verify("wl-a", &older, 1_030),
            Err(AdmissionRecordRefusal::RevisionRewound),
            "a restored older publication is refused once a newer one has been seen"
        );
    }

    /// The floor is PER WORKLOAD. A shared counter would make one workload's publication
    /// cadence refuse another's records, which is an outage with a security-sounding name.
    #[test]
    fn one_workloads_floor_does_not_refuse_another_workloads_record() {
        let key = SigningKey::from_seed_bytes(&[3u8; 32]);
        let v = verifier_for(&key, 60, 5);
        assert!(v
            .verify("wl-a", &signed_admitted(&key, "wl-a", 7, 9, 1_000), 1_030)
            .is_ok());
        assert!(
            v.verify("wl-b", &signed_admitted(&key, "wl-b", 7, 1, 1_000), 1_030)
                .is_ok(),
            "wl-b's first record is not a rewind of wl-a's ninth"
        );
    }

    /// The verifier is the boundary: a record from any other key is refused whatever the
    /// store says, which is the whole proposition store-write access cannot defeat.
    #[test]
    fn a_record_from_an_unconfigured_key_is_refused() {
        let configured = SigningKey::from_seed_bytes(&[3u8; 32]);
        let attacker = SigningKey::from_seed_bytes(&[4u8; 32]);
        let v = verifier_for(&configured, 60, 5);
        assert_eq!(
            v.verify(
                "wl-a",
                &signed_admitted(&attacker, "wl-a", 7, 1, 1_000),
                1_030
            ),
            Err(AdmissionRecordRefusal::SignatureInvalid)
        );
    }

    /// A record whose issuer this deployment does not configure at all.
    #[test]
    fn a_record_naming_an_unknown_issuer_is_refused() {
        let key = SigningKey::from_seed_bytes(&[3u8; 32]);
        let v = verifier_for(&key, 60, 5);
        let mut claims = crate::admission_source::test_support::claims("wl-a", 7, 1, 1_000);
        claims.issuer_kid = "someone/else/1".to_owned();
        assert_eq!(
            v.verify("wl-a", &issue(&key, &claims), 1_030),
            Err(AdmissionRecordRefusal::IssuerUntrusted)
        );
        assert_ne!(claims.issuer_kid, AUTHORITY_KID);
        assert_eq!(PROFILE, "mcp-re-http-v1");
    }
}
