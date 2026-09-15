// SPDX-License-Identifier: Apache-2.0
//! A single-process admission record store.
//!
//! The same shape as the shared Redis one and for the same reason: it holds SIGNED records
//! and verifies them on the way out. It is a substrate, not an authority, so the value it
//! hands the gate is the verifier's product and not something it can assert by itself.
//!
//! That is what makes it safe to ship. A source that could hand over unauthenticated state
//! would be a second producer of the thing
//! [`CurrentAdmissionState`](mcp_re_http_profile::authoritative_admission::record::CurrentAdmissionState)
//! exists to make unforgeable — and it would be the easiest one to reach, because it takes
//! no key.
//!
//! What it CANNOT do is carry a revocation across replicas: each process holds its own map,
//! so revoking here says nothing to any other replica. A fleet wires the shared store.

use std::collections::HashMap;
use std::sync::Mutex;

use mcp_re_http_profile::authoritative_admission::record::CurrentAdmissionState;

use super::verifier::AdmissionRecordVerifier;
use super::{AdmissionFuture, AdmissionSourceError, AsyncAdmissionSource};

/// A single-process in-memory admission source — single-replica runs and test harnesses.
pub struct InMemoryAdmissionSource {
    /// Signed records, by the id they were published under.
    records: Mutex<HashMap<String, String>>,
    /// When set, every lookup fails as unavailable — for exercising the §5.2 degraded fork
    /// without taking a real store down.
    unavailable: Mutex<bool>,
    /// The one place stored bytes become authoritative state.
    verifier: AdmissionRecordVerifier,
}

impl InMemoryAdmissionSource {
    /// A store that will act on records from the authority `verifier` trusts.
    pub fn new(verifier: AdmissionRecordVerifier) -> Self {
        InMemoryAdmissionSource {
            records: Mutex::new(HashMap::new()),
            unavailable: Mutex::new(false),
            verifier,
        }
    }

    /// Store a signed record under `admission_id`.
    ///
    /// No signing happens here: this is the substrate, and it holds no key. A record filed
    /// under a workload it is not about is not refused HERE — the reader refuses it, which
    /// is the honest place, because in a real deployment the writer is not this process.
    pub fn publish(&self, admission_id: &str, signed_record: String) {
        self.records
            .lock()
            .unwrap_or_else(recover)
            .insert(admission_id.to_owned(), signed_record);
    }

    /// Remove a workload's record. The authority's DELETE, which every source must survive:
    /// a missing record is a definitive negative, not an outage.
    pub fn remove(&self, admission_id: &str) {
        self.records
            .lock()
            .unwrap_or_else(recover)
            .remove(admission_id);
    }

    /// Make every subsequent lookup fail as unavailable (or stop doing so).
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().unwrap_or_else(recover) = unavailable;
    }
}

/// A poisoned record set, as the outage this source already reports.
///
/// A lock is poisoned because a thread panicked while holding it: runtime state, not a fact
/// about this call. `Unavailable` is what a record set nobody can trust means to an
/// admission decision, and the caller fails closed on it already.
fn poisoned<T>(_: std::sync::PoisonError<T>) -> AdmissionSourceError {
    AdmissionSourceError::Unavailable {
        details: "in-memory admission records are poisoned".to_owned(),
    }
}

/// The guard behind a poisoned lock, for the writers that have no verdict to report.
///
/// `publish`, `remove` and `set_unavailable` return `()`, so there is nowhere to carry an
/// outage to, and the map is a plain `HashMap`. Every READER below reports the outage
/// instead, which is where a decision is actually taken on this state. Nothing a writer can
/// leave behind admits anybody: the records are signed, and the reader verifies them.
fn recover<T>(poisoned: std::sync::PoisonError<T>) -> T {
    poisoned.into_inner()
}

impl InMemoryAdmissionSource {
    /// The read, written as a plain function so the trait method is the `Box::pin` and
    /// nothing else. The async block is not a scope this logic belongs inside: none of it
    /// awaits.
    fn read(
        &self,
        admission_id: &str,
        now: i64,
    ) -> Result<Option<CurrentAdmissionState>, AdmissionSourceError> {
        // Class R: a poisoned lock is runtime state, reported through the outage the
        // caller already handles.
        if *self.unavailable.lock().map_err(poisoned)? {
            return Err(AdmissionSourceError::Unavailable {
                details: "in-memory source marked unavailable".to_owned(),
            });
        }
        let raw = self
            .records
            .lock()
            .map_err(poisoned)?
            .get(admission_id)
            .cloned();
        let Some(raw) = raw else {
            return Ok(None);
        };
        // A record this store HAS but cannot authenticate is a definitive negative, exactly
        // as an absent one is. Never an outage: that fork serves the caller on its own
        // assertion.
        Ok(self.verifier.verify(admission_id, &raw, now).ok())
    }
}

impl AsyncAdmissionSource for InMemoryAdmissionSource {
    fn current<'a>(
        &'a self,
        admission_id: &'a str,
        now: i64,
    ) -> AdmissionFuture<'a, Option<CurrentAdmissionState>> {
        Box::pin(async move { self.read(admission_id, now) })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{signed_admitted, signed_revoked, verifier_for};
    use super::*;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::AdmissionStatus;
    use std::future::Future;

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    fn authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[3u8; 32])
    }

    fn source(key: &SigningKey) -> InMemoryAdmissionSource {
        InMemoryAdmissionSource::new(verifier_for(key, 60, 5))
    }

    #[test]
    fn an_unknown_workload_is_a_definitive_negative_not_an_outage() {
        let key = authority();
        assert!(matches!(
            block_on(source(&key).current("nobody", 1_030)),
            Ok(None)
        ));
    }

    #[test]
    fn an_outage_is_distinguishable_from_an_unknown_workload() {
        let key = authority();
        let s = source(&key);
        s.publish(
            "workload-7",
            signed_admitted(&key, "workload-7", 5, 1, 1_000),
        );
        s.set_unavailable(true);
        assert!(matches!(
            block_on(s.current("workload-7", 1_030)),
            Err(AdmissionSourceError::Unavailable { .. })
        ));
    }

    #[test]
    fn revoking_keeps_the_generation_and_changes_the_status() {
        // The generation is the anti-rollback counter, not a revocation signal: a revoked
        // record that also advanced the generation would be refused for the wrong reason,
        // and an auditor could not tell a revocation from a rotation.
        let key = authority();
        let s = source(&key);
        s.publish(
            "workload-7",
            signed_admitted(&key, "workload-7", 5, 1, 1_000),
        );
        s.publish(
            "workload-7",
            signed_revoked(&key, "workload-7", 5, 2, 1_000),
        );
        let state = block_on(s.current("workload-7", 1_030))
            .expect("reachable")
            .expect("record");
        assert_eq!(state.state().generation(), 5);
        assert_eq!(state.state().status(), AdmissionStatus::Revoked);
    }

    /// **A store writer is not an authority, in the single-process store too.** Writing a
    /// record signed by anything else — or bytes that are not a record at all — is a
    /// definitive negative and never an outage, so it cannot reach the degraded fork.
    #[test]
    fn a_record_this_store_cannot_authenticate_is_a_definitive_negative() {
        let key = authority();
        let attacker = SigningKey::from_seed_bytes(&[4u8; 32]);
        let s = source(&key);
        for forged in [
            signed_admitted(&attacker, "workload-7", 5, 1, 1_000),
            "not-a-record".to_owned(),
            String::new(),
        ] {
            s.publish("workload-7", forged);
            assert!(
                matches!(block_on(s.current("workload-7", 1_030)), Ok(None)),
                "an unauthenticatable record must be Ok(None), never an outage"
            );
        }
    }

    /// A genuine record filed under the WRONG workload answers for nobody.
    #[test]
    fn a_record_filed_under_another_workload_is_refused() {
        let key = authority();
        let s = source(&key);
        s.publish(
            "workload-9",
            signed_admitted(&key, "workload-7", 5, 1, 1_000),
        );
        assert!(matches!(block_on(s.current("workload-9", 1_030)), Ok(None)));
    }

    /// The rollback attack in the single-process store: revoke, then restore the old bytes.
    /// The revision floor refuses them immediately here, because this replica saw the
    /// revocation; the currentness budget is what covers a replica that did not.
    #[test]
    fn restoring_an_older_publication_after_a_revocation_is_refused() {
        let key = authority();
        let s = source(&key);
        let admitted = signed_admitted(&key, "workload-7", 5, 1, 1_000);
        s.publish("workload-7", admitted.clone());
        assert!(block_on(s.current("workload-7", 1_010))
            .expect("reachable")
            .is_some());

        s.publish(
            "workload-7",
            signed_revoked(&key, "workload-7", 5, 2, 1_000),
        );
        assert_eq!(
            block_on(s.current("workload-7", 1_020))
                .expect("reachable")
                .expect("record")
                .state()
                .status(),
            AdmissionStatus::Revoked
        );

        s.publish("workload-7", admitted);
        assert!(
            matches!(block_on(s.current("workload-7", 1_030)), Ok(None)),
            "the restored publication is older than one this replica accepted"
        );
    }

    /// An absent record after a DELETE is the authority having nothing to say, refused
    /// outright rather than routed to the degraded fork.
    #[test]
    fn a_deleted_record_is_a_definitive_negative() {
        let key = authority();
        let s = source(&key);
        s.publish(
            "workload-7",
            signed_admitted(&key, "workload-7", 5, 1, 1_000),
        );
        s.remove("workload-7");
        assert!(matches!(block_on(s.current("workload-7", 1_030)), Ok(None)));
    }
}
