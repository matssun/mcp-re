// SPDX-License-Identifier: Apache-2.0
//! The Redis-backed authoritative admission source (#414 rev 2 §4.3) — the shared
//! tier that carries a REVOCATION to every replica.
//!
//! The same shape as [`crate::redis_continuation_store`]: one auto-reconnecting,
//! multiplexed [`ConnectionManager`] cloned per op. What lives under
//! `mcp-re:admission:<id>` is a compact JWS signed by the admission authority — see
//! [`mcp_re_http_profile::authoritative_admission::record`] for what it binds and why.
//!
//! # Redis is the substrate, not the authority
//!
//! The record used to be a bare `<generation>:<status>` string, and the argument for
//! believing it was that only trusted parties can write the key. That made the STORE the
//! admission authority. A party that obtains write access without the admission signing
//! authority can still delete state, corrupt it, or make the store unreachable — all of
//! which this deployment survives by failing closed. What it cannot do is mint an admission,
//! rewind a generation, move one workload's record onto another's key, or restore an old
//! admitted record past the deployment's declared currentness budget.
//!
//! Neither Redis ACLs nor `SET ... NX` are part of that argument. An ACL binds who may
//! connect, not what a record means, and a compare-and-set is an agreement between honest
//! writers rather than a defence against a malicious one. Cryptographic origin plus bounded
//! freshness is the boundary; everything else here is availability.
//!
//! # Live lookup, not push — and the claim is bounded accordingly
//!
//! #414 §5 frames propagation as push-invalidation with a bound P; this reads the
//! authoritative record per request instead. That is a stronger position than a cache, not
//! a weaker one — there is no staleness window to reason about, because there is no copy —
//! and it is what makes P measurable at all: propagation delay is the time for a write to
//! become visible to a reader, which is the store's own replication behaviour and nothing
//! this code can paper over.
//!
//! What it costs is a round trip on the request path. A deployment that cannot pay it wants
//! a bounded cache, and a bounded cache is a DIFFERENT claim — it reintroduces exactly the
//! staleness window `RevocationTier` exists to make honest.
//!
//! # What reaches the degraded fork, and what does not
//!
//! Only a store that did not ANSWER. A connect failure or a failed `GET` is
//! [`AdmissionSourceError::Unavailable`], which the serving path routes to the §5.2
//! degraded fork — served only if the deployment opted in, and only within P.
//!
//! A store that answered with something this deployment will not act on — absent, malformed,
//! wrongly signed, wrongly issued, about another workload, or past the currentness budget —
//! is `Ok(None)`, a definitive negative. Routing those to the degraded fork would serve the
//! caller on its own assertion, so corrupting a `revoked` record would be a cheaper
//! un-revoke than issuing a new admission.

use redis::aio::ConnectionManager;

use mcp_re_http_profile::authoritative_admission::record::CurrentAdmissionState;

use crate::admission_source::admission_key;
use crate::admission_source::AdmissionFuture;
use crate::admission_source::AdmissionRecordVerifier;
use crate::admission_source::AdmissionSourceError;
use crate::admission_source::AsyncAdmissionSource;

/// A cross-process authoritative admission source backed by Redis.
pub struct RedisAdmissionSource {
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
    /// The one place stored bytes become authoritative state.
    verifier: AdmissionRecordVerifier,
}

impl RedisAdmissionSource {
    /// Connect to `url` (e.g. `redis://host:port`). Fails closed if the client cannot be
    /// opened or the initial async connection cannot be established.
    ///
    /// The verifier is supplied rather than derived here: which authority this deployment
    /// trusts, and how current it requires a record to be, are the validated deployment's
    /// facts and not a store adapter's.
    pub async fn connect(
        url: &str,
        verifier: AdmissionRecordVerifier,
    ) -> Result<Self, AdmissionSourceError> {
        let client = redis::Client::open(url).map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let conn = client.get_connection_manager().await.map_err(|e| {
            AdmissionSourceError::Unavailable {
                details: format!("connect redis async: {e}"),
            }
        })?;
        Ok(RedisAdmissionSource { conn, verifier })
    }

    /// Store an already-signed authoritative record — the admission-authority side of the
    /// seam, and the write a propagation measurement times.
    ///
    /// **No signing happens here.** The authority's private key is control-plane material
    /// and never enters the serving process; this is the substrate accepting bytes.
    ///
    /// The record is VERIFIED before it is written, and the key comes from the subject the
    /// verifier read out of it. A caller therefore cannot file workload A's record under
    /// workload B's key, and cannot publish a record this deployment's own readers would
    /// refuse — the failure surfaces at the publisher, where it is attributable, instead of
    /// as a fleet-wide admission outage.
    ///
    /// No TTL on the key: an admission record is authoritative state, not a lease. Expiring
    /// the KEY would turn a healthy authority's silence into "no record", which the serving
    /// path treats as a definitive negative — every workload would fall out of admission on
    /// a timer. The record's own `exp` is what bounds it, and the authority republishes.
    pub async fn publish(
        &self,
        signed_record: &str,
        subject: &str,
        now: i64,
    ) -> Result<(), AdmissionSourceError> {
        let verified = self
            .verifier
            .verify(subject, signed_record, now)
            .map_err(|refusal| AdmissionSourceError::Unavailable {
                details: format!(
                    "refusing to publish an admission record this deployment would not \
                     accept: {refusal}"
                ),
            })?;
        let mut conn = self.conn.clone();
        let result: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(admission_key(verified.state().admission_id()))
            .arg(signed_record)
            .query_async(&mut conn)
            .await;
        result.map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("redis SET admission failed: {e}"),
        })
    }

    /// The inherent read, so `publish` need not go through the trait object.
    async fn current_state(
        &self,
        admission_id: &str,
        now: i64,
    ) -> Result<Option<CurrentAdmissionState>, AdmissionSourceError> {
        let mut conn = self.conn.clone();
        let raw: Result<Option<String>, redis::RedisError> = redis::cmd("GET")
            .arg(admission_key(admission_id))
            .query_async(&mut conn)
            .await;
        // The ONLY outage. Everything below is the store having answered.
        let raw = raw.map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("redis GET admission failed: {e}"),
        })?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        match self.verifier.verify(admission_id, &raw, now) {
            Ok(verified) => Ok(Some(verified)),
            Err(refusal) => {
                // Named, because an operator asking why a revocation has not taken effect —
                // or why an admitted workload is being refused — needs to know WHICH of the
                // seven classes fired. The raw value is withheld: it is attacker-influenced
                // and this line is a line-oriented record.
                eprintln!(
                    "mcp-re-proxy: the admission record for a workload in the shared store \
                     is not the configured authority's current statement ({refusal}); \
                     treating the workload as NOT ADMITTED. A reachable store that answered \
                     is not an outage. Raw value withheld."
                );
                Ok(None)
            }
        }
    }
}

impl AsyncAdmissionSource for RedisAdmissionSource {
    fn current<'a>(
        &'a self,
        admission_id: &'a str,
        now: i64,
    ) -> AdmissionFuture<'a, Option<CurrentAdmissionState>> {
        Box::pin(async move { self.current_state(admission_id, now).await })
    }
}

#[cfg(test)]
mod tests {
    use crate::admission_source::test_support::{
        signed_admitted, signed_revoked, verifier_for, AUTHORITY_KID,
    };
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;
    use mcp_re_http_profile::AdmissionStatus;

    fn authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[3u8; 32])
    }

    /// The decision this source delegates, exercised where it is decided. Connecting a real
    /// Redis is a different lane (`admission_propagation_measure_test`); what belongs here
    /// is that the bytes-to-state step refuses everything a store writer can produce.
    #[test]
    fn a_store_writer_without_the_signing_authority_produces_nothing_admitted() {
        let key = authority();
        let attacker = SigningKey::from_seed_bytes(&[4u8; 32]);
        let v = verifier_for(&key, 60, 5);

        // Mint: a record signed by a key the deployment does not configure.
        assert_eq!(
            v.verify("wl", &signed_admitted(&attacker, "wl", 9, 1, 1_000), 1_030),
            Err(AdmissionRecordRefusal::SignatureInvalid)
        );
        // Move: a genuine record under another workload's key.
        assert_eq!(
            v.verify("wl-b", &signed_admitted(&key, "wl-a", 7, 1, 1_000), 1_030),
            Err(AdmissionRecordRefusal::SubjectMismatch)
        );
        // Corrupt: bytes that are not a record.
        assert_eq!(
            v.verify("wl", "5:admitted", 1_030),
            Err(AdmissionRecordRefusal::Malformed)
        );
    }

    /// **The exact attack the ruling pins.** A legitimate ADMITTED record, a legitimate
    /// REVOKED one, and then the old bytes restored by a party that can write the store.
    /// Service is not restored beyond the authorized currentness bound.
    #[test]
    fn a_restored_admitted_record_does_not_outlive_the_authorized_window() {
        let key = authority();
        let v = verifier_for(&key, 60, 5);
        let admitted = signed_admitted(&key, "wl", 7, 1, 1_000);

        assert_eq!(
            v.verify("wl", &signed_revoked(&key, "wl", 7, 2, 1_010), 1_020)
                .expect("the revocation is genuine")
                .state()
                .status(),
            AdmissionStatus::Revoked
        );
        // Restored by a replica that has already seen publication 2: refused at once.
        assert_eq!(
            v.verify("wl", &admitted, 1_020),
            Err(AdmissionRecordRefusal::RevisionRewound)
        );
        // And on a replica that has seen nothing, the budget alone closes it.
        let fresh = verifier_for(&key, 60, 5);
        assert!(
            fresh.verify("wl", &admitted, 1_020).is_ok(),
            "inside the budget"
        );
        assert_eq!(
            fresh.verify("wl", &admitted, 1_066),
            Err(AdmissionRecordRefusal::Expired),
            "past it, without anybody detecting the substitution"
        );
    }

    /// The key an operator reads in `redis-cli` is still the workload's own name.
    #[test]
    fn the_record_is_addressed_by_the_workloads_own_name() {
        assert_eq!(
            crate::admission_source::admission_key("workload-7"),
            "mcp-re:admission:workload-7"
        );
        assert_eq!(AUTHORITY_KID, "admission-authority/root/1");
    }
}
