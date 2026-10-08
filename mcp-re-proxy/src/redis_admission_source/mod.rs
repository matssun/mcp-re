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
//! Only a store that did not ANSWER — a connect failure, or a `GET` [`reply`] classes as
//! unanswered (a dropped, refused or timed-out connection, or a server answering nothing right
//! now) — is [`AdmissionSourceError::Unavailable`], routed to the §5.2 degraded fork within P.
//!
//! A store that answered with something this deployment will not act on — absent, malformed,
//! wrongly signed, wrongly issued, about another workload, past the currentness budget, or
//! rejecting this deployment's credentials — is a definitive negative (`AnsweredAs::NoRecord`
//! or `AnsweredAs::Refused`). Routing those to the degraded fork would serve the caller on its
//! own assertion, so corrupting a `revoked` record would be a cheaper un-revoke.

use redis::aio::ConnectionManager;

/// Saying WHICH refusal class fired, at a pace a caller cannot set.
mod refusal_report;
/// What one `GET` reply is: an outage, or the store's answer about the key.
mod reply;

use refusal_report::ReportedClasses;

use crate::admission_source::admission_key;
use crate::admission_source::classify_stored_bytes;
use crate::admission_source::classify_unreadable_reply;
use crate::admission_source::AdmissionFuture;
use crate::admission_source::AdmissionRecordVerifier;
use crate::admission_source::AdmissionSourceError;
use crate::admission_source::AnsweredAs;
use crate::admission_source::AsyncAdmissionSource;
use crate::async_redis_store::retention_promise;
use crate::deployment_request::RedactedLocator;
use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;

/// A cross-process authoritative admission source backed by Redis.
pub struct RedisAdmissionSource {
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
    /// The one place stored bytes become authoritative state.
    verifier: AdmissionRecordVerifier,
    /// Which refusal classes have already been reported. See [`Self::report_once`].
    reported: ReportedClasses,
}

impl RedisAdmissionSource {
    /// The shared retention verdict in this source's own error type. Separate from
    /// [`Self::connect`] so the mapping an operator reads is exercised without a server.
    fn retention_refusal(policy: Option<&str>) -> Result<(), AdmissionSourceError> {
        retention_promise::retention_verdict(policy, &retention_promise::ADMISSION)
            .map_err(|details| AdmissionSourceError::Unavailable { details })
    }

    /// Connect to `url` (e.g. `redis://host:port`). Fails closed if the client cannot be
    /// opened, the connection cannot be established, or the instance may evict the key.
    ///
    /// The verifier is supplied rather than derived here: which authority this deployment
    /// trusts, and how current it requires a record to be, are the validated deployment's
    /// facts and not a store adapter's. `url` is operator-supplied and its authority may
    /// carry a credential, so a diagnostic names it rather than echoing it.
    pub async fn connect(
        url: &str,
        verifier: AdmissionRecordVerifier,
    ) -> Result<Self, AdmissionSourceError> {
        let client = redis::Client::open(url).map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("open redis client for {}: {e}", RedactedLocator::of(url)),
        })?;
        let mut conn = client.get_connection_manager().await.map_err(|e| {
            AdmissionSourceError::Unavailable {
                details: format!("connect redis async to {}: {e}", RedactedLocator::of(url)),
            }
        })?;
        Self::retention_refusal(retention_promise::read_policy(&mut conn).await.as_deref())?;
        Ok(RedisAdmissionSource {
            conn,
            verifier,
            reported: ReportedClasses::default(),
        })
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
    /// Setting no expiry is only half of that: an evicting instance drops the key anyway at
    /// `maxmemory`, so [`Self::connect`] refuses one that does not promise otherwise.
    ///
    /// The outer error is an outage: the store did not answer. The inner one is the record
    /// refused, a verdict on the bytes. The decision does not raise this replica's read
    /// floor, because a record this process has not read back is not one it observed.
    pub async fn publish(
        &self,
        signed_record: &str,
        subject: &str,
        now: i64,
    ) -> Result<Result<(), AdmissionRecordRefusal>, AdmissionSourceError> {
        let verified = match self.verifier.verify_unobserved(subject, signed_record, now) {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut conn = self.conn.clone();
        let result: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(admission_key(verified.state().admission_id()))
            .arg(signed_record)
            .query_async(&mut conn)
            .await;
        result
            .map(Ok)
            .map_err(|e| AdmissionSourceError::Unavailable {
                details: format!("redis SET admission failed: {e}"),
            })
    }

    /// The inherent read, so `publish` need not go through the trait object.
    async fn current_state(
        &self,
        admission_id: &str,
        now: i64,
    ) -> Result<AnsweredAs, AdmissionSourceError> {
        let mut conn = self.conn.clone();
        let raw: Result<redis::Value, redis::RedisError> = redis::cmd("GET")
            .arg(admission_key(admission_id))
            .query_async(&mut conn)
            .await;
        // The ONLY outage is `read_reply`'s `Err`. Everything below is the store having
        // answered, and what an answer means is `crate::admission_source::answer`'s — a
        // classification with no outage inhabitant, so no arm of it can reach the degraded
        // fork.
        let answer = match reply::read_reply(raw)? {
            reply::StoreReply::Absent => {
                classify_stored_bytes(&self.verifier, admission_id, None, now)
            }
            reply::StoreReply::Bytes(bytes) => {
                classify_stored_bytes(&self.verifier, admission_id, Some(&bytes), now)
            }
            reply::StoreReply::Unreadable => classify_unreadable_reply(),
        };
        // What this adapter adds to the shared classification: saying WHICH class fired, at
        // a pace a caller cannot set. The answer itself still carries the class to the gate.
        if let AnsweredAs::Refused(refusal) = &answer {
            self.reported.report_once(*refusal);
        }
        Ok(answer)
    }
}

impl AsyncAdmissionSource for RedisAdmissionSource {
    fn current<'a>(&'a self, admission_id: &'a str, now: i64) -> AdmissionFuture<'a, AnsweredAs> {
        Box::pin(async move { self.current_state(admission_id, now).await })
    }
}

#[cfg(test)]
mod tests {
    use super::RedisAdmissionSource;
    use crate::admission_source::test_support::{
        signed_admitted, signed_revoked, verifier_for, AUTHORITY_KID,
    };
    use crate::admission_source::AdmissionSourceError;
    use crate::async_redis_store::retention_promise::scripted_server::redis_reporting;
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

    /// The connect diagnostic NAMES the endpoint instead of echoing it. A URL redis
    /// refuses to open still carries its userinfo, so this failure path is where an
    /// operator's password would otherwise reach the log. The scheme is one redis does
    /// not accept, so the locator decomposes and its host can be named.
    #[tokio::test]
    async fn a_connect_diagnostic_names_the_endpoint_without_its_credentials() {
        let key = authority();
        let err = RedisAdmissionSource::connect(
            "redis+bogus://mats:hunter2@redis.internal:6379",
            verifier_for(&key, 60, 5),
        )
        .await
        .err()
        .expect("a locator redis cannot open is a connect failure");
        let AdmissionSourceError::Unavailable { details } = err;
        assert!(
            !details.contains("hunter2"),
            "the password reached the diagnostic: {details}"
        );
        assert!(
            details.contains("redis.internal"),
            "the endpoint is what an operator needs named: {details}"
        );
    }

    /// An admission record carries no TTL because absence is a definitive negative, so an
    /// instance that may evict it is refused at connect. Driven on the verdict-to-error
    /// mapping rather than a store double: the decision is pure, and a scripted server
    /// would only re-prove the shared module's own test.
    #[test]
    fn an_evicting_admission_instance_is_refused_with_the_admission_consequence() {
        let err = RedisAdmissionSource::retention_refusal(Some("allkeys-lru"))
            .expect_err("an instance that may evict an admission record must not back it");
        let AdmissionSourceError::Unavailable { details } = err;
        assert!(details.contains("allkeys-lru"), "{details}");
        assert!(
            details.contains("admission outage") && details.contains("--admission-redis-url"),
            "the refusal must state the admission consequence and the endpoint: {details}"
        );
        assert!(
            RedisAdmissionSource::retention_refusal(Some("noeviction")).is_ok(),
            "the supported configuration must still connect"
        );
        assert!(
            RedisAdmissionSource::retention_refusal(None).is_err(),
            "an unreadable policy is not evidence of a safe one"
        );
    }

    /// The mapping above is the consequence; this is that `connect` REACHES it. Driven
    /// against a scripted server reporting an evicting policy, so deleting the check
    /// from [`RedisAdmissionSource::connect`] turns this red — where the pure test on
    /// `retention_refusal` alone stays green with the connect path unguarded.
    #[tokio::test]
    async fn an_evicting_redis_is_refused_by_the_admission_connect_itself() {
        let key = authority();
        let url = redis_reporting("allkeys-lru").await;
        let err = RedisAdmissionSource::connect(&url, verifier_for(&key, 60, 5))
            .await
            .err()
            .expect("an instance that may evict an admission record must not be connected");
        let AdmissionSourceError::Unavailable { details } = err;
        assert!(
            details.contains("allkeys-lru") && details.contains("admission outage"),
            "the connect refusal must carry the admission consequence: {details}"
        );
    }

    /// The companion the refusal above needs: the identical connect against a server
    /// reporting `noeviction` has to SUCCEED, or the refusal proves only that the
    /// scripted server is broken.
    #[tokio::test]
    async fn a_noeviction_redis_is_accepted_by_the_admission_connect() {
        let key = authority();
        let url = redis_reporting("noeviction").await;
        RedisAdmissionSource::connect(&url, verifier_for(&key, 60, 5))
            .await
            .map(|_| ())
            .expect("noeviction is the supported configuration");
    }

    /// A record this deployment would not accept is a verdict on the bytes, so it must not
    /// inhabit the outage variant the serving path routes to the degraded fork.
    #[tokio::test]
    async fn a_publish_refusal_is_a_verdict_and_not_an_outage() {
        let url = redis_reporting("noeviction").await;
        let source = RedisAdmissionSource::connect(&url, verifier_for(&authority(), 60, 5))
            .await
            .expect("noeviction is the supported configuration");
        let attacker = SigningKey::from_seed_bytes(&[4u8; 32]);
        let outcome = source
            .publish(&signed_admitted(&attacker, "wl", 9, 1, 1_000), "wl", 1_030)
            .await;
        assert!(
            matches!(outcome, Ok(Err(AdmissionRecordRefusal::SignatureInvalid))),
            "{outcome:?}"
        );
    }

    /// The floor is this process's READ history: a publication whose SET may not have
    /// landed is not one it observed, so a later read of an older record still passes.
    #[tokio::test]
    async fn publishing_a_record_does_not_raise_this_replicas_read_floor() {
        let key = authority();
        let url = redis_reporting("noeviction").await;
        let source = RedisAdmissionSource::connect(&url, verifier_for(&key, 60, 5))
            .await
            .expect("noeviction is the supported configuration");
        assert!(matches!(
            source
                .publish(&signed_admitted(&key, "wl", 7, 4, 1_000), "wl", 1_030)
                .await,
            Ok(Ok(()))
        ));
        assert!(source
            .verifier
            .verify("wl", &signed_admitted(&key, "wl", 7, 1, 1_000), 1_030)
            .is_ok());
    }

    /// A connected source over a scripted server answering every `GET` with `reply`.
    async fn source_answering_get(reply: &str) -> RedisAdmissionSource {
        use crate::async_redis_store::retention_promise::scripted_server::{serve, Script};
        let (url, _) = serve(Script {
            policy: Some("noeviction".to_string()),
            recorded: vec!["GET".to_string()],
            reply: reply.to_string(),
        })
        .await;
        RedisAdmissionSource::connect(&url, verifier_for(&authority(), 60, 5))
            .await
            .expect("noeviction is the supported configuration")
    }

    /// THM-0129's adversary can write the store and holds no signing key. Giving a revoked
    /// workload's key another Redis type makes the server answer `WRONGTYPE`; that is the
    /// store's answer about the key and must be a refused record, because an outage would
    /// reach the replica-wide degraded window that other workloads' reads keep open.
    #[tokio::test]
    async fn a_key_of_another_type_is_a_refused_record_and_not_an_outage() {
        let source = source_answering_get(
            "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n",
        )
        .await;
        let answer = source.current_state("wl", 1_030).await;
        assert!(
            matches!(
                answer,
                Ok(crate::admission_source::AnsweredAs::Refused(
                    AdmissionRecordRefusal::Malformed
                ))
            ),
            "{answer:?}"
        );
    }

    /// A reply of another shape than a string is the same class of answer.
    #[tokio::test]
    async fn a_reply_that_is_not_a_string_is_a_refused_record_and_not_an_outage() {
        let source = source_answering_get(":5\r\n").await;
        let answer = source.current_state("wl", 1_030).await;
        assert!(
            matches!(
                answer,
                Ok(crate::admission_source::AnsweredAs::Refused(
                    AdmissionRecordRefusal::Malformed
                ))
            ),
            "{answer:?}"
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
