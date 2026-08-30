// SPDX-License-Identifier: Apache-2.0
//! The Redis-backed authoritative admission source (#414 rev 2 §4.3) — the shared
//! tier that carries a REVOCATION to every replica.
//!
//! The same shape as [`crate::redis_continuation_store`]: one auto-reconnecting,
//! multiplexed [`ConnectionManager`] cloned per op. The record is a small
//! `<generation>:<status>` string under `mcp-re:admission:<id>`, read on the serving
//! path and written by whatever holds the admission authority.
//!
//! **Live lookup, not push — and the claim is bounded accordingly.** #414 §5 frames
//! propagation as push-invalidation with a bound P; this reads the authoritative
//! record per request instead. That is a stronger position than a cache, not a weaker
//! one — there is no staleness window to reason about, because there is no copy —
//! and it is what makes P measurable at all: propagation delay is the time for a
//! write to become visible to a reader, which is the store's own replication
//! behaviour and nothing this code can paper over.
//!
//! What it costs is a round trip on the request path. A deployment that cannot pay it
//! wants a bounded cache, and a bounded cache is a DIFFERENT claim — it reintroduces
//! exactly the staleness window `RevocationTier` exists to make honest. Whichever is
//! chosen must be declared, because "revocation propagates within P" means nothing
//! without saying which mechanism produced P.
//!
//! Any transient error fails closed as [`AdmissionSourceError::Unavailable`], which
//! the serving path routes to the §5.2 degraded fork — served only if the deployment
//! opted in, and only within P.

use redis::aio::ConnectionManager;

use mcp_re_http_profile::authoritative_admission::AuthoritativeAdmission;
use mcp_re_http_profile::AdmissionStatus;

use crate::admission_source::admission_key;
use crate::admission_source::AdmissionFuture;
use crate::admission_source::AdmissionSourceError;
use crate::admission_source::AsyncAdmissionSource;

/// The stored record: `<generation>:<status>`. A fixed two-field shape, so it needs
/// no serde — and it stays legible in `redis-cli`, which matters when an operator is
/// asking why a revocation has not taken effect.
fn encode(state: &AuthoritativeAdmission) -> String {
    let status = match state.status() {
        AdmissionStatus::Admitted => "admitted",
        AdmissionStatus::Suspended => "suspended",
        AdmissionStatus::Revoked => "revoked",
    };
    format!("{}:{}", state.generation(), status)
}

/// Inverse of [`encode`]. `None` on a malformed record — the same answer as a record
/// that is absent, and for the same reason: neither is the authority admitting this
/// workload, so both are refused outright.
///
/// A malformed record must never become an OUTAGE. An outage reaches the §5.2 degraded
/// fork, which serves on the caller's own assertion within P — so overwriting a
/// `revoked` record with garbage would restore service to the revoked workload under
/// `--admission-allow-degraded true`, making corruption a cheaper un-revoke than
/// issuing a new admission. See [`RedisAdmissionSource::current_state`] for the call
/// site that holds that line.
///
/// `admission_id` is the id the record was LOOKED UP UNDER, and it is the only honest
/// answer available: the stored record is `<generation>:<status>` and carries no subject
/// of its own, so the key is what says whose state this is. Passing it here rather than
/// letting the call site attach it afterwards is what keeps the store's key and the
/// value's subject from being two facts that merely happen to agree.
fn decode(admission_id: &str, value: &str) -> Option<AuthoritativeAdmission> {
    let (generation, status) = value.split_once(':')?;
    Some(AuthoritativeAdmission::new(
        admission_id.to_owned(),
        generation.parse().ok()?,
        match status {
            "admitted" => AdmissionStatus::Admitted,
            "suspended" => AdmissionStatus::Suspended,
            "revoked" => AdmissionStatus::Revoked,
            _ => return None,
        },
    ))
}

/// A cross-process authoritative admission source backed by Redis.
pub struct RedisAdmissionSource {
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
}

impl RedisAdmissionSource {
    /// Connect to `url` (e.g. `redis://host:port`). Fails closed if the client
    /// cannot be opened or the initial async connection cannot be established.
    pub async fn connect(url: &str) -> Result<Self, AdmissionSourceError> {
        let client = redis::Client::open(url).map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let conn = client.get_connection_manager().await.map_err(|e| {
            AdmissionSourceError::Unavailable {
                details: format!("connect redis async: {e}"),
            }
        })?;
        Ok(RedisAdmissionSource { conn })
    }

    /// Write the authoritative record for a workload — the admission-authority side
    /// of the seam, and the write a propagation measurement times.
    ///
    /// No TTL: an admission record is authoritative state, not a lease. Expiring it
    /// would turn a healthy authority's silence into "no record", which the serving
    /// path treats as a definitive negative — every workload would fall out of
    /// admission on a timer.
    ///
    /// The key comes from the record's OWN subject. Taking an id alongside the state
    /// would let a caller file workload A's record under workload B's key, and every
    /// later reader would be correct about the value and wrong about whose it is.
    pub async fn publish(
        &self,
        state: &AuthoritativeAdmission,
    ) -> Result<(), AdmissionSourceError> {
        let mut conn = self.conn.clone();
        let result: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(admission_key(state.admission_id()))
            .arg(encode(state))
            .query_async(&mut conn)
            .await;
        result.map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("redis SET admission failed: {e}"),
        })
    }

    /// Revoke a workload, keeping its generation.
    ///
    /// The generation is the anti-rollback counter, not a revocation signal: bumping
    /// it here would refuse the call for the wrong reason and leave an auditor unable
    /// to tell a revocation from a rotation.
    pub async fn revoke(&self, admission_id: &str) -> Result<(), AdmissionSourceError> {
        let generation = self
            .current_state(admission_id)
            .await?
            .map(|s| s.generation())
            .unwrap_or(0);
        self.publish(&AuthoritativeAdmission::new(
            admission_id.to_owned(),
            generation,
            AdmissionStatus::Revoked,
        ))
        .await
    }

    /// The inherent read, so `publish`/`revoke` need not go through the trait object.
    async fn current_state(
        &self,
        admission_id: &str,
    ) -> Result<Option<AuthoritativeAdmission>, AdmissionSourceError> {
        let mut conn = self.conn.clone();
        let raw: Result<Option<String>, redis::RedisError> = redis::cmd("GET")
            .arg(admission_key(admission_id))
            .query_async(&mut conn)
            .await;
        let raw = raw.map_err(|e| AdmissionSourceError::Unavailable {
            details: format!("redis GET admission failed: {e}"),
        })?;
        match raw {
            None => Ok(None),
            // A MALFORMED record is a definitive negative, not an outage.
            //
            // Reporting it as `Unavailable` sent it to the §5.2 degraded fork, which
            // serves on the caller's own assertion within P — so overwriting a
            // `revoked` record with garbage RESTORED service to the revoked workload
            // under `--admission-allow-degraded true`. Corrupting a record must never
            // be a cheaper way to un-revoke than issuing a new one. `Ok(None)` is the
            // authority saying it has no valid record for this workload, which the
            // gate refuses outright.
            Some(value) => {
                if decode(admission_id, &value).is_none() {
                    eprintln!(
                        "mcp-re-proxy: malformed admission record for a workload in the shared \
                         store; treating it as NOT ADMITTED (a corrupt record is not an outage). \
                         Raw value withheld."
                    );
                }
                Ok(decode(admission_id, &value))
            }
        }
    }
}

impl AsyncAdmissionSource for RedisAdmissionSource {
    fn current<'a>(
        &'a self,
        admission_id: &'a str,
    ) -> AdmissionFuture<'a, Option<AuthoritativeAdmission>> {
        Box::pin(async move { self.current_state(admission_id).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_through_its_wire_form() {
        for state in [
            AuthoritativeAdmission::new("wl".to_owned(), 7, AdmissionStatus::Admitted),
            AuthoritativeAdmission::new("wl".to_owned(), 0, AdmissionStatus::Revoked),
            AuthoritativeAdmission::new("wl".to_owned(), u64::MAX, AdmissionStatus::Suspended),
        ] {
            assert_eq!(decode("wl", &encode(&state)), Some(state));
        }
    }

    /// The wire record carries no subject, so the decoded value's subject can only come
    /// from the key. This pins that it does: the same bytes read under two different keys
    /// are two different states, which is what stops a lookup for one workload from
    /// yielding a state that claims to be another's.
    #[test]
    fn the_decoded_subject_is_the_key_the_record_was_read_under() {
        let raw = "5:admitted";
        let a = decode("wl-a", raw).expect("decodes");
        let b = decode("wl-b", raw).expect("decodes");
        assert_eq!(a.admission_id(), "wl-a");
        assert_eq!(b.admission_id(), "wl-b");
        assert_ne!(a, b);
    }

    #[test]
    fn a_malformed_record_is_a_definitive_negative_not_an_outage() {
        // `None` is the authority saying it has no valid record, which the gate refuses
        // outright. Reporting an outage instead would route the call to the §5.2
        // degraded fork, where corrupting a `revoked` record un-revokes the workload.
        for bad in ["", "7", "seven:admitted", "7:unknown", "7:", ":admitted"] {
            assert_eq!(decode("wl", bad), None, "{bad:?} must not decode");
        }
    }

    #[test]
    fn the_record_is_legible_to_an_operator() {
        assert_eq!(
            encode(&AuthoritativeAdmission::new(
                "wl".to_owned(),
                5,
                AdmissionStatus::Revoked
            )),
            "5:revoked"
        );
    }
}
