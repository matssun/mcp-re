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

use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::AuthoritativeAdmission;

use crate::admission_source::admission_key;
use crate::admission_source::AdmissionFuture;
use crate::admission_source::AdmissionSourceError;
use crate::admission_source::AsyncAdmissionSource;

/// The stored record: `<generation>:<status>`. A fixed two-field shape, so it needs
/// no serde — and it stays legible in `redis-cli`, which matters when an operator is
/// asking why a revocation has not taken effect.
fn encode(state: &AuthoritativeAdmission) -> String {
    let status = match state.status {
        AdmissionStatus::Admitted => "admitted",
        AdmissionStatus::Suspended => "suspended",
        AdmissionStatus::Revoked => "revoked",
    };
    format!("{}:{}", state.generation, status)
}

/// Inverse of [`encode`]. `None` on a malformed record.
///
/// A malformed record is NOT read as "absent": absent means the authority has no
/// record, which is a definitive negative the caller refuses, while malformed means
/// the store answered with something this reader cannot trust to mean anything. The
/// caller turns that into an outage, so it reaches the degraded fork rather than
/// silently denying every call in a fleet whose store got corrupted.
fn decode(value: &str) -> Option<AuthoritativeAdmission> {
    let (generation, status) = value.split_once(':')?;
    Some(AuthoritativeAdmission {
        generation: generation.parse().ok()?,
        status: match status {
            "admitted" => AdmissionStatus::Admitted,
            "suspended" => AdmissionStatus::Suspended,
            "revoked" => AdmissionStatus::Revoked,
            _ => return None,
        },
    })
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
    pub async fn publish(
        &self,
        admission_id: &str,
        state: &AuthoritativeAdmission,
    ) -> Result<(), AdmissionSourceError> {
        let mut conn = self.conn.clone();
        let result: Result<(), redis::RedisError> = redis::cmd("SET")
            .arg(admission_key(admission_id))
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
            .map(|s| s.generation)
            .unwrap_or(0);
        self.publish(
            admission_id,
            &AuthoritativeAdmission {
                generation,
                status: AdmissionStatus::Revoked,
            },
        )
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
                if decode(&value).is_none() {
                    eprintln!(
                        "mcp-re-proxy: malformed admission record for a workload in the shared \
                         store; treating it as NOT ADMITTED (a corrupt record is not an outage). \
                         Raw value withheld."
                    );
                }
                Ok(decode(&value))
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
            AuthoritativeAdmission {
                generation: 7,
                status: AdmissionStatus::Admitted,
            },
            AuthoritativeAdmission {
                generation: 0,
                status: AdmissionStatus::Revoked,
            },
            AuthoritativeAdmission {
                generation: u64::MAX,
                status: AdmissionStatus::Suspended,
            },
        ] {
            assert_eq!(decode(&encode(&state)), Some(state));
        }
    }

    #[test]
    fn a_malformed_record_is_not_read_as_absent() {
        // Absent is a verdict about the workload; malformed is a broken store. Reading
        // one as the other would deny every call in a fleet whose store got corrupted.
        for bad in ["", "7", "seven:admitted", "7:unknown", "7:", ":admitted"] {
            assert_eq!(decode(bad), None, "{bad:?} must not decode");
        }
    }

    #[test]
    fn the_record_is_legible_to_an_operator() {
        assert_eq!(
            encode(&AuthoritativeAdmission {
                generation: 5,
                status: AdmissionStatus::Revoked,
            }),
            "5:revoked"
        );
    }
}
