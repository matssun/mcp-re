// SPDX-License-Identifier: Apache-2.0
//! The Redis-backed MRTR continuation correlation store (ADR-MCPS-047) — the shared
//! tier that carries a multi-round-trip continuation across a replica switch.
//!
//! One auto-reconnecting, multiplexed [`ConnectionManager`] cloned per op. The open leg
//! runs [`CREATE`], one server-side script: it prunes expired members from the live set,
//! answers a taken key as a collision, refuses a new key once the live set holds the
//! [`ContinuationCapacity`], and otherwise writes `SET key <handles> NX PX <ttl_ms>` and
//! adds the key to the live set scored by the same expiry. The answer leg reads with a
//! non-destructive `GET`, then runs [`CONSUME`]: a `DEL` whose count is the one-shot
//! verdict, and a `ZREM` of the key from the live set. Redis runs a script atomically, so
//! across replicas no two open legs both take the last slot or one key, and exactly one of
//! two concurrent answer legs is told it removed the entry. Any transient error fails
//! closed as [`ContinuationStoreError::Unavailable`], whose meaning is the trait's per
//! operation: on `GET` nothing was read, on create nothing may have been recorded, and on
//! consume the removal may or may not have executed.

use redis::aio::ConnectionManager;

use crate::continuation_store::AsyncContinuationStore;
use crate::continuation_store::Consumption;
use crate::continuation_store::ContinuationCapacity;
use crate::continuation_store::ContinuationFuture;
use crate::continuation_store::ContinuationKey;
use crate::continuation_store::ContinuationStoreError;
use crate::continuation_store::Creation;
use crate::continuation_store::RetainedHandles;

mod scripts;
use scripts::{CONSUME, CREATE, LIVE_SET_KEY};

/// The on-the-wire value: the two retained evidence handles, each `<digest_alg>:<digest_value>`,
/// joined with a `.`. Neither the algorithm token nor a base64url digest contains `.` or `:`,
/// so the split is unambiguous. No signature base is stored.
fn encode_handles(handles: &RetainedHandles) -> String {
    let one = |h: &mcp_re_http_profile::RequestEvidenceDigest| {
        format!("{}:{}", h.digest_alg, h.digest_value)
    };
    format!(
        "{}.{}",
        one(&handles.previous_request_evidence),
        one(&handles.input_required_response_evidence)
    )
}

/// Inverse of [`encode_handles`]. `None` on a malformed value (wrong field count, a missing
/// separator, or an empty or non-token part).
fn decode_handles(value: &str) -> Option<RetainedHandles> {
    let token = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && b != b'.');
    let one = |s: &str| {
        let (alg, digest) = s.split_once(':')?;
        (token(alg) && token(digest) && !digest.contains(':')).then(|| {
            mcp_re_http_profile::RequestEvidenceDigest {
                digest_alg: alg.to_owned(),
                digest_value: digest.to_owned(),
            }
        })
    };
    let (p, i) = value.split_once('.')?;
    Some(RetainedHandles {
        previous_request_evidence: one(p)?,
        input_required_response_evidence: one(i)?,
    })
}

/// A durable, cross-process ASYNC continuation store with a bounded live population:
/// [`CREATE`] and [`CONSUME`] scripts around a non-destructive `GET`.
///
/// Not `GETDEL`: that is the destructive read the peek/consume split exists to forbid,
/// and it would let a request whose binding is about to fail delete a live entry on its
/// way out.
pub struct RedisContinuationStore {
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
    /// The most live entries the shared tier holds.
    capacity: ContinuationCapacity,
}

impl RedisContinuationStore {
    /// Connect to `url` (e.g. `redis://host:port`), bounding the live set at `capacity`.
    /// Fails closed ([`ContinuationStoreError::Unavailable`]) if the client cannot be
    /// opened or the initial async connection cannot be established.
    pub async fn connect(
        url: &str,
        capacity: ContinuationCapacity,
    ) -> Result<Self, ContinuationStoreError> {
        let client = redis::Client::open(url).map_err(|e| ContinuationStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let conn = client.get_connection_manager().await.map_err(|e| {
            ContinuationStoreError::Unavailable {
                details: format!("connect redis async: {e}"),
            }
        })?;
        Ok(RedisContinuationStore { conn, capacity })
    }
}

impl AsyncContinuationStore for RedisContinuationStore {
    fn create<'a>(
        &'a self,
        key: &'a ContinuationKey,
        bases: &'a RetainedHandles,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, Creation> {
        let key = key.as_str().to_string();
        let value = encode_handles(bases);
        let max = self.capacity.max_live_entries();
        let mut conn = self.conn.clone();
        // A non-positive TTL would ask Redis for a <=0 PX; clamp to a 1s floor so a
        // degenerate window still records a briefly-live entry rather than erroring. A TTL
        // whose millisecond count does not fit i64 is refused, as the in-memory tier does.
        let ttl_ms = ttl_secs.max(1).checked_mul(1000);
        Box::pin(async move {
            let ttl_ms = ttl_ms.ok_or_else(|| ContinuationStoreError::Unavailable {
                details: "continuation ttl is not representable in milliseconds".to_string(),
            })?;
            // One script, so the prune, the occupancy test, the capacity test and the
            // write cannot be interleaved with another replica's: a read-then-write would
            // hand two racing open legs the same key or the same last slot. `PX` rides in
            // the `SET` itself, so no crash can strand an entry without an expiry.
            let reply: Result<i64, redis::RedisError> = redis::cmd("EVAL")
                .arg(CREATE)
                .arg(2)
                .arg(&key)
                .arg(LIVE_SET_KEY)
                .arg(value)
                .arg(ttl_ms)
                .arg(max)
                .query_async(&mut conn)
                .await;
            // Every reply the script can give is named; anything else is a store this code
            // does not understand, which fails closed rather than reading as a write.
            match reply {
                Ok(1) => Ok(Creation::Stored),
                Ok(0) => Ok(Creation::Collision),
                Ok(-1) => Ok(Creation::AtCapacity),
                Ok(other) => Err(ContinuationStoreError::Unavailable {
                    details: format!("redis SET NX continuation script answered {other}"),
                }),
                Err(e) => Err(ContinuationStoreError::Unavailable {
                    details: format!("redis SET NX continuation failed: {e}"),
                }),
            }
        })
    }

    fn peek<'a>(
        &'a self,
        key: &'a ContinuationKey,
    ) -> ContinuationFuture<'a, Option<RetainedHandles>> {
        let key = key.as_str().to_string();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            // A plain GET: reading the handles the binding is checked against must not
            // remove them, or a request that is about to fail the binding would destroy
            // a live entry on its way out.
            let raw: Result<Option<String>, redis::RedisError> =
                redis::cmd("GET").arg(&key).query_async(&mut conn).await;
            let raw = raw.map_err(|e| ContinuationStoreError::Unavailable {
                details: format!("redis GET continuation failed: {e}"),
            })?;
            let Some(value) = raw else {
                return Ok(None);
            };
            decode_handles(&value)
                .map(Some)
                .ok_or_else(|| ContinuationStoreError::Unavailable {
                    details: "malformed continuation value in shared store".to_string(),
                })
        })
    }

    fn consume<'a>(&'a self, key: &'a ContinuationKey) -> ContinuationFuture<'a, Consumption> {
        let key = key.as_str().to_string();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            // DEL returns the number of keys it actually removed, and the script runs
            // atomically — so across replicas exactly one concurrent answer leg is told it
            // removed the entry. That count IS the one-shot decision; the ZREM in the same
            // script returns the slot.
            let removed: Result<i64, redis::RedisError> = redis::cmd("EVAL")
                .arg(CONSUME)
                .arg(2)
                .arg(&key)
                .arg(LIVE_SET_KEY)
                .query_async(&mut conn)
                .await;
            removed
                .map(|n| match n {
                    0 => Consumption::NoLiveEntry,
                    _ => Consumption::Consumed,
                })
                .map_err(|e| ContinuationStoreError::Unavailable {
                    details: format!("redis DEL continuation failed: {e}"),
                })
        })
    }
}

#[cfg(test)]
mod tests {
    //! The store is driven against a SCRIPTED RESP SERVER rather than a real Redis, so
    //! the commands it actually puts on the wire — and the replies it accepts — are
    //! asserted on every build of this feature lane, with no external dependency.
    //!
    //! What that buys: the keys and arguments each script is handed, the mapping of
    //! every script reply, the fact that the answer leg's read is a `GET` and not a
    //! destructive command, that the `DEL` count is what decides one-shot, and that every
    //! error reply becomes [`ContinuationStoreError::Unavailable`] instead of a silent "no
    //! entry". What it does not buy: the scripts running on a real server — that is the
    //! live lane's (`redis_continuation_e2e_test`), and Redis's atomicity is the server's
    //! property, not this code's.

    use super::*;
    use crate::async_redis_store::retention_promise::scripted_server::serve;
    use crate::async_redis_store::retention_promise::scripted_server::Commands;
    use crate::async_redis_store::retention_promise::scripted_server::Script;

    /// The store's own commands. Anything else the client library sends is connection
    /// setup, answered with a bare `+OK` and not recorded.
    const STORE_COMMANDS: [&str; 2] = ["EVAL", "GET"];

    fn bases() -> RetainedHandles {
        RetainedHandles::over(b"prev-base", b"irr-base")
    }

    /// The one key every wire test addresses.
    fn key() -> ContinuationKey {
        ContinuationKey::of_parts("aud", "actor", b"abc")
    }

    /// A store wired to a scripted server, plus that server's recording.
    async fn store_against(reply: &str) -> (RedisContinuationStore, Commands) {
        let (url, seen) = serve(Script::recording(&STORE_COMMANDS, reply)).await;
        let store = RedisContinuationStore::connect(&url, ContinuationCapacity::DEFAULT)
            .await
            .expect("the scripted server accepts the connect handshake");
        (store, seen)
    }

    fn recorded(seen: &Commands) -> Vec<Vec<String>> {
        seen.lock().expect("commands").clone()
    }

    #[test]
    fn the_encoded_value_round_trips_and_a_malformed_one_is_rejected() {
        // The two slots must not come back swapped, and the value is a pair of handles,
        // not bases.
        let bases = RetainedHandles::over(&[0xfb, 0xff, 0x00, 1], &[0xff, 0xef, 0xbe]);
        let encoded = encode_handles(&bases);
        assert_eq!(encoded.matches('.').count(), 1, "one unambiguous separator");
        assert_eq!(decode_handles(&encoded), Some(bases));

        // A value that never came out of `encode_handles` is not a continuation.
        assert_eq!(decode_handles("no-separator"), None);
        assert_eq!(decode_handles("sha-256:aaaa"), None);
        assert_eq!(decode_handles("sha-256aaaa.sha-256:bbbb"), None);
        assert_eq!(decode_handles("sha-256:aaaa.sha-256:"), None);
        assert_eq!(decode_handles("sha-256:aa:aa.sha-256:bbbb"), None);
    }

    /// CONTROL 8 — the wire evidence: `NX` and `PX` are both requested, in ONE atomic step.
    ///
    /// The whole uniqueness argument rests on this being a single atomic operation. A
    /// GET-then-SET, or a SET followed by a separate EXPIRE, reads identically from the
    /// caller's side and from every higher-level test — the difference is only visible
    /// here, in the bytes. So it is asserted here: one `EVAL` of the create script, which
    /// guards the key with `NX` and bounds it with `PX` in its one `SET`, handed the entry,
    /// the live set, the value, the TTL in ms and the capacity.
    #[tokio::test]
    async fn the_open_leg_records_the_handles_under_an_nx_guarded_bounded_px_ttl() {
        let (store, seen) = store_against(":1\r\n").await;
        assert_eq!(
            store
                .create(&key(), &bases(), 300)
                .await
                .expect("script accepted"),
            Creation::Stored,
            "a 1 reply is the key having been established by THIS call"
        );

        let commands = recorded(&seen);
        assert_eq!(
            commands.len(),
            1,
            "one command: a test-then-set pair would be two, with a race between them"
        );
        let eval = &commands[0];
        assert_eq!(eval.len(), 8);
        assert_eq!(eval[0], "EVAL");
        assert_eq!(eval[1], CREATE);
        assert!(
            CREATE.contains("'NX', 'PX'"),
            "without NX this is the overwrite that destroys a live approval, and without \
             PX an entry retains evidence handles forever"
        );
        assert_eq!(
            eval[2], "2",
            "the entry and the live set are both declared keys"
        );
        assert_eq!(eval[3], key().as_str());
        assert_eq!(eval[4], LIVE_SET_KEY);
        assert_eq!(
            decode_handles(&eval[5]),
            Some(bases()),
            "the recorded value is the pair the answer leg binds against"
        );
        assert_eq!(eval[6], "300000", "the TTL is seconds, the argument is ms");
        assert_eq!(eval[7], "100000", "the capacity the store was built with");
    }

    /// CONTROL 2 + 3, at the mechanism: a NIL reply is a collision, and it is NOT an error.
    ///
    /// The create script answers 0 when the key was taken, which is the one signal that
    /// distinguishes a refused write from a successful one. Reading it as an error would
    /// send the open leg into its retry budget — three more attempts at a key that will
    /// still be taken — and would make a collision indistinguishable from an outage.
    #[tokio::test]
    async fn a_taken_key_answers_collision_and_not_an_error() {
        let (store, seen) = store_against(":0\r\n").await;
        assert_eq!(
            store
                .create(&key(), &bases(), 300)
                .await
                .expect("a 0 reply is an ANSWER, not a transport failure"),
            Creation::Collision,
        );
        // Exactly one attempt was made: the incumbent's value was never sent a second
        // time and no unguarded write followed the refusal.
        let commands = recorded(&seen);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0][1], CREATE);
    }

    #[tokio::test]
    async fn a_non_positive_ttl_still_asks_for_an_expiring_entry() {
        // Redis rejects `PX 0` outright, and a store that errored there would fail the
        // open leg closed on a merely degenerate window.
        for ttl_secs in [0, -5] {
            let (store, seen) = store_against(":1\r\n").await;
            store
                .create(&key(), &bases(), ttl_secs)
                .await
                .expect("EVAL");
            let commands = recorded(&seen);
            assert_eq!(commands[0][6], "1000", "ttl_secs {ttl_secs} must clamp up");
        }
    }

    #[tokio::test]
    async fn an_unrepresentable_ttl_is_refused_before_any_command() {
        let (store, seen) = store_against(":1\r\n").await;
        let refused = store.create(&key(), &bases(), i64::MAX).await;
        assert!(
            matches!(&refused, Err(ContinuationStoreError::Unavailable { details }) if details.contains("ttl")),
            "got {refused:?}"
        );
        assert!(recorded(&seen).is_empty());
    }

    #[tokio::test]
    async fn reading_the_retained_handles_does_not_remove_them() {
        // The binding is checked against these bytes BEFORE anything is removed, so the
        // read leg must not be a destructive command.
        let encoded = encode_handles(&bases());
        let reply = format!("${}\r\n{encoded}\r\n", encoded.len());
        let (store, seen) = store_against(&reply).await;

        assert_eq!(store.peek(&key()).await.expect("GET"), Some(bases()));
        assert_eq!(store.peek(&key()).await.expect("GET"), Some(bases()));

        let commands = recorded(&seen);
        assert_eq!(commands.len(), 2);
        for command in &commands {
            assert_eq!(
                command[0], "GET",
                "a read-and-remove here lets an unadmitted request destroy a live entry"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_entry_reads_as_absent_but_a_malformed_one_does_not() {
        let (store, _) = store_against("$-1\r\n").await;
        assert_eq!(store.peek(&key()).await.expect("GET"), None);

        // A value this code cannot decode is a broken shared tier, not the answer
        // "never opened, expired, or already answered".
        let (store, _) = store_against("$5\r\nwrong\r\n").await;
        let err = store
            .peek(&key())
            .await
            .expect_err("an undecodable entry must not read as no entry");
        let ContinuationStoreError::Unavailable { details } = err;
        assert!(details.contains("malformed"), "got: {details}");
    }

    #[tokio::test]
    async fn the_delete_count_is_the_one_shot_verdict() {
        let (store, seen) = store_against(":1\r\n").await;
        assert_eq!(
            store.consume(&key()).await.expect("DEL"),
            Consumption::Consumed,
            "removing a live entry is what admits this answer leg"
        );
        let commands = recorded(&seen);
        assert_eq!(
            commands[0][..5],
            ["EVAL", CONSUME, "2", key().as_str(), LIVE_SET_KEY],
            "the removal and the slot's return are one script over the entry and the set"
        );

        // Nothing removed: the entry was already answered, so this leg must be refused.
        let (store, _) = store_against(":0\r\n").await;
        assert_eq!(
            store.consume(&key()).await.expect("DEL"),
            Consumption::NoLiveEntry,
            "a second answer leg spends a human approval twice"
        );
    }

    /// Parity with the single-process tier: a live entry removed by this call, and no live
    /// entry left to remove, are the same two answers from both implementations, so the
    /// serving path's response does not depend on which tier a deployment selected.
    #[tokio::test]
    async fn consume_answers_as_the_single_process_tier_answers() {
        let memory = crate::continuation_store::InMemoryContinuationStore::new();
        memory.create(&key(), &bases(), 300).await.expect("stored");

        let (redis, _) = store_against(":1\r\n").await;
        let first = memory.consume(&key()).await.expect("answered");
        assert_eq!(first, Consumption::Consumed);
        assert_eq!(redis.consume(&key()).await.expect("DEL"), first);

        let (redis, _) = store_against(":0\r\n").await;
        let second = memory.consume(&key()).await.expect("answered");
        assert_eq!(second, Consumption::NoLiveEntry);
        assert_eq!(redis.consume(&key()).await.expect("DEL"), second);
    }

    #[tokio::test]
    async fn every_error_reply_fails_closed_as_unavailable() {
        let (store, _) = store_against("-ERR backend down\r\n").await;

        let store_err = store
            .create(&key(), &bases(), 300)
            .await
            .expect_err("an unrecorded open leg cannot be honoured cross-replica");
        let ContinuationStoreError::Unavailable { details } = store_err;
        assert!(details.contains("SET"), "got: {details}");

        let peek_err = store
            .peek(&key())
            .await
            .expect_err("a transient failure must not be indistinguishable from no entry");
        let ContinuationStoreError::Unavailable { details } = peek_err;
        assert!(details.contains("GET"), "got: {details}");

        let consume_err = store
            .consume(&key())
            .await
            .expect_err("an unconfirmed removal must not read as a one-shot win");
        let ContinuationStoreError::Unavailable { details } = consume_err;
        assert!(details.contains("DEL"), "got: {details}");
    }

    /// The capacity refusal is its own answer, and a reply the script cannot give fails
    /// closed rather than reading as a write.
    #[tokio::test]
    async fn a_full_live_set_answers_at_capacity_and_an_unknown_reply_is_unavailable() {
        let (store, _) = store_against(":-1\r\n").await;
        assert_eq!(
            store
                .create(&key(), &bases(), 300)
                .await
                .expect("an answer"),
            Creation::AtCapacity,
            "a full live set refuses the new key; it is not an outage and not a collision"
        );
        let (store, _) = store_against(":2\r\n").await;
        assert!(matches!(
            store.create(&key(), &bases(), 300).await,
            Err(ContinuationStoreError::Unavailable { .. })
        ));
    }

    /// The store hands the script the capacity it was built with.
    #[tokio::test]
    async fn the_configured_capacity_is_the_bound_the_script_enforces() {
        let (url, seen) = serve(Script::recording(&STORE_COMMANDS, ":1\r\n")).await;
        let capacity = ContinuationCapacity::new(7).expect("in range");
        let store = RedisContinuationStore::connect(&url, capacity)
            .await
            .expect("connect");
        store.create(&key(), &bases(), 300).await.expect("stored");
        assert_eq!(recorded(&seen)[0][7], "7");
    }
}
