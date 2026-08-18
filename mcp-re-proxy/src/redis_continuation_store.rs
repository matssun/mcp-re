// SPDX-License-Identifier: Apache-2.0
//! The Redis-backed MRTR continuation correlation store (ADR-MCPS-047) — the shared
//! tier that carries a multi-round-trip continuation across a replica switch.
//!
//! The async analogue of the design in [`crate::async_redis_store`]: one
//! auto-reconnecting, multiplexed [`ConnectionManager`] cloned per op. The open leg
//! records the retained bases with `SET key <bases> PX <ttl_ms>`; the answer leg
//! reads them with a non-destructive `GET`, then removes them with a `DEL` whose
//! returned count is the one-shot verdict (a continuation can be answered at most
//! once). Redis executes the `DEL` atomically, so across replicas exactly one of two
//! concurrent answer legs is told it removed the entry. Any transient error fails
//! closed
//! ([`ContinuationStoreError::Unavailable`]): on the answer leg that reads as "no
//! retained continuation" (the pure dispatcher then rejects the binding), and on the
//! open leg it means the reply cannot be honoured cross-replica.

use redis::aio::ConnectionManager;

use crate::continuation_store::AsyncContinuationStore;
use crate::continuation_store::ContinuationFuture;
use crate::continuation_store::ContinuationStoreError;
use crate::continuation_store::RetainedBases;

/// The on-the-wire value: the two retained signature bases, each base64url-encoded
/// and joined with a `.` (base64url alphabet never contains `.`, so the split is
/// unambiguous). The bases are opaque bytes; base64url keeps the Redis value a clean
/// ASCII string. Avoids a serde dependency for one fixed two-field shape.
fn encode_bases(bases: &RetainedBases) -> String {
    format!(
        "{}.{}",
        mcp_re_core::b64url_encode(&bases.previous_request_base),
        mcp_re_core::b64url_encode(&bases.input_required_response_base),
    )
}

/// Inverse of [`encode_bases`]. `None` on a malformed value (wrong field count or
/// an undecodable segment).
fn decode_bases(value: &str) -> Option<RetainedBases> {
    let (p, i) = value.split_once('.')?;
    Some(RetainedBases {
        previous_request_base: mcp_re_core::b64url_decode(p).ok()?,
        input_required_response_base: mcp_re_core::b64url_decode(i).ok()?,
    })
}

/// A durable, cross-process ASYNC continuation store backed by Redis
/// `SET ... PX` + `GETDEL`.
pub struct RedisContinuationStore {
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
}

impl RedisContinuationStore {
    /// Connect to `url` (e.g. `redis://host:port`). Fails closed
    /// ([`ContinuationStoreError::Unavailable`]) if the client cannot be opened or
    /// the initial async connection cannot be established.
    pub async fn connect(url: &str) -> Result<Self, ContinuationStoreError> {
        let client = redis::Client::open(url).map_err(|e| ContinuationStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let conn = client.get_connection_manager().await.map_err(|e| {
            ContinuationStoreError::Unavailable {
                details: format!("connect redis async: {e}"),
            }
        })?;
        Ok(RedisContinuationStore { conn })
    }
}

impl AsyncContinuationStore for RedisContinuationStore {
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, ()> {
        let key = key.to_string();
        let value = encode_bases(bases);
        let mut conn = self.conn.clone();
        // A non-positive TTL would ask Redis for a <=0 PX; clamp to a 1s floor so a
        // degenerate window still records a briefly-live entry rather than erroring.
        let ttl_ms = (ttl_secs.max(1)) * 1000;
        Box::pin(async move {
            let result: Result<(), redis::RedisError> = redis::cmd("SET")
                .arg(&key)
                .arg(value)
                .arg("PX")
                .arg(ttl_ms)
                .query_async(&mut conn)
                .await;
            result.map_err(|e| ContinuationStoreError::Unavailable {
                details: format!("redis SET continuation failed: {e}"),
            })
        })
    }

    fn peek<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>> {
        let key = key.to_string();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            // A plain GET: reading the bases the binding is checked against must not
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
            decode_bases(&value)
                .map(Some)
                .ok_or_else(|| ContinuationStoreError::Unavailable {
                    details: "malformed continuation value in shared store".to_string(),
                })
        })
    }

    fn consume<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, bool> {
        let key = key.to_string();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            // DEL returns the number of keys it actually removed, and Redis executes it
            // atomically — so across replicas exactly one concurrent answer leg is told
            // it removed the entry. That count IS the one-shot decision.
            let removed: Result<i64, redis::RedisError> =
                redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
            removed
                .map(|n| n > 0)
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
    //! What that buys: the value carried by the open leg's `SET` and its `PX` bound,
    //! the fact that the answer leg's read is a `GET` and not a destructive command,
    //! that the `DEL` count is what decides one-shot, and that every error reply
    //! becomes [`ContinuationStoreError::Unavailable`] instead of a silent "no entry".
    //! What it does not buy: Redis's own atomicity — that is the server's property,
    //! not this code's, and the only thing asserted here is that the code asks for it.

    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::io::BufReader;

    /// Every store command the scripted server received, in order.
    type Commands = Arc<Mutex<Vec<Vec<String>>>>;

    /// The store's own commands. Anything else the client library sends is connection
    /// setup, answered with a bare `+OK` and not recorded.
    const STORE_COMMANDS: [&str; 3] = ["SET", "GET", "DEL"];

    fn bases() -> RetainedBases {
        RetainedBases {
            previous_request_base: b"prev-base".to_vec(),
            input_required_response_base: b"irr-base".to_vec(),
        }
    }

    const KEY: &str = "mcp-re:cont:abc";

    /// Read one RESP command (an array of bulk strings) from a client.
    async fn read_command<R: tokio::io::AsyncBufRead + Unpin>(
        reader: &mut R,
    ) -> Option<Vec<String>> {
        let mut header = String::new();
        if reader.read_line(&mut header).await.ok()? == 0 {
            return None;
        }
        let argc: usize = header.trim_end().strip_prefix('*')?.parse().ok()?;
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            let mut len_line = String::new();
            if reader.read_line(&mut len_line).await.ok()? == 0 {
                return None;
            }
            let len: usize = len_line.trim_end().strip_prefix('$')?.parse().ok()?;
            // The trailing CRLF is part of the framing, so read it and drop it.
            let mut buf = vec![0u8; len + 2];
            reader.read_exact(&mut buf).await.ok()?;
            buf.truncate(len);
            args.push(String::from_utf8(buf).ok()?);
        }
        Some(args)
    }

    /// A server that speaks just enough RESP to complete the connect handshake,
    /// answers every store command with the raw `reply` frame, and records those
    /// commands. Returns its `redis://` URL and the recording.
    async fn scripted_redis(reply: &str) -> (String, Commands) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Commands = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let reply = reply.to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let recorder = Arc::clone(&recorder);
                let reply = reply.clone();
                tokio::spawn(async move {
                    let (rx, mut tx) = stream.into_split();
                    let mut reader = BufReader::new(rx);
                    while let Some(args) = read_command(&mut reader).await {
                        let is_store_op = args.first().is_some_and(|c| {
                            STORE_COMMANDS.iter().any(|k| c.eq_ignore_ascii_case(k))
                        });
                        let frame = if is_store_op {
                            recorder.lock().expect("commands").push(args);
                            reply.as_str()
                        } else {
                            "+OK\r\n"
                        };
                        if tx.write_all(frame.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (format!("redis://{addr}"), seen)
    }

    /// A store wired to a scripted server, plus that server's recording.
    async fn store_against(reply: &str) -> (RedisContinuationStore, Commands) {
        let (url, seen) = scripted_redis(reply).await;
        let store = RedisContinuationStore::connect(&url)
            .await
            .expect("the scripted server accepts the connect handshake");
        (store, seen)
    }

    fn recorded(seen: &Commands) -> Vec<Vec<String>> {
        seen.lock().expect("commands").clone()
    }

    #[test]
    fn the_encoded_value_round_trips_and_a_malformed_one_is_rejected() {
        // Bytes that exercise the URL alphabet: standard base64 would spell 0xfb/0xff
        // with `+` and `/`, and the two fields must not come back swapped.
        let bases = RetainedBases {
            previous_request_base: vec![0xfb, 0xff, 0x00, 1],
            input_required_response_base: vec![0xff, 0xef, 0xbe],
        };
        let encoded = encode_bases(&bases);
        assert_eq!(encoded.matches('.').count(), 1, "one unambiguous separator");
        assert_eq!(decode_bases(&encoded), Some(bases));

        // A value that never came out of `encode_bases` is not a continuation.
        assert_eq!(decode_bases("no-separator"), None);
        assert_eq!(decode_bases("not!base64.aaaa"), None);
        assert_eq!(decode_bases("aaaa.not!base64"), None);
    }

    #[tokio::test]
    async fn the_open_leg_records_the_bases_under_a_bounded_px_ttl() {
        let (store, seen) = store_against("+OK\r\n").await;
        store.store(KEY, &bases(), 300).await.expect("SET accepted");

        let commands = recorded(&seen);
        assert_eq!(commands.len(), 1);
        let set = &commands[0];
        assert_eq!(set[0], "SET");
        assert_eq!(set[1], KEY);
        assert_eq!(
            decode_bases(&set[2]),
            Some(bases()),
            "the recorded value is the pair the answer leg binds against"
        );
        assert_eq!(set.len(), 5);
        assert_eq!(
            set[3], "PX",
            "an entry with no expiry retains signature bases forever"
        );
        assert_eq!(set[4], "300000", "the TTL is seconds, the argument is ms");
    }

    #[tokio::test]
    async fn a_non_positive_ttl_still_asks_for_an_expiring_entry() {
        // Redis rejects `PX 0` outright, and a store that errored there would fail the
        // open leg closed on a merely degenerate window.
        for ttl_secs in [0, -5] {
            let (store, seen) = store_against("+OK\r\n").await;
            store.store(KEY, &bases(), ttl_secs).await.expect("SET");
            let commands = recorded(&seen);
            assert_eq!(commands[0][4], "1000", "ttl_secs {ttl_secs} must clamp up");
        }
    }

    #[tokio::test]
    async fn reading_the_retained_bases_does_not_remove_them() {
        // The binding is checked against these bytes BEFORE anything is removed, so the
        // read leg must not be a destructive command.
        let encoded = encode_bases(&bases());
        let reply = format!("${}\r\n{encoded}\r\n", encoded.len());
        let (store, seen) = store_against(&reply).await;

        assert_eq!(store.peek(KEY).await.expect("GET"), Some(bases()));
        assert_eq!(store.peek(KEY).await.expect("GET"), Some(bases()));

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
        assert_eq!(store.peek(KEY).await.expect("GET"), None);

        // A value this code cannot decode is a broken shared tier, not the answer
        // "never opened, expired, or already answered".
        let (store, _) = store_against("$5\r\nwrong\r\n").await;
        let err = store
            .peek(KEY)
            .await
            .expect_err("an undecodable entry must not read as no entry");
        let ContinuationStoreError::Unavailable { details } = err;
        assert!(details.contains("malformed"), "got: {details}");
    }

    #[tokio::test]
    async fn the_delete_count_is_the_one_shot_verdict() {
        let (store, seen) = store_against(":1\r\n").await;
        assert!(
            store.consume(KEY).await.expect("DEL"),
            "removing a live entry is what admits this answer leg"
        );
        assert_eq!(recorded(&seen)[0][0], "DEL");

        // Nothing removed: the entry was already answered, so this leg must be refused.
        let (store, _) = store_against(":0\r\n").await;
        assert!(
            !store.consume(KEY).await.expect("DEL"),
            "a second answer leg spends a human approval twice"
        );
    }

    #[tokio::test]
    async fn every_error_reply_fails_closed_as_unavailable() {
        let (store, _) = store_against("-ERR backend down\r\n").await;

        let store_err = store
            .store(KEY, &bases(), 300)
            .await
            .expect_err("an unrecorded open leg cannot be honoured cross-replica");
        let ContinuationStoreError::Unavailable { details } = store_err;
        assert!(details.contains("SET"), "got: {details}");

        let peek_err = store
            .peek(KEY)
            .await
            .expect_err("a transient failure must not be indistinguishable from no entry");
        let ContinuationStoreError::Unavailable { details } = peek_err;
        assert!(details.contains("GET"), "got: {details}");

        let consume_err = store
            .consume(KEY)
            .await
            .expect_err("an unconfirmed removal must not read as a one-shot win");
        let ContinuationStoreError::Unavailable { details } = consume_err;
        assert!(details.contains("DEL"), "got: {details}");
    }
}
