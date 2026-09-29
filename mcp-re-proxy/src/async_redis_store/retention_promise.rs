// SPDX-License-Identifier: Apache-2.0
//! Whether a Redis instance promises to keep a key this deployment asked it to hold.
//!
//! The authority for BOTH redis-backed stores. The async replay tier needs it because a
//! replay key carries a `PX` TTL and an evicted nonce reads as `Fresh` again; the
//! admission source needs it because an admission record carries NO TTL and an evicted
//! record reads as "no record", which the serving path treats as a definitive negative.
//! The two consequences are opposite in kind and identical in mechanism, so the DECISION
//! lives here once and each store supplies only what an eviction costs it.
//!
//! The verdict is store-agnostic: it returns the refusal detail as a `String` and never
//! names an error type, so a store wraps it in its own. That is what lets one decision
//! serve two error enums without either store importing the other's.
//!
//! # Why the file sits beside `async_redis_store.rs` rather than at the crate root
//!
//! A crate-root module is where a shared authority belongs, and
//! `mcp-re-proxy/src/lib.rs` sits at exactly its `config/module-size-debt.toml` baseline,
//! so the `mod` line a crate-root module needs fails the ratchet. Manufacturing headroom
//! in `lib.rs` to relocate this file would be metric-driven churn, which the project
//! rules forbid. Rust 2018 path resolution puts a non-mod-root file's children in a
//! directory beside it, so `async_redis_store/retention_promise.rs` is reachable as
//! `crate::async_redis_store::retention_promise` from both stores.

use redis::aio::ConnectionManager;

/// The Redis parameter that decides whether a key survives to the moment its owner
/// expects it to.
pub(crate) const MAXMEMORY_POLICY_PARAM: &str = "maxmemory-policy";

/// The only `maxmemory-policy` under which Redis never removes a key it was asked to
/// hold. Every other policy — `allkeys-*` and, for a keyspace with TTLs, `volatile-*` —
/// can drop a live key at `maxmemory`.
pub(crate) const REQUIRED_MAXMEMORY_POLICY: &str = "noeviction";

/// What an eviction costs ONE store, in that store's own terms.
///
/// The decision below is the same for every caller; the sentence an operator reads is
/// not, because what a dropped key means differs — a replay bypass on one tier, an
/// admission outage on the other.
pub(crate) struct RetentionConsequence {
    /// What losing a key early does to this store's guarantee.
    pub(crate) eviction: &'static str,
    /// What this store's guarantee rests on, said so an unreadable policy is visibly not
    /// evidence of it.
    pub(crate) unverified: &'static str,
    /// The flag naming the instance, so the remedy points at the right endpoint.
    pub(crate) locator_flag: &'static str,
}

/// The async replay tier: every record carries a `PX` TTL and "key present" is the whole
/// replay signal.
pub(crate) const REPLAY: RetentionConsequence = RetentionConsequence {
    eviction: "Every replay record carries a PX TTL, so an evicted nonce reads as Fresh \
               again for the rest of its freshness window on every replica — a replay \
               bypass with no error and no audit reason.",
    unverified: "This tier's replay guarantee is exactly the server's promise to keep a \
                 key for its PX TTL.",
    locator_flag: "--replay-redis-url",
};

/// The authoritative admission source: a record carries NO TTL precisely because its
/// absence is read as a definitive negative, which is the assumption eviction breaks.
pub(crate) const ADMISSION: RetentionConsequence = RetentionConsequence {
    eviction: "An admission record carries no TTL because its absence is a definitive \
               negative, so an instance that may evict one turns a memory-pressure event \
               into a fleet-wide admission outage with no diagnosis.",
    unverified: "An admission record's persistence is exactly the server's promise to \
                 keep a key nobody set an expiry on.",
    locator_flag: "--admission-redis-url",
};

/// Pull the single value out of a `CONFIG GET <param>` reply.
///
/// RESP2 answers with a flat array (`[param, value]`) and RESP3 with a map, and the
/// connection's protocol is a URL detail nothing here controls — so both are read, and
/// anything else yields `None`, which the caller treats as an unverified policy.
pub(crate) fn config_get_value(reply: &redis::Value, param: &str) -> Option<String> {
    fn as_text(value: &redis::Value) -> Option<String> {
        match value {
            redis::Value::BulkString(bytes) => String::from_utf8(bytes.clone()).ok(),
            redis::Value::SimpleString(text) => Some(text.clone()),
            _ => None,
        }
    }
    match reply {
        redis::Value::Map(pairs) => pairs
            .iter()
            .find(|(name, _)| as_text(name).as_deref() == Some(param))
            .and_then(|(_, value)| as_text(value)),
        redis::Value::Array(items) => items
            .chunks_exact(2)
            .find(|pair| as_text(&pair[0]).as_deref() == Some(param))
            .and_then(|pair| as_text(&pair[1])),
        _ => None,
    }
}

/// Ask the server for its `maxmemory-policy`. `None` means it would not say — a renamed
/// or forbidden `CONFIG`, a transport failure, or a reply shape nothing here recognises.
pub(crate) async fn read_policy(conn: &mut ConnectionManager) -> Option<String> {
    let reply: Option<redis::Value> = redis::cmd("CONFIG")
        .arg("GET")
        .arg(MAXMEMORY_POLICY_PARAM)
        .query_async(conn)
        .await
        .ok();
    reply
        .as_ref()
        .and_then(|reply| config_get_value(reply, MAXMEMORY_POLICY_PARAM))
}

/// Whether a server reporting `policy` can be trusted to keep `consequence`'s keys.
/// `None` means the policy could not be read at all.
///
/// Fail closed either way: an evicting policy silently breaks the store's guarantee, and
/// a policy nobody can read is not evidence that it is safe. `Err` carries the refusal
/// detail; the caller wraps it in its own error type.
pub(crate) fn retention_verdict(
    policy: Option<&str>,
    consequence: &RetentionConsequence,
) -> Result<(), String> {
    let flag = consequence.locator_flag;
    match policy {
        Some(policy)
            if policy
                .trim()
                .eq_ignore_ascii_case(REQUIRED_MAXMEMORY_POLICY) =>
        {
            Ok(())
        }
        Some(policy) => Err(format!(
            "{MAXMEMORY_POLICY_PARAM} is {policy:?}, which evicts keys at maxmemory. {} \
             Set {MAXMEMORY_POLICY_PARAM} to {REQUIRED_MAXMEMORY_POLICY} on the instance \
             {flag} names (give other keyspaces their own instance if they need \
             eviction).",
            consequence.eviction
        )),
        None => Err(format!(
            "could not read {MAXMEMORY_POLICY_PARAM} (CONFIG GET unavailable or \
             unparseable). {} An unverifiable eviction policy is not that promise. Permit \
             CONFIG GET for the proxy's Redis user, or point {flag} at an instance where \
             it is readable.",
            consequence.unverified
        )),
    }
}

#[cfg(test)]
pub(crate) mod scripted_server {
    //! The scripted RESP server every redis-backed store's tests drive against — shared
    //! by the replay tier, the continuation store and the admission source.
    //!
    //! It lives beside the retention decision because the thing a store's connect path
    //! has to be driven against is a `CONFIG GET maxmemory-policy` reply, which is this
    //! module's own subject. Every store that refuses an evicting instance needs a
    //! server that reports one, and a per-store copy of that server is a per-store
    //! chance for a connect-path control to be missing without anybody noticing.
    //!
    //! It speaks just enough RESP to complete the client library's connect handshake:
    //! anything not in the script is answered with a bare `+OK` and not recorded.

    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::io::BufReader;

    use super::MAXMEMORY_POLICY_PARAM;

    /// Every scripted command the server received, in order.
    pub(crate) type Commands = Arc<Mutex<Vec<Vec<String>>>>;

    /// Read one RESP command (an array of bulk strings) from a client.
    pub(crate) async fn read_command<R: tokio::io::AsyncBufRead + Unpin>(
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

    /// What one scripted server answers, and what it writes down.
    pub(crate) struct Script {
        /// `Some(policy)` answers `CONFIG GET` with that `maxmemory-policy`. `None`
        /// leaves `CONFIG` to the `+OK` default, which is a reply nothing can read a
        /// policy out of — the "unverifiable policy" case.
        pub(crate) policy: Option<String>,
        /// The commands recorded and answered with [`Self::reply`]. Everything else is
        /// connection setup.
        pub(crate) recorded: Vec<String>,
        /// The raw RESP frame answering a recorded command.
        pub(crate) reply: String,
    }

    impl Script {
        /// A server whose whole script is its `maxmemory-policy`.
        pub(crate) fn reporting(policy: &str) -> Self {
            Script {
                policy: Some(policy.to_string()),
                recorded: Vec::new(),
                reply: String::new(),
            }
        }

        /// A server that records `recorded` and answers each with `reply`, and that
        /// will not say what its eviction policy is.
        pub(crate) fn recording(recorded: &[&str], reply: &str) -> Self {
            Script {
                policy: None,
                recorded: recorded.iter().map(|c| (*c).to_string()).collect(),
                reply: reply.to_string(),
            }
        }

        /// The frame answering `args`, recording it first when the script says to.
        fn answer(&self, args: &[String], recorder: &Commands) -> String {
            let command = args.first().map_or("", String::as_str);
            let policy = self
                .policy
                .as_deref()
                .filter(|_| command.eq_ignore_ascii_case("CONFIG"));
            if let Some(policy) = policy {
                return format!(
                    "*2\r\n${}\r\n{MAXMEMORY_POLICY_PARAM}\r\n${}\r\n{policy}\r\n",
                    MAXMEMORY_POLICY_PARAM.len(),
                    policy.len()
                );
            }
            if self
                .recorded
                .iter()
                .any(|scripted| command.eq_ignore_ascii_case(scripted))
            {
                recorder.lock().expect("commands").push(args.to_vec());
                return self.reply.clone();
            }
            "+OK\r\n".to_string()
        }
    }

    /// Start `script` on a loopback port. Returns its `redis://` URL and the recording.
    pub(crate) async fn serve(script: Script) -> (String, Commands) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Commands = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let script = Arc::new(script);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let recorder = Arc::clone(&recorder);
                let script = Arc::clone(&script);
                tokio::spawn(async move {
                    let (rx, mut tx) = stream.into_split();
                    let mut reader = BufReader::new(rx);
                    while let Some(args) = read_command(&mut reader).await {
                        let frame = script.answer(&args, &recorder);
                        if tx.write_all(frame.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (format!("redis://{addr}"), seen)
    }

    /// A server that speaks just enough RESP to answer the connect handshake and one
    /// `CONFIG GET maxmemory-policy`, reporting `policy`. Returns its `redis://` URL.
    pub(crate) async fn redis_reporting(policy: &str) -> String {
        serve(Script::reporting(policy)).await.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bulk(text: &str) -> redis::Value {
        redis::Value::BulkString(text.as_bytes().to_vec())
    }

    #[test]
    fn the_policy_is_read_out_of_either_resp_protocols_reply() {
        let resp2 = redis::Value::Array(vec![bulk(MAXMEMORY_POLICY_PARAM), bulk("noeviction")]);
        assert_eq!(
            config_get_value(&resp2, MAXMEMORY_POLICY_PARAM).as_deref(),
            Some("noeviction")
        );
        let resp3 = redis::Value::Map(vec![(bulk(MAXMEMORY_POLICY_PARAM), bulk("volatile-lru"))]);
        assert_eq!(
            config_get_value(&resp3, MAXMEMORY_POLICY_PARAM).as_deref(),
            Some("volatile-lru")
        );
        // A server that answers something else (an empty reply for an unknown
        // parameter, an error, a renamed CONFIG) leaves the policy unread.
        assert_eq!(
            config_get_value(&redis::Value::Array(vec![]), MAXMEMORY_POLICY_PARAM),
            None
        );
        assert_eq!(
            config_get_value(&redis::Value::Nil, MAXMEMORY_POLICY_PARAM),
            None
        );
    }

    #[test]
    fn only_noeviction_is_a_retention_promise() {
        for consequence in [&REPLAY, &ADMISSION] {
            assert!(retention_verdict(Some("noeviction"), consequence).is_ok());
            assert!(
                retention_verdict(Some("  NOEVICTION "), consequence).is_ok(),
                "the reply is a server string, not a token this code chose"
            );
            // `volatile-*` is not the safer half: a keyspace with TTLs makes those keys
            // the PREFERRED victims, and a keyspace without them is untouched only until
            // another one on the instance sets an expiry.
            for policy in [
                "volatile-lru",
                "volatile-lfu",
                "volatile-ttl",
                "volatile-random",
                "allkeys-lru",
                "allkeys-lfu",
                "allkeys-random",
            ] {
                let detail = retention_verdict(Some(policy), consequence)
                    .expect_err("an evicting policy breaks the store's guarantee");
                assert!(detail.contains(policy), "the refusal must name the policy");
                assert!(
                    detail.contains(consequence.locator_flag),
                    "and the instance the operator must fix: {detail}"
                );
            }
            let unreadable = retention_verdict(None, consequence)
                .expect_err("an unverifiable policy is not evidence of a safe one");
            assert!(unreadable.contains(MAXMEMORY_POLICY_PARAM));
        }
    }

    /// The two stores fail for opposite reasons, and an operator reading one refusal must
    /// be told which store's guarantee broke.
    #[test]
    fn each_store_states_its_own_consequence() {
        let replay = retention_verdict(Some("allkeys-lru"), &REPLAY).expect_err("refused");
        assert!(replay.contains("replay"), "{replay}");
        let admission = retention_verdict(Some("allkeys-lru"), &ADMISSION).expect_err("refused");
        assert!(admission.contains("admission outage"), "{admission}");
        assert!(
            !admission.contains("--replay-redis-url"),
            "the admission refusal must point at its own endpoint: {admission}"
        );
    }
}
