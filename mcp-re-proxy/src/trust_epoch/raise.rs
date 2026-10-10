// SPDX-License-Identifier: Apache-2.0
//! The one write a replica may make to the shared trust-epoch counter: move it past a
//! rollback, never back.
//!
//! The delegated-signing plane refuses to mint under a counter below the highest value it
//! has read (THM-0133). On its own that refusal turns a rolled-back store into a fleet that
//! never mints again until an operator repairs the key by hand.
//! [`EpochRaiser::raise_past`] is the repair: when the counter is absent or below the
//! caller's mark, it sets the counter to a target the caller computes strictly above that
//! mark, and reports what the counter holds afterwards.
//!
//! A counter at or above the mark is left untouched, so an advance beyond the mark
//! is never overwritten, and a second replica repairing from the same mark finds the first
//! one's write and writes nothing. It is one atomic step in the store.

use super::EpochReadError;
use super::EpochReader;

/// An [`EpochReader`] that can also move the counter it reads past a rollback.
pub(crate) trait EpochRaiser: EpochReader {
    /// Set the counter to `to` if it is absent or below `mark`; return the value it holds
    /// afterwards. A counter at or above `mark` is left untouched.
    fn raise_past(&self, mark: i64, to: i64) -> Result<i64, EpochReadError>;
}

/// The repair, in one server-side step: a non-integer value is an error rather than
/// something to overwrite.
#[cfg(feature = "redis_replay")]
const RAISE_SCRIPT: &str = "local v = redis.call('GET', KEYS[1]) \
     local c = tonumber(v) \
     if v and not c then return redis.error_reply('trust-epoch key holds a non-integer') end \
     if c == nil or c < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[2]) return tonumber(ARGV[2]) end \
     return c";

#[cfg(feature = "redis_replay")]
fn raise_command(epoch_key: &str, mark: i64, to: i64) -> redis::Cmd {
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(RAISE_SCRIPT)
        .arg(1)
        .arg(epoch_key)
        .arg(mark)
        .arg(to);
    cmd
}

#[cfg(feature = "redis_replay")]
impl EpochRaiser for super::RedisEpochReader {
    fn raise_past(&self, mark: i64, to: i64) -> Result<i64, EpochReadError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| EpochReadError("trust-epoch connection lock poisoned".into()))?;
        // A read that failed dropped the socket; the repair establishes its own.
        if guard.is_none() {
            *guard = Some(Self::fresh_conn(&self.client)?);
        }
        let Some(conn) = guard.as_mut() else {
            return Err(EpochReadError("trust-epoch connection missing".into()));
        };
        let raised = raise_command(&self.epoch_key, mark, to).query::<i64>(conn);
        if raised.is_err() {
            *guard = None;
        }
        raised.map_err(|e| {
            EpochReadError(format!("raise {} past {mark} to {to}: {e}", self.epoch_key))
        })
    }
}

#[cfg(all(test, feature = "redis_replay"))]
mod tests {
    use super::raise_command;
    use super::RAISE_SCRIPT;

    /// The key travels as `KEYS[1]`, the mark as `ARGV[1]` and the target as `ARGV[2]`,
    /// which is what the script reads; a key passed as an argument would make the script
    /// raise a key named by nothing.
    #[test]
    fn the_raise_names_the_key_as_a_key_and_the_mark_and_target_as_arguments() {
        let packed = String::from_utf8_lossy(
            &raise_command("mcp-re:trust:epoch", 9, 10).get_packed_command(),
        )
        .into_owned();
        let parts: Vec<&str> = packed
            .split("\r\n")
            .filter(|p| !p.starts_with(['*', '$']))
            .collect();
        assert_eq!(
            parts[..6],
            ["EVAL", RAISE_SCRIPT, "1", "mcp-re:trust:epoch", "9", "10"]
        );
    }
}

/// The raise against a live Redis. Skipped when `MCP_RE_TEST_REDIS_URL` is unset, and a
/// failure under `MCP_RE_REQUIRE_LIVE_INFRA`, which the live-infra workflow sets.
#[cfg(test)]
#[cfg(feature = "redis_replay")]
pub(crate) mod live {
    use super::EpochRaiser;
    use crate::trust_epoch::EpochReader;
    use crate::trust_epoch::RedisEpochReader;

    pub(crate) fn redis_url() -> Option<String> {
        let url = std::env::var("MCP_RE_TEST_REDIS_URL")
            .ok()
            .filter(|u| !u.trim().is_empty());
        if url.is_none() && std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
        {
            panic!("MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable");
        }
        url
    }

    /// Distinct per test process and tag; a test that needs the key absent deletes it first.
    pub(crate) fn unique_key(tag: &str) -> String {
        format!("mcp-re:test:trust:epoch:{tag}:{}", std::process::id())
    }

    /// The operator's own connection, which sets the key the way a rollback or an `INCR` would.
    pub(crate) fn admin(url: &str) -> redis::Connection {
        redis::Client::open(url)
            .expect("open redis client")
            .get_connection()
            .expect("admin connection")
    }

    pub(crate) fn set(conn: &mut redis::Connection, key: &str, value: &str) {
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query::<()>(conn)
            .expect("SET");
    }

    fn get(conn: &mut redis::Connection, key: &str) -> Option<String> {
        redis::cmd("GET").arg(key).query(conn).expect("GET")
    }

    #[test]
    fn a_rolled_back_counter_is_moved_past_the_mark_and_a_higher_one_is_left_alone() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP raise live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let key = unique_key("raise");
        let mut operator = admin(&url);
        let replica = RedisEpochReader::connect_lazy(&url, key.clone()).expect("reader");

        set(&mut operator, &key, "2");
        assert_eq!(replica.raise_past(9, 10).expect("raise"), 10);
        assert_eq!(get(&mut operator, &key).as_deref(), Some("10"));
        assert_eq!(replica.read_epoch().expect("read"), 10);

        // A raw INCR on the rolled-back store, at or below the mark, still ends past it.
        set(&mut operator, &key, "2");
        redis::cmd("INCR")
            .arg(&key)
            .query::<i64>(&mut operator)
            .expect("INCR");
        assert_eq!(replica.raise_past(9, 10).expect("raise"), 10);

        set(&mut operator, &key, "12");
        assert_eq!(
            replica.raise_past(9, 10).expect("raise"),
            12,
            "an advance above the mark stays"
        );
        assert_eq!(get(&mut operator, &key).as_deref(), Some("12"));
    }

    #[test]
    fn an_absent_counter_is_created_past_the_mark_and_a_non_integer_is_refused() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP raise live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let key = unique_key("absent");
        let mut operator = admin(&url);
        redis::cmd("DEL")
            .arg(&key)
            .query::<()>(&mut operator)
            .expect("DEL");
        let replica = RedisEpochReader::connect_lazy(&url, key.clone()).expect("reader");

        assert_eq!(replica.raise_past(4, 5).expect("raise"), 5);
        assert_eq!(get(&mut operator, &key).as_deref(), Some("5"));

        set(&mut operator, &key, "not-a-number");
        assert!(replica.raise_past(4, 5).is_err());
        assert_eq!(get(&mut operator, &key).as_deref(), Some("not-a-number"));
    }

    /// Replicas repairing the same rolled-back key at once, over their own connections, each
    /// leave it at or above their own mark whatever the interleaving, and never lower it.
    #[test]
    fn concurrent_repairs_leave_the_counter_at_or_above_every_mark() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP raise live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let mut operator = admin(&url);
        for round in 0..20 {
            let key = unique_key(&format!("race{round}"));
            set(&mut operator, &key, "1");
            let raisers: Vec<_> = [7_i64, 9, 8, 9, 3]
                .into_iter()
                .map(|mark: i64| {
                    let (url, key) = (url.clone(), key.clone());
                    std::thread::spawn(move || {
                        let after = RedisEpochReader::connect_lazy(&url, key)
                            .expect("reader")
                            .raise_past(mark, mark + 1)
                            .expect("raise");
                        (mark, after)
                    })
                })
                .collect();
            for raiser in raisers {
                let (mark, after) = raiser.join().expect("raiser");
                assert!(
                    after >= mark,
                    "a repair never leaves the counter below its mark"
                );
            }
            let end: i64 = get(&mut operator, &key)
                .expect("present")
                .parse()
                .expect("integer");
            assert!((9..=10).contains(&end), "round {round}: {end}");
        }
    }
}
