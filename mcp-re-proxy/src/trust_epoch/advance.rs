// SPDX-License-Identifier: Apache-2.0
//! The operator's supported way to advance the shared trust epoch: a fresh authoritative
//! advance that every replica can tell apart from a store returning to a value it already saw.
//!
//! A raw `INCR` moves only the number. After a rollback the number can come back to a value a
//! replica has already minted under, and nothing in the store then distinguishes that advance
//! from no change at all. [`run_command`] commits the incremented counter together with a fresh
//! 128-bit generation drawn from the OS, in one server-side step. A replica that reads a
//! generation it has not seen on a counter it has already minted under moves the counter past
//! its own mark before minting again (`signing_plane::epoch_watch`), so an advance ends
//! strictly beyond every epoch a live replica has acknowledged.
//!
//! No floor key is kept beside the counter: the epochs a fleet has acknowledged live in its
//! replicas' high-water marks, and a floor written to the same store would roll back with the
//! counter it was meant to bound. The generation is drawn before anything is written, and a
//! failed draw refuses the advance with the store untouched; there is no fallback generation.
//! The generation gives freshness and collision resistance, not secrecy.

use super::DEFAULT_TRUST_EPOCH_KEY;

/// The key holding the generation of the advance that last set `epoch_key`.
#[cfg(feature = "redis_replay")]
pub(crate) fn generation_key(epoch_key: &str) -> String {
    format!("{epoch_key}:generation")
}

/// A fresh advance's identity: 128 bits from the OS entropy source, as lowercase hex.
#[cfg(any(test, feature = "redis_replay"))]
struct Generation(String);

#[cfg(any(test, feature = "redis_replay"))]
impl Generation {
    /// Draw a generation with `fill`; `None` when the source fails. This is the only
    /// constructor, so every generation was drawn.
    fn draw(fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>) -> Option<Self> {
        let mut bytes = [0u8; 16];
        fill(&mut bytes).ok()?;
        Some(Generation(
            bytes.iter().map(|b| format!("{b:02x}")).collect(),
        ))
    }
}

/// Draw the generation, then commit it. A failed draw never reaches `commit`.
#[cfg(any(test, feature = "redis_replay"))]
fn advance_through(
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
    commit: impl FnOnce(&Generation) -> Result<i64, String>,
) -> Result<i64, String> {
    let generation = Generation::draw(fill).ok_or_else(|| {
        "the OS entropy source failed; the trust epoch was NOT advanced".to_string()
    })?;
    commit(&generation)
}

/// The advance, in one server-side step. `INCR` refuses a non-integer or overflowing counter
/// before anything is written, and the generation is written only beside the counter it names.
#[cfg(feature = "redis_replay")]
const ADVANCE_SCRIPT: &str = "local n = redis.call('INCR', KEYS[1]) \
     redis.call('SET', KEYS[2], ARGV[1]) \
     return n";

#[cfg(feature = "redis_replay")]
fn advance_command(epoch_key: &str, generation: &Generation) -> redis::Cmd {
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(ADVANCE_SCRIPT)
        .arg(2)
        .arg(epoch_key)
        .arg(generation_key(epoch_key))
        .arg(&generation.0);
    cmd
}

/// Advance the counter at `epoch_key` on the store at `url`; returns the new counter.
#[cfg(feature = "redis_replay")]
pub(crate) fn advance(url: &str, epoch_key: &str) -> Result<i64, String> {
    use crate::deployment_request::RedactedLocator;
    advance_through(getrandom::fill, |generation| {
        let client = redis::Client::open(url)
            .map_err(|e| format!("open redis {}: {e}", RedactedLocator::of(url)))?;
        let mut conn = client
            .get_connection_with_timeout(super::TRUST_EPOCH_TIMEOUT)
            .map_err(|e| format!("connect: {e}"))?;
        advance_command(epoch_key, generation)
            .query::<i64>(&mut conn)
            .map_err(|e| format!("advance {epoch_key}: {e}"))
    })
}

/// `trust-epoch advance --trust-epoch-redis-url <url> [--trust-epoch-key <key>]`, the
/// arguments after the binary name's `trust-epoch`. Returns the line to print.
///
/// `pub` because the `mcp-re-proxy` binary is its own crate; it is the operator's one entry
/// point to the advance and exposes nothing but the command.
pub fn run_command(args: &[String]) -> Result<String, String> {
    let (url, key) = parse(args)?;
    #[cfg(feature = "redis_replay")]
    {
        let counter = advance(&url, &key)?;
        Ok(format!(
            "advanced trust epoch {key} to {counter} under a fresh generation; point the \
             verifiers' accepted epochs at the new label"
        ))
    }
    #[cfg(not(feature = "redis_replay"))]
    {
        let _ = (url, key);
        Err("this build has no Redis support (feature redis_replay)".into())
    }
}

/// The store URL and the epoch key; anything else is refused.
fn parse(args: &[String]) -> Result<(String, String), String> {
    const USAGE: &str =
        "usage: mcp-re-proxy trust-epoch advance --trust-epoch-redis-url <url> [--trust-epoch-key <key>]";
    let Some((verb, flags)) = args.split_first() else {
        return Err(USAGE.into());
    };
    if verb != "advance" {
        return Err(format!("unknown trust-epoch command {verb:?}; {USAGE}"));
    }
    let (mut url, mut key) = (None, None);
    let mut rest = flags.iter();
    while let Some(flag) = rest.next() {
        let slot = match flag.as_str() {
            "--trust-epoch-redis-url" => &mut url,
            "--trust-epoch-key" => &mut key,
            other => return Err(format!("unknown flag {other:?}; {USAGE}")),
        };
        let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if slot.replace(value.clone()).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    let url = url.ok_or_else(|| format!("--trust-epoch-redis-url is required; {USAGE}"))?;
    Ok((
        url,
        key.unwrap_or_else(|| DEFAULT_TRUST_EPOCH_KEY.to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::advance_through;
    use super::parse;
    use super::Generation;
    use std::cell::Cell;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A failed draw refuses the advance and never reaches the store: there is no fallback
    /// generation to commit.
    #[test]
    fn a_failed_draw_advances_nothing() {
        let committed = Cell::new(false);
        let outcome = advance_through(
            |_| Err(getrandom::Error::UNSUPPORTED),
            |_| {
                committed.set(true);
                Ok(1)
            },
        );
        assert!(outcome.is_err_and(|e| e.contains("NOT advanced")));
        assert!(!committed.get(), "nothing is written after a failed draw");
    }

    /// The generation committed is the one drawn, 128 bits as 32 hex digits, and two draws
    /// from the OS differ.
    #[test]
    fn the_committed_generation_is_the_drawn_one() {
        let seen = std::cell::RefCell::new(String::new());
        advance_through(
            |bytes| {
                bytes.fill(0xab);
                Ok(())
            },
            |generation| {
                seen.replace(generation.0.clone());
                Ok(7)
            },
        )
        .expect("advance");
        assert_eq!(*seen.borrow(), "ab".repeat(16));
        let a = Generation::draw(getrandom::fill).expect("draw");
        let b = Generation::draw(getrandom::fill).expect("draw");
        assert_eq!(a.0.len(), 32);
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn the_command_takes_the_store_url_and_an_optional_key() {
        assert_eq!(
            parse(&args(&[
                "advance",
                "--trust-epoch-redis-url",
                "rediss://r:6380"
            ])),
            Ok(("rediss://r:6380".into(), "mcp-re:trust:epoch".into()))
        );
        assert_eq!(
            parse(&args(&[
                "advance",
                "--trust-epoch-key",
                "k",
                "--trust-epoch-redis-url",
                "rediss://r"
            ])),
            Ok(("rediss://r".into(), "k".into()))
        );
        for refused in [
            &["advance"][..],
            &["incr", "--trust-epoch-redis-url", "u"],
            &["advance", "--trust-epoch-redis-url"],
            &[
                "advance",
                "--trust-epoch-redis-url",
                "u",
                "--trust-epoch-redis-url",
                "v",
            ],
            &["advance", "--trust-epoch-redis-url", "u", "--extra", "x"],
            &[],
        ] {
            assert!(parse(&args(refused)).is_err(), "{refused:?}");
        }
    }
}

/// The advance against a live Redis. Skipped when `MCP_RE_TEST_REDIS_URL` is unset, and a
/// failure under `MCP_RE_REQUIRE_LIVE_INFRA`.
#[cfg(test)]
#[cfg(feature = "redis_replay")]
mod live {
    use super::advance;
    use super::generation_key;
    use crate::trust_epoch::raise::live::admin;
    use crate::trust_epoch::raise::live::redis_url;
    use crate::trust_epoch::raise::live::set;
    use crate::trust_epoch::raise::live::unique_key;

    fn get(conn: &mut redis::Connection, key: &str) -> Option<String> {
        redis::cmd("GET").arg(key).query(conn).expect("GET")
    }

    /// Each advance increments the counter and writes a new generation beside it; a
    /// non-integer counter is refused with neither key written.
    #[test]
    fn an_advance_commits_the_counter_and_a_fresh_generation_together() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP advance live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let key = unique_key("advance");
        let mut operator = admin(&url);
        set(&mut operator, &key, "4");
        redis::cmd("DEL")
            .arg(generation_key(&key))
            .query::<()>(&mut operator)
            .expect("DEL");

        assert_eq!(advance(&url, &key), Ok(5));
        let first = get(&mut operator, &generation_key(&key)).expect("generation written");
        assert_eq!(advance(&url, &key), Ok(6));
        let second = get(&mut operator, &generation_key(&key)).expect("generation written");
        assert_ne!(first, second);

        set(&mut operator, &key, "not-a-number");
        assert!(advance(&url, &key).is_err());
        assert_eq!(get(&mut operator, &key).as_deref(), Some("not-a-number"));
        assert_eq!(get(&mut operator, &generation_key(&key)), Some(second));
    }

    /// Advances racing over their own connections each get a distinct counter, and the
    /// counter ends at the start plus the number of advances: none is lost or merged.
    #[test]
    fn concurrent_advances_are_each_counted_once() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP advance live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let key = unique_key("advance-race");
        set(&mut admin(&url), &key, "100");
        let racers: Vec<_> = (0..8)
            .map(|_| {
                let (url, key) = (url.clone(), key.clone());
                std::thread::spawn(move || advance(&url, &key).expect("advance"))
            })
            .collect();
        let mut got: Vec<i64> = racers
            .into_iter()
            .map(|r| r.join().expect("racer"))
            .collect();
        got.sort_unstable();
        assert_eq!(got, (101..=108).collect::<Vec<i64>>());
    }
}
