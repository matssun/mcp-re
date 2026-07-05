//! MCPS-84 (ADR-MCPS-049 W2) — trust-epoch invalidation source.
//!
//! A networked [`InvalidationChannel`](crate::push_trust::InvalidationChannel)
//! (ADR-MCPS-021 Tier 3) driven by a **monotonic trust-epoch counter**: an
//! operator bumps a shared epoch (e.g. `INCR mcps:trust:epoch`) whenever the trust
//! store changes (a key revoked or rotated). Each replica polls the epoch; when it
//! has ADVANCED past the last value this node saw, the source emits a single
//! coarse [`InvalidationEvent::FlushAll`] so the bounded trust cache drops all
//! positive entries and re-resolves live.
//!
//! Why an epoch, not pub/sub: pub/sub is fire-and-forget — a replica that
//! reconnects or restarts silently misses a one-shot message and never recovers.
//! An epoch is pull-based and **self-healing**: on any poll a node compares the
//! current epoch to the last it saw, so it detects a change that happened during
//! an outage without having observed the intermediate event. The poll interval is
//! the bounded window `T`; a read failure fails closed (the source goes unhealthy
//! and the cache reverts to its bounded-`T` guarantee — never zero-window).
//!
//! The epoch→event logic is generic over an [`EpochReader`] so it is unit-tested
//! without Redis; [`RedisEpochReader`] (feature `redis_replay`) is the networked
//! reader, proven by the gated live e2e.

use std::sync::Mutex;

use crate::push_trust::InvalidationChannel;
use crate::push_trust::InvalidationEvent;

/// Default Redis key holding the monotonic trust epoch.
pub const DEFAULT_TRUST_EPOCH_KEY: &str = "mcps:trust:epoch";

/// A failure to read the current trust epoch (connection or op error). Surfaced as
/// a source-unhealthy signal → bounded-`T` fallback, never a silent success.
#[derive(Debug)]
pub struct EpochReadError(pub String);

/// The seam between the epoch→invalidation logic and its backend, so the logic is
/// testable without a live store. Implementors read the current monotonic epoch (a
/// missing/unset epoch reads as `0`).
pub trait EpochReader: Send + Sync {
    /// Read the current trust epoch. A missing key MUST read as `0` (baseline), an
    /// operational failure as [`EpochReadError`] (fail closed).
    fn read_epoch(&self) -> Result<i64, EpochReadError>;
}

/// A poll-based, self-healing [`InvalidationChannel`] over an [`EpochReader`].
///
/// On each `drain_pending` it reads the epoch and emits a coarse
/// [`InvalidationEvent::FlushAll`] iff the epoch differs from the last value this
/// node saw (an advance — or, defensively, any change, since a monotonic counter
/// only moves forward and a decrease would mean a store reset that also warrants a
/// flush). The FIRST successful poll only establishes the baseline (no spurious
/// startup flush). A read error marks the source unhealthy and emits nothing.
pub struct TrustEpochSource<R: EpochReader> {
    reader: R,
    last_seen: Mutex<Option<i64>>,
    healthy: Mutex<bool>,
}

impl<R: EpochReader> TrustEpochSource<R> {
    /// A fresh source over `reader`, healthy until the first failed read, with no
    /// baseline yet (the first successful poll establishes it).
    pub fn new(reader: R) -> Self {
        TrustEpochSource {
            reader,
            last_seen: Mutex::new(None),
            healthy: Mutex::new(true),
        }
    }
}

impl<R: EpochReader> InvalidationChannel for TrustEpochSource<R> {
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        let epoch = match self.reader.read_epoch() {
            Ok(e) => e,
            Err(_) => {
                // Fail closed: mark unhealthy so the honesty contract reverts to
                // bounded-`T`; do NOT advance the baseline, so a change that
                // happened during the outage is still caught on recovery.
                if let Ok(mut h) = self.healthy.lock() {
                    *h = false;
                }
                return Vec::new();
            }
        };
        if let Ok(mut h) = self.healthy.lock() {
            *h = true;
        }
        let mut last = match self.last_seen.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        match *last {
            None => {
                // First poll: establish the baseline, emit nothing.
                *last = Some(epoch);
                Vec::new()
            }
            Some(prev) if epoch != prev => {
                *last = Some(epoch);
                vec![InvalidationEvent::FlushAll]
            }
            Some(_) => Vec::new(),
        }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.lock().map(|h| *h).unwrap_or(false)
    }
}

// --- Redis-backed reader (feature `redis_replay`) -----------------------------

/// Bounded connect/op timeout so a sinkholed/half-open Redis cannot wedge the
/// serve loop: the trust lookup runs before dispatch, so an unbounded blocking GET
/// would stall the whole proxy. Mirrors `redis_store::DEFAULT_REDIS_TIMEOUT`.
#[cfg(feature = "redis_replay")]
const TRUST_EPOCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A [`EpochReader`] that reads the trust epoch from a Redis key via `GET`, with a
/// bounded connection and ONE reconnect-and-retry on a broken connection (mirrors
/// `redis_store`'s M19 single-reconnect resilience). Operators advance the epoch
/// with `INCR <key>`.
#[cfg(feature = "redis_replay")]
pub struct RedisEpochReader {
    client: redis::Client,
    conn: Mutex<redis::Connection>,
    epoch_key: String,
}

#[cfg(feature = "redis_replay")]
impl RedisEpochReader {
    /// Connect to `url` and read epoch key `epoch_key` (e.g.
    /// [`DEFAULT_TRUST_EPOCH_KEY`]). Fails closed on an unreachable backend.
    pub fn connect(url: &str, epoch_key: impl Into<String>) -> Result<Self, EpochReadError> {
        let client = redis::Client::open(url)
            .map_err(|e| EpochReadError(format!("open redis {url}: {e}")))?;
        let conn = Self::fresh_conn(&client)?;
        Ok(RedisEpochReader {
            client,
            conn: Mutex::new(conn),
            epoch_key: epoch_key.into(),
        })
    }

    fn fresh_conn(client: &redis::Client) -> Result<redis::Connection, EpochReadError> {
        let c = client
            .get_connection_with_timeout(TRUST_EPOCH_TIMEOUT)
            .map_err(|e| EpochReadError(format!("connect: {e}")))?;
        // Best-effort socket timeouts; a failure to set them is not fatal (the
        // connect timeout already bounded the handshake).
        let _ = c.set_read_timeout(Some(TRUST_EPOCH_TIMEOUT));
        let _ = c.set_write_timeout(Some(TRUST_EPOCH_TIMEOUT));
        Ok(c)
    }
}

/// A Redis error meaning the connection is broken and must be replaced (one
/// reconnect-and-retry). Mirrors `redis_store::is_transient_connection_error`.
#[cfg(feature = "redis_replay")]
fn is_transient(error: &redis::RedisError) -> bool {
    error.is_io_error()
        || error.is_connection_dropped()
        || error.is_connection_refusal()
        || error.is_unrecoverable_error()
}

#[cfg(feature = "redis_replay")]
impl EpochReader for RedisEpochReader {
    fn read_epoch(&self) -> Result<i64, EpochReadError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| EpochReadError("trust-epoch connection lock poisoned".into()))?;
        match redis::cmd("GET")
            .arg(&self.epoch_key)
            .query::<Option<i64>>(&mut *guard)
        {
            Ok(v) => Ok(v.unwrap_or(0)),
            Err(e) if is_transient(&e) => {
                // One reconnect-and-retry: a broken socket is replaced, then the
                // read is attempted once more; a second failure fails closed.
                let mut fresh = Self::fresh_conn(&self.client)?;
                let v = redis::cmd("GET")
                    .arg(&self.epoch_key)
                    .query::<Option<i64>>(&mut fresh)
                    .map_err(|e| EpochReadError(format!("GET after reconnect: {e}")))?;
                *guard = fresh;
                Ok(v.unwrap_or(0))
            }
            Err(e) => Err(EpochReadError(format!("GET {}: {e}", self.epoch_key))),
        }
    }
}

/// Build a networked trust-epoch invalidation source over Redis for the ADR-021
/// Push tier. Returns an error string suitable for a fail-closed startup abort.
#[cfg(feature = "redis_replay")]
pub fn redis_trust_epoch_source(
    url: &str,
    epoch_key: &str,
) -> Result<TrustEpochSource<RedisEpochReader>, String> {
    let reader = RedisEpochReader::connect(url, epoch_key).map_err(|e| e.0)?;
    Ok(TrustEpochSource::new(reader))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scriptable in-memory epoch reader: `Some(n)` reads epoch `n`, `None`
    /// simulates a read failure.
    struct FakeReader {
        epoch: Mutex<Option<i64>>,
    }
    impl FakeReader {
        fn new(initial: i64) -> Self {
            FakeReader {
                epoch: Mutex::new(Some(initial)),
            }
        }
        fn set(&self, epoch: i64) {
            *self.epoch.lock().unwrap() = Some(epoch);
        }
        fn fail(&self) {
            *self.epoch.lock().unwrap() = None;
        }
    }
    impl EpochReader for FakeReader {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            match *self.epoch.lock().unwrap() {
                Some(e) => Ok(e),
                None => Err(EpochReadError("fake reader down".into())),
            }
        }
    }

    #[test]
    fn first_poll_establishes_baseline_without_flush() {
        let src = TrustEpochSource::new(FakeReader::new(7));
        assert!(src.drain_pending().is_empty(), "baseline poll must not flush");
        assert!(src.is_healthy());
        // A steady epoch on the next poll is still no flush.
        assert!(src.drain_pending().is_empty());
    }

    #[test]
    fn epoch_advance_emits_a_single_flush_all() {
        // The test submodule can reach the private `reader` field to script epochs.
        let src = TrustEpochSource::new(FakeReader::new(1));
        assert!(src.drain_pending().is_empty()); // baseline @1
        // Advance the epoch and poll: exactly one FlushAll.
        src.reader.set(2);
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        // No further flush while the epoch is steady.
        assert!(src.drain_pending().is_empty());
        // A second advance flushes again.
        src.reader.set(5);
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
    }

    #[test]
    fn read_error_marks_unhealthy_and_emits_nothing() {
        let src = TrustEpochSource::new(FakeReader::new(3));
        assert!(src.drain_pending().is_empty()); // baseline @3
        src.reader.fail();
        assert!(src.drain_pending().is_empty(), "a read error emits no events");
        assert!(!src.is_healthy(), "a read error marks the source unhealthy");
    }

    #[test]
    fn recovery_after_outage_catches_an_epoch_that_advanced_during_it() {
        // Self-healing: the baseline is NOT advanced during the outage, so a change
        // that happened while the source was down is detected on the first good poll.
        let src = TrustEpochSource::new(FakeReader::new(10));
        assert!(src.drain_pending().is_empty()); // baseline @10
        src.reader.fail();
        assert!(src.drain_pending().is_empty());
        assert!(!src.is_healthy());
        // The epoch advanced to 12 while we were blind; recovery detects it.
        src.reader.set(12);
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        assert!(src.is_healthy(), "a successful read restores health");
    }
}
