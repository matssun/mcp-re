//! MCPS-84 (ADR-MCPS-049 W2) — trust-epoch invalidation source.
//!
//! A networked [`InvalidationChannel`](crate::push_trust::InvalidationChannel)
//! (ADR-MCPS-021 Tier 3) driven by a **monotonic trust-epoch counter**: an
//! operator bumps a shared epoch (e.g. `INCR mcp-re:trust:epoch`) whenever the trust
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
pub const DEFAULT_TRUST_EPOCH_KEY: &str = "mcp-re:trust:epoch";

/// A failure to read the current trust epoch (connection or op error). Surfaced as
/// a source-unhealthy signal → bounded-`T` fallback, never a silent success.
#[derive(Debug)]
pub struct EpochReadError(pub String);

/// The seam between the epoch→invalidation logic and its backend, so the logic is
/// testable without a live store. Implementors read the current monotonic epoch (a
/// missing/unset epoch reads as `0`).
pub trait EpochReader: Send + Sync {
    /// Read the current trust epoch. An ABSENT key and an operational failure are
    /// both [`EpochReadError`] (fail closed) — see
    /// [`RedisEpochReader::require_present`] for why absence is not a baseline.
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
    /// Events produced by [`poll_once`](TrustEpochSource::poll_once) and not yet
    /// drained. This is what keeps the store read OFF the request path.
    pending: Mutex<Vec<InvalidationEvent>>,
}

impl<R: EpochReader> TrustEpochSource<R> {
    /// A fresh source over `reader`, healthy until the first failed read, with no
    /// baseline yet (the first successful poll establishes it).
    pub fn new(reader: R) -> Self {
        TrustEpochSource {
            reader,
            last_seen: Mutex::new(None),
            healthy: Mutex::new(true),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Read the epoch ONCE and queue a [`InvalidationEvent::FlushAll`] if it moved.
    ///
    /// **Called from a background poller, never from the request path.** The read is a
    /// blocking network round trip behind a single connection mutex, and
    /// `TrustResolver::resolve` runs it before signature verification for any kid
    /// present in the trust file. Inline, that made every served request pay a Redis
    /// round trip serialized across the whole fleet on one connection — so a
    /// half-open store stalled the per-core runtimes for the socket timeout, and an
    /// unauthenticated peer replaying an observed `keyid` could force it. It also
    /// inverted the tier: a Tier-3 cache HIT cost a network read, making it more
    /// expensive than Tier 2.
    ///
    /// Polling on a cadence changes the honest guarantee from "flush on the next
    /// request after an advance" to "flush within one poll interval", which is what
    /// the startup line now says.
    pub fn poll_once(&self) {
        let epoch = match self.reader.read_epoch() {
            Ok(e) => e,
            Err(_) => {
                // Fail closed: mark unhealthy so the honesty contract reverts to
                // bounded-`T`; do NOT advance the baseline, so a change that
                // happened during the outage is still caught on recovery.
                if let Ok(mut h) = self.healthy.lock() {
                    *h = false;
                }
                return;
            }
        };
        if let Ok(mut h) = self.healthy.lock() {
            *h = true;
        }
        let mut last = match self.last_seen.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        match *last {
            None => {
                // First poll: establish the baseline, emit nothing.
                *last = Some(epoch);
            }
            Some(prev) if epoch != prev => {
                *last = Some(epoch);
                if let Ok(mut pending) = self.pending.lock() {
                    pending.push(InvalidationEvent::FlushAll);
                }
            }
            Some(_) => {}
        }
    }
}

impl<R: EpochReader> InvalidationChannel for TrustEpochSource<R> {
    /// Take whatever the background poller has queued. NO I/O: this is on the request
    /// path (`PushInvalidationTrustCache::resolve` calls it before every lookup), so
    /// it must cost a mutex acquisition and nothing more.
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        match self.pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => Vec::new(),
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
    /// `None` until the first successful connection. Deferring it lets a replica start
    /// (and keep retrying) while the epoch store is briefly unreachable, instead of the
    /// one-shot startup connect that used to leave a replica with no cross-replica
    /// kill switch for its entire lifetime.
    conn: Mutex<Option<redis::Connection>>,
    epoch_key: String,
}

#[cfg(feature = "redis_replay")]
impl RedisEpochReader {
    /// An ABSENT epoch key is a read FAILURE, not epoch 0.
    ///
    /// Redis nil used to map to `Ok(0)`, indistinguishable from a live counter at 0.
    /// Two things followed, both silent:
    ///
    ///   * The source reported itself HEALTHY and established 0 as its baseline, so
    ///     it never emitted a flush. A `--trust-epoch-key` pointing at a name nobody
    ///     INCRs, at the wrong database, or at a key that has since been deleted left
    ///     the Tier-3 kill switch inert while the startup line still advertised a
    ///     near-zero revocation window. The operator's `INCR` never reached the data
    ///     plane.
    ///   * On the response side, a counter lost to a snapshot restore, FLUSHDB, LRU
    ///     eviction (the key carries no TTL) or a failover to a replica that never saw
    ///     the INCR read back as 0, and a restarting replica — whose `high_water`
    ///     guard is per-process and starts empty — re-minted under `<base>#0`. Inside
    ///     the bounded `{current, previous}` acceptance window that silently UNDOES a
    ///     revocation the operator performed.
    ///
    /// Failing closed makes both of those an unhealthy source, which reverts the
    /// surfaced guarantee to bounded-`T` and refuses to mint under a rolled-back
    /// epoch. Seeding the key (`SET <key> 0`) is a one-line deployment step; silently
    /// treating its absence as a live baseline is not recoverable after the fact.
    fn require_present(value: Option<i64>, epoch_key: &str) -> Result<i64, EpochReadError> {
        value.ok_or_else(|| {
            EpochReadError(format!(
                "trust-epoch key {epoch_key:?} does not exist. An absent key is NOT epoch 0: it \
                 is indistinguishable from a counter that was never created, was deleted, or \
                 was lost to a restore/eviction, and reading it as a baseline would leave the \
                 push kill switch inert or let a restarted replica mint under a rolled-back \
                 epoch. Seed it with SET {epoch_key} 0 (or INCR it) before serving."
            ))
        })
    }

    /// Connect to `url` and read epoch key `epoch_key` (e.g.
    /// [`DEFAULT_TRUST_EPOCH_KEY`]). Fails closed on an unreachable backend.
    pub fn connect(url: &str, epoch_key: impl Into<String>) -> Result<Self, EpochReadError> {
        let reader = Self::connect_lazy(url, epoch_key)?;
        // Eager callers want the connection proven now.
        reader.read_epoch()?;
        Ok(reader)
    }

    /// Build a reader WITHOUT contacting the store. `redis::Client::open` only parses
    /// the URL, so this cannot fail on an unreachable backend; the connection is
    /// established on the first [`read_epoch`](EpochReader::read_epoch) and re-established
    /// after any failure. A read while the store is down still returns
    /// [`EpochReadError`] — lazy connectivity changes WHEN we try, never whether an
    /// unreadable epoch is treated as fail-closed.
    pub fn connect_lazy(url: &str, epoch_key: impl Into<String>) -> Result<Self, EpochReadError> {
        let client = redis::Client::open(url)
            .map_err(|e| EpochReadError(format!("open redis {url}: {e}")))?;
        Ok(RedisEpochReader {
            client,
            conn: Mutex::new(None),
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
        // Not connected yet (first read, or a previous failure dropped the socket):
        // establish now. A failure here is an ordinary fail-closed read error.
        if guard.is_none() {
            *guard = Some(Self::fresh_conn(&self.client)?);
        }
        let conn = guard.as_mut().expect("connection established above");
        match redis::cmd("GET")
            .arg(&self.epoch_key)
            .query::<Option<i64>>(conn)
        {
            Ok(v) => Self::require_present(v, &self.epoch_key),
            Err(e) if is_transient(&e) => {
                // One reconnect-and-retry: a broken socket is replaced, then the
                // read is attempted once more; a second failure fails closed. The
                // socket is dropped on failure so the NEXT read reconnects rather
                // than reusing a known-broken connection.
                *guard = None;
                let mut fresh = Self::fresh_conn(&self.client)?;
                let v = redis::cmd("GET")
                    .arg(&self.epoch_key)
                    .query::<Option<i64>>(&mut fresh)
                    .map_err(|e| EpochReadError(format!("GET after reconnect: {e}")))?;
                *guard = Some(fresh);
                Self::require_present(v, &self.epoch_key)
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

/// Poll `source` on a cadence from a dedicated thread until `shutdown` flips.
///
/// The poller is what keeps the blocking store read off the request path (see
/// [`TrustEpochSource::poll_once`]). An immediate first poll establishes the baseline
/// before serving, so the first advance after startup is detected rather than adopted.
pub fn spawn_trust_epoch_poller<R: EpochReader + Send + Sync + 'static>(
    source: std::sync::Arc<TrustEpochSource<R>>,
    interval_secs: u64,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        source.poll_once();
        // Nap in small increments so a shutdown signal is observed within one
        // increment rather than after a whole interval.
        let ticks = interval_secs.saturating_mul(20).max(1); // 20 * 50ms = 1s
        loop {
            for _ in 0..ticks {
                if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            source.poll_once();
        }
    });
}

/// An [`InvalidationChannel`] view of a shared [`TrustEpochSource`], so the poller
/// thread and the request path hold the same source.
pub struct SharedEpochChannel<R: EpochReader>(pub std::sync::Arc<TrustEpochSource<R>>);

impl<R: EpochReader> InvalidationChannel for SharedEpochChannel<R> {
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        self.0.drain_pending()
    }
    fn is_healthy(&self) -> bool {
        self.0.is_healthy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scriptable in-memory epoch reader: `Some(n)` reads epoch `n`, `None`
    /// simulates a read failure.
    struct FakeReader {
        epoch: Mutex<Option<i64>>,
        /// Counts reads, so a test can assert the REQUEST path performs none.
        reads: std::sync::atomic::AtomicUsize,
    }
    impl FakeReader {
        fn new(initial: i64) -> Self {
            FakeReader {
                epoch: Mutex::new(Some(initial)),
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn set(&self, epoch: i64) {
            *self.epoch.lock().unwrap() = Some(epoch);
        }
        fn fail(&self) {
            *self.epoch.lock().unwrap() = None;
        }
        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl EpochReader for FakeReader {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match *self.epoch.lock().unwrap() {
                Some(e) => Ok(e),
                None => Err(EpochReadError("fake reader down".into())),
            }
        }
    }

    #[test]
    fn first_poll_establishes_baseline_without_flush() {
        let src = TrustEpochSource::new(FakeReader::new(7));
        src.poll_once();
        assert!(
            src.drain_pending().is_empty(),
            "baseline poll must not flush"
        );
        assert!(src.is_healthy());
        // A steady epoch on the next poll is still no flush.
        src.poll_once();
        assert!(src.drain_pending().is_empty());
    }

    #[test]
    fn epoch_advance_emits_a_single_flush_all() {
        // The test submodule can reach the private `reader` field to script epochs.
        // `poll_once` is the READ (background thread); `drain_pending` is the queue
        // the request path takes and does no I/O of its own.
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @1
                                                 // Advance the epoch and poll: exactly one FlushAll.
        src.reader.set(2);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        // No further flush while the epoch is steady.
        src.poll_once();
        assert!(src.drain_pending().is_empty());
        // A second advance flushes again.
        src.reader.set(5);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
    }

    /// The property the poller exists for: draining costs NO store read. Inline, this
    /// was a blocking Redis round trip on every served request, serialized fleet-wide
    /// behind one connection mutex and reached before signature verification.
    #[test]
    fn draining_does_not_read_the_store() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.poll_once();
        let before = src.reader.reads();
        for _ in 0..100 {
            let _ = src.drain_pending();
        }
        assert_eq!(
            src.reader.reads(),
            before,
            "the request path must not touch the store"
        );
    }

    #[test]
    fn read_error_marks_unhealthy_and_emits_nothing() {
        let src = TrustEpochSource::new(FakeReader::new(3));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @3
        src.reader.fail();
        src.poll_once();
        assert!(
            src.drain_pending().is_empty(),
            "a read error emits no events"
        );
        assert!(!src.is_healthy(), "a read error marks the source unhealthy");
    }

    #[test]
    fn recovery_after_outage_catches_an_epoch_that_advanced_during_it() {
        // Self-healing: the baseline is NOT advanced during the outage, so a change
        // that happened while the source was down is detected on the first good poll.
        let src = TrustEpochSource::new(FakeReader::new(10));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @10
        src.reader.fail();
        src.poll_once();
        assert!(src.drain_pending().is_empty());
        assert!(!src.is_healthy());
        // The epoch advanced to 12 while we were blind; recovery detects it.
        src.reader.set(12);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        assert!(src.is_healthy(), "a successful read restores health");
    }
}
