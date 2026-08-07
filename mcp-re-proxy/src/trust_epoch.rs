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
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use crate::push_trust::InvalidationChannel;
use crate::push_trust::InvalidationEvent;

/// Take a lock, recovering it if a panic elsewhere poisoned it.
///
/// What these mutexes guard is a queue of pending invalidations, the last epoch this
/// node saw, and two liveness readings — none of which a panic can leave in a state
/// that is unsafe to read. Treating poison as a failure instead drops an operator's
/// revocation on the floor permanently and silently, because the queue is the only
/// path a `FlushAll` has to the trust cache.
fn recover<'a, T>(
    lock: Result<MutexGuard<'a, T>, PoisonError<MutexGuard<'a, T>>>,
) -> MutexGuard<'a, T> {
    lock.unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    /// When [`poll_once`](TrustEpochSource::poll_once) last ran to completion.
    last_poll: Mutex<Option<Instant>>,
    /// How long this source may go unpolled before it stops calling itself healthy.
    /// `None` when no poller was spawned over it (a directly-driven source has no
    /// cadence to fall behind).
    liveness_bound: Mutex<Option<Duration>>,
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
            last_poll: Mutex::new(None),
            liveness_bound: Mutex::new(None),
        }
    }

    /// Start requiring a poll within `bound`, because a poller is now responsible for
    /// producing one. Called by [`spawn_trust_epoch_poller`].
    fn require_polling_within(&self, bound: Duration) {
        *recover(self.liveness_bound.lock()) = Some(bound);
    }

    /// Whether this source has been polled recently enough for `healthy` to still
    /// describe it.
    ///
    /// `healthy` is a latch that only `poll_once` writes, so a poller that has stopped
    /// running — a panic, a thread that never started, a wedged read — leaves it at
    /// whatever it last said, which is `true` for every replica that was working when
    /// it stopped. That replica would keep asserting a one-poll-interval revocation
    /// window it no longer provides, and an operator's `INCR` would never reach its
    /// trust cache. Silence past the bound is therefore unhealthy on its own.
    fn polled_recently(&self) -> bool {
        let Some(bound) = *recover(self.liveness_bound.lock()) else {
            return true;
        };
        match *recover(self.last_poll.lock()) {
            Some(at) => at.elapsed() <= bound,
            // A poller is expected but has not produced its first poll yet: there is no
            // baseline, so there is no invalidation guarantee to claim.
            None => false,
        }
    }

    /// Record that the poller is gone, so `healthy` stops describing a source nothing
    /// is driving.
    fn report_poller_death(&self) {
        *recover(self.healthy.lock()) = false;
        *recover(self.last_poll.lock()) = None;
        eprintln!(
            "mcp-re-proxy: WARNING: the trust-epoch poller thread has stopped; this replica no \
             longer detects epoch advances and now reports its push tier UNHEALTHY, which \
             reverts the surfaced guarantee to the bounded-T trust-cache TTL."
        );
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
        // Recorded whatever the read says: this timestamp is proof the POLLER is
        // running, which is a different question from whether the STORE answered.
        *recover(self.last_poll.lock()) = Some(Instant::now());
        let epoch = match self.reader.read_epoch() {
            Ok(e) => e,
            Err(_) => {
                // Fail closed: mark unhealthy so the honesty contract reverts to
                // bounded-`T`; do NOT advance the baseline, so a change that
                // happened during the outage is still caught on recovery.
                *recover(self.healthy.lock()) = false;
                return;
            }
        };
        *recover(self.healthy.lock()) = true;
        let mut last = recover(self.last_seen.lock());
        match *last {
            None => {
                // First poll: establish the baseline, emit nothing.
                *last = Some(epoch);
            }
            Some(prev) if epoch != prev => {
                // The queue push and the baseline advance have to happen together:
                // advancing without queueing loses the flush permanently, since the
                // next poll sees no further change.
                recover(self.pending.lock()).push(InvalidationEvent::FlushAll);
                *last = Some(epoch);
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
        std::mem::take(&mut *recover(self.pending.lock()))
    }

    /// Healthy means BOTH that the last read succeeded and that a read is still
    /// happening: a latch nothing writes any more says only what was true when the
    /// poller was last alive.
    fn is_healthy(&self) -> bool {
        self.polled_recently() && *recover(self.healthy.lock())
    }
}

// --- Redis-backed reader (feature `redis_replay`) -----------------------------

/// Worst-case wall time ONE [`EpochReader::read_epoch`] may consume.
///
/// The delegated rotation loop reads the epoch on its critical path at `exp - overlap`
/// and cannot mint a successor until the read returns, so this budget is spent out of
/// the rotation overlap. A read allowed to outlast the overlap lets a single
/// half-open (not down) connection consume the whole minting window: the successor is
/// never issued, the current key reaches its `exp`, and every replica answers
/// `mcp-re.delegated_signing_unavailable` on 100% of requests while the root issuer is
/// healthy and the epoch never changed. The default overlap is 60s, so the budget
/// leaves the great majority of it for the mint itself.
#[cfg(feature = "redis_replay")]
const TRUST_EPOCH_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);

/// Bounded network operations in one read: connect, `GET`, and — on a transient error
/// — a reconnect and the retried `GET`.
#[cfg(feature = "redis_replay")]
const TRUST_EPOCH_OPS_PER_READ: u32 = 4;

/// Bounded connect/op timeout so a sinkholed/half-open Redis cannot wedge the
/// serve loop: the trust lookup runs before dispatch, so an unbounded blocking GET
/// would stall the whole proxy. Sized so the WHOLE read fits in
/// [`TRUST_EPOCH_READ_BUDGET`], since it is the read the caller waits on, not one
/// socket operation.
#[cfg(feature = "redis_replay")]
const TRUST_EPOCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(
    TRUST_EPOCH_READ_BUDGET.as_secs() / TRUST_EPOCH_OPS_PER_READ as u64,
);

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

/// Missed poll rounds tolerated before a source calls itself unhealthy. A poll that
/// is merely late — a scheduling delay, a slow read inside its own timeout — must not
/// read as a dead poller.
const TRUST_EPOCH_MISSED_POLLS_TOLERATED: u64 = 3;

/// The body of the trust-epoch poller: poll `source` on a cadence until `stop` says to
/// finish. Returns the work; it does NOT start a thread.
///
/// The caller spawns it through whatever owns its lifetime, so a process-lifetime poller
/// cannot be started by a module that has no way to stop it (ADR-MCPRE-056 §9). Handing
/// back a body rather than taking the owner as a parameter keeps this module free of the
/// runtime's internal lifecycle types.
///
/// The poller is what keeps the blocking store read off the request path (see
/// [`TrustEpochSource::poll_once`]). An immediate first poll establishes the baseline
/// before serving, so the first advance after startup is detected rather than adopted.
///
/// SUPERVISED, because everything downstream believes what this thread last wrote: the
/// source requires a poll within a bound before it will call itself healthy, and a body
/// that unwinds says so on its way out instead of leaving the latch at `true`.
///
/// The liveness bound is registered HERE, before the body is handed back, so a caller
/// that takes the body and never runs it leaves the source failing closed rather than
/// reporting a health it has no poller to earn.
pub fn trust_epoch_poller_body<R: EpochReader + Send + Sync + 'static>(
    source: std::sync::Arc<TrustEpochSource<R>>,
    interval_secs: u64,
    stop: impl Fn() -> bool + Send + 'static,
) -> impl FnOnce() + Send + 'static {
    source.require_polling_within(Duration::from_secs(
        interval_secs
            .max(1)
            .saturating_mul(TRUST_EPOCH_MISSED_POLLS_TOLERATED)
            // The read itself is bounded, and a poll that is out reading has not
            // fallen behind; allow for one full read on top of the missed rounds.
            .saturating_add(interval_secs.max(1)),
    ));
    let poller = std::sync::Arc::clone(&source);
    move || {
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            poller.poll_once();
            // Nap in small increments so a stop is observed within one increment rather
            // than after a whole interval.
            let ticks = interval_secs.saturating_mul(20).max(1); // 20 * 50ms = 1s
            loop {
                for _ in 0..ticks {
                    if stop() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                poller.poll_once();
            }
        }));
        if ran.is_err() {
            source.report_poller_death();
        }
    }
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

    /// The delegated rotation loop blocks on ONE `read_epoch` at `exp - overlap` and
    /// cannot mint until it returns, so the read's worst case is spent out of the
    /// overlap. Sized above it, a single half-open connection consumes the whole
    /// minting window and takes response signing down fleet-wide at the current key's
    /// `exp` — an outage produced by timeout sizing, not by a lost kill switch.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn one_epoch_read_cannot_consume_the_rotation_overlap() {
        /// `--delegated-overlap-secs` default (cli.rs).
        const DEFAULT_OVERLAP: std::time::Duration = std::time::Duration::from_secs(60);
        assert!(
            TRUST_EPOCH_TIMEOUT * TRUST_EPOCH_OPS_PER_READ <= TRUST_EPOCH_READ_BUDGET,
            "every network operation a single read can issue must fit the budget"
        );
        assert!(
            TRUST_EPOCH_READ_BUDGET * 2 <= DEFAULT_OVERLAP,
            "the read must leave the overlap mostly free for the mint it precedes"
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

    /// `healthy` is a latch only `poll_once` writes, so a source nothing polls any
    /// more keeps reporting whatever was true when its poller was last alive — which
    /// is `true` for every replica that was working when the thread died. The replica
    /// then asserts a revocation guarantee (`channel_is_healthy`, the startup posture
    /// line) that it no longer provides.
    #[test]
    fn a_source_that_stops_being_polled_stops_reporting_healthy() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.require_polling_within(std::time::Duration::from_millis(40));
        src.poll_once();
        assert!(src.is_healthy(), "a freshly polled source is healthy");
        // Nothing polls it again.
        std::thread::sleep(std::time::Duration::from_millis(90));
        assert!(
            !src.is_healthy(),
            "silence past the bound is unhealthy on its own"
        );
        // And it recovers the moment polling resumes.
        src.poll_once();
        assert!(src.is_healthy());
    }

    /// A source under a poller that has not produced its first read has no baseline,
    /// so it has no invalidation guarantee to claim either.
    #[test]
    fn a_poller_that_never_ran_is_not_healthy() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.require_polling_within(std::time::Duration::from_secs(60));
        assert!(!src.is_healthy());
    }

    /// A source nobody spawned a poller over is driven directly, so it has no cadence
    /// to fall behind and the liveness bound must not apply to it.
    #[test]
    fn a_directly_driven_source_is_not_subject_to_the_liveness_bound() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.poll_once();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(src.is_healthy());
    }

    /// A poisoned queue used to swallow the FlushAll silently — `poll_once` skipped
    /// the push, `drain_pending` returned an empty vec forever, and neither touched
    /// `healthy`. The operator's `INCR` then never reached this node's trust cache.
    #[test]
    fn a_poisoned_queue_still_delivers_the_flush() {
        let src = std::sync::Arc::new(TrustEpochSource::new(FakeReader::new(1)));
        src.poll_once(); // baseline @1
        let poisoner = std::sync::Arc::clone(&src);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.pending.lock().expect("first acquisition");
            panic!("poison the queue");
        })
        .join();

        src.reader.set(2);
        src.poll_once();
        assert_eq!(
            src.drain_pending(),
            vec![InvalidationEvent::FlushAll],
            "a revocation must not be lost because a lock is poisoned"
        );
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
