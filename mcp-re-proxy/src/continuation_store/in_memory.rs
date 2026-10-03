// SPDX-License-Identifier: Apache-2.0
//! The SINGLE-PROCESS continuation tier: one correlation map behind a mutex.
//!
//! Its own module because it is one of two implementations of the same contract, and the
//! other lives in another crate's feature lane. What it owns beyond the map is the
//! translation of an in-process fault into this tier's vocabulary: a poisoned lock is
//! runtime state, not a fact about the call that met it, and `Unavailable` is what a
//! correlation map nobody can trust means to a continuation — fail closed on the answer
//! leg, un-honourable cross-replica on the open leg.

use super::AsyncContinuationStore;
use super::ContinuationFuture;
use super::ContinuationStoreError;
use super::Creation;
use super::RetainedBases;

/// A poisoned correlation map, as the verdict this store already has for it.
///
/// Class R: a poisoned lock is runtime state, not a fact about this call. The variant is
/// the right one — this module's own documentation says `Unavailable` is "to treat as no
/// retained continuation (fail closed) on the answer leg", and on the open leg that the
/// reply cannot be honoured cross-replica.
fn poisoned<T>(_: std::sync::PoisonError<T>) -> ContinuationStoreError {
    ContinuationStoreError::Unavailable {
        details: "in-process continuation map is poisoned".to_owned(),
    }
}

/// A single-process in-memory continuation store — for TESTS ONLY.
///
/// It is not a shipped tier and not a fallback: no composition root installs it, and a
/// deployment that selected no shared store installs nothing rather than this. It cannot
/// carry a continuation across replicas (each process has its own map), so wiring it into
/// a serving binary would hold a capability the deployment model does not offer and the
/// posture line does not describe. It exists so the serving path has a non-`None` store in
/// tests without a Redis dependency.
#[derive(Default)]
pub struct InMemoryContinuationStore {
    /// Entry plus its monotonic expiry instant. The TTL is part of the trait contract — RF-07
    /// requires a completed or abandoned continuation chain to leave no correlation
    /// state — and binding it as `_ttl_secs` meant an unanswered continuation lived for
    /// the whole process lifetime, so a long-running harness accumulated retained
    /// signature bases that nothing would ever consume. The Redis twin sets a
    /// real key TTL; this is the same bound, enforced on read.
    entries:
        std::sync::Mutex<std::collections::HashMap<String, (RetainedBases, std::time::Instant)>>,
}

impl InMemoryContinuationStore {
    /// A fresh empty in-memory store.
    pub fn new() -> Self {
        InMemoryContinuationStore {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The expiry instant for a TTL taken at `now`. The store owns its own clock because
    /// the trait's `create` takes a DURATION, not an instant, so there is no
    /// caller-supplied `now` to anchor expiry to; a monotonic instant cannot be unreadable
    /// or stepped backwards. A negative TTL is a zero lifetime; `None` is a TTL no instant
    /// can represent.
    fn expiry(now: std::time::Instant, ttl_secs: i64) -> Option<std::time::Instant> {
        let secs = u64::try_from(ttl_secs).unwrap_or(0);
        now.checked_add(std::time::Duration::from_secs(secs))
    }
}

impl InMemoryContinuationStore {
    /// The whole of `create`, synchronously — this tier does no I/O, so the async wrapper
    /// next door is a shape the trait asks for and not a thing this store does.
    ///
    /// Written as its own function so the critical section is a plain body with an early
    /// return rather than a branch nested inside a pinned async block. The lock is what
    /// makes the test and the set ATOMIC: releasing it between the occupancy check and the
    /// insert would reopen the window two racing open legs land in, which is the shape
    /// `create` exists to refuse. The Redis twin gets the same property from `SET NX`.
    fn insert_if_absent(
        &self,
        key: String,
        bases: RetainedBases,
        ttl_secs: i64,
    ) -> Result<Creation, ContinuationStoreError> {
        let now = std::time::Instant::now();
        let expires_at =
            Self::expiry(now, ttl_secs).ok_or_else(|| ContinuationStoreError::Unavailable {
                details: "continuation ttl is not representable".to_owned(),
            })?;
        let mut entries = self.entries.lock().map_err(poisoned)?;
        // Drop everything already expired on the way past, so an abandoned chain does not
        // accumulate — and so the occupancy test below reads LIVE entries only. An expired
        // key is not a collision; it is a key that is free again.
        entries.retain(|_, (_, expires_at)| *expires_at > now);
        if entries.contains_key(&key) {
            return Ok(Creation::Collision);
        }
        entries.insert(key, (bases, expires_at));
        Ok(Creation::Stored)
    }
}

impl AsyncContinuationStore for InMemoryContinuationStore {
    fn create<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, Creation> {
        let key = key.to_string();
        let bases = bases.clone();
        Box::pin(async move { self.insert_if_absent(key, bases, ttl_secs) })
    }

    fn peek<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>> {
        let key = key.to_string();
        Box::pin(async move {
            let now = std::time::Instant::now();
            Ok(self
                .entries
                .lock()
                .map_err(poisoned)?
                .get(&key)
                .filter(|(_, expires_at)| *expires_at > now)
                .map(|(bases, _)| bases.clone()))
        })
    }

    fn consume<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, bool> {
        let key = key.to_string();
        Box::pin(async move {
            // `remove` returning Some is the single-process form of "this call is the
            // one that removed a live entry" — the map lock makes it atomic. An EXPIRED
            // entry is removed but reported as not-live: consuming a continuation past
            // its TTL would honour an answer leg the Redis twin would already have
            // dropped.
            let now = std::time::Instant::now();
            Ok(self
                .entries
                .lock()
                .map_err(poisoned)?
                .remove(&key)
                .is_some_and(|(_, expires_at)| expires_at > now))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::AsyncContinuationStore;
    use super::ContinuationStoreError;
    use super::InMemoryContinuationStore;
    use super::RetainedBases;
    use std::future::Future;
    use std::sync::Arc;

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    fn bases() -> RetainedBases {
        RetainedBases {
            previous_request_base: b"prev-base".to_vec(),
            input_required_response_base: b"irr-base".to_vec(),
        }
    }

    /// A poisoned correlation map is `Unavailable` on ALL THREE operations.
    ///
    /// # What this establishes that the sibling battery cannot
    ///
    /// Every other control over this tier lives in
    /// [`crate::continuation_store`]'s own test module and drives the store through the
    /// trait, which is the right place for the contract. None of them can reach this
    /// path: a poisoned lock is not a value a caller can pass, so the only way to observe
    /// [`super::poisoned`] is from inside the module that owns the map.
    ///
    /// The conjunct is load-bearing rather than tidy. The variant chosen here decides what
    /// the serving path does with a dead thread: `Unavailable` means the answer leg treats
    /// the entry as no retained continuation and fails CLOSED, and the open leg reports
    /// that the reply cannot be honoured cross-replica. The other plausible mapping — a
    /// poisoned map reading as an ABSENT entry — would let a panic under the lock silently
    /// turn a live approval into "no such continuation", which is an answer leg completing
    /// against bytes nobody retained.
    ///
    /// All three operations, not one: they fail in three separate `map_err(poisoned)`
    /// sites, and a control over `peek` alone would leave two of them free to be written
    /// differently.
    #[test]
    fn a_poisoned_correlation_map_is_unavailable_on_every_operation() {
        let store = Arc::new(InMemoryContinuationStore::new());
        block_on(store.create("k", &bases(), 300)).expect("a fresh map stores");

        let poisoner = Arc::clone(&store);
        let died = std::thread::spawn(move || {
            let _guard = poisoner.entries.lock().expect("not yet poisoned");
            panic!("a thread dies holding the correlation map");
        })
        .join();
        assert!(died.is_err(), "the fixture must actually have panicked");

        assert!(
            matches!(
                block_on(store.create("k2", &bases(), 300)),
                Err(ContinuationStoreError::Unavailable { .. })
            ),
            "an open leg must not be told a key is free by a map nobody can trust"
        );
        assert!(
            matches!(
                block_on(store.peek("k")),
                Err(ContinuationStoreError::Unavailable { .. })
            ),
            "a poisoned map must not read as an absent entry — that is an answer leg \
             completing against bytes nobody retained"
        );
        assert!(
            matches!(
                block_on(store.consume("k")),
                Err(ContinuationStoreError::Unavailable { .. })
            ),
            "and consumption must not report a removal it cannot have performed"
        );
    }

    /// A TTL no instant can represent is refused, not stored as an immortal entry.
    #[test]
    fn an_unrepresentable_ttl_is_refused_not_stored() {
        let store = InMemoryContinuationStore::new();
        assert!(matches!(
            block_on(store.create("k", &bases(), i64::MAX)),
            Err(ContinuationStoreError::Unavailable { .. })
        ));
        assert!(matches!(block_on(store.peek("k")), Ok(None)));
    }

    /// Consuming past TTL would honour an answer leg the Redis twin already dropped: an
    /// expired entry is removed but reported not-live.
    #[test]
    fn consuming_an_expired_entry_removes_it_but_reports_not_live() {
        let store = InMemoryContinuationStore::new();
        block_on(store.create("expired", &bases(), -1)).expect("stored");
        assert!(matches!(block_on(store.consume("expired")), Ok(false)));
        assert!(!store
            .entries
            .lock()
            .expect("not poisoned")
            .contains_key("expired"));
        block_on(store.create("live", &bases(), 300)).expect("stored");
        assert!(matches!(block_on(store.consume("live")), Ok(true)));
    }
}
