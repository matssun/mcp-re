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

/// A single-process in-memory continuation store — for unit tests and single-replica
/// runs ONLY. It cannot carry a continuation across replicas (each process has its
/// own map), so a fleet MUST wire the Redis store; this exists so the serving path
/// has a non-`None` store in tests without a Redis dependency.
#[derive(Default)]
pub struct InMemoryContinuationStore {
    /// Entry plus its expiry instant. The TTL is part of the trait contract — RF-07
    /// requires a completed or abandoned continuation chain to leave no correlation
    /// state — and binding it as `_ttl_secs` meant an unanswered continuation lived for
    /// the whole process lifetime, so a long-running single-replica proxy accumulated
    /// retained signature bases that nothing would ever consume. The Redis twin sets a
    /// real key TTL; this is the same bound, enforced on read.
    entries: std::sync::Mutex<std::collections::HashMap<String, (RetainedBases, i64)>>,
}

impl InMemoryContinuationStore {
    /// A fresh empty in-memory store.
    pub fn new() -> Self {
        InMemoryContinuationStore {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Wall-clock seconds. The store owns its own clock because the trait's `store`
    /// takes a DURATION, not an instant, so there is no caller-supplied `now` to
    /// anchor expiry to.
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

impl AsyncContinuationStore for InMemoryContinuationStore {
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, ()> {
        let key = key.to_string();
        let bases = bases.clone();
        Box::pin(async move {
            let now = Self::now();
            let mut entries = self.entries.lock().map_err(poisoned)?;
            // Drop everything already expired on the way past, so an abandoned chain
            // does not accumulate.
            entries.retain(|_, (_, expires_at)| *expires_at > now);
            entries.insert(key, (bases, now.saturating_add(ttl_secs)));
            Ok(())
        })
    }

    fn peek<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>> {
        let key = key.to_string();
        Box::pin(async move {
            let now = Self::now();
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
            let now = Self::now();
            Ok(self
                .entries
                .lock()
                .map_err(poisoned)?
                .remove(&key)
                .is_some_and(|(_, expires_at)| expires_at > now))
        })
    }
}
