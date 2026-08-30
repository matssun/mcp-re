// SPDX-License-Identifier: Apache-2.0
//! What the reference L2 is holding, and how it stops holding it.
//!
//! The REPRESENTATION and its two mutations, kept apart from the store's policy. The store
//! decides whether an insert is admitted; this decides what *admitted* looks like in
//! memory, and it is the only thing that touches the three maps — so the per-actor
//! accounting cannot drift from the set it accounts for by anyone editing one of them.
//!
//! Two structural choices carry the cost argument. Eviction walks `by_expiry` buckets
//! rather than sweeping `seen`, because a sweep is O(max_entries) — a million-entry scan,
//! plus a map lookup per evicted entry — inside the one mutex every per-core serving
//! runtime shares, in a future with no await point; at the ceiling that is a global
//! serialization point on the request path. And an entry's expiry is the bucket it sits in
//! rather than a field beside it, because two copies of an instant eviction must agree on
//! is a way for them to disagree.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use super::bounds::ASYNC_PRUNE_EVERY_N_INSERTS;

#[derive(Default)]
pub(super) struct RetainedSet {
    /// composite key -> the retained entry.
    pub(super) seen: HashMap<String, RetainedEntry>,
    /// `retain_until` -> the keys that stop being retained at that instant.
    ///
    /// Eviction walks only the buckets that have actually expired. Sweeping `seen`
    /// instead is O(max_entries) — a million-entry scan, plus a map lookup per evicted
    /// entry — inside the one mutex every per-core serving runtime shares, in a future
    /// with no await point. At the ceiling that is a global serialization point on the
    /// request path, which is the opposite of what this store claims to be.
    pub(super) by_expiry: BTreeMap<i64, Vec<String>>,
    /// Admitted inserts since the last prune; drives the eviction cadence.
    inserts_since_prune: u64,
    /// Retained entries per actor. The `Arc<str>` is shared with every entry charged
    /// to that actor, so an actor's name is dropped as soon as its last entry is
    /// pruned — the accounting map cannot outgrow the set it accounts for.
    pub(super) per_actor: HashMap<Arc<str>, usize>,
}

/// One retained entry: who is holding it.
///
/// The instant it stops being retained is the `by_expiry` bucket it sits in, so it is
/// not repeated here — two copies of an expiry that eviction must agree on is a way for
/// them to disagree.
pub(super) struct RetainedEntry {
    actor: Arc<str>,
}

/// A unix-seconds clock. Local to this module so the async in-memory store keeps its
/// eviction anchor in the default build — `redis_store`'s twin is feature-gated.
pub(super) type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Wall-clock unix seconds; the production anchor for the inline prune.
pub(super) fn system_clock() -> UnixClock {
    Box::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

impl RetainedSet {
    /// Evict everything past its retain-until, on a bounded cadence.
    ///
    /// The anchor is the STORE's own clock — never the caller's `retain_until`, which is
    /// derived from the request's `expires` and can sit arbitrarily far ahead of real time,
    /// so using it would over-evict still-live entries and reopen a replay window.
    pub(super) fn prune_if_due(&mut self, clock: &UnixClock) {
        let state = self;
        state.inserts_since_prune = state.inserts_since_prune.saturating_add(1);
        if state.inserts_since_prune >= ASYNC_PRUNE_EVERY_N_INSERTS {
            state.inserts_since_prune = 0;
            let now = clock();
            let RetainedSet {
                seen,
                by_expiry,
                per_actor,
                ..
            } = &mut *state;
            // Only the buckets strictly before `now` have stopped being retained.
            // `split_off` leaves those behind and returns the live tail, so the work is
            // proportional to what actually expired — and a prune with nothing to do
            // costs one B-tree descent rather than a full scan.
            let live = by_expiry.split_off(&now);
            let dead = std::mem::replace(by_expiry, live);
            for (_retain_until, keys) in dead {
                for key in keys {
                    // A key can only leave `seen` through this loop, but the guard
                    // keeps the accounting honest if that ever stops being true.
                    let Some(entry) = seen.remove(&key) else {
                        continue;
                    };
                    // The per-actor charge is released with the entry it accounts for,
                    // and the actor's last release drops its name from the map
                    // entirely.
                    if let Some(held) = per_actor.get_mut(&entry.actor) {
                        // Saturating is the algebra of a charge count: zero is the state
                        // that drops the actor's name. Wrapping would leave it holding
                        // `usize::MAX` and refuse a legitimate signer for the life of
                        // the process.
                        *held = held.saturating_sub(1);
                        if *held == 0 {
                            per_actor.remove(&entry.actor);
                        }
                    }
                }
            }
        }
    }

    /// Record one retained entry, and charge it to its actor.
    pub(super) fn record(&mut self, key: &str, actor: &str, retain_until: i64) {
        let state = self;
        // One `Arc<str>` per actor, shared by every entry charged to it, so the entry
        // map carries a pointer rather than a copy of the signer id.
        let actor: Arc<str> = match state.per_actor.get_key_value(actor) {
            Some((name, _)) => Arc::clone(name),
            None => Arc::from(actor),
        };
        // Bounded by the retained-entry ceiling this set is admitted under; saturating
        // names the direction that stays restrictive.
        let charged = state.per_actor.entry(Arc::clone(&actor)).or_insert(0);
        *charged = charged.saturating_add(1);
        state
            .by_expiry
            .entry(retain_until)
            .or_default()
            .push(key.to_string());
        state.seen.insert(key.to_string(), RetainedEntry { actor });
    }
}
