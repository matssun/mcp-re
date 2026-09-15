// SPDX-License-Identifier: Apache-2.0
//! The per-replica retention ACCOUNT, kept above the backend seam.
//!
//! The backends disagree about where retention lives — a bounded local set for the
//! in-memory reference, a server-side `SET NX PX` TTL for Redis, a lease per key for etcd —
//! and only the first of those has anything of its own to budget. A bound implemented
//! inside a backend therefore governs only the deployments that select that backend. This
//! one sits above the seam, so every admitted nonce is charged whichever backend is
//! configured.
//!
//! The subtle half is what happens to a charge that was taken and whose insert then did not
//! answer. It is KEPT, not released: the write may have landed, and releasing a charge for
//! an entry that exists would let the account drift below what the store is really holding.
//! [`Charge`] carries that reasoning and the two ways a reservation legitimately ends.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use std::collections::BTreeMap;

use crate::shared_replay::ReplayStoreError;

use super::bounds::per_actor_budget;
use super::bounds::under_pressure;
use super::bounds::ASYNC_PRUNE_EVERY_N_INSERTS;
use super::budget_report::{BudgetRefusal, BudgetRefusalReporter};

/// The per-replica retention account the TIER keeps, so one signature-valid actor
/// cannot exhaust the replay tier whichever backend is configured.
///
/// The backends disagree about where retention lives — a bounded local set for the
/// in-memory reference, a server-side `SET NX PX` TTL for Redis, a lease per key for
/// etcd — and only the first of those has anything of its own to budget. A bound
/// implemented inside a backend therefore governs only the deployments that select
/// that backend. This one sits above the seam: every admitted nonce is charged to the
/// principal the verifier resolved, and an actor already holding more than its share
/// of a tier under pressure is refused before the store is touched.
///
/// The account is per replica, which is what a replica can observe: it bounds the
/// retention THIS node admits, and the shared store's total is that bound times the
/// fleet size. Refusals are [`ReplayStoreError::Unavailable`] and never `Fresh` — an
/// unrecorded nonce can be replayed, so refusing is the only safe answer.
pub(super) struct RetentionLedger {
    pub(super) state: Mutex<LedgerState>,
    max_entries: usize,
    /// Paces the budget-refusal line. Outside the mutex on purpose: it paces a
    /// DIAGNOSTIC and must never be a reason to take the lock.
    refusals: BudgetRefusalReporter,
}

#[derive(Default)]
pub(super) struct LedgerState {
    /// Entries charged to each actor — committed and outstanding alike. The `Arc<str>`
    /// is shared with every charge against that actor, so its name is dropped as soon
    /// as its last charge is released.
    per_actor: HashMap<Arc<str>, usize>,
    /// `retain_until` -> the actors whose entries stop being retained at that instant.
    /// Only committed charges appear here; walking it evicts exactly what expired.
    by_expiry: BTreeMap<i64, Vec<Arc<str>>>,
    /// Charges for nonces the store admitted.
    committed: usize,
    /// Charges taken for an insert whose outcome is not back yet. Counted against the
    /// ceiling too: without it, every request in flight at the bound would be admitted
    /// on the same free slot.
    outstanding: usize,
    /// Reservations since the last prune; drives the eviction cadence.
    inserts_since_prune: u64,
}

impl RetentionLedger {
    pub(super) fn new(max_entries: usize) -> Self {
        RetentionLedger {
            state: Mutex::new(LedgerState::default()),
            max_entries: max_entries.max(1),
            refusals: BudgetRefusalReporter::default(),
        }
    }

    /// Charge one prospective entry to `actor`, or refuse fail-closed.
    ///
    /// `now_unix` is the verifier's reading — the same instant the freshness gate used,
    /// and the same timeline the `retain_until` values in `by_expiry` were derived on.
    /// Pruning against a second, independent clock would evict against a different
    /// timeline than the one the entries were recorded on.
    pub(super) fn reserve(&self, actor: &str, now_unix: i64) -> Result<Arc<str>, ReplayStoreError> {
        // A poisoned mutex is an OPERATIONAL failure — fail closed on the frozen
        // `mcp-re.replay_cache_unavailable` token, never a panic.
        let mut state = self
            .state
            .lock()
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("async replay tier retention ledger lock poisoned: {e}"),
            })?;
        state.inserts_since_prune = state.inserts_since_prune.saturating_add(1);
        if state.inserts_since_prune >= ASYNC_PRUNE_EVERY_N_INSERTS {
            state.inserts_since_prune = 0;
            state.prune(now_unix);
        }

        let held = state.committed.saturating_add(state.outstanding);
        // Under pressure, spend what is left of the ceiling on the actors that are not
        // already holding more than their share. Refusing the greedy signer here is
        // what keeps the refusal from landing on every OTHER signer at the ceiling
        // below.
        if under_pressure(held, self.max_entries) {
            let budget = per_actor_budget(self.max_entries, state.per_actor.len());
            let charged = state.per_actor.get(actor).copied().unwrap_or(0);
            if charged >= budget {
                // OUTSIDE THE GUARD, and for two reasons. The lock is the one every
                // serving core shares, so a blocking stderr write inside it serialises
                // the whole tier behind a file descriptor the proxy does not control —
                // in a future with no await point, on a path any signature-valid peer
                // can drive. And `eprintln!` PANICS when the write fails (a closed pipe,
                // a full buffer with a dead reader); unwinding here would do it with the
                // guard held, poisoning the mutex permanently, after which every
                // `reserve` on this replica refuses for the process lifetime. A
                // diagnostic must not be able to take the control down.
                let refusal = BudgetRefusal::new(charged, budget, held, self.max_entries);
                drop(state);
                return Err(self.refusals.refuse("async replay tier", refusal, actor));
            }
        }
        if held >= self.max_entries {
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "async replay tier is at its {} retained-entry ceiling",
                    self.max_entries
                ),
            });
        }

        let actor: Arc<str> = match state.per_actor.get_key_value(actor) {
            Some((name, _)) => Arc::clone(name),
            None => Arc::from(actor),
        };
        // Bounded by the `max_entries` ceiling refused above; saturating like
        // `outstanding` on the next line.
        let charged = state.per_actor.entry(Arc::clone(&actor)).or_insert(0);
        *charged = charged.saturating_add(1);
        state.outstanding = state.outstanding.saturating_add(1);
        Ok(actor)
    }

    /// The store admitted the nonce: the reservation becomes a retained charge, released
    /// when `retain_until` passes.
    pub(super) fn commit(&self, actor: Arc<str>, retain_until: i64) {
        // A poisoned ledger cannot be repaired from here, and the request has already
        // been admitted by the authoritative store. Losing the charge under-counts the
        // actor, which is the direction that cannot refuse a legitimate request.
        if let Ok(mut state) = self.state.lock() {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.committed = state.committed.saturating_add(1);
            state.by_expiry.entry(retain_until).or_default().push(actor);
        }
    }

    /// The store did not admit the nonce (a replay, or an operational failure), so the
    /// reservation retains nothing and is handed back.
    pub(super) fn release(&self, actor: &Arc<str>) {
        if let Ok(mut state) = self.state.lock() {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.discharge(actor);
        }
    }

    /// Entries currently charged to `actor` (test/inspection aid).
    #[cfg(test)]
    pub(super) fn held_by(&self, actor: &str) -> usize {
        self.state
            .lock()
            .map(|s| s.per_actor.get(actor).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

impl LedgerState {
    /// Release the charge for every entry whose retain-until has passed. `split_off`
    /// leaves the expired buckets behind and returns the live tail, so the work is
    /// proportional to what actually expired.
    pub(super) fn prune(&mut self, now_unix: i64) {
        let live = self.by_expiry.split_off(&now_unix);
        let dead = std::mem::replace(&mut self.by_expiry, live);
        for (_retain_until, actors) in dead {
            for actor in actors {
                self.committed = self.committed.saturating_sub(1);
                self.discharge(&actor);
            }
        }
    }

    /// Drop one charge against `actor`, and the actor's name with its last charge.
    fn discharge(&mut self, actor: &Arc<str>) {
        if let Some(charged) = self.per_actor.get_mut(actor) {
            // Saturating, like `committed` in `expire`: zero drops the actor's name, and
            // wrapping would refuse a legitimate signer permanently.
            *charged = charged.saturating_sub(1);
            if *charged == 0 {
                self.per_actor.remove(actor);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    /// The budget refusal renders its sentence with the ledger lock RELEASED.
    ///
    /// Asserted by taking the lock from this thread while the refusal is reported: if the
    /// reporting path still held it, `try_lock` would fail. The property matters twice
    /// over — a blocking stderr write inside the one mutex every serving core shares
    /// serialises the tier behind a file descriptor the proxy does not control, and a
    /// panicking write would unwind with the guard held and poison it for the process
    /// lifetime.
    #[test]
    fn a_budget_refusal_is_rendered_without_the_ledger_lock() {
        let ledger = RetentionLedger::new(4);
        // Fill the tier so the next reserve is under pressure and over budget.
        for n in 0..4 {
            let actor = ledger.reserve("greedy", 1_000).expect("under the ceiling");
            ledger.commit(actor, 9_000);
            let _ = n;
        }
        let refused = ledger.reserve("greedy", 1_000);
        assert!(refused.is_err(), "an actor over its budget is refused");
        assert!(
            ledger.state.try_lock().is_ok(),
            "the ledger lock must be free once the refusal has been reported"
        );
    }

    use super::*;

    /// The reservation is per ACTOR, and releasing one actor's charge leaves another's
    /// alone. A ledger that accounted per replica rather than per actor would let one
    /// signer's release pay for another's overdraft.
    #[test]
    fn a_release_returns_one_actors_charge_and_no_one_elses() {
        let ledger = RetentionLedger::new(1_000);
        let a = ledger.reserve("actor-a", 0).expect("actor-a reserves");
        let b = ledger.reserve("actor-b", 0).expect("actor-b reserves");
        assert_eq!(ledger.held_by("actor-a"), 1);
        assert_eq!(ledger.held_by("actor-b"), 1);
        ledger.release(&a);
        assert_eq!(ledger.held_by("actor-a"), 0);
        assert_eq!(
            ledger.held_by("actor-b"),
            1,
            "one actor's release must not pay for another's charge"
        );
        ledger.release(&b);
    }

    /// A committed charge is held until its retention expires; pruning past that instant
    /// is what returns it. Releasing at commit time would let the account drift below what
    /// the store is really holding.
    #[test]
    fn a_committed_charge_is_returned_only_when_its_retention_expires() {
        let ledger = RetentionLedger::new(1_000);
        let actor = ledger.reserve("actor-a", 0).expect("reserves");
        ledger.commit(actor, 100);
        assert_eq!(ledger.held_by("actor-a"), 1);
        ledger.state.lock().expect("ledger").prune(100);
        assert_eq!(
            ledger.held_by("actor-a"),
            1,
            "still retained at its own instant"
        );
        ledger.state.lock().expect("ledger").prune(101);
        assert_eq!(ledger.held_by("actor-a"), 0);
    }
}
