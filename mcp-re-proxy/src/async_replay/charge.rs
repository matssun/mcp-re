// SPDX-License-Identifier: Apache-2.0
//! One reservation against the [`super::retention_ledger`], and the three ways an insert
//! can end.
//!
//! Three outcomes, not two, because the store round trip has three — and collapsing the
//! third into the second is what let the budget be bypassed. A charge that was taken and
//! whose insert then did not answer is INDETERMINATE: the write may have landed, so
//! releasing it would let the account drift below what the store is really holding.
//!
//! The settlement is a guard rather than a call on each exit path. The charge is taken
//! before the store round-trip and settled after it, and the request in between can simply
//! STOP: the serving path awaits the handler inside a hyper service, so a peer that closes
//! its connection — or a deadline that fires — drops the future mid-await. Settling by hand
//! would leak a charge on exactly the path nobody wrote, and a guard cannot miss the path
//! it was not written for.

use std::sync::Arc;

use crate::shared_replay::ReplayStoreError;

use super::retention_ledger::RetentionLedger;

/// How an insert's retention was settled against the ledger.
///
/// Three outcomes, not two, because the store round trip has three. Collapsing the third
/// into the second is what let the budget be bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settlement {
    /// No answer has been consumed yet. For a remote store the write may already have
    /// landed, so this is UNKNOWN-whether-retained, never proven-absent.
    Indeterminate,
    /// The store answered `Fresh`: the entry exists and is retained until `retain_until`.
    Retained,
    /// The store answered authoritatively that THIS insert retained nothing — a `Replay`,
    /// where the entry was already present and already charged to whoever created it.
    ProvenAbsent,
}

/// One reservation, held for as long as its insert is in flight.
///
/// The charge is taken before the store round-trip and settled after it, and the
/// request in between can simply STOP: the serving path awaits the handler inside a
/// hyper service, so a peer that closes its connection (or a deadline that fires) drops
/// the future mid-await. Settling by hand on each exit path would leak a charge on
/// exactly that one, so the settlement is a guard: a guard cannot miss the path it was
/// not written for.
///
/// # What an unsettled charge means
///
/// [`Settlement::Indeterminate`] is the DEFAULT, and dropping while still in it does not
/// hand the charge back. Retention for the Redis and etcd backends is created by the round
/// trip itself — a `SET NX PX`, an etcd lease — so a future dropped after the command
/// reached the server and before its reply was consumed has, as far as this process can
/// know, retained an entry. Handing the charge back there would be recording did-not-retain
/// for unknown-whether-retained, and it is a bypass rather than a rounding error: a peer
/// that aborts its connection after every request writes keys into a shared store whose
/// only bound is this ledger, while its occupancy stays at zero and `under_pressure` never
/// trips.
///
/// So an indeterminate charge is kept, on the same `retain_until` timeline as a committed
/// one. If the write landed, the account is right; if it did not, the actor is over-charged
/// for at most the freshness window and `prune` reclaims it. Over-charging costs one actor
/// some of its own budget; under-charging costs every signer the tier.
pub(super) struct Charge {
    ledger: Arc<RetentionLedger>,
    actor: Arc<str>,
    /// The instant the entry this charge accounts for stops being retained. Known before
    /// the round trip, so an indeterminate settlement can still be given a real expiry
    /// rather than being held forever or dropped.
    retain_until: i64,
    settlement: Settlement,
}

impl Charge {
    /// Charge one prospective entry to `actor`, or refuse fail-closed.
    pub(super) fn reserve(
        ledger: &Arc<RetentionLedger>,
        actor: &str,
        now_unix: i64,
        retain_until: i64,
    ) -> Result<Charge, ReplayStoreError> {
        let actor = ledger.reserve(actor, now_unix)?;
        Ok(Charge {
            ledger: Arc::clone(ledger),
            actor,
            retain_until,
            settlement: Settlement::Indeterminate,
        })
    }

    /// The store admitted the nonce, so the reservation becomes retention that expires
    /// with it rather than with this request.
    pub(super) fn commit(mut self) {
        self.settlement = Settlement::Retained;
        self.ledger
            .commit(Arc::clone(&self.actor), self.retain_until);
    }

    /// The store reported a replay: the entry was already there, so this insert added no
    /// retention and the reservation is handed back.
    ///
    /// The ONLY proven-absent settlement. An error is not one — a store that failed to
    /// answer has not said the write did not happen.
    pub(super) fn release_proven_absent(mut self) {
        self.settlement = Settlement::ProvenAbsent;
        self.ledger.release(&self.actor);
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        match self.settlement {
            // Already settled eagerly by the consuming method.
            Settlement::Retained | Settlement::ProvenAbsent => {}
            // Cancelled mid-await, or an error that leaves the write's fate unknown. Keep
            // the charge, expiring with the entry it may have created.
            Settlement::Indeterminate => {
                self.ledger
                    .commit(Arc::clone(&self.actor), self.retain_until);
            }
        }
    }
}
