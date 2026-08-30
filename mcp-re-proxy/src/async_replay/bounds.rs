// SPDX-License-Identifier: Apache-2.0
//! How much retention there is, and whose share of it one actor may hold.
//!
//! One definition, applied at two levels. The in-memory L2 applies it to what IT is
//! holding; the [`super::retention_ledger`] applies the same arithmetic per replica, above
//! the backend seam, so a deployment on Redis or etcd — backends with nothing local to
//! budget — gets the same bound. Two copies of this arithmetic is how the two levels would
//! come to disagree about what a fair share is.
//!
//! The reserve is what makes the per-actor budget mean anything. A ceiling alone is a
//! global resource one signer can exhaust, and exhausting it answers
//! `mcp-re.replay_cache_unavailable` to EVERY other signer on the replica — a
//! signature-valid peer streaming distinct fresh nonces takes the whole replay tier down
//! with it. Holding a reserve back means the greedy actor hits its own wall while the store
//! still has room for everyone else.

/// How often (in admitted inserts) a retention level evicts entries past their
/// retain-until.
///
/// Every accepted request adds one entry, and a signature-valid peer can stream
/// distinct fresh nonces at will, so without eviction the set grows with total
/// request volume rather than with the freshness window. Pruning on every insert
/// would itself be O(n); a small cadence amortises it while keeping the bound tight.
/// Mirrors the file-backed cache's `PRUNE_EVERY_N_INSERTS`.
pub(super) const ASYNC_PRUNE_EVERY_N_INSERTS: u64 = 64;

/// Fail-closed ceiling on retained entries. Within a single freshness window a
/// pathological peer can present more distinct fresh nonces than the prune cadence
/// drains, so past this the store refuses further inserts with
/// [`ReplayStoreError::Unavailable`] (→ `mcp-re.replay_cache_unavailable`) rather
/// than growing without bound — never a silent allow. Mirrors the file-backed
/// cache's `MAX_ENTRIES`.
pub(super) const ASYNC_MAX_ENTRIES: usize = 1_000_000;

/// The share of [`ASYNC_MAX_ENTRIES`] no single actor may occupy, as a divisor: the
/// reserve is `max_entries / ASYNC_RESERVE_DIVISOR`.
///
/// The ceiling alone is a global resource one signer can exhaust, and exhausting it
/// answers `mcp-re.replay_cache_unavailable` to EVERY other signer on the replica —
/// a signature-valid peer streaming distinct fresh nonces takes the whole replay tier
/// down with it. Holding a reserve back means the greedy actor hits its own wall while
/// the store still has room for everyone else.
pub(super) const ASYNC_RESERVE_DIVISOR: usize = 5;

/// The per-actor retention budget, evaluated only when the store is under pressure.
///
/// `actors` is the number of actors currently holding entries. The budget is an equal
/// split of the SPENDABLE capacity — the ceiling minus the reserve — so the sum of
/// every actor's budget is `max_entries - reserve` for any number of actors, and the
/// reserve stays unspendable. That is the property the reserve exists for: an actor
/// holding nothing yet is still admitted while an actor over its share is refused.
///
/// Splitting the FULL ceiling instead would make the reserve reachable the moment a
/// second actor appears — `k` actors at `max/k` sum to exactly `max`, the ceiling is
/// hit, and the next signer is refused by the global bound with the reserve already
/// spent. That is the outage this budget was introduced to prevent, merely needing two
/// actors instead of one.
///
/// Minting identities to shrink everyone's share is not free: `actor` is the PRINCIPAL
/// the verifier resolved — an authenticated delegation credential rooted in a trust
/// anchor, with the keyid deliberately excluded (see [`mcp_re_core::ReplayKey`]), so a
/// subject cannot present as several actors by holding several keys.
///
/// Under pressure this is a fair share, which means an actor holding more than its
/// share is refused while its existing entries drain. That is the intended ordering —
/// the greedy signer stops before the quiet one — and it is bounded by the freshness
/// window, not permanent.
pub(super) fn per_actor_budget(max_entries: usize, actors: usize) -> usize {
    let reserve = max_entries / ASYNC_RESERVE_DIVISOR;
    let spendable = max_entries.saturating_sub(reserve);
    // Class C: `.max(1)` on the divisor is why this division is total, and is the reason
    // that call is written at all.
    #[allow(clippy::arithmetic_side_effects)]
    let share = spendable / actors.max(1);
    share.max(1)
}

/// Occupancy at which per-actor budgeting starts applying. Below it the store has room
/// for every caller, so budgeting could only refuse a request the store could have
/// served — one busy legitimate signer must not be throttled for being busy.
pub(super) fn under_pressure(len: usize, max_entries: usize) -> bool {
    len >= max_entries.saturating_sub(max_entries / ASYNC_RESERVE_DIVISOR)
}

// Everything below is test code.
#[cfg(test)]
mod tests {
    use super::*;
    /// The budget tightens as actors appear, and never below one entry.
    #[test]
    fn the_budget_reserves_headroom_and_splits_evenly() {
        // Solo: capped below the ceiling, so a newcomer always has room.
        assert_eq!(per_actor_budget(1_000_000, 1), 800_000);
        // Shared: an equal split of the SPENDABLE capacity, not of the ceiling.
        assert_eq!(per_actor_budget(1_000_000, 2), 400_000);
        assert_eq!(per_actor_budget(1_000_000, 100), 8_000);
        // Never zero — a budget of 0 would refuse every actor and close the tier.
        assert_eq!(per_actor_budget(10, 1_000), 1);
        assert!(under_pressure(800_000, 1_000_000));
        assert!(!under_pressure(799_999, 1_000_000));
    }

    /// The reserve must survive ANY number of actors, which is the whole point of it.
    ///
    /// Splitting the full ceiling makes the reserve reachable as soon as a second actor
    /// appears: `k` budgets of `max/k` sum to exactly `max`, so the store fills, the
    /// global ceiling refuses the next signer, and the outage the budget exists to
    /// prevent needs two actors rather than one.
    #[test]
    fn no_number_of_actors_can_spend_the_reserve() {
        const MAX: usize = 1_000_000;
        let reserve = MAX / ASYNC_RESERVE_DIVISOR;
        for actors in 1..=64usize {
            let total = per_actor_budget(MAX, actors) * actors;
            assert!(
                total <= MAX - reserve,
                "{actors} actors may hold {total} of {MAX}, which leaves \
                 {} against a reserve of {reserve}",
                MAX.saturating_sub(total)
            );
        }
    }
}
