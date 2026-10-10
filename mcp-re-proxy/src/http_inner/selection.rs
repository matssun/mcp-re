// SPDX-License-Identifier: Apache-2.0
//! WHICH inner backend a dispatch may use, and whether any is usable at all.
//!
//! One authority: the pool's health-aware choice. It reads breaker state and claims the
//! single recovery probe when it takes one. What it does NOT do is run the round trip or
//! fold an outcome back — that is [`super::HttpInnerPool::record_outcome`]'s, and keeping
//! the two apart is what stops a question about the pool from silently changing it.
//!
//! ONE projection leaves this owner: `select_backend`, the claiming form. It used to have a
//! read-only twin, `any_dispatchable`, because the seam's `admit` had to answer the same
//! question without taking anything — and two functions deciding *is a backend usable* from
//! the same atomics is one fact stated twice, with a race living in the gap between the
//! answer and the claim. #741 removed the caller that needed the non-claiming form, so the
//! second statement is gone with it. `rotating_start` and `scan_from` stay private: the
//! order in which backends are tried is this module's business, and a consumer that could
//! ask for it could take the choice apart.
//!
//! The scan ORDER is expressed as a split rather than as `(start + k) % n` reads: the two
//! halves are the order, so it is carried by the iterator instead of by an index recomputed
//! at each step and used to look the backend back up.

use std::sync::atomic::Ordering;

use super::Backend;
use super::HttpInnerPool;
use super::STATE_CLOSED;
use super::STATE_HALF_OPEN;
use super::STATE_OPEN;

impl HttpInnerPool {
    /// Health-aware selection. Returns `(index, is_probe, backend)` of a dispatchable one,
    /// or `None` when every backend is ejected (all Open, cooldown not elapsed) —
    /// the caller then fails closed WITHOUT dispatching.
    ///
    /// Preference order, scanning round-robin from a rotating start so healthy load
    /// spreads evenly:
    ///   1. any `Closed` backend (normal healthy traffic), else
    ///   2. an `Open` backend past its cooldown, claimed as a Half-Open probe, or a
    ///      `HalfOpen` backend with no probe currently in flight.
    pub(super) fn select_backend(&self, now_nanos: u64) -> Option<(usize, bool, &Backend)> {
        let start = self.rotating_start();

        // Pass 1: prefer a healthy (Closed) backend.
        for (i, b) in self.scan_from(start) {
            if b.state.load(Ordering::Acquire) == STATE_CLOSED {
                return Some((i, false, b));
            }
        }

        // Pass 2: no Closed backend — try to claim a single recovery probe.
        for (i, b) in self.scan_from(start) {
            match b.state.load(Ordering::Acquire) {
                STATE_OPEN => {
                    if now_nanos >= b.reopen_at_nanos.load(Ordering::Acquire)
                        && b.state
                            .compare_exchange(
                                STATE_OPEN,
                                STATE_HALF_OPEN,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                    {
                        // The state transition does not itself own the trial; the slot
                        // CAS does, so at most one probe per backend is in flight. A
                        // scanner that took the slot through the HalfOpen arm first
                        // keeps it, and this backend is skipped.
                        if b.probe_inflight
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                        {
                            return Some((i, true, b));
                        }
                    }
                }
                STATE_HALF_OPEN
                    if b.probe_inflight
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok() =>
                {
                    return Some((i, true, b));
                }
                _ => {}
            }
        }

        None
    }

    /// Where this dispatch begins its round-robin scan: a pool index, always.
    ///
    /// Class C. The remainder is total because the pool is NON-EMPTY BY CONSTRUCTION:
    /// `with_breaker_config` refuses an empty backend list, `backends` is private, and
    /// every constructor routes through it. The counter's wrap-around is the intended
    /// algebra — it is a rotation.
    #[allow(clippy::arithmetic_side_effects)]
    fn rotating_start(&self) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed) % self.backends.len()
    }

    /// Every backend once, in scan order from `start`, each paired with its pool index.
    ///
    /// Class B: the rotation is a SPLIT, so the scan order is carried by the iterator
    /// rather than by an index recomputed at each step and used to look the backend back
    /// up, and `split_at_checked` establishes `start`'s range. The index is still yielded
    /// because it is the identity `record_outcome` folds an outcome back onto.
    #[allow(clippy::arithmetic_side_effects)] // `start + k` indexes `self.backends`
    fn scan_from(&self, start: usize) -> impl Iterator<Item = (usize, &Backend)> {
        let (head, tail) = self
            .backends
            .split_at_checked(start)
            .unwrap_or((&self.backends, &[]));
        tail.iter()
            .enumerate()
            .map(move |(k, b)| (start + k, b))
            .chain(head.iter().enumerate())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::BreakerConfig;
    use super::*;

    #[test]
    fn an_open_backend_whose_trial_slot_is_already_taken_is_not_probed_twice() {
        let uri = "http://127.0.0.1:1/mcp".parse().expect("static uri parses");
        let cooldown = Duration::from_secs(30);
        let pool = HttpInnerPool::with_breaker_config(
            vec![uri],
            Duration::from_secs(1),
            BreakerConfig {
                failure_threshold: 1,
                ejection_duration: cooldown,
            },
        )
        .expect("one backend and a non-zero threshold build a pool");

        let (i, is_probe, _) = pool
            .select_backend(0)
            .expect("a closed backend is selected");
        pool.record_outcome(i, is_probe, false, 0);

        let backend = pool.backends.first().expect("one backend");
        backend.probe_inflight.store(true, Ordering::Release);

        let after_cooldown = u64::try_from(cooldown.as_nanos()).expect("30s fits u64") + 1;
        assert!(pool.select_backend(after_cooldown).is_none());
        assert!(backend.probe_inflight.load(Ordering::Acquire));
    }
}
