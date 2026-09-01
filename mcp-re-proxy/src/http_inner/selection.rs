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
                        // This thread won the Open→HalfOpen transition; it owns the
                        // trial. (A benign race can admit a second concurrent probe;
                        // both are trial requests, never harmful.)
                        b.probe_inflight.store(true, Ordering::Release);
                        return Some((i, true, b));
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
