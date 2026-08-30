// SPDX-License-Identifier: Apache-2.0
//! The fixed table every stage accumulates into, and the one place a [`Stage`] becomes an
//! index into it.
//!
//! The table's width IS the enum's cardinality, as a compile-time fact rather than a
//! counted one — which is what makes every stage-keyed access total. Routing them all
//! through [`Acc::cell`] keeps that argument in one place instead of restated at each site
//! that used to index directly (`docs/dev/partial-operations.md`, class C).

use std::sync::atomic::AtomicU64;

use super::Stage;

pub(super) const STAGES: usize = 12;
pub(super) const NAMES: [&str; STAGES] = [
    "admission",
    "body_read",
    "handler",
    "replay_insert",
    "inner_dispatch",
    "total",
    "scheduler_latency",
    "verify",
    "sign",
    "replay_prep",
    "replay_set",
    "replay_wait",
];

/// The table width IS the enum's cardinality, as a compile-time fact rather than a counted
/// one. The discriminants run contiguously from `0`, so adding a variant without widening
/// `NAMES` and `Acc` stops the build here rather than indexing past the end at runtime.
const _: () = assert!(Stage::ReplayWait as usize + 1 == STAGES);

pub(super) struct Acc {
    pub(super) nanos: [AtomicU64; STAGES],
    pub(super) count: [AtomicU64; STAGES],
    pub(super) reported: AtomicU64,
    /// Replay calls currently between entry and exit.
    pub(super) inflight: AtomicU64,
    /// Sum of the occupancy observed on entry, and how many entries — their ratio is
    /// the mean concurrency actually reaching the store.
    pub(super) inflight_sum: AtomicU64,
    pub(super) inflight_samples: AtomicU64,
    pub(super) inflight_max: AtomicU64,
}

impl Acc {
    /// The `(nanos, count)` cell one stage accumulates into.
    ///
    /// Class C, and the single place a `Stage` becomes an index: the tables are `STAGES`
    /// wide, `STAGES` is the enum's cardinality as the assertion above checks, and a
    /// `Stage` has no inhabitant outside its own discriminants.
    #[allow(clippy::indexing_slicing)]
    pub(super) fn cell(&self, stage: Stage) -> (&AtomicU64, &AtomicU64) {
        let i = stage as usize;
        (&self.nanos[i], &self.count[i])
    }
}
