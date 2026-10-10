// SPDX-License-Identifier: Apache-2.0
//! The rotor's health, as counters an observer reads without locking.

use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Cold-path rotation observability (ADR-MCPRE-052 §6, MCPRE-122). Plain atomic
/// counters the single rotor owner writes and reads without locking. The proxy has no
/// health or metrics endpoint: its operator surface for rotor health is stderr, where
/// each rotation success line carries `rotations_ok` and each issuance failure line the
/// other three, so nothing reports a failing rotor as healthy. NONE of these touch the
/// hot signing path — they describe the rotor's health, not per-request work.
///
/// `time-to-expiry` is intentionally NOT stored here: it is a function of the live
/// snapshot and `now`, so it is computed on demand from
/// [`DelegatedServerSigner::seconds_to_expiry`](super::DelegatedServerSigner::seconds_to_expiry) rather than cached and left to go stale.
#[derive(Debug, Default)]
pub struct DelegatedRotationMetrics {
    /// Total successful issue/rotate cycles.
    rotations_ok: AtomicU64,
    /// Total failed rotation attempts (root issuer unavailable at attempt time).
    rotation_failures: AtomicU64,
    /// Failures since the last success — the exponential-backoff attempt counter. Reset
    /// to 0 on any success. A non-zero value means the rotor is retrying issuance.
    consecutive_failures: AtomicU64,
    /// Unix seconds of the last successful rotation (0 before the first).
    last_success_unix: AtomicI64,
}

impl DelegatedRotationMetrics {
    /// Record a successful rotation at `now`: bump the success counter, reset the
    /// consecutive-failure streak, and stamp the success time.
    pub fn record_success(&self, now: i64) {
        self.rotations_ok.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success_unix.store(now, Ordering::Relaxed);
    }

    /// Record a failed rotation attempt and return the new consecutive-failure count
    /// (≥ 1) that drives the backoff schedule.
    pub fn record_failure(&self) -> u32 {
        self.rotation_failures.fetch_add(1, Ordering::Relaxed);
        let prev = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        // Saturating, then clamped to the width the backoff schedule reads. A streak
        // counter's ceiling is the most-backed-off end; wrapping would restore the
        // shortest retry interval for a rotation that has never succeeded.
        prev.saturating_add(1).min(u32::MAX as u64) as u32
    }

    /// Total successful rotations.
    pub fn rotations_ok(&self) -> u64 {
        self.rotations_ok.load(Ordering::Relaxed)
    }

    /// Total failed rotation attempts.
    pub fn rotation_failures(&self) -> u64 {
        self.rotation_failures.load(Ordering::Relaxed)
    }

    /// Failures since the last success (0 in steady state).
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last successful rotation (0 before the first).
    pub fn last_success_unix(&self) -> i64 {
        self.last_success_unix.load(Ordering::Relaxed)
    }
}
